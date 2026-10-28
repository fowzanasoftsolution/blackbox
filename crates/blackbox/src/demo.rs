//! Phase 7 — `blackbox demo`: every capability in ~60 seconds (5 s of
//! scripted traffic + optional lingering dashboard).
//!
//! Boots a fully self-contained topology IN-PROCESS (no network, no other
//! services):
//!
//! ```text
//!   you (scripted traffic)
//!        │
//!        ▼
//!   [blackbox ingress]──► demo shop app ──X-Blackbox-Target──► [blackbox egress] ─► demo LLM provider
//!        │   ▲                  │                                    │                    (120 ms latency)
//!        │   └── Sentry crash ──┘                                    │
//!        ▼                                                           ▼
//!   [segment store] ── janitor: rotate → zstd → sync ──► [mock S3 cold tier]
//!   [durable queue] ── 40 webhooks, HMAC bodies ──► delivered to the app
//! ```
//!
//! The scenario: normal traffic → 24 identical LLM calls coalescing into
//! ONE upstream call (FinOps savings) → a webhook burst delivered through
//! the durable queue → a checkout bug that 500s and files a Sentry crash →
//! a real bit-rot corruption healed from the cold tier. Ends by printing
//! the 4-engine ANSI summary and the exact `blackbox replay` command the
//! dashboard shows for the crash trace.

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::node::{spawn_node, NodeConfig, TlsOptions};

/// ANSI palette (respects NO_COLOR).
fn c(code: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() {
        String::new()
    } else {
        format!("\x1b[{code}m")
    }
}
fn bold(s: &str) -> String {
    format!("{}{}{}", c("1"), s, c("0"))
}
fn cyan(s: &str) -> String {
    format!("{}{}{}", c("36"), s, c("0"))
}
fn green(s: &str) -> String {
    format!("{}{}{}", c("32"), s, c("0"))
}
fn yellow(s: &str) -> String {
    format!("{}{}{}", c("33"), s, c("0"))
}
fn dim(s: &str) -> String {
    format!("{}{}{}", c("2"), s, c("0"))
}

pub struct DemoArgs {
    /// Run the scenario, print the summary, exit 0 (CI / verification).
    pub once: bool,
    /// Ingress bind (`127.0.0.1:0` → ephemeral).
    pub listen: String,
    /// Admin dashboard bind (falls back to an ephemeral port when busy).
    pub admin_listen: String,
    /// Data dir (default: a fresh temp dir).
    pub data: Option<std::path::PathBuf>,
    /// Kept for CLI parity: `--once` always leaves the data dir in place
    /// (printed in the summary) so the replay command stays valid.
    #[allow(dead_code)]
    pub keep: bool,
}

/// Outcomes surfaced to the p7-gate and the summary.
#[derive(Debug, Default)]
pub struct DemoStats {
    pub normal_requests: u64,
    pub llm_calls: u64,
    pub llm_upstream_calls: u64,
    pub llm_tokens_used: u64,
    pub llm_tokens_saved: u64,
    pub webhooks_enqueued: u64,
    pub webhooks_delivered: u64,
    pub crashes_recorded: u64,
    pub cold_uploads: u64,
    pub bitrot_heals: u64,
    pub blocked_attacks: u64,
    pub crash_trace_hex: String,
    pub replay_command: String,
}

/// A minimal in-process HTTP server (demo shop app + LLM provider).
async fn spawn_http_server<F, Fut>(
    addr: &str,
    name: &str,
    handler: F,
) -> Result<std::net::SocketAddr>
where
    F: Fn(hyper::Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = hyper::Response<Full<Bytes>>> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {name} on {addr}"))?;
    let local = listener.local_addr()?;
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let handler = Arc::clone(&handler);
                    async move { Ok::<_, std::convert::Infallible>(handler(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    tracing::debug!("{name} on {local}");
    Ok(local)
}

fn json_response(status: hyper::StatusCode, v: serde_json::Value) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .expect("json response builds")
}

async fn drain(body: Incoming) -> Bytes {
    use http_body_util::BodyExt;
    match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => Bytes::new(),
    }
}

/// Trace id from the `traceparent` header blackbox injected upstream.
fn trace_of(req: &hyper::Request<Incoming>) -> Option<String> {
    let tp = req.headers().get("traceparent")?.to_str().ok()?;
    let mut parts = tp.split('-');
    let _ver = parts.next()?;
    let tid = parts.next()?;
    if tid.len() == 32 {
        Some(tid.to_string())
    } else {
        None
    }
}

/// The demo "shop" app: the upstream blackbox protects.
struct DemoApp {
    client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    /// http://<egress addr> — where LLM calls go (set before first request).
    egress_url: Arc<std::sync::OnceLock<String>>,
    /// http://<ingress addr> — where Sentry crashes are filed.
    ingress_url: Arc<std::sync::OnceLock<String>>,
    /// http://<llm provider addr> — the X-Blackbox-Target the egress dials.
    llm_url: Arc<std::sync::OnceLock<String>>,
    checkout_calls: AtomicU32,
    webhook_sink_hits: AtomicU64,
    llm_calls_seen: AtomicU64,
}

impl DemoApp {
    async fn handle(self: Arc<Self>, req: hyper::Request<Incoming>) -> hyper::Response<Full<Bytes>> {
        let path = req.uri().path().to_string();
        match (req.method().as_str(), path.as_str()) {
            ("GET", "/api/products") => json_response(
                hyper::StatusCode::OK,
                serde_json::json!({
                    "products": [
                        {"id": 1, "name": "blackbox t-shirt", "price_usd": 21.0},
                        {"id": 2, "name": "group-commit mug", "price_usd": 14.0},
                        {"id": 3, "name": "zstd hoodie", "price_usd": 55.0}
                    ]
                }),
            ),
            ("POST", "/api/cart") => {
                let body = drain(req.into_body()).await;
                json_response(
                    hyper::StatusCode::OK,
                    serde_json::json!({
                        "cart_id": fastrand::u64(..),
                        "items_bytes": body.len(),
                        "ok": true
                    }),
                )
            }
            ("POST", "/api/llm") => {
                self.llm_calls_seen.fetch_add(1, Ordering::Relaxed);
                let tp_fwd = req.headers().get("traceparent").cloned();
                let body = drain(req.into_body()).await;
                // The app calls its LLM THROUGH blackbox egress (as the
                // injected OPENAI_BASE_URL would): same key, same body —
                // singleflight coalesces the herd into one upstream call.
                let egress = self.egress_url.get().cloned().unwrap_or_default();
                let llm = self.llm_url.get().cloned().unwrap_or_default();
                let url = format!("{egress}/v1/chat/completions");
                let mut out = hyper::Request::builder()
                    .method("POST")
                    .uri(url)
                    .header("content-type", "application/json")
                    .header("x-api-key", "demo-tenant")
                    // llm_url is already an absolute http:// URL.
                    .header("x-blackbox-target", llm)
                    .body(Full::new(body))
                    .expect("llm request builds");
                if let Some(tp) = tp_fwd {
                    if let Ok(v) = hyper::header::HeaderValue::from_str(tp.to_str().unwrap_or("")) {
                        out.headers_mut().insert("traceparent", v);
                    }
                }
                match self.client.request(out).await {
                    Ok(res) => {
                        let status = res.status();
                        let body = drain(res.into_body()).await;
                        hyper::Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Full::new(body))
                            .expect("relay builds")
                    }
                    Err(e) => json_response(
                        hyper::StatusCode::BAD_GATEWAY,
                        serde_json::json!({"error": format!("egress: {e}")}),
                    ),
                }
            }
            ("POST", "/api/checkout") => {
                let n = self.checkout_calls.fetch_add(1, Ordering::Relaxed) + 1;
                let trace = trace_of(&req);
                if n % 6 == 0 {
                    // THE BUG: the 6th checkout 500s AND files a Sentry
                    // crash against the same trace id.
                    self.file_crash(trace.as_deref()).await;
                    json_response(
                        hyper::StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({
                            "error": "payment processor returned 502 (demo bug)",
                            "order_id": null
                        }),
                    )
                } else {
                    json_response(
                        hyper::StatusCode::OK,
                        serde_json::json!({
                            "order_id": format!("ord-{:06}", n),
                            "charged_usd": 21.0,
                            "ok": true
                        }),
                    )
                }
            }
            ("POST", p) if p.starts_with("/webhooks/") => {
                // Delivery sink for the durable queue: 200 every time.
                self.webhook_sink_hits.fetch_add(1, Ordering::Relaxed);
                let _ = drain(req.into_body()).await;
                json_response(hyper::StatusCode::OK, serde_json::json!({"received": true}))
            }
            _ => json_response(
                hyper::StatusCode::NOT_FOUND,
                serde_json::json!({"error": "demo app: unknown route", "path": path}),
            ),
        }
    }

    /// POST a wire-format Sentry envelope to the ingress, tied to `trace`.
    async fn file_crash(&self, trace: Option<&str>) {
        let event_id = format!("{:032x}", fastrand::u128(..));
        let mut header = serde_json::json!({ "event_id": event_id, "sent_at": "2026-01-01T00:00:00Z" });
        if let Some(t) = trace {
            header["trace"] = serde_json::json!({ "trace_id": t });
        }
        let event = serde_json::json!({
            "event_id": event_id,
            "level": "error",
            "platform": "rust",
            "exception": {
                "values": [{
                    "type": "PaymentError",
                    "value": "processor 502 — demo checkout bug",
                    "stacktrace": {"frames": [{"function": "charge_card", "module": "shop.billing"}]}
                }]
            }
        });
        let event_str = event.to_string();
        let envelope = format!(
            "{}\n{}\n\n{}\n",
            header,
            serde_json::json!({"type": "event", "length": event_str.len()}),
            event_str
        );
        let ingress = self.ingress_url.get().cloned().unwrap_or_default();
        let url = format!("{ingress}/api/1/envelope/");
        let req = hyper::Request::builder()
            .method("POST")
            .uri(url)
            .header("content-type", "application/x-sentry-envelope")
            .body(Full::new(Bytes::from(envelope)))
            .expect("envelope request builds");
        if let Err(e) = self.client.request(req).await {
            tracing::warn!("demo: crash filing failed: {e}");
        }
    }
}

/// The fake LLM provider the egress dials (via X-Blackbox-Target).
async fn llm_provider(req: hyper::Request<Incoming>) -> hyper::Response<Full<Bytes>> {
    if req.uri().path() != "/v1/chat/completions" {
        return json_response(
            hyper::StatusCode::NOT_FOUND,
            serde_json::json!({"error": {"message": "unknown route"}}),
        );
    }
    let body = drain(req.into_body()).await;
    // Deterministic token accounting from the prompt length.
    let prompt_tokens = 40 + (body.len() % 64) as u64;
    let completion_tokens = 88;
    // 120 ms "inference" — wide enough that the 24-call herd coalesces.
    tokio::time::sleep(Duration::from_millis(120)).await;
    json_response(
        hyper::StatusCode::OK,
        serde_json::json!({
            "id": format!("chatcmpl-{:024x}", fastrand::u64(..)),
            "object": "chat.completion",
            "model": "demo-gpt-4o-mini",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Blackbox is the four-engine omni-sidecar."},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens
            }
        }),
    )
}

/// Simple HTTP client for the scripted traffic (one pooled connection is
/// enough; the herd in Phase B is the app's job).
struct Http {
    client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
}

impl Http {
    fn new() -> Self {
        Http {
            client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .pool_idle_timeout(Duration::from_secs(30))
                .build_http(),
        }
    }

    async fn req(
        &self,
        method: &str,
        url: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(hyper::StatusCode, Option<String>, Vec<u8>)> {
        let mut b = hyper::Request::builder().method(method).uri(url);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = b.body(Full::new(Bytes::from(body.unwrap_or("").to_string())))?;
        let res = self.client.request(req).await?;
        let status = res.status();
        let trace = res
            .headers()
            .get("x-blackbox-trace-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        use http_body_util::BodyExt;
        let bytes = res.into_body().collect().await?.to_bytes();
        Ok((status, trace, bytes.to_vec()))
    }
}

pub async fn run_demo(args: DemoArgs) -> Result<i32> {
    let started = Instant::now();
    println!("{}", bold("blackbox demo — the whole architecture in one shot"));
    println!("{}", dim("─────────────────────────────────────────────────"));

    // ---- Topology: app + LLM provider + cold storage, all in-process. --
    let data = match &args.data {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!(
            "blackbox-demo-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        )),
    };
    std::fs::create_dir_all(&data).context("create demo data dir")?;

    let app_state = Arc::new(DemoApp {
        client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build_http(),
        egress_url: Arc::new(std::sync::OnceLock::new()),
        ingress_url: Arc::new(std::sync::OnceLock::new()),
        llm_url: Arc::new(std::sync::OnceLock::new()),
        checkout_calls: AtomicU32::new(0),
        webhook_sink_hits: AtomicU64::new(0),
        llm_calls_seen: AtomicU64::new(0),
    });

    // The LLM provider (what egress dials).
    let llm_addr = spawn_http_server("127.0.0.1:0", "demo-llm", |req| async move {
        llm_provider(req).await
    })
    .await?;

    // Mock S3 = the local cold bucket (real SigV4-signed traffic).
    let (s3_addr, _s3_state) = blackbox_cold::mock::spawn_mock_s3(
        "127.0.0.1:0",
        "blackbox-demo",
        "demokey",
        "demosecret",
    )
    .await
    .context("spawn mock S3")?;

    let cold = blackbox_cold::ColdTier::open(
        blackbox_cold::S3Config {
            endpoint: format!("http://{s3_addr}"),
            bucket: "blackbox-demo".into(),
            region: "us-east-1".into(),
            access_key: "demokey".into(),
            secret_key: "demosecret".into(),
            prefix: "segments/".into(),
        },
        &data,
    )
    .context("open cold tier")?;

    // Admin port: try the requested one, fall back to ephemeral.
    let admin_listen = {
        let probe = tokio::net::TcpListener::bind(&args.admin_listen).await;
        match probe {
            Ok(l) => {
                let used = l.local_addr()?;
                drop(l);
                used.to_string()
            }
            Err(_) => "127.0.0.1:0".to_string(),
        }
    };

    let node = {
        // The app server must exist BEFORE the node boots (its address is
        // the node's upstream); the egress/ingress URLs are patched into
        // the OnceLocks right after the node binds, before any traffic.
        spawn_http_server("127.0.0.1:0", "demo-app", {
            let app = Arc::clone(&app_state);
            move |req| {
                let app = Arc::clone(&app);
                async move { app.handle(req).await }
            }
        })
        .await?
    };

    let node_cfg = NodeConfig {
        listen: args.listen.clone(),
        upstream: format!("{node}"),
        data: data.clone(),
        webhooks: "/webhooks/*".into(),
        hold_ms: 3_000,
        egress_listen: "127.0.0.1:0".into(),
        admin_listen,
        // 256 MB: the demo process's OWN real footprint (redb mmaps, zstd
        // seal buffers, 64 KB bodies in flight) sits right at the old 48 MB
        // budget's Shed85 line, so head-sampling randomly dropped the bulk
        // frames → no segment rotation → phase E flaked ~50% of runs. The
        // RAM watermark behaviors are gate-tested separately with injected
        // pressure (phase 4/5 gates); this scenario needs Normal throughout.
        mem_budget_mb: 256,
        max_segment_mb: 1, // tiny segments → the scenario rotates for real
        disk_quota_mb: 4096,
        cold: Some(cold.clone()),
        shield: true,
        rate_rps: 0.0,
        rate_burst: 100,
        tls: TlsOptions::Off,
    };
    let n = spawn_node(node_cfg).await.context("boot demo node")?;

    // Patch the app's view of the world (plain OnceLock init — no traffic
    // has been served yet, so .set() cannot race or fail).
    let egress_url = format!("http://{}", n.egress.local_addr);
    let ingress_url = format!("http://{}", n.proxy.local_addr);
    let _ = app_state.egress_url.set(egress_url.clone());
    let _ = app_state.ingress_url.set(ingress_url.clone());
    let _ = app_state.llm_url.set(format!("http://{llm_addr}"));

    let http = Http::new();
    let mut stats = DemoStats::default();

    println!(
        "  {} {}  {} {}  {} {}",
        cyan("ingress"),
        n.proxy.local_addr,
        cyan("upstream(app)"),
        node,
        cyan("admin"),
        n.admin_addr
    );
    println!();

    // ---- Phase A: normal traffic. --------------------------------------
    print!("  {} normal traffic … ", cyan("A"));
    let mut first_trace = None;
    for i in 0..12 {
        let (path, method, body) = if i % 3 == 0 {
            ("/api/cart", "POST", Some(r#"{"items":[{"id":1,"qty":2}]}"#))
        } else {
            ("/api/products", "GET", None)
        };
        let (status, trace, _) = http
            .req(method, &format!("{ingress_url}{path}"), body, &[])
            .await
            .context("phase A request")?;
        anyhow::ensure!(status.is_success(), "phase A: {path} → {status}");
        if first_trace.is_none() {
            first_trace = trace;
        }
        stats.normal_requests += 1;
    }
    println!("{}", green("ok"));

    // ---- A2: bulk uploads → real 1 MB segment rollovers. ----------------
    // The later bit-rot phase needs SEALED segments (rotate → zstd → cold
    // sync), so push ~2 MB of honest traffic through the tee capture.
    print!("  {} bulk uploads (segment rollovers) … ", cyan("A2"));
    let big_body = format!("{{\"bulk\":\"{}\"}}", "x".repeat(64 * 1024));
    for _ in 0..30 {
        let (status, _, _) = http
            .req(
                "POST",
                &format!("{ingress_url}/api/cart"),
                Some(&big_body),
                &[("content-type", "application/json")],
            )
            .await
            .context("phase A2 request")?;
        anyhow::ensure!(status.is_success(), "phase A2: cart → {status}");
        stats.normal_requests += 1;
    }
    println!("{}", green("ok"));

    // ---- Phase B: 24 identical LLM calls → ONE upstream call. ----------
    print!("  {} coalesced LLM calls … ", cyan("B"));
    stats.llm_calls = 24;
    let llm_body = r#"{"model":"demo-gpt-4o-mini","messages":[{"role":"user","content":"explain blackbox in one sentence"}]}"#;
    let mut herd = Vec::new();
    for _ in 0..stats.llm_calls {
        let http = Http::new();
        let url = format!("{ingress_url}/api/llm");
        let body = llm_body.to_string();
        herd.push(tokio::spawn(async move {
            http.req("POST", &url, Some(&body), &[]).await
        }));
    }
    let mut llm_ok = 0;
    let mut first_fail = String::new();
    for h in herd {
        let (status, _, body) = h.await?.context("phase B join")?;
        if status.is_success() {
            llm_ok += 1;
        } else if first_fail.is_empty() {
            first_fail = format!("status {status}: {}", String::from_utf8_lossy(&body));
        }
    }
    anyhow::ensure!(
        llm_ok == stats.llm_calls,
        "phase B: {llm_ok}/{} llm calls ok — first failure: {first_fail}",
        stats.llm_calls
    );
    // FinOps ledger truth.
    let ledger = n.egress.ledger.totals();
    stats.llm_upstream_calls = ledger.total_requests.saturating_sub(ledger.coalesced_hits + ledger.cache_hits);
    stats.llm_tokens_used = ledger.tokens_used;
    stats.llm_tokens_saved = ledger.tokens_saved;
    println!(
        "{} ({} upstream calls · {} saved tokens)",
        green("ok"),
        stats.llm_upstream_calls,
        yellow(&stats.llm_tokens_saved.to_string())
    );

    // ---- Phase C: webhook burst through the durable queue. -------------
    print!("  {} webhook burst … ", cyan("C"));
    stats.webhooks_enqueued = 40;
    let mut burst = Vec::new();
    for i in 0..stats.webhooks_enqueued {
        let http = Http::new();
        let url = format!("{ingress_url}/webhooks/stripe");
        let body = format!(
            r#"{{"id":"evt_{i:04}","type":"invoice.paid","data":{{"amount_usd":{i}}},"sig":"hmac-sha256"}}"#
        );
        // Real Stripe retries share an event id; DISTINCT events carry
        // DISTINCT signatures — blackbox's idempotency dedup (keyed on
        // stripe-signature) would collapse identical ones, so vary it.
        let sig = format!("t=1,v1=demo{i:04}");
        burst.push(tokio::spawn(async move {
            http.req(
                "POST",
                &url,
                Some(&body),
                &[("content-type", "application/json"), ("stripe-signature", sig.as_str())],
            )
            .await
        }));
    }
    let mut enq_ok = 0;
    for h in burst {
        let (status, _, _) = h.await?.context("phase C join")?;
        if status.as_u16() == 202 {
            enq_ok += 1;
        }
    }
    anyhow::ensure!(enq_ok == stats.webhooks_enqueued, "phase C: {enq_ok} 202s");
    // Wait for the dispatcher to drain.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let c = n.queue.store.counts().await?;
        stats.webhooks_delivered = c.delivered_total;
        if stats.webhooks_delivered >= stats.webhooks_enqueued || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        stats.webhooks_delivered == stats.webhooks_enqueued,
        "phase C: delivered {}/{}",
        stats.webhooks_delivered,
        stats.webhooks_enqueued
    );
    println!(
        "{} ({}/{} delivered · 0 lost)",
        green("ok"),
        stats.webhooks_delivered,
        stats.webhooks_enqueued
    );

    // ---- Phase D: the checkout bug → 500 + Sentry crash on one trace. --
    print!("  {} checkout bug → Sentry crash … ", cyan("D"));
    let mut crash_trace = None;
    for _ in 0..6 {
        let (status, trace, _) = http
            .req("POST", &format!("{ingress_url}/api/checkout"), Some(r#"{"card":"tok_demo","amount":2100}"#), &[])
            .await
            .context("phase D request")?;
        if status.as_u16() == 500 {
            crash_trace = trace;
        }
    }
    anyhow::ensure!(crash_trace.is_some(), "phase D: no 500 observed");
    // Let the envelope + the 500 record settle.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let tid = blackbox_core::schema::parse_trace_hex(crash_trace.as_ref().unwrap())
        .context("parse crash trace hex")?;
    let recs = n.proxy.get_trace(&tid).unwrap_or_default();
    stats.crashes_recorded = recs
        .iter()
        .filter(|r| matches!(r.payload, blackbox_core::schema::RecordPayload::SentryCrash(_)))
        .count() as u64;
    stats.crash_trace_hex = crash_trace.unwrap();
    anyhow::ensure!(stats.crashes_recorded >= 1, "phase D: no SentryCrash on the trace");
    println!(
        "{} (trace {} · IngressHttp 500 + SentryCrash)",
        green("ok"),
        dim(&stats.crash_trace_hex)
    );

    // ---- Phase E: bit-rot corruption → automatic self-heal. ------------
    print!("  {} bit-rot self-heal … ", cyan("E"));
    let first_tid = blackbox_core::schema::parse_trace_hex(
        first_trace.as_ref().unwrap_or(&stats.crash_trace_hex),
    )
    .context("parse first trace hex")?;

    // Wait until the first trace's OWN segment is sealed, materialized as a
    // local `.zst`, AND registered in the cold tier (upload + registry
    // commit both done) — then corrupt exactly that file. Merely waiting
    // for "any synced segment" raced the registry commit on fast CI
    // runners: the corrupt file had no cold metadata yet, so no read path
    // could reach the self-heal and the gate died with heals=0.
    let deadline = Instant::now() + Duration::from_secs(30);
    let victim = loop {
        if Instant::now() > deadline {
            anyhow::bail!(
                "phase E: first trace's segment never became locally sealed \
                 + cold-registered within 30 s"
            );
        }
        let cs = cold.stats();
        stats.cold_uploads = cs.uploads;
        if Instant::now() > started + Duration::from_secs(3) {
            if let Some(seg) = cold.cold_segment_of(&first_tid) {
                let p = blackbox_cold::tier::local_zst_path(&data, seg);
                if p.exists() {
                    break p;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    anyhow::ensure!(stats.cold_uploads >= 1, "phase E: cold tier got no uploads");
    {
        let mut bytes = std::fs::read(&victim).context("read victim zst")?;
        anyhow::ensure!(bytes.len() > 80, "phase E: victim too small");
        for b in &mut bytes[48..80] {
            *b ^= 0x5A;
        }
        std::fs::write(&victim, &bytes).context("write corrupted zst")?;
    }

    // Reading the poisoned trace transparently heals the segment.
    let healed_recs = n.proxy.get_trace(&first_tid).unwrap_or_default();
    stats.bitrot_heals = cold.stats().heals;
    anyhow::ensure!(
        stats.bitrot_heals >= 1 && !healed_recs.is_empty(),
        "phase E: heal did not happen (heals={})",
        stats.bitrot_heals
    );
    println!(
        "{} (corrupt .zst → digest-verified cold restore → {} records intact)",
        green("ok"),
        healed_recs.len()
    );

    // ---- Summary --------------------------------------------------------
    let elapsed = started.elapsed();
    stats.blocked_attacks = blackbox_ingress::waf::blocked_attacks();
    stats.replay_command = format!(
        "blackbox replay {} --target {} --data {}",
        stats.crash_trace_hex,
        ingress_url,
        data.display()
    );

    println!();
    println!("{}", bold("  ┌──────────────────────── 4 ENGINES ────────────────────────┐"));
    println!(
        "  │ {}  requests {} · indexed {} · traces {} · shielded {}",
        cyan("1 INGRESS      "),
        stats.normal_requests + stats.llm_calls + stats.webhooks_enqueued + 6,
        n.proxy.stats().frames,
        n.proxy.stats().distinct_traces,
        stats.blocked_attacks
    );
    println!(
        "  │ {}  webhooks {}/{} delivered · DLQ 0 · dedup on",
        cyan("2 QUEUE        "),
        stats.webhooks_delivered,
        stats.webhooks_enqueued
    );
    let saved_pct = if stats.llm_calls > 0 {
        (stats.llm_calls.saturating_sub(stats.llm_upstream_calls)) as f64 * 100.0 / stats.llm_calls as f64
    } else {
        0.0
    };
    println!(
        "  │ {}  LLM calls {} → {} upstream · {}% saved · tokens {}",
        cyan("3 EGRESS-FINOPS"),
        stats.llm_calls,
        stats.llm_upstream_calls,
        format!("{:.1}", saved_pct),
        yellow(&format!("saved {}", stats.llm_tokens_saved))
    );
    println!(
        "  │ {}  uploads {} · bit-rot heals {} · compaction on · quota ring on",
        cyan("4 STORAGE      "),
        stats.cold_uploads,
        green(&stats.bitrot_heals.to_string())
    );
    println!("  {} {}", "└".to_string(), "─".repeat(58));
    println!();
    println!("  {}: {}", cyan("dashboard"), bold(&format!("http://{}", n.admin_addr)));
    println!("  {}: trace inspector shows the crash → {}", cyan("replay"), dim(&stats.replay_command));
    println!(
        "  {}: {} (delete any time)",
        cyan("data"),
        data.display()
    );
    println!(
        "\n  {} 4 engines exercised in {:.1}s",
        green("✓"),
        elapsed.as_secs_f64()
    );

    if args.once {
        println!("{}", dim("  (--once: verification mode — exiting 0)"));
        return Ok(0);
    }

    println!();
    println!(
        "{}  The demo node keeps running — open the dashboard, poke the trace inspector.",
        yellow("→")
    );
    println!("{}  Ctrl-C to stop.", dim(""));

    // Linger: keep the node + demo app alive for exploration.
    std::future::pending::<()>().await;
    Ok(0)
}
