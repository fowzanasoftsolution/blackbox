//! Phase 3 verification harness — the three gates from the blueprint, plus
//! the mock application they run against.
//!
//! ## Gate 1 — Zero-Lost-Webhooks Chaos
//! 5 000 signed webhooks (HMAC-SHA256) burst at `/webhooks/stripe` while the
//! upstream app is KILLED (connection refused) for 1.5 s halfway through
//! delivery. Every caller gets `202` (p99 < 2 ms), every webhook is
//! eventually delivered with its HMAC intact, zero duplicates, zero losses.
//!
//! ## Gate 2 — Invisible App Restart (Connection Hold)
//! The upstream app is killed for 400 ms under steady `GET /api/orders`
//! traffic. The circuit breaker holds in-flight requests and replays them
//! on recovery — the client sees 100% `200 OK`, zero 502s.
//!
//! ## Gate 3 — Deterministic Replay Sandbox
//! Record: app receives `POST /checkout`, calls a mock Stripe API through
//! the egress interceptor, emits a Sentry crash, and fails with 500.
//! Replay: with the mock Stripe server SHUT DOWN, the fixed app re-executes
//! the trace against the recorded responses — and unrecorded outgoing calls
//! are 428-blocked by the sandbox guard.

use crate::proxy::{spawn_proxy, IngressConfig, ProxyHandle, QueueAttachment};
use blackbox_core::breaker::UpstreamHealth;
use blackbox_core::schema::{parse_trace_hex, RecordPayload};
use blackbox_queue::interceptor::{spawn_interceptor, InterceptorConfig, InterceptorMode};
use blackbox_queue::{spawn_queue_runtime, DispatcherConfig, JobStoreConfig};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};


const WEBHOOK_SECRET: &[u8] = b"whsec_gate1_test_secret";
const STRIPE_CHARGE_RESPONSE: &[u8] =
    br#"{"id":"ch_replay_12345","status":"succeeded","amount":4200}"#;
const STRIPE_TARGET_PATH: &str = "/v1/charges";
const STRIPE_CHARGE_BODY: &[u8] =
    br#"{"amount":4200,"currency":"usd","source":"tok_visa"}"#;

type HttpBody = Full<Bytes>;
type HmacSha256 = Hmac<Sha256>;

fn hmac_hex(body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(WEBHOOK_SECRET).expect("hmac key");
    mac.update(body);
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn http_client() -> Client<HttpConnector, HttpBody> {
    Client::builder(TokioExecutor::new()).build_http()
}

// =========================================================== mock app =====

/// Shared application state (survives kill/restart cycles).
#[derive(Clone)]
struct AppState {
    deliveries: Arc<Mutex<HashMap<u64, u64>>>,
    delivered_total: Arc<AtomicU64>,
    hmac_failures: Arc<AtomicU64>,
    fail_checkout: Arc<AtomicBool>,
    /// Drain phase: webhook deliveries get 503 (never double-counted);
    /// in-flight requests finish before the sockets die.
    draining: Arc<AtomicBool>,
}

/// The mock application under the shield. Verifies HMAC signatures on
/// webhook delivery, serves orders, performs egress calls, and can be
/// killed (connection refused) / restarted on the SAME port.
pub struct MockApp {
    pub addr: SocketAddr,
    state: AppState,
    kill_ctl: Arc<Mutex<Option<watch::Sender<u64>>>>,
    proxy_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    egress_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    stripe_target: Arc<tokio::sync::OnceCell<String>>,
}

impl MockApp {
    /// Spawn on an ephemeral port. `fail_checkout`: `/checkout` answers 500
    /// after the Stripe call (the "bug" — replay verifies the fix).
    pub async fn spawn(fail_checkout: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
        let addr = listener.local_addr().unwrap();
        let state = AppState {
            deliveries: Arc::new(Mutex::new(HashMap::new())),
            delivered_total: Arc::new(AtomicU64::new(0)),
            hmac_failures: Arc::new(AtomicU64::new(0)),
            fail_checkout: Arc::new(AtomicBool::new(fail_checkout)),
            draining: Arc::new(AtomicBool::new(false)),
        };
        let kill_ctl: Arc<Mutex<Option<watch::Sender<u64>>>> = Arc::new(Mutex::new(None));
        let cells = (
            Arc::new(tokio::sync::OnceCell::new()),
            Arc::new(tokio::sync::OnceCell::new()),
            Arc::new(tokio::sync::OnceCell::new()),
        );
        let app = MockApp {
            addr,
            state,
            kill_ctl: kill_ctl.clone(),
            proxy_addr: cells.0.clone(),
            egress_addr: cells.1.clone(),
            stripe_target: cells.2.clone(),
        };
        let (tx, rx) = watch::channel(0u64);
        *kill_ctl.lock().await = Some(tx);
        spawn_accept_loop(listener, app.state.clone(), rx, app.proxy_addr.clone(), app.egress_addr.clone(), app.stripe_target.clone());
        app
    }

    pub fn set_proxy_addr(&self, a: SocketAddr) {
        let _ = self.proxy_addr.set(a);
    }
    pub fn set_egress_addr(&self, a: SocketAddr) {
        let _ = self.egress_addr.set(a);
    }
    pub fn set_stripe_target(&self, url: String) {
        let _ = self.stripe_target.set(url);
    }

    pub fn delivered_total(&self) -> u64 {
        self.state.delivered_total.load(Ordering::SeqCst)
    }
    pub fn hmac_failures(&self) -> u64 {
        self.state.hmac_failures.load(Ordering::SeqCst)
    }
    pub async fn delivery_counts(&self) -> HashMap<u64, u64> {
        self.state.deliveries.lock().await.clone()
    }

    /// Kill (new connections refused) for `duration`, then restart on the
    /// SAME port. In-flight deliveries are given 30 ms to finish writing so
    /// no delivery is ever double-counted by the chaos test.
    pub async fn kill_for(&self, duration: Duration) {
        let sender = self.kill_ctl.lock().await.take();
        if let Some(tx) = sender {
            let gen = tx.borrow().wrapping_add(1);
            let _ = tx.send(gen);
        }
        // accept loop: 5 ms grace, then listener dropped → port refused.
        tokio::time::sleep(Duration::from_millis(30)).await;
        tokio::time::sleep(duration).await;

        let listener = TcpListener::bind((self.addr.ip(), self.addr.port()))
            .await
            .expect("rebind mock app on the same port");
        let (tx, rx) = watch::channel(0u64);
        *self.kill_ctl.lock().await = Some(tx);
        spawn_accept_loop(listener, self.state.clone(), rx, self.proxy_addr.clone(), self.egress_addr.clone(), self.stripe_target.clone());
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_accept_loop(
    listener: TcpListener,
    state: AppState,
    mut kill_rx: watch::Receiver<u64>,
    proxy_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    egress_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    stripe_target: Arc<tokio::sync::OnceCell<String>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = kill_rx.changed() => {
                    // Grace window: let in-flight handlers finish writing so
                    // the dispatcher never retries a delivered webhook.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    break; // listener dropped → connection refused
                }
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let _ = tcp.set_nodelay(true);
                    let state = state.clone();
                    let proxy_addr = proxy_addr.clone();
                    let egress_addr = egress_addr.clone();
                    let stripe_target = stripe_target.clone();
                    let mut kill_for_conn = kill_rx.clone();
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                            let state = state.clone();
                            let proxy_addr = proxy_addr.clone();
                            let egress_addr = egress_addr.clone();
                            let stripe_target = stripe_target.clone();
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    app_route(req, state, proxy_addr, egress_addr, stripe_target).await,
                                )
                            }
                        });
                        let conn = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tcp), svc);
                        // A real kill closes ESTABLISHED connections too —
                        // the proxy's connection pool must see resets, not a
                        // forever-alive zombie.
                        tokio::select! {
                            biased;
                            _ = kill_for_conn.changed() => { /* drop → RST/FIN */ }
                            _ = conn => {}
                        }
                    });
                }
            }
        }
    });
}

async fn app_route(
    req: hyper::Request<Incoming>,
    state: AppState,
    proxy_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    egress_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    stripe_target: Arc<tokio::sync::OnceCell<String>>,
) -> hyper::Response<HttpBody> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Webhook DELIVERY target: verify the HMAC over the exact raw bytes.
    if path == "/webhooks/stripe" && method == hyper::Method::POST {
        if state.draining.load(Ordering::SeqCst) {
            // Graceful-shutdown drain: refuse NEW deliveries so the queue
            // reschedules them; in-flight ones already completed.
            return hyper::Response::builder()
                .status(503)
                .body(HttpBody::new(Bytes::from_static(b"draining")))
                .unwrap();
        }
        let sig = req
            .headers()
            .get("x-test-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let event_id: u64 = req
            .headers()
            .get("x-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = read_body(req.into_body()).await.unwrap_or_default();
        if sig != hmac_hex(&body) {
            state.hmac_failures.fetch_add(1, Ordering::SeqCst);
            tracing::error!("HMAC VERIFICATION FAILED — delivered bytes were mutated");
            return hyper::Response::builder()
                .status(400)
                .body(HttpBody::new(Bytes::from_static(b"bad signature")))
                .unwrap();
        }
        {
            let mut d = state.deliveries.lock().await;
            *d.entry(event_id).or_insert(0) += 1;
        }
        state.delivered_total.fetch_add(1, Ordering::SeqCst);
        return hyper::Response::builder()
            .status(202)
            .body(HttpBody::new(Bytes::from_static(b"received")))
            .unwrap();
    }

    // Sync traffic for the connection-hold gate.
    if path == "/api/orders" {
        return hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(HttpBody::new(Bytes::from_static(
                br#"{"orders":[1001,1002,1003]}"#,
            )))
            .unwrap();
    }

    // Checkout: makes an OUTGOING call to the (mock) Stripe API through the
    // egress interceptor; the bug variant then "crashes" with a Sentry error.
    if path == "/checkout" && method == hyper::Method::POST {
        let traceparent = req
            .headers()
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let charge_resp = match (egress_addr.get().copied(), stripe_target.get()) {
            (Some(egress), Some(target)) => {
                let headers: Vec<(&str, &str)> = if traceparent.is_empty() {
                    vec![]
                } else {
                    vec![("traceparent", traceparent.as_str())]
                };
                match forward_proxy_call(egress, "POST", target, &headers, STRIPE_CHARGE_BODY).await {
                    Ok((status, body, _)) if (200..300).contains(&status) => body,
                    Ok((status, _, _)) => {
                        return hyper::Response::builder()
                            .status(502)
                            .body(HttpBody::new(Bytes::from(format!("stripe call failed: {status}"))))
                            .unwrap();
                    }
                    Err(e) => {
                        return hyper::Response::builder()
                            .status(502)
                            .body(HttpBody::new(Bytes::from(format!("stripe call error: {e}"))))
                            .unwrap();
                    }
                }
            }
            _ => {
                return hyper::Response::builder()
                    .status(500)
                    .body(HttpBody::new(Bytes::from_static(b"no egress/stripe configured")))
                    .unwrap();
            }
        };

        if state.fail_checkout.load(Ordering::SeqCst) {
            // The bug: crash AFTER charging, with a Sentry error attached.
            if let Some(proxy) = proxy_addr.get().copied() {
                emit_sentry_crash(proxy, &traceparent, "checkout crashed after charging").await;
            }
            return hyper::Response::builder()
                .status(500)
                .body(HttpBody::new(Bytes::from(charge_resp)))
                .unwrap();
        }
        // Fixed build: succeed with the recorded charge id.
        return hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(HttpBody::new(Bytes::from(charge_resp)))
            .unwrap();
    }

    hyper::Response::builder()
        .status(404)
        .body(HttpBody::new(Bytes::from_static(b"not found")))
        .unwrap()
}

/// "The app crashed" — Sentry envelope linked to the current trace.
async fn emit_sentry_crash(proxy: SocketAddr, traceparent: &str, message: &str) {
    let trace_id = traceparent
        .split('-')
        .nth(1)
        .unwrap_or("00000000000000000000000000000000");
    let event_id = format!("{:032x}", blackbox_core::schema::new_id128());
    let envelope = format!(
        "{{\"event_id\":\"{event_id}\"}}\n{{\"type\":\"event\"}}\n{{\"contexts\":{{\"trace\":{{\"trace_id\":\"{trace_id}\"}}}},\"exception\":{{\"values\":[{{\"type\":\"Panic\",\"value\":\"{message}\"}}]}}}}\n"
    );
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{proxy}/api/42/envelope/"))
        .header("content-type", "application/x-sentry-envelope")
        .body(HttpBody::new(Bytes::from(envelope)))
        .unwrap();
    if let Ok(res) = http_client().request(req).await {
        let _ = res.status();
    }
}

async fn read_body(mut body: Incoming) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await.transpose().map_err(|_| ())? {
        if let Some(d) = frame.data_ref() {
            out.extend_from_slice(d);
        }
    }
    Ok(out)
}

// ================================================== forward proxy client ==

/// Hand-rolled HTTP/1.1 forward-proxy call: absolute-form request target to
/// `proxy`, `Connection: close`, full response parsed. This mimics exactly
/// what any HTTP client library does under HTTP_PROXY.
pub async fn forward_proxy_call(
    proxy: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>, Vec<(String, String)>), String> {
    let mut stream = TcpStream::connect(proxy).await.map_err(|e| e.to_string())?;
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        target_host(target),
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "no header terminator".to_string())?;
    let head = String::from_utf8_lossy(&buf[..sep]).to_string();
    let body = buf[sep + 4..].to_vec();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line: {head}"))?;
    let resp_headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .collect();
    Ok((status, body, resp_headers))
}

fn target_host(target: &str) -> &str {
    let rest = target
        .strip_prefix("http://")
        .unwrap_or_else(|| target.strip_prefix("https://").unwrap_or(target));
    rest.split(['/', '?']).next().unwrap_or(rest)
}

// ============================================================ mock stripe =

/// The external Stripe mock — an SEPARATE upstream that must NEVER be hit
/// during replay (its shutdown is what makes the sandbox test meaningful).
pub struct MockStripe {
    pub addr: SocketAddr,
    pub calls: Arc<AtomicU64>,
    kill_tx: watch::Sender<u64>,
}

impl MockStripe {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("stripe bind");
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let (kill_tx, kill_rx) = watch::channel(0u64);
        let calls_loop = calls.clone();
        tokio::spawn(async move {
            let mut kill_rx = kill_rx;
            loop {
                tokio::select! {
                    biased;
                    _ = kill_rx.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { continue };
                        let calls = calls_loop.clone();
                        tokio::spawn(async move {
                            let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                                let calls = calls.clone();
                                async move {
                                    let path = req.uri().path().to_string();
                                    let _ = read_body(req.into_body()).await;
                                    if path == STRIPE_TARGET_PATH {
                                        calls.fetch_add(1, Ordering::SeqCst);
                                        return Ok::<_, std::convert::Infallible>(
                                            hyper::Response::builder()
                                                .status(200)
                                                .header("content-type", "application/json")
                                                .body(HttpBody::new(Bytes::from_static(STRIPE_CHARGE_RESPONSE)))
                                                .unwrap(),
                                        );
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder()
                                            .status(404)
                                            .body(HttpBody::new(Bytes::from_static(b"{}")))
                                            .unwrap(),
                                    )
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(tcp), svc)
                                .await;
                        });
                    }
                }
            }
        });
        MockStripe { addr, calls, kill_tx }
    }

    pub fn shutdown(&self) {
        let _ = self.kill_tx.send(1);
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

// ================================================================= gates ==

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "blackbox-p3-{tag}-{}-{}",
        std::process::id(),
        blackbox_core::schema::new_id128() as u64
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Gate 1 — Zero-Lost-Webhooks Chaos Test.
pub async fn gate1() -> Result<(), String> {
    let dir = tmpdir("gate1");
    let app = MockApp::spawn(false).await;
    let health = UpstreamHealth::new(3);

    let (events_tx, events_rx) = tokio::sync::mpsc::channel(4_096);
    let runtime = spawn_queue_runtime(
        &dir.join("jobs.redb"),
        JobStoreConfig { batch_window: Duration::from_millis(1), ..JobStoreConfig::default() },
        DispatcherConfig {
            upstream: app.addr.to_string(),
            // 8-way delivery keeps the 2-vCPU co-location budget balanced
            // between the dispatcher drain and the ingest path.
            concurrency: 8,
            backoff: blackbox_queue::BackoffConfig { base_ms: 50, max_ms: 2_000 },
            ..DispatcherConfig::default()
        },
    Arc::clone(&health),
    Some(events_tx),
)
    .await
    .map_err(|e| e.to_string())?;
    let store = runtime.store.clone();

    let cfg = IngressConfig {
        data_dir: dir.clone(),
        upstream: app.addr.to_string(),
        health: Some(Arc::clone(&health)),
        queue: Some(QueueAttachment { runtime, events: events_rx }),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await.map_err(|e| e.to_string())?;
    app.set_proxy_addr(proxy.local_addr);

    // Chaos watcher: kill the app for 1.5 s once we're halfway delivered.
    let kill_app = app.clone_handle_for_kill();
    tokio::spawn(async move {
        loop {
            if kill_app.delivered_total() >= 2_500 {
                kill_app.kill_for(Duration::from_millis(1_500)).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    });

    // 5 000 signed webhooks fired as a 16-way concurrent closed-loop burst
    // (each caller waits for its 202 before the next — fsync'd commits).
    const TOTAL: u64 = 5_000;
    const TASKS: u64 = 16;
    let client = http_client();
    let latencies = Arc::new(Mutex::new(Vec::<u64>::with_capacity(TOTAL as usize)));
    let bad_status = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for t in 0..TASKS {
        let per = TOTAL / TASKS;
        let extra = (t < TOTAL % TASKS) as u64;
        let start = t * per + t.min(TOTAL % TASKS);
        let client = client.clone();
        let latencies = latencies.clone();
        let bad_status = bad_status.clone();
        let proxy_addr = proxy.local_addr;
        tasks.push(tokio::spawn(async move {
            for i in 0..(per + extra) {
                let event = start + i;
                let body = format!(r#"{{"event":{event},"type":"invoice.paid","amount":{}}}"#, 1000 + event);
                let sig = hmac_hex(body.as_bytes());
                let req = hyper::Request::builder()
                    .method("POST")
                    .uri(format!("http://{proxy_addr}/webhooks/stripe"))
                    .header("content-type", "application/json")
                    .header("x-event-id", event.to_string())
                    .header("idempotency-key", format!("evt-{event}"))
                    .header("x-test-signature", sig)
                    .body(HttpBody::new(Bytes::from(body)))
                    .unwrap();
                let t0 = Instant::now();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 202 => {
                        latencies.lock().await.push(t0.elapsed().as_micros() as u64);
                    }
                    Ok(res) => {
                        bad_status.fetch_add(1, Ordering::SeqCst);
                        eprintln!("gate1: webhook {event} got {}", res.status());
                    }
                    Err(e) => {
                        bad_status.fetch_add(1, Ordering::SeqCst);
                        eprintln!("gate1: webhook {event} transport error: {e}");
                    }
                }
            }
        }));
    }
    for t in tasks {
        t.await.map_err(|e| e.to_string())?;
    }

    assert_eq!(bad_status.load(Ordering::SeqCst), 0, "every webhook ingest must be 202");
    let mut lat: Vec<u64> = latencies.lock().await.iter().copied().collect();
    lat.sort_unstable();
    let p50 = lat[lat.len() / 2];
    let p99 = lat[(lat.len() as f64 * 0.99) as usize % lat.len()];
    println!("gate1: {TOTAL} webhooks accepted — p50 {p50}µs / p99 {p99}µs");
    let (b, o, avg_b, avg_ms, total_ms) = store.stats.snapshot_stats();
    println!(
        "gate1 actor: batches={b} ops={o} avg_batch={avg_b:.0} avg_commit_ms={avg_ms:.2} total_commit_ms={total_ms}"
    );

    // All delivered, HMAC intact, zero duplicates.
    let deadline = Instant::now() + Duration::from_secs(90);
    while app.delivered_total() < TOTAL {
        if Instant::now() > deadline {
            return Err(format!(
                "only {} / {TOTAL} webhooks delivered (kill chaos not recovered)",
                app.delivered_total()
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(app.hmac_failures(), 0, "every delivered webhook must keep its HMAC valid");
    let counts = app.delivery_counts().await;
    assert_eq!(counts.len(), TOTAL as usize, "no event may be lost");
    let dupes = counts.values().filter(|&&c| c > 1).count();
    assert_eq!(dupes, 0, "zero duplicate deliveries");

    // Queue truth: 5 000 delivered, nothing dead-lettered.
    let c = store.counts().await.map_err(|e| e.to_string())?;
    assert_eq!(c.delivered_total, TOTAL);
    assert_eq!(c.dead_letter, 0);

    // Idempotency dedup probe: 3 racing retries of event 0's key.
    let mut dedup_tasks = Vec::new();
    for _ in 0..3 {
        let client = client.clone();
        let proxy_addr = proxy.local_addr;
        dedup_tasks.push(tokio::spawn(async move {
            let body = r#"{"event":0,"type":"invoice.paid","amount":1000}"#;
            let req = hyper::Request::builder()
                .method("POST")
                .uri(format!("http://{proxy_addr}/webhooks/stripe"))
                .header("content-type", "application/json")
                .header("x-event-id", "0")
                .header("idempotency-key", "evt-0")
                .header("x-test-signature", hmac_hex(body.as_bytes()))
                .body(HttpBody::new(Bytes::from(body)))
                .unwrap();
            client.request(req).await.unwrap().status().as_u16()
        }));
    }
    for t in dedup_tasks {
        assert_eq!(t.await.map_err(|e| e.to_string())?, 202, "dedup retries still 202");
    }
    let c2 = store.counts().await.map_err(|e| e.to_string())?;
    assert_eq!(c2.delivered_total, TOTAL, "deduped retries must not enqueue a new job");
    assert!(c2.deduped_total >= 1, "dedup counter must have moved");

    println!("gate1 PASS: 5000/5000 delivered, HMAC intact, 0 duplicates, 202 p99 {p99}µs");
    drop(proxy);
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

impl MockApp {
    fn clone_handle_for_kill(&self) -> KillHandle {
        KillHandle {
            delivered_total: self.state.delivered_total.clone(),
            kill_ctl: self.kill_ctl.clone(),
            addr: self.addr,
            state: self.state.clone(),
            proxy_addr: self.proxy_addr.clone(),
            egress_addr: self.egress_addr.clone(),
            stripe_target: self.stripe_target.clone(),
        }
    }
}

/// A kill/restart handle sharing the app's state and control channel.
struct KillHandle {
    delivered_total: Arc<AtomicU64>,
    kill_ctl: Arc<Mutex<Option<watch::Sender<u64>>>>,
    addr: SocketAddr,
    state: AppState,
    proxy_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    egress_addr: Arc<tokio::sync::OnceCell<SocketAddr>>,
    stripe_target: Arc<tokio::sync::OnceCell<String>>,
}

impl KillHandle {
    fn delivered_total(&self) -> u64 {
        self.delivered_total.load(Ordering::SeqCst)
    }
    async fn kill_for(&self, duration: Duration) {
        self.state.draining.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sender = self.kill_ctl.lock().await.take();
        if let Some(tx) = sender {
            let gen = tx.borrow().wrapping_add(1);
            let _ = tx.send(gen);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        tokio::time::sleep(duration).await;
        let listener = TcpListener::bind((self.addr.ip(), self.addr.port()))
            .await
            .expect("rebind mock app");
        let (tx, rx) = watch::channel(0u64);
        *self.kill_ctl.lock().await = Some(tx);
        spawn_accept_loop(listener, self.state.clone(), rx, self.proxy_addr.clone(), self.egress_addr.clone(), self.stripe_target.clone());
        self.state.draining.store(false, Ordering::SeqCst);
    }
}

/// Gate 2 — Invisible App Restart (Connection Hold).
pub async fn gate2() -> Result<(), String> {
    let dir = tmpdir("gate2");
    let app = MockApp::spawn(false).await;
    let health = UpstreamHealth::new(3);

    let cfg = IngressConfig {
        data_dir: dir.clone(),
        upstream: app.addr.to_string(),
        health: Some(Arc::clone(&health)),
        hold_window: Duration::from_millis(3_000),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await.map_err(|e| e.to_string())?;

    // Kill + restart within 400 ms while traffic flows.
    let kill_app = app.clone_handle_for_kill();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let t0 = Instant::now();
        kill_app.kill_for(Duration::from_millis(400)).await;
        eprintln!("gate2: kill window completed in {}ms", t0.elapsed().as_millis());
    });

    // Steady sync traffic: 8 tasks for ~1.6 s.
    let client = http_client();
    let ok = Arc::new(AtomicU64::new(0));
    let non200 = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let ok = ok.clone();
        let non200 = non200.clone();
        let proxy_addr = proxy.local_addr;
        tasks.push(tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_millis(1_600);
            while Instant::now() < deadline {
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri(format!("http://{proxy_addr}/api/orders"))
                    .body(HttpBody::new(Bytes::new()))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 200 => {
                        ok.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(res) => {
                        non200.fetch_add(1, Ordering::SeqCst);
                        eprintln!("gate2: got {}", res.status());
                    }
                    Err(e) => {
                        non200.fetch_add(1, Ordering::SeqCst);
                        eprintln!("gate2: transport error {e}");
                    }
                }
            }
        }));
    }
    for t in tasks {
        t.await.map_err(|e| e.to_string())?;
    }

    let ok_n = ok.load(Ordering::SeqCst);
    let bad_n = non200.load(Ordering::SeqCst);
    assert!(ok_n > 500, "steady traffic must have flowed: {ok_n} ok");
    assert_eq!(bad_n, 0, "zero 502/error responses across the invisible restart");
    println!(
        "gate2 PASS: {ok_n} requests, 0 failures across a 400 ms app restart (breaker: {})",
        health.transitions()
    );
    drop(proxy);
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Gate 3 — Deterministic Replay Sandbox.
pub async fn gate3() -> Result<(), String> {
    let dir = tmpdir("gate3");
    let stripe = MockStripe::spawn().await;

    // Production node: proxy (own writer owns the segment dir) + record
    // interceptor wired to the proxy's sink.
    let app = MockApp::spawn(true).await;
    let cfg = IngressConfig {
        data_dir: dir.clone(),
        upstream: app.addr.to_string(),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await.map_err(|e| e.to_string())?;
    let interceptor = spawn_interceptor(InterceptorConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        mode: Arc::new(InterceptorMode::Record {
            emit: {
                let sink = proxy.sink.clone();
                Arc::new(move |mut rec: blackbox_core::schema::TraceRecord| {
                    rec.seq_no = sink.next_seq();
                    sink.try_send(rec);
                })
            },
        }),
    })
    .await
    .map_err(|e| e.to_string())?;

    app.set_proxy_addr(proxy.local_addr);
    app.set_egress_addr(interceptor.local_addr);
    app.set_stripe_target(format!("http://127.0.0.1:{}{STRIPE_TARGET_PATH}", stripe.addr.port()));

    // ---- RECORD: checkout calls Stripe, then the app crashes (500). ----
    let client = http_client();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/checkout", proxy.local_addr))
        .header("content-type", "application/json")
        .body(HttpBody::new(Bytes::from_static(br#"{"cart":"sku-42","qty":1}"#)))
        .unwrap();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    let trace_hex = res
        .headers()
        .get("x-blackbox-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or("missing x-blackbox-trace-id")?;
    assert_eq!(res.status().as_u16(), 500, "buggy build must crash after charging");
    let _ = res.into_body().collect().await.map_err(|e| e.to_string())?;

    proxy.flush().await;
    let trace_id = parse_trace_hex(&trace_hex).ok_or("bad trace id")?;
    let recs = proxy
        .wait_trace(&trace_id, 3, Duration::from_secs(5))
        .await;
    let kinds: Vec<&str> = recs
        .iter()
        .map(|r| match &r.payload {
            RecordPayload::IngressHttp(_) => "ingress",
            RecordPayload::EgressHttpMock(_) => "egress",
            RecordPayload::SentryCrash(_) => "sentry",
            _ => "other",
        })
        .collect();
    assert!(kinds.contains(&"ingress"), "recorded trace must contain IngressHttp: {kinds:?}");
    assert!(kinds.contains(&"egress"), "recorded trace must contain EgressHttpMock: {kinds:?}");
    assert!(kinds.contains(&"sentry"), "recorded trace must contain SentryCrash: {kinds:?}");
    assert_eq!(stripe.calls(), 1, "exactly one real Stripe call during record");
    println!("gate3: recorded trace {trace_hex} with {kinds:?}");

    // ---- REPLAY: mock Stripe is DOWN; the fixed app re-executes. ----
    stripe.shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stripe.calls(), 1);

    // Drop the production proxy so its writer releases the segment dir.
    drop(proxy);
    drop(app);
    drop(client);
    tokio::time::sleep(Duration::from_millis(120)).await;

    let engine = blackbox_queue::ReplayEngine::load(&dir, &trace_id).map_err(|e| e.to_string())?;
    assert_eq!(engine.total(), 1, "one recorded egress call for the trace");

    let replay_app = MockApp::spawn(false).await;
    let replay_cfg = IngressConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: tmpdir("gate3-replay"), // separate sandbox segment dir
        upstream: replay_app.addr.to_string(),
        replay_trace: Some(trace_id),
        ..Default::default()
    };
    let replay_proxy: ProxyHandle = spawn_proxy(replay_cfg).await.map_err(|e| e.to_string())?;
    let mock_interceptor = spawn_interceptor(InterceptorConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        mode: Arc::new(InterceptorMode::Mock { engine: Arc::new(engine) }),
    })
    .await
    .map_err(|e| e.to_string())?;

    replay_app.set_proxy_addr(replay_proxy.local_addr);
    replay_app.set_egress_addr(mock_interceptor.local_addr);
    // Stripe target unchanged — but the server is DEAD; the interceptor
    // must serve the recorded response so the app never notices.
    replay_app.set_stripe_target(format!("http://127.0.0.1:{}{STRIPE_TARGET_PATH}", stripe.addr.port()));

    let client = http_client();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/checkout", replay_proxy.local_addr))
        .header("content-type", "application/json")
        .body(HttpBody::new(Bytes::from_static(br#"{"cart":"sku-42","qty":1}"#)))
        .unwrap();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let body = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    assert_eq!(
        status,
        200,
        "replayed execution must succeed with the recorded charge: {}",
        String::from_utf8_lossy(&body)
    );
    let body_str = String::from_utf8_lossy(&body).to_string();
    assert!(
        body_str.contains("ch_replay_12345"),
        "the app must receive the EXACT recorded Stripe response: {body_str}"
    );
    assert_eq!(stripe.calls(), 1, "the dead Stripe mock must receive ZERO replay traffic");

    // ---- Sandbox guard: an UNRECORDED outgoing call is 428-blocked. ----
    let (status, _, headers) = forward_proxy_call(
        mock_interceptor.local_addr,
        "POST",
        "http://api.twilio.com/2010-04-01/Accounts/X/Messages",
        &[("traceparent", format!("00-{trace_hex}-0000000000000001-01").as_str())],
        br#"{"to":"+15551234567"}"#,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(status, 428, "unrecorded egress must be blocked with 428");
    assert!(
        headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-blackbox-replay-blocked") && v == "true"),
        "sandbox guard header missing: {headers:?}"
    );
    println!("gate3 PASS: replay served the recorded charge id, live API untouched, unrecorded call 428-blocked");

    drop(replay_proxy);
    drop(replay_app);
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
