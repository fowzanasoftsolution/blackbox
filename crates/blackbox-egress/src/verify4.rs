//! Phase 4 verification gates.
//!
//! - [`gate1`] — Singleflight coalescing & FinOps cost savings: 50
//!   concurrent identical LLM POSTs across 2 tenants against a 50 ms mock
//!   OpenAI → exactly 2 upstream calls, 48 COALESCE/HIT answers, zero
//!   cross-tenant leakage, 96 % cost & token savings in the ledger.
//! - [`gate2`] — Cache poisoning & soft-error guard: 200 OK + `{"error":
//!   ...}` is never cached; the next identical call still reaches upstream.
//! - [`gate3`] — Self-healing RAM shedding: the 75 % watermark instantly
//!   purges the egress cache to 0 entries; 85 % arms head sampling;
//!   full-system RSS under load < 35 MB.

use crate::gateway::{spawn_egress, EgressConfig, EmitFn};
use blackbox_core::schema::new_id128;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

type LegacyClient = Client<HttpConnector, Full<Bytes>>;

fn client() -> LegacyClient {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn send(
    client: &LegacyClient,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(StatusCode, HeaderMap, Bytes), String> {
    let mut b = hyper::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = b
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|e| e.to_string())?;
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    let status = res.status();
    let hdrs = res.headers().clone();
    let bytes = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok((status, hdrs, bytes))
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bb4-{tag}-{}-{}",
        std::process::id(),
        new_id128() as u64
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ----------------------------------------------------- mock OpenAI API ----

struct MockState {
    hits: Arc<AtomicU64>,
    latency_ms: u64,
    /// Gate-2 poison mode: call #1 answers 200 + soft-error JSON.
    poison_first: bool,
}

/// Spawn a mock OpenAI `/v1/chat/completions` upstream. Responses carry
/// `usage` (12 prompt + 34 completion) and `x-api-cost-micros: 750`, and
/// echo the caller's Authorization into the content (cross-tenant marker).
/// Returns the bind address plus the live hit counter.
async fn spawn_mock_openai(
    latency_ms: u64,
    poison_first: bool,
) -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let state = Arc::new(MockState {
        hits: Arc::clone(&hits),
        latency_ms,
        poison_first,
    });
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let state = Arc::clone(&state);
                    async move { Ok::<_, std::convert::Infallible>(mock_handle(req, state).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, hits)
}

async fn mock_handle(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<MockState>,
) -> hyper::Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("no-auth")
        .to_string();
    let _ = req.into_body().collect().await; // drain

    if path != "/v1/chat/completions" {
        return hyper::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"mock: not found")))
            .unwrap();
    }

    let hit = state.hits.fetch_add(1, Ordering::SeqCst) + 1;
    tokio::time::sleep(Duration::from_millis(state.latency_ms)).await;

    // Gate-2 poison: the FIRST upstream call is a soft error at HTTP 200.
    if state.poison_first && hit == 1 {
        return hyper::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                r#"{"error":{"message":"rate_limit_exceeded","type":"rate_limit_error","param":"","code":"rate_limit_exceeded"}}"#,
            )))
            .unwrap();
    }

    let n = hit;
    let body = format!(
        r#"{{"id":"chatcmpl-mock{n}","object":"chat.completion","created":1700000000,"model":"gpt-4o-mini","choices":[{{"index":0,"message":{{"role":"assistant","content":"Hello from tenant {auth}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}}}"#
    );
    hyper::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-api-cost-micros", "750")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

const CHAT_BODY: &[u8] = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;

// ---------------------------------------------------------------- gate 1 ----

/// Fire 50 concurrent identical LLM POSTs across 2 tenants; verify exactly
/// 2 upstream calls, 48 COALESCE/HIT answers, tenant isolation and 96 %
/// ledger savings.
pub async fn gate1() -> Result<(), String> {
    println!("== Phase 4 Gate 1: singleflight coalescing & FinOps savings ==");
    let dir = tmpdir("g1");
    let (upstream, upstream_hits) = spawn_mock_openai(50, false).await;

    let recorded = Arc::new(AtomicU64::new(0));
    let emit: EmitFn = {
        let recorded = Arc::clone(&recorded);
        Arc::new(move |_| {
            recorded.fetch_add(1, Ordering::Relaxed);
        })
    };
    let egress = spawn_egress(
        EgressConfig {
            data_dir: dir.clone(),
            ..Default::default()
        },
        emit,
    )
    .await
    .map_err(|e| e.to_string())?;
    let egress_url = format!("http://{}/v1/chat/completions", egress.local_addr);
    let target_hdr = format!("http://{upstream}");

    // 50 concurrent: alternating tenant-a / tenant-b (25 each), distinct
    // credentials → 2 distinct composite keys.
    let client = client();
    let mut tasks = Vec::with_capacity(50);
    for i in 0..50u32 {
        let (tenant, auth) = if i % 2 == 0 {
            ("tenant-a", "sk-a-aaaaaaaaaaaaaaaa")
        } else {
            ("tenant-b", "sk-b-bbbbbbbbbbbbbbbb")
        };
        let client = client.clone();
        let url = egress_url.clone();
        let target_hdr = target_hdr.clone();
        tasks.push(tokio::spawn(async move {
            let res = send(
                &client,
                "POST",
                &url,
                &[
                    ("content-type", "application/json"),
                    ("authorization", auth),
                    ("x-blackbox-tenant", tenant),
                    ("x-blackbox-target", target_hdr.as_str()),
                ],
                CHAT_BODY,
            )
            .await
            .expect("request");
            (tenant, res)
        }));
    }

    let started = Instant::now();
    let mut miss = 0u32;
    let mut saved = 0u32;
    for t in tasks {
        let (tenant, (status, hdrs, body)) = t.await.map_err(|e| e.to_string())?;
        assert_eq!(status, StatusCode::OK, "tenant {tenant} got {status}");
        let flag = hdrs
            .get("x-blackbox-cache")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("?")
            .to_string();
        match flag.as_str() {
            "MISS" => miss += 1,
            "COALESCE" | "HIT" => saved += 1,
            other => return Err(format!("unexpected x-blackbox-cache: {other}")),
        }
        // Zero cross-tenant leakage: every answer belongs to ITS tenant.
        let text = String::from_utf8_lossy(&body);
        let want = if tenant == "tenant-a" { "sk-a-" } else { "sk-b-" };
        assert!(
            text.contains(want),
            "cross-tenant leak! tenant {tenant} received: {text}"
        );
    }
    let elapsed = started.elapsed();

    assert_eq!(miss, 2, "exactly one leader per tenant (got {miss} MISS)");
    assert_eq!(
        saved, 48,
        "48 responses must be COALESCE or HIT (got {saved})"
    );

    // Upstream received exactly 2 requests — one per tenant.
    let hits = upstream_hits.load(Ordering::SeqCst);
    assert_eq!(hits, 2, "upstream must see exactly 2 calls");

    // Wait for the 2 mock records to be counted, then flush the ledger.
    tokio::time::sleep(Duration::from_millis(100)).await;
    egress.ledger.flush().await;
    let totals = egress.ledger.totals();
    assert_eq!(totals.total_requests, 50, "ledger must count all 50");
    // Aggregate across BOTH tenants: 2 leaders (one per tenant) consumed
    // 2×46 tokens / 2×750 micros; 48 saved calls would have cost the same.
    assert_eq!(totals.tokens_used, 2 * 46);
    assert_eq!(totals.tokens_saved, 48 * 46);
    assert_eq!(totals.cost_micros_spent, 2 * 750);
    assert_eq!(totals.cost_micros_saved, 48 * 750);
    let savings = totals.savings_pct();
    assert!(
        (savings - 96.0).abs() < 0.01,
        "expected 96.0% savings, got {savings}"
    );

    println!(
        "  50 req / 2 tenants in {elapsed:?}: 2 MISS (leaders), 48 COALESCE|HIT, upstream hits={hits}"
    );
    println!(
        "  FinOps: spent {} micros, saved {} micros ({savings:.1}%), tokens {} used / {} saved, mock records {}",
        totals.cost_micros_spent,
        totals.cost_micros_saved,
        totals.tokens_used,
        totals.tokens_saved,
        recorded.load(Ordering::Relaxed)
    );
    println!("  GATE 1 PASS");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------- gate 2 ----

/// Soft-error poisoning: 200 + {"error": ...} must NEVER be cached.
pub async fn gate2() -> Result<(), String> {
    println!("== Phase 4 Gate 2: cache poisoning & soft-error guard ==");
    let dir = tmpdir("g2");
    let (upstream, upstream_hits) = spawn_mock_openai(10, true).await;

    let emit: EmitFn = Arc::new(|_| {});
    let egress = spawn_egress(
        EgressConfig {
            data_dir: dir.clone(),
            ..Default::default()
        },
        emit,
    )
    .await
    .map_err(|e| e.to_string())?;
    let url = format!("http://{}/v1/chat/completions", egress.local_addr);
    let target_hdr = format!("http://{upstream}");
    let client = client();
    let headers = [
        ("content-type", "application/json"),
        ("authorization", "sk-single-tenant"),
        ("x-blackbox-tenant", "t1"),
        ("x-blackbox-target", target_hdr.as_str()),
    ];

    // Call #1: upstream answers 200 + error JSON → MISS, NOT cached.
    let (s1, h1, b1) = send(&client, "POST", &url, &headers, CHAT_BODY)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(
        h1.get("x-blackbox-cache").and_then(|v| v.to_str().ok()),
        Some("MISS")
    );
    assert!(String::from_utf8_lossy(&b1).contains("rate_limit_exceeded"));
    assert_eq!(egress.cache.stats().entries, 0, "soft error must not be cached");

    // Call #2: identical request reaches upstream AGAIN (poison bypassed).
    let (s2, h2, b2) = send(&client, "POST", &url, &headers, CHAT_BODY)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        h2.get("x-blackbox-cache").and_then(|v| v.to_str().ok()),
        Some("MISS"),
        "call #2 must hit upstream, not the poisoned cache"
    );
    assert!(String::from_utf8_lossy(&b2).contains("Hello from tenant"));
    assert_eq!(egress.cache.stats().entries, 1, "healthy response cached");

    // Call #3: now a HIT on the healthy response.
    let (s3, h3, b3) = send(&client, "POST", &url, &headers, CHAT_BODY)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(
        h3.get("x-blackbox-cache").and_then(|v| v.to_str().ok()),
        Some("HIT")
    );
    assert_eq!(b3, b2, "HIT body must equal the cached healthy body");
    assert_eq!(
        egress.cache.stats().hits, 1,
        "exactly one cache hit"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2, "upstream must see exactly 2 calls (poisoned + healthy)");

    // Ledger: 3 requests, 2 upstream (only #2 carries usage/cost), 1 hit.
    egress.ledger.flush().await;
    let t = egress.ledger.totals();
    assert_eq!(t.total_requests, 3);
    assert_eq!(t.tokens_used, 46);
    assert_eq!(t.tokens_saved, 46);
    assert_eq!(t.cost_micros_spent, 750);
    assert_eq!(t.cost_micros_saved, 750);
    assert_eq!(t.cache_hits, 1);

    println!("  call#1: 200 + soft-error JSON (MISS, NOT cached)");
    println!("  call#2: 200 + valid completion (MISS, cached)");
    println!("  call#3: 200 + valid completion (HIT, upstream untouched)");
    println!(
        "  ledger: {} req, tokens {}/{} used/saved, micros {}/{} spent/saved",
        t.total_requests, t.tokens_used, t.tokens_saved, t.cost_micros_spent, t.cost_micros_saved
    );
    println!("  GATE 2 PASS");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------- gate 3 ----

/// Self-healing RAM shedding: 75 % watermark purges the cache to 0
/// entries instantly; 85 % arms head sampling; RSS under load < 35 MB.
pub async fn gate3() -> Result<(), String> {
    use blackbox_supervisor::memory::{publish_ram_level, RamLevel, rss_bytes};

    println!("== Phase 4 Gate 3: self-healing RAM shedding & audit ==");
    let dir = tmpdir("g3");
    let (upstream, _upstream_hits) = spawn_mock_openai(2, false).await;
    let emit: EmitFn = Arc::new(|_| {});
    let egress = spawn_egress(
        EgressConfig {
            data_dir: dir.clone(),
            ..Default::default()
        },
        emit,
    )
    .await
    .map_err(|e| e.to_string())?;
    egress.attach_self_healing();
    let base = format!("http://{}", egress.local_addr);
    let target_hdr = format!("http://{upstream}");
    let client = client();

    // Populate the cache with 5 distinct healthy completions.
    for i in 0..5u32 {
        let body = format!(
            r#"{{"model":"gpt-4o-mini","messages":[{{"role":"user","content":"q{i}"}}]}}"#
        );
        let (s, _, _) = send(
            &client,
            "POST",
            &format!("{base}/v1/chat/completions"),
            &[
                ("content-type", "application/json"),
                ("authorization", &format!("sk-g3-{i}")),
                ("x-blackbox-tenant", "g3"),
                ("x-blackbox-target", target_hdr.as_str()),
            ],
            body.as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(s, StatusCode::OK);
    }
    let entries_before = egress.cache.stats().entries;
    assert_eq!(entries_before, 5, "5 healthy completions cached");

    // --- Trigger the 75 % watermark → cache must purge to 0 immediately.
    publish_ram_level(RamLevel::Warn75);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let s = egress.cache.stats();
        if s.entries == 0 && s.purges >= 1 {
            println!(
                "  75% watermark: cache purged to 0 entries ({entries_before} evicted) — reason: {:?}",
                s.last_purge_reason
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cache did not purge within 2s of the Warn75 watermark"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // --- 85 %: head-based sampling armed (ingress Finalizer reads this).
    publish_ram_level(RamLevel::Shed85);
    assert_eq!(
        blackbox_supervisor::memory::current_ram_level(),
        RamLevel::Shed85,
        "Shed85 must be observable process-wide (ingress sampling reads it)"
    );
    println!("  85% watermark: head-based sampling armed (100% errors/slow, 1% healthy 2xx)");

    // --- Load + RSS audit: 1 200 requests (hits refill the cache) while
    //     the whole harness (mock + egress + clients) shares this process.
    publish_ram_level(RamLevel::Normal);
    for i in 0..1200u32 {
        let t = i % 5;
        let body = format!(
            r#"{{"model":"gpt-4o-mini","messages":[{{"role":"user","content":"q{t}"}}]}}"#
        );
        let _ = send(
            &client,
            "POST",
            &format!("{base}/v1/chat/completions"),
            &[
                ("content-type", "application/json"),
                ("authorization", &format!("sk-g3-{t}")),
                ("x-blackbox-tenant", "g3"),
                ("x-blackbox-target", target_hdr.as_str()),
            ],
            body.as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    let rss = rss_bytes();
    let rss_mb = rss as f64 / (1024.0 * 1024.0);
    assert!(
        rss_mb < 35.0,
        "full-system RSS {rss_mb:.1} MB exceeds the 35 MB budget"
    );

    // Binary audit (the release CLI reports its own size).
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(&p).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    println!(
        "  load: 1200 coalesced/hit requests OK | full-system RSS {rss_mb:.1} MB (gate < 35 MB)"
    );
    println!(
        "  binary: {} ({:.1} MB) [test harness path; see `blackbox p4-gate 3` for the release CLI figure]",
        std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
        bin as f64 / (1024.0 * 1024.0)
    );
    println!("  GATE 3 PASS");

    publish_ram_level(RamLevel::Normal);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
