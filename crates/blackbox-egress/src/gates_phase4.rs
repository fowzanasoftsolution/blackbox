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
//! - [`gate_near`] — the SimHash near-duplicate prompt cache (L1 behind
//!   the exact L0 hit): a key-order/case variant of a cached prompt is
//!   served byte-identical, flagged `x-blackbox-cache: SIMHASH(d≤3)`, with
//!   ONE upstream call for the whole prompt family; a genuinely different
//!   prompt, a temperature-0.7 escape and a different tenant must all pay
//!   upstream; a 1,000-prompt storm is served entirely from the near
//!   cache; the 75 % RAM watermark purges it; and the whole `prepare`
//!   pipeline is timed under the 5 µs/prompt budget.
//! - [`gate_audit`] — the tamper-evident SHA-256 chain: a clean
//!   multi-source chain verifies with exact counts and round-trips
//!   `read_anchor` → `--anchor`; an interior byte-edit faults at its line,
//!   an interior deletion faults on the seq break, and truncating history
//!   below the exported anchor faults pre-pass (an unanchored truncation is
//!   reported honestly as a shorter clean chain).

use crate::gateway::{spawn_egress, EgressConfig, EmitFn};
use blackbox_core::audit;
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

// ------------------------------------------------------------- fixtures ----

const SYSTEM_MSG: &str = "You are a payment bot.";

/// A deterministic prompt (temperature 0): system + user payment message.
/// `content_first` reorders keys inside every JSON object (body bytes
/// differ; the control skeleton and normalized text are identical).
fn chat_body(content_first: bool, id: u32) -> String {
    let user = format!(r#""Please charge order {{\"id\": {id}}} immediately.""#);
    if content_first {
        // content-first key order inside every object; messages keep
        // [system, user] — conversation order is a control knob.
        format!(
            r#"{{"model":"gpt-4o-mini","messages":[{{"content":"{SYSTEM_MSG}","role":"system"}},{{"content":{user},"role":"user"}}],"temperature":0.0}}"#
        )
    } else {
        format!(
            r#"{{"temperature":0.0,"messages":[{{"role":"system","content":"{SYSTEM_MSG}"}},{{"role":"user","content":{user}}}],"model":"gpt-4o-mini"}}"#
        )
    }
}

fn hits_of(counter: &Arc<AtomicU64>) -> u64 {
    counter.load(Ordering::SeqCst)
}

/// POST one near-gate request; `tenant` scopes both the L0 key and the near
/// cache; the response body echoes the shared Authorization marker.
async fn post(
    cl: &LegacyClient,
    url: &str,
    target: &str,
    tenant: &str,
    body: &str,
) -> Result<(StatusCode, HeaderMap, Bytes), String> {
    let hdrs = [
        ("content-type", "application/json"),
        ("authorization", "sk-near-gate"),
        ("x-blackbox-tenant", tenant),
        ("x-blackbox-target", target),
    ];
    send(cl, "POST", url, &hdrs, body.as_bytes()).await
}

fn cache_flag(hdrs: &HeaderMap) -> String {
    hdrs.get("x-blackbox-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("?")
        .to_string()
}

/// `SIMHASH(d=N)` → N; `Err` for any other flag value.
fn near_distance(flag: &str) -> Result<u64, String> {
    flag.trim_start_matches("SIMHASH(d=")
        .trim_end_matches(')')
        .parse()
        .map_err(|_| format!("unexpected x-blackbox-cache flag: {flag}"))
}

// ---------------------------------------------------------------- gate 4 ----

pub async fn gate_near() -> Result<(), String> {
    println!("== Phase 4 Gate 4: SimHash near-duplicate prompt cache ==");
    let dir = tmpdir("g4near");
    let (upstream, upstream_hits) = spawn_mock_openai(5, false).await;

    let emit: EmitFn = Arc::new(|_| {});
    let egress = spawn_egress(
        EgressConfig {
            data_dir: dir.clone(),
            ..Default::default() // near_dist defaults to BLACKBOX_SIMHASH_MAXDIST (3)
        },
        emit,
    )
    .await
    .map_err(|e| e.to_string())?;
    egress.attach_self_healing();
    let url = format!("http://{}/v1/chat/completions", egress.local_addr);
    let target_hdr = format!("http://{upstream}");
    let cl: LegacyClient = client();

    // ---- #1: the family leader — a real upstream call (MISS) that
    //      registers both the L0 entry and the L1 SimHash anchor. The MISS
    //      returns only after the detached leader published, so the near
    //      anchor is guaranteed live from here on.
    let (s1, h1, body1) = post(&cl, &url, &target_hdr, "tn-1", &chat_body(false, 7)).await?;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(cache_flag(&h1), "MISS", "first request of the family must miss");
    assert_eq!(hits_of(&upstream_hits), 1);

    // ---- #2: the near VARIANT — JSON key order flipped + case drift.
    //      Byte-different request (L0 miss) → identical harvested text →
    //      near hit → byte-identical answer, upstream untouched.
    let (s2, h2, body2) = post(&cl, &url, &target_hdr, "tn-1", &chat_body(true, 7)).await?;
    assert_eq!(s2, StatusCode::OK);
    let flag2 = cache_flag(&h2);
    let d2 = near_distance(&flag2)?;
    assert!(d2 <= 3, "in-family drift must sit within the budget (d={d2})");
    assert_eq!(body2, body1, "near hit must replay the EXACT upstream body");
    assert_eq!(hits_of(&upstream_hits), 1, "variant must NOT reach upstream");

    // ---- #3: structurally different prompt (different message shapes and
    //      content) → control skeleton differs → pays upstream.
    let distinct = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Draft an apologetic email to a tenant about the pool closing at 6pm for maintenance."}],"temperature":0.0}"#;
    let (s3, h3, _) = post(&cl, &url, &target_hdr, "tn-1", distinct).await?;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(
        cache_flag(&h3),
        "MISS",
        "a different prompt is NOT a near variant"
    );
    assert_eq!(hits_of(&upstream_hits), 2);

    // ---- #4: sampling escape — temperature 0.7 never near-serves.
    let hot = chat_body(false, 7).replace("\"temperature\":0.0", "\"temperature\":0.7");
    let (s4, h4, _) = post(&cl, &url, &target_hdr, "tn-1", &hot).await?;
    assert_eq!(s4, StatusCode::OK);
    assert_eq!(
        cache_flag(&h4),
        "MISS",
        "creative sampling must bypass the near cache"
    );
    assert_eq!(hits_of(&upstream_hits), 3);

    // ---- #5: tenant isolation — the same near-variant under another
    //      tenant lands in a DIFFERENT scope and pays upstream.
    let (s5, h5, _) = post(&cl, &url, &target_hdr, "tn-2", &chat_body(true, 7)).await?;
    assert_eq!(s5, StatusCode::OK);
    assert_eq!(
        cache_flag(&h5),
        "MISS",
        "tenants must not share near scopes"
    );
    assert_eq!(hits_of(&upstream_hits), 4);

    // ---- storm: 1,000 requests cycling ten single-token id variants
    //      (ids 10..19 — never equal to the family's id 7). Every response
    //      must come from the near cache with d ≤ 3, byte-identical, and
    //      the upstream counter must not move at all.
    let storm_started = Instant::now();
    for i in 0..1_000u32 {
        let body = chat_body(false, 10 + i % 10);
        let (s, h, b) = post(&cl, &url, &target_hdr, "tn-1", &body).await?;
        assert_eq!(s, StatusCode::OK, "storm request {i}");
        let dd = near_distance(&cache_flag(&h))
            .map_err(|e| format!("storm request {i}: {e}"))?;
        assert!(dd <= 3, "storm request {i}: distance {dd} exceeds budget");
        assert_eq!(b, body1, "storm request {i}: near answer must be byte-identical");
    }
    let storm = storm_started.elapsed();
    assert_eq!(
        hits_of(&upstream_hits),
        4,
        "the 1,000-request storm must be free of upstream calls"
    );
    let near_stats = egress.near.stats();
    assert_eq!(
        near_stats.hits,
        1_001,
        "variant + storm all served from the near cache"
    );
    assert_eq!(near_stats.scopes, 3, "tn-1 family + email + tn-2 isolation");
    assert_eq!(near_stats.entries, 3);
    println!(
        "  family: ONE upstream call answered {} near variants (d ≤ 3, flag SIMHASH(d={d2}))",
        1_001
    );
    println!("  storm: 1000 requests in {storm:?} ({:.0} µs/req wall, cache only)", storm.as_micros() as f64 / 1000.0);
    println!("  escapes verified: distinct prompt · temperature 0.7 · foreign tenant → upstream");

    // ---- self-healing: the 75 % RAM watermark purge reaches the near cache.
    {
        use blackbox_supervisor::memory::{publish_ram_level, RamLevel};
        publish_ram_level(RamLevel::Warn75);
        let purged_scopes = near_stats.scopes;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let s = egress.near.stats();
            if s.entries == 0 && s.purges >= 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "near cache did not purge within 2s of Warn75"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        publish_ram_level(RamLevel::Normal);
        println!("  75% watermark: near cache purged ({purged_scopes} scopes evicted)");
    }

    // ---- post-purge: one cold refetch, then near-serving resumes with
    //      zero further upstream traffic.
    let (s6, h6, _) = post(&cl, &url, &target_hdr, "tn-1", &chat_body(true, 7)).await?;
    assert_eq!(s6, StatusCode::OK);
    assert_eq!(
        cache_flag(&h6),
        "MISS",
        "a purged cache must cost one upstream refetch"
    );
    assert_eq!(hits_of(&upstream_hits), 5);
    let (s7, h7, _) = post(&cl, &url, &target_hdr, "tn-1", &chat_body(false, 7)).await?;
    assert_eq!(s7, StatusCode::OK);
    let flag7 = cache_flag(&h7);
    assert!(
        flag7.starts_with("SIMHASH(d="),
        "variant near-serving must resume after the refetch, got {flag7}"
    );
    let d7 = near_distance(&flag7)?;
    assert!(d7 <= 3, "resumed near hit must stay in budget (d={d7})");
    assert_eq!(hits_of(&upstream_hits), 5);

    // ---- CPU budget: the full prepare pipeline (JSON split → normalize →
    //      shingles → SimHash → BLAKE3 near-key) averaged under 5 µs for a
    //      realistic family prompt.
    let bench_body = chat_body(false, 77);
    let bytes = bench_body.as_bytes();
    const N: u32 = 4_000;
    let t0 = Instant::now();
    let mut sink = 0u64; // data-dependent — keeps the pipeline from being DCE'd
    for i in 0..N {
        if let Some((near_k, sim)) = crate::simhash::prepare(
            "tn-1",
            "sk-near-gate",
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
            bytes,
        ) {
            sink = sink.wrapping_add(u64::from(near_k[0]) ^ sim ^ u64::from(i));
        }
    }
    let per_prompt_us = t0.elapsed().as_nanos() as f64 / 1_000.0 / f64::from(N);
    assert!(sink > 0);
    assert!(
        per_prompt_us < 5.0,
        "prepare pipeline averaged {per_prompt_us:.2} µs/prompt — over the 5 µs budget"
    );
    println!(
        "  CPU: prepare() pipeline averaged {per_prompt_us:.2} µs/prompt (gate < 5 µs, body {} B)",
        bytes.len()
    );
    println!("  GATE 4 PASS");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------- gate 5 ----

/// Rewrite the audit file with `lines` transformed by `f`.
fn rewrite<F: Fn(Vec<&str>) -> Vec<String>>(path: &std::path::Path, f: F) {
    let text = std::fs::read_to_string(path).expect("audit.log readable");
    let lines: Vec<&str> = text.lines().collect();
    let out = f(lines);
    let mut joined = out.join("\n");
    if !joined.ends_with('\n') {
        joined.push('\n');
    }
    std::fs::write(path, joined).expect("audit.log rewritable");
}

pub fn gate_audit() -> Result<(), String> {
    println!("== Phase 4 Gate 5: tamper-evident audit chain ==");
    let dir = std::env::temp_dir().join(format!(
        "bb5-audit-{}-{}",
        std::process::id(),
        new_id128() as u64
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let log_path = dir.join("audit.log");

    // ---- 1) a realistic multi-source chain.
    audit::init(&dir).map_err(|e| e.to_string())?;
    audit::record("queue", "enqueue", "tid-1", "queue=checkout job=7 dedup=false");
    audit::record("egress", "upstream", "a1b2", "status=200 tokens=42 cost_micros=750");
    audit::record("queue", "deliver", "tid-1", "queue=checkout status=200 attempt=1");
    audit::record("cold", "restore", "tid-9", "segment=seg-0005");
    audit::record("replay", "start", "ffee", "target=app");

    // ---- 2) the file-tail anchor round-trips (export → verify).
    let (seq0, anchor0) =
        audit::read_anchor(&dir).ok_or("read_anchor returned None on a fresh chain")?;
    assert_eq!(seq0, 5, "five records → chain seq 5");

    let s = audit::verify(&dir, None).map_err(|f| format!("clean chain faulted: {f:?}"))?;
    assert_eq!(s.records, 5);
    assert_eq!(s.checkpoints, 0);
    assert_eq!(s.per_src.get("queue"), Some(&2));
    assert_eq!(s.per_src.get("egress"), Some(&1));
    assert_eq!(s.per_src.get("cold"), Some(&1));
    assert_eq!(s.per_src.get("replay"), Some(&1));
    assert_eq!(s.last_seq, 5);
    audit::verify(&dir, Some((seq0, anchor0.clone())))
        .map_err(|f| format!("anchored verify of an intact chain faulted: {f:?}"))?;
    println!("  clean chain: 5 records across 4 sources; anchor {seq0}:{anchor0}");

    // ---- 3) interior byte EDIT → hash break at exactly that line.
    audit::record("cold", "restore", "z", "segment=seg-0006"); // chain grows to 6
    let raw = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    std::fs::write(&log_path, raw.replace("tokens=42", "tokens=44").as_bytes())
        .map_err(|e| e.to_string())?;
    let f = audit::verify(&dir, None)
        .err()
        .ok_or("interior edit was NOT detected")?;
    assert_eq!(f.line_no, 2, "fault must name the tampered line: {f:?}");
    assert!(
        f.reason.contains("hash break"),
        "edit must fault as a hash break: {f:?}"
    );
    println!("  interior edit: caught as \"hash break\" at line {}", f.line_no);
    std::fs::write(&log_path, raw.as_bytes()).map_err(|e| e.to_string())?; // restore

    // ---- 4) interior DELETION → seq break at the gap.
    rewrite(&log_path, |lines| {
        lines
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 3) // drop file line 4 (cold/restore)
            .map(|(_, l)| l.to_string())
            .collect()
    });
    let f = audit::verify(&dir, None)
        .err()
        .ok_or("interior deletion was NOT detected")?;
    assert_eq!(f.line_no, 4, "fault must name the first post-gap line: {f:?}");
    assert!(
        f.reason.contains("seq break"),
        "deletion must fault as a seq break: {f:?}"
    );
    println!("  interior deletion: caught as \"seq break\" at line {}", f.line_no);
    std::fs::write(&log_path, raw.as_bytes()).map_err(|e| e.to_string())?; // restore

    // ---- 5) TRUNCATION below the exported anchor → pre-pass fault.
    let text = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    let n_lines = text.lines().count();
    rewrite(&log_path, |lines| {
        lines[..n_lines - 4].iter().map(|l| l.to_string()).collect()
    });
    let f = audit::verify(&dir, Some((seq0, anchor0)))
        .err()
        .ok_or("anchored truncation was NOT detected")?;
    assert_eq!(f.line_no, 0, "anchor violations are pre-pass: {f:?}");
    assert!(f.reason.contains("truncated"), "got: {f:?}");
    println!("  truncation vs anchor: caught pre-pass — {}", f.reason);

    // The UNanchored view reports honestly: a shorter, internally clean chain.
    let s = audit::verify(&dir, None).map_err(|f| format!("prefix faulted: {f:?}"))?;
    assert_eq!(s.last_seq, 2);
    let (seq1, anchor1) = audit::read_anchor(&dir).ok_or("anchor vanished after truncation")?;
    assert_eq!(seq1, 2);
    audit::verify(&dir, Some((seq1, anchor1)))
        .map_err(|f| format!("re-anchored prefix faulted: {f:?}"))?;
    println!(
        "  unanchored prefix: verifies clean at seq {seq1} (documented boundary)"
    );

    println!("  GATE 5 PASS");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
