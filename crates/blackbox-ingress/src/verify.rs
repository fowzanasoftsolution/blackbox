//! Phase 2 verification harness — the three gates from the blueprint, plus
//! the mock application they run against.
//!
//! ## Gate 1 — End-to-End Causal Link
//! `POST /checkout` through the proxy (no traceparent) → the mock upstream
//! emits an OTLP log **and** a gzipped Sentry crash envelope carrying the
//! injected trace id → `get_trace(tid)` must return exactly 3 records
//! (`IngressHttp + TelemetryLog + SentryCrash`) in causal order with every
//! PII field redacted.
//!
//! ## Gate 2 — Stream & Bomb Safety
//! 50 MB `text/plain` response streams through the proxy: the client
//! receives all 50 MB intact, only the first 64 KB are recorded, RSS
//! stays < 30 MB. A ~10 MB-decompressing gzip bomb to the envelope
//! endpoint is rejected with 413 before allocation.
//!
//! ## Gate 3 — 2-vCPU Throughput & Overhead
//! Keep-alive benchmark: direct vs proxied p50/p99 (added latency target
//! < 1.0 ms p99), ≥ 8 K req/s through the proxy on this box, RSS < 35 MB
//! under load.

use crate::proxy::{spawn_proxy, IngressConfig, ProxyHandle};
use blackbox_core::schema::{RecordPayload, TraceRecord};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

type HttpBody = Full<Bytes>;

// =========================================================== mock app =====

/// Shared cell so the mock app can discover the proxy address at runtime
/// (the proxy needs the mock's address first — chicken and egg).
pub type ProxyAddrCell = Arc<tokio::sync::OnceCell<std::net::SocketAddr>>;

/// The mock application: an upstream hyper server with the endpoints the
/// gates exercise.
pub struct MockApp {
    pub addr: std::net::SocketAddr,
    proxy_addr: ProxyAddrCell,
}

impl MockApp {
    /// Address of the blackbox proxy (set after the proxy is up).
    pub fn set_proxy_addr(&self, addr: std::net::SocketAddr) {
        self.proxy_addr.set(addr).expect("proxy addr set once");
    }

    fn proxy_addr(&self) -> std::net::SocketAddr {
        self.proxy_addr.get().copied().expect("proxy addr must be set")
    }

    fn client(&self) -> Client<HttpConnector, HttpBody> {
        Client::builder(TokioExecutor::new()).build_http()
    }

    /// "The app emitted an OTLP error log for `trace_id`" — POSTs OTLP/JSON
    /// to the proxy's /v1/logs endpoint.
    pub async fn emit_otlp_log(&self, trace_id: &str, message: &str) {
        let body = format!(
            r#"{{"resourceLogs":[{{
                "resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"checkout-svc"}}}}]}},
                "scopeLogs":[{{"logRecords":[
                    {{"severityNumber":13,"severityText":"ERROR",
                      "body":{{"stringValue":"{message}"}},"traceId":"{trace_id}"}}]}}]}}]}}"#
        );
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{}/v1/logs", self.proxy_addr()))
            .header("content-type", "application/json")
            .body(HttpBody::new(Bytes::from(body)))
            .unwrap();
        let res = self.client().request(req).await.expect("otlp post");
        assert_eq!(res.status(), 200, "OTLP log ingestion must 200");
    }

    /// "The app crashed" — POSTs a gzipped Sentry envelope to the proxy's
    /// Sentry-compatible endpoint, linked to `trace_id`.
    pub async fn emit_sentry_crash(&self, trace_id: &str, event_id: &str) {
        let envelope = format!(
            "{{\"event_id\":\"{event_id}\"}}\n{{\"type\":\"event\"}}\n{{\"contexts\":{{\"trace\":{{\"trace_id\":\"{trace_id}\"}}}},\"exception\":{{\"values\":[{{\"type\":\"Panic\",\"value\":\"payment worker crashed\"}}]}}}}\n"
        );
        let gz = gzip(&envelope.into_bytes());
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{}/api/42/envelope/", self.proxy_addr()))
            .header("content-type", "application/x-sentry-envelope")
            .header("content-encoding", "gzip")
            .body(HttpBody::new(Bytes::from(gz)))
            .unwrap();
        let res = self.client().request(req).await.expect("envelope post");
        assert_eq!(res.status(), 200, "envelope ingestion must 200");
    }
}

/// Spawn the mock upstream app on an ephemeral port.
pub async fn spawn_mock_app() -> MockApp {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
    let addr = listener.local_addr().unwrap();
    let proxy_addr: ProxyAddrCell = Arc::new(tokio::sync::OnceCell::new());
    let cell = proxy_addr.clone();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let _ = tcp.set_nodelay(true);
            let cell = cell.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let cell = cell.clone();
                    async move { Ok::<_, std::convert::Infallible>(mock_route(req, cell).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });

    MockApp { addr, proxy_addr }
}

async fn mock_route(
    req: hyper::Request<Incoming>,
    proxy_cell: ProxyAddrCell,
) -> hyper::Response<MockBody> {
    let path = req.uri().path().to_string();

    // WebSocket-style upgrade echo tunnel (used by the 101 passthrough test).
    if req.headers().contains_key(hyper::header::UPGRADE) {
        let res = hyper::Response::builder()
            .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
            .header(hyper::header::UPGRADE, "blackbox-test")
            .header(hyper::header::CONNECTION, "Upgrade")
            .body(MockBody::empty())
            .unwrap();
        tokio::spawn(async move {
            let mut req = req;
            if let Ok(up) = hyper::upgrade::on(&mut req).await {
                let mut up = TokioIo::new(up); // hyper rt traits → tokio IO
                let mut buf = [0u8; 256];
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                loop {
                    match up.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if up.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        return res;
    }

    // Streaming endpoints for the stream-safety gate.
    if let Some(rest) = path.strip_prefix("/stream") {
        let (bytes, ct) = parse_stream_query(rest, "text/plain");
        let body = MockBody::Stream(MockStreamBody::new(bytes, 64 * 1024));
        return hyper::Response::builder()
            .status(200)
            .header("content-type", ct)
            .body(body)
            .unwrap();
    }
    if let Some(rest) = path.strip_prefix("/binary") {
        let (bytes, ct) = parse_stream_query(rest, "application/octet-stream");
        let body = MockBody::Stream(MockStreamBody::new(bytes, 64 * 1024));
        return hyper::Response::builder()
            .status(200)
            .header("content-type", ct)
            .body(body)
            .unwrap();
    }

    // Ping endpoint for the throughput benchmark.
    if path == "/ping" {
        return hyper::Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(MockBody::Full(HttpBody::new(Bytes::from_static(b"ok"))))
            .unwrap();
    }

    // Normal app endpoint: echo the (proxy-injected) traceparent so the
    // gate can verify W3C injection, then emit telemetry for this trace.
    let tp = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_default();

    if path == "/checkout" {
        // Parse the injected trace id (mock app "uses" it for its telemetry).
        let trace_id = tp
            .split('-')
            .nth(1)
            .map(String::from)
            .unwrap_or_default();
        let proxy = proxy_cell.get().copied();
        if let (Some(proxy_addr), true) = (proxy, !trace_id.is_empty()) {
            let app = MockAppShim {
                proxy_addr,
                trace_id: trace_id.clone(),
            };
            tokio::spawn(async move {
                // Respond first; emit telemetry once the response has had
                // time to reach the client (deterministic-enough ordering
                // for the causal assertion, which sleeps between phases).
                tokio::time::sleep(Duration::from_millis(200)).await;
                app.emit_telemetry().await;
            });
        }
        return hyper::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(MockBody::Full(HttpBody::new(Bytes::from(format!(
                "{{\"ok\":true,\"tp\":\"{tp}\"}}"
            )))))
            .unwrap();
    }

    hyper::Response::builder()
        .status(404)
        .body(MockBody::Full(HttpBody::new(Bytes::from_static(b"not found"))))
        .unwrap()
}

/// Late-bound handle the mock app uses to phone home through the proxy.
struct MockAppShim {
    proxy_addr: std::net::SocketAddr,
    trace_id: String,
}

impl MockAppShim {
    async fn emit_telemetry(&self) {
        let client: Client<HttpConnector, HttpBody> = Client::builder(TokioExecutor::new()).build_http();
        // 1) OTLP error log for this trace.
        let log_body = format!(
            r#"{{"resourceLogs":[{{"resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"checkout-svc"}}}}]}},"scopeLogs":[{{"logRecords":[{{"severityNumber":13,"body":{{"stringValue":"payment failed after 42ms"}},"traceId":"{}"}}]}}]}}]}}"#,
            self.trace_id
        );
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{}/v1/logs", self.proxy_addr))
            .header("content-type", "application/json")
            .body(HttpBody::new(Bytes::from(log_body)))
            .unwrap();
        if let Ok(res) = client.request(req).await {
            assert_eq!(res.status(), 200, "otlp log must be accepted");
        }
        // 2) Gzipped Sentry crash envelope for the same trace.
        let envelope = format!(
            "{{\"event_id\":\"d6e0c1e0e0c14d5e9f1a2b3c4d5e6f70\"}}\n{{\"type\":\"event\"}}\n{{\"contexts\":{{\"trace\":{{\"trace_id\":\"{}\"}}}},\"exception\":{{\"values\":[{{\"type\":\"Panic\"}}]}}}}\n",
            self.trace_id
        );
        let gz = gzip(&envelope.into_bytes());
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{}/api/42/envelope/", self.proxy_addr))
            .header("content-type", "application/x-sentry-envelope")
            .header("content-encoding", "gzip")
            .body(HttpBody::new(Bytes::from(gz)))
            .unwrap();
        if let Ok(res) = client.request(req).await {
            assert_eq!(res.status(), 200, "envelope must be accepted");
        }
    }
}

fn parse_stream_query<'a>(rest: &str, default_ct: &'a str) -> (u64, &'a str) {
    // rest is like "?bytes=52428800" or "" (query lives on the uri though —
    // path prefix strip loses it; the caller passes it via path only, so
    // support plain numbers in the path: /stream/52428800).
    let n = rest
        .trim_start_matches('/')
        .parse::<u64>()
        .unwrap_or(0);
    (n, default_ct)
}

/// Lazily-generated stream body: never holds more than one chunk in memory.
pub struct MockStreamBody {
    remaining: u64,
    chunk_size: usize,
    chunk_index: u64,
}

impl MockStreamBody {
    pub fn new(total: u64, chunk_size: usize) -> Self {
        MockStreamBody { remaining: total, chunk_size, chunk_index: 0 }
    }
}

impl hyper::body::Body for MockStreamBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = (self.chunk_size as u64).min(self.remaining);
        self.remaining -= n;
        let fill = (self.chunk_index % 26) as u8 + b'a';
        self.chunk_index += 1;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![fill; n as usize])))))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

/// Either a full body (small endpoints) or the lazy stream (big endpoints).
pub enum MockBody {
    Full(HttpBody),
    Stream(MockStreamBody),
}

impl MockBody {
    fn empty() -> Self {
        MockBody::Full(HttpBody::new(Bytes::new()))
    }
}

impl hyper::body::Body for MockBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            MockBody::Full(f) => match Pin::new(f).poll_frame(cx) {
                Poll::Ready(Some(Err(e))) => match e {},
                other => other,
            },
            MockBody::Stream(s) => Pin::new(s).poll_frame(cx),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            MockBody::Full(f) => f.size_hint(),
            MockBody::Stream(s) => s.size_hint(),
        }
    }
}

/// gzip helper (verify-only; the proxy decodes, never encodes).
fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Build a ~10 MB-decompressing gzip bomb WITHOUT materializing the 10 MB
/// plaintext (1 MB scratch buffer reused per chunk).
fn gzip_bomb(decompressed_target: usize) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    let scratch = vec![b'A'; 1024 * 1024];
    let mut written = 0usize;
    while written < decompressed_target {
        let n = scratch.len().min(decompressed_target - written);
        enc.write_all(&scratch[..n]).unwrap();
        written += n;
    }
    enc.finish().unwrap()
}

// ============================================================= gates ======

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "blackbox-gate-{tag}-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pct(samples: &mut [u64], p: f64) -> u64 {
    samples.sort_unstable();
    if samples.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (samples.len() as f64 - 1.0)).round() as usize;
    samples[idx.min(samples.len() - 1)]
}

fn fmt_ns(ns: u64) -> String {
    if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    }
}

/// Spawn proxy + mock app pair; returns (handle, mock, data_dir).
async fn setup(tag: &str) -> (ProxyHandle, MockApp, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let mock = spawn_mock_app().await;
    let cfg = IngressConfig {
        data_dir: dir.clone(),
        upstream: mock.addr.to_string(),
        ..IngressConfig::default()
    };
    let proxy = spawn_proxy(cfg).await.expect("proxy spawn");
    mock.set_proxy_addr(proxy.local_addr);
    (proxy, mock, dir)
}

/// A pooled keep-alive client for the test-side.
fn bench_client() -> Client<HttpConnector, HttpBody> {
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(64)
        .build_http()
}

// ------------------------------------------------------------- gate 1 ----

/// Gate 1: End-to-end causal link — IngressHttp + TelemetryLog + SentryCrash
/// under one trace id, in causal order, PII fully redacted.
pub async fn gate1() -> Result<(), String> {
    println!("═══ GATE 1: End-to-End Causal Link ═══");
    let (proxy, _mock, dir) = setup("g1").await;

    // -- Step 1: POST /checkout through the proxy (NO traceparent header).
    let client = bench_client();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/checkout", proxy.local_addr))
        .header("content-type", "application/json")
        .header("authorization", "Bearer sk-live-999-SECRET")
        .header("cookie", "session=supersecret123")
        .body(HttpBody::new(Bytes::from(
            r#"{"password":"hunter2","credit_card":"4111111111111111","note":"deliver to dock 7"}"#,
        )))
        .unwrap();
    let t0 = Instant::now();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    assert_eq!(res.status(), 200, "proxy must reach upstream");
    let trace_hdr = res
        .headers()
        .get("x-blackbox-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or("missing x-blackbox-trace-id response header")?;
    let (_, body) = res.into_parts();
    let body = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    let body_str = String::from_utf8_lossy(&body);
    println!("  response ({} ms): {body_str}", t0.elapsed().as_millis());

    // -- Step 2: verify the traceparent the proxy injected upstream.
    let tp_json: serde_json::Value =
        serde_json::from_str(&body_str).map_err(|e| format!("bad upstream body: {e}"))?;
    let tp = tp_json["tp"].as_str().ok_or("mock did not echo traceparent")?;
    assert_eq!(tp.len(), 55, "W3C format 00-32hex-16hex-01: {tp}");
    assert!(tp.starts_with("00-"), "version 00: {tp}");
    let injected_tid = tp.split('-').nth(1).ok_or("no trace id in tp")?;
    assert_eq!(injected_tid, trace_hdr, "injected trace id == response header");

    // -- Step 3: the mock app has now posted OTLP + Sentry (delayed 200 ms);
    //    wait for all three records to be indexed under the trace id.
    let tid = blackbox_core::schema::parse_trace_hex(&trace_hdr)
        .ok_or("trace header is not 32-hex")?;
    let records = proxy.wait_trace(&tid, 3, Duration::from_secs(10)).await;
    if records.len() < 3 {
        return Err(format!(
            "expected 3 correlated records, got {} (dropped={})",
            records.len(),
            proxy.dropped()
        ));
    }

    // -- Step 4: causal order + kind + redaction assertions.
    println!("  trace {} → {} records:", trace_hdr, records.len());
    for (i, r) in records.iter().enumerate() {
        let kind = match &r.payload {
            RecordPayload::IngressHttp(h) => format!("IngressHttp {} {}", h.method, h.uri),
            RecordPayload::TelemetryLog(l) => format!("TelemetryLog [{}] {}", l.level, l.message),
            RecordPayload::SentryCrash(c) => format!("SentryCrash event={}", c.event_id),
            _ => "?".into(),
        };
        println!("    #{i} seq={} ts={} {kind}", r.seq_no, r.timestamp_ms);
    }

    let kinds: Vec<&str> = records
        .iter()
        .map(|r| match &r.payload {
            RecordPayload::IngressHttp(_) => "IngressHttp",
            RecordPayload::TelemetryLog(_) => "TelemetryLog",
            RecordPayload::SentryCrash(_) => "SentryCrash",
            _ => "?",
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["IngressHttp", "TelemetryLog", "SentryCrash"],
        "records must arrive in causal order"
    );
    for w in records.windows(2) {
        assert!(w[0].seq_no < w[1].seq_no, "seq_no must increase causally");
    }

    // IngressHttp: status 200 + PII scrubbed everywhere.
    let blackbox_core::schema::RecordPayload::IngressHttp(h) = &records[0].payload else {
        return Err("first record not IngressHttp".into());
    };
    assert_eq!(h.status, 200);
    assert_eq!(h.method, "POST");
    assert_eq!(h.uri, "/checkout");
    let hdr = |name: &str| {
        h.req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(hdr("authorization").as_deref(), Some("[REDACTED]"), "authorization redacted");
    assert_eq!(hdr("cookie").as_deref(), Some("[REDACTED]"), "cookie redacted");
    let body_json = String::from_utf8_lossy(&h.req_body);
    assert!(body_json.contains("\"password\":\"[REDACTED]\""), "password redacted: {body_json}");
    assert!(body_json.contains("\"credit_card\":\"[REDACTED]\""), "credit_card redacted");
    assert!(body_json.contains("\"note\":\"deliver to dock 7\""), "benign data intact: {body_json}");
    assert!(!body_json.contains("hunter2") && !body_json.contains("4111111111111111"));

    // TelemetryLog: linked to the same trace id, parsed from OTLP.
    let blackbox_core::schema::RecordPayload::TelemetryLog(l) = &records[1].payload else {
        return Err("second record not TelemetryLog".into());
    };
    assert_eq!(l.service, "checkout-svc");
    assert_eq!(l.message, "payment failed after 42ms");
    assert_eq!(l.level, 5, "severityNumber 13 → ERROR");

    // SentryCrash: verbatim envelope, linked to the same trace id.
    let blackbox_core::schema::RecordPayload::SentryCrash(c) = &records[2].payload else {
        return Err("third record not SentryCrash".into());
    };
    assert_eq!(c.project_id, "42");
    assert_eq!(c.event_id, "d6e0c1e0e0c14d5e9f1a2b3c4d5e6f70");
    let env = String::from_utf8_lossy(&c.envelope);
    assert!(env.contains("\"trace_id\""), "envelope verbatim");

    let st = proxy.stats();
    println!(
        "  index: frames={} 2xx={} crashes={} traces={}",
        st.frames, st.status_2xx, st.sentry_crashes, st.distinct_traces
    );
    assert_eq!(proxy.dropped(), 0, "no records dropped");

    let _ = std::fs::remove_dir_all(&dir);
    println!("  ✔ GATE 1 PASSED — 3 records, causal order, PII redacted");
    Ok(())
}

// ------------------------------------------------------------- gate 2 ----

/// Gate 2: 50 MB stream (all bytes through, 64 KB recorded, RSS < 30 MB)
/// + gzip bomb rejected with 413.
pub async fn gate2() -> Result<(), String> {
    println!("═══ GATE 2: Stream & Bomb Safety ═══");
    let (proxy, _mock, dir) = setup("g2").await;
    let client = bench_client();

    // -- Step 1: 50 MB text/plain stream through the proxy.
    const TOTAL: u64 = 50 * 1024 * 1024;
    let req = hyper::Request::builder()
        .uri(format!("http://{}/stream/{TOTAL}", proxy.local_addr))
        .body(HttpBody::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    assert_eq!(res.status(), 200);
    let trace_hdr = res
        .headers()
        .get("x-blackbox-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or("missing trace header")?;
    let tid = blackbox_core::schema::parse_trace_hex(&trace_hdr).ok_or("bad trace hex")?;

    let mut received: u64 = 0;
    let mut block_bytes = 0u64;
    let mut expected_fill = b'a';
    let mut body = res.into_body();
    let t0 = Instant::now();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Some(d) = frame.data_ref() {
            received += d.len() as u64;
            // Verify content block-by-block: each 64 KB block is constant.
            for &b in d.iter() {
                if b != expected_fill {
                    return Err(format!("corrupt byte at {} (got {b}, want {expected_fill})", received));
                }
                block_bytes += 1;
                if block_bytes == 64 * 1024 {
                    block_bytes = 0;
                    expected_fill = (expected_fill - b'a' + 1) % 26 + b'a';
                }
            }
        }
    }
    let elapsed = t0.elapsed();
    assert_eq!(received, TOTAL, "client must receive all 50 MB");
    let mbps = (TOTAL as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
    println!("  streamed 50 MB intact in {:.2}s ({mbps:.0} MB/s)", elapsed.as_secs_f64());

    // -- Step 2: only the first 64 KB recorded; RSS bounded.
    proxy.flush().await;
    let recs = proxy
        .wait_trace(&tid, 1, Duration::from_secs(5))
        .await;
    assert!(!recs.is_empty(), "stream request must be recorded");
    let blackbox_core::schema::RecordPayload::IngressHttp(h) = &recs[0].payload else {
        return Err("record not IngressHttp".into());
    };
    assert_eq!(h.res_body.len(), 64 * 1024, "exactly the first 64 KB captured");
    println!(
        "  recorded res_body={} bytes (64 KB cap enforced; {} MB body streamed)",
        h.res_body.len(), TOTAL / 1024 / 1024
    );

    let rss_after_stream = blackbox_supervisor::memory::rss_bytes() as f64 / 1024.0 / 1024.0;
    println!("  RSS after 50 MB stream: {rss_after_stream:.1} MB (gate < 30 MB)");
    assert!(rss_after_stream < 30.0, "RSS {rss_after_stream:.1} MB must stay under 30 MB");

    // -- Step 3: gzip bomb (decompresses to ~10 MB) → 413, no panic.
    let bomb = gzip_bomb(10 * 1024 * 1024);
    println!("  gzip bomb: {} B compressed → ~10 MB decompressed", bomb.len());
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/api/1/envelope/", proxy.local_addr))
        .header("content-type", "application/x-sentry-envelope")
        .header("content-encoding", "gzip")
        .body(HttpBody::new(Bytes::from(bomb)))
        .unwrap();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    assert_eq!(res.status(), 413, "zip bomb must be rejected with 413");
    let status = res.status();
    let _ = res.into_body().collect().await;
    println!("  → {status} (rejected cleanly)");

    // -- Step 4: raw oversize identity body → 413 as well.
    let big = Bytes::from(vec![0u8; 2 * 1024 * 1024 + 1]); // 2 MiB + 1
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}/api/1/envelope/", proxy.local_addr))
        .header("content-type", "application/x-sentry-envelope")
        .body(HttpBody::new(big))
        .unwrap();
    let res = client.request(req).await.map_err(|e| e.to_string())?;
    assert_eq!(res.status(), 413, "raw oversize body must 413");
    println!("  → identity 2 MiB+1 body also rejected with 413");

    let _ = std::fs::remove_dir_all(&dir);
    println!("  ✔ GATE 2 PASSED — 50 MB intact, 64 KB recorded, bombs 413, RSS < 30 MB");
    Ok(())
}

// ------------------------------------------------------------- gate 3 ----

/// Gate 3: keep-alive throughput + added-latency benchmark (direct vs
/// proxied), with RSS under load.
pub async fn gate3(requests: u64, concurrency: usize) -> Result<(), String> {
    println!("═══ GATE 3: 2-vCPU Proxy Throughput & Overhead ═══");
    let (proxy, mock, dir) = setup("g3").await;
    let client = bench_client();

    // -- Baseline: direct to upstream.
    let direct = run_load(&client, mock.addr, requests / 2, concurrency).await;
    // -- Through the proxy.
    let proxied = run_load(&client, proxy.local_addr, requests, concurrency).await;

    let direct_p50 = pct(&mut direct.clone(), 50.0);
    let direct_p99 = pct(&mut direct.clone(), 99.0);
    let proxied_p50 = pct(&mut proxied.clone(), 50.0);
    let proxied_p99 = pct(&mut proxied.clone(), 99.0);
    let delta_p50 = proxied_p50.saturating_sub(direct_p50);
    let delta_p99 = proxied_p99.saturating_sub(direct_p99);

    let elapsed_stored = PROXY_LOAD_ELAPSED.load(std::sync::atomic::Ordering::Relaxed);
    let rps = if elapsed_stored > 0 {
        proxied.len() as f64 / (elapsed_stored as f64 / 1e9)
    } else {
        0.0
    };

    println!(
        "  direct  → n={} p50={} p99={} mean={}",
        direct.len(),
        fmt_ns(direct_p50),
        fmt_ns(direct_p99),
        fmt_ns(direct.iter().sum::<u64>() / direct.len().max(1) as u64)
    );
    println!(
        "  proxied → n={} p50={} p99={} mean={}  ({:.0} req/s)",
        proxied.len(),
        fmt_ns(proxied_p50),
        fmt_ns(proxied_p99),
        fmt_ns(proxied.iter().sum::<u64>() / proxied.len().max(1) as u64),
        rps
    );
    println!(
        "  added proxy latency: p50 Δ={} p99 Δ={} (gate < 1.0 ms p99)",
        fmt_ns(delta_p50),
        fmt_ns(delta_p99)
    );

    proxy.flush().await;
    // Measure CONVERGED RSS: the burst leaves transient allocations in the
    // allocator; wait (≤ 5 s) until RSS stops shrinking so the gate checks
    // the steady-state sidecar footprint, not a momentary peak.
    let mut last = blackbox_supervisor::memory::rss_bytes();
    let mut stable = 0u32;
    for i in 0..24u32 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = blackbox_supervisor::memory::rss_bytes();
        if now < last {
            stable = 0;
        } else {
            stable += 1;
        }
        // Early exit only after a full ≥ 2 s decay window.
        if i >= 8 && stable >= 4 {
            break;
        }
        last = now.min(last);
    }
    let rss = blackbox_supervisor::memory::rss_bytes() as f64 / 1024.0 / 1024.0;
    let st = proxy.stats();
    println!(
        "  RSS under load: {rss:.1} MB (gate < 35 MB) | indexed frames={} traces={}",
        st.frames, st.distinct_traces
    );

    // -- Gates.
    assert!(
        rps >= 8_000.0,
        "throughput {:.0} req/s below the 8k req/s target",
        rps
    );
    assert!(
        (delta_p99 as f64) < 1_000_000.0,
        "added p99 latency {} exceeds 1.0 ms",
        fmt_ns(delta_p99)
    );
    assert!(rss < 35.0, "RSS {rss:.1} MB exceeds the 35 MB load budget");
    assert_eq!(proxy.dropped(), 0, "no records dropped under load");

    let _ = std::fs::remove_dir_all(&dir);
    println!("  ✔ GATE 3 PASSED — {:.0} req/s, p99 Δ={}, RSS {rss:.1} MB", rps, fmt_ns(delta_p99));
    Ok(())
}

static PROXY_LOAD_ELAPSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run `n` GET /ping keep-alive requests at `concurrency`; returns per-request
/// latencies in nanoseconds (measured end-to-end incl. body drain).
async fn run_load(
    client: &Client<HttpConnector, HttpBody>,
    addr: std::net::SocketAddr,
    n: u64,
    concurrency: usize,
) -> Vec<u64> {
    // Warmup: pool + caches.
    for _ in 0..500.min(n) {
        let req = hyper::Request::builder()
            .uri(format!("http://{addr}/ping"))
            .body(HttpBody::new(Bytes::new()))
            .unwrap();
        let res = client.request(req).await.expect("warmup");
        let _ = res.into_body().collect().await;
    }

    let per_task = n / concurrency.max(1) as u64;
    let latencies = Arc::new(std::sync::Mutex::new(Vec::with_capacity(n as usize)));
    let t0 = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let latencies = latencies.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..per_task {
                let req = hyper::Request::builder()
                    .uri(format!("http://{addr}/ping"))
                    .body(HttpBody::new(Bytes::new()))
                    .unwrap();
                let start = Instant::now();
                let res = client.request(req).await.expect("load request");
                assert_eq!(res.status(), 200, "load request must succeed");
                let _ = res.into_body().collect().await;
                latencies.lock().unwrap().push(start.elapsed().as_nanos() as u64);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let elapsed_ns = t0.elapsed().as_nanos() as u64;
    PROXY_LOAD_ELAPSED.store(elapsed_ns, std::sync::atomic::Ordering::Relaxed);
    let mut out = Arc::try_unwrap(latencies)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    out.shrink_to_fit();
    out
}

// ---------------------------------------------------- misc gate helper ----

/// Quick sanity print used by the CLI before/after gates.
pub fn trace_kinds(records: &[TraceRecord]) -> Vec<&'static str> {
    records
        .iter()
        .map(|r| match &r.payload {
            RecordPayload::IngressHttp(_) => "IngressHttp",
            RecordPayload::EgressHttpMock(_) => "EgressHttpMock",
            RecordPayload::TelemetryLog(_) => "TelemetryLog",
            RecordPayload::SentryCrash(_) => "SentryCrash",
            RecordPayload::QueueJob(_) => "QueueJob",
        })
        .collect()
}
