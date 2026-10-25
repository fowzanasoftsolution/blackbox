//! Real-World SDK wire-shape regression tests (the "SDK Compatibility
//! Matrix" — validated live against the OFFICIAL sentry-sdk + openai-python
//! in an ephemeral Daytona sandbox; these tests pin the wire contracts so
//! the live behaviors can never silently regress).
//!
//! ## What the live matrix proved (and these tests freeze)
//!
//! 1. The official sentry-sdk does NOT read W3C `traceparent` — it
//!    continues traces exclusively from the `sentry-trace` header. The
//!    proxy must therefore inject BOTH upstream (same 128-bit trace id),
//!    or a real SDK attached to the injected `SENTRY_DSN` starts a random
//!    trace and its crash envelope lands apart from the request that
//!    caused it. Caller-supplied `sentry-trace` is never overridden.
//! 2. The official SDK's envelope wire format — envelope header line
//!    (`event_id`/`sent_at`/`sdk`), `{"type":"event","length":N}` item
//!    framing, `X-Sentry-Auth: Sentry sentry_key=…` auth, uncompressed
//!    body, `application/x-sentry-envelope` content type, and the trace id
//!    inside `event.contexts.trace.trace_id` — must ingest 200 and
//!    correlate to the same trace, stored verbatim.

use crate::proxy::{spawn_proxy, IngressConfig, ProxyHandle};
use blackbox_core::schema::{parse_trace_hex, RecordPayload, TraceId};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

type HttpBody = Full<Bytes>;

/// Everything the mock upstream saw, for header assertions.
#[derive(Clone, Debug)]
struct Captured {
    path: String,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Minimal upstream that captures the wire (headers + body) and answers 200.
struct CaptureApp {
    addr: std::net::SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
}

impl CaptureApp {
    fn captured(&self) -> Vec<Captured> {
        self.captured.lock().unwrap().clone()
    }
}

async fn spawn_capture_app() -> CaptureApp {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let _ = tcp.set_nodelay(true);
            let sink = sink.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let sink = sink.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<bin>").to_string()))
                            .collect();
                        let body = BodyExt::collect(req.into_body())
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        sink.lock().unwrap().push(Captured {
                            path,
                            headers,
                            body,
                        });
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(HttpBody::new(Bytes::from_static(b"up ok")))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    CaptureApp { addr, captured }
}

async fn spawn_proxy_for(upstream: std::net::SocketAddr, tag: &str) -> ProxyHandle {
    let dir = std::env::temp_dir().join(format!("bb-sdk-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = IngressConfig {
        data_dir: dir,
        upstream: upstream.to_string(),
        ..IngressConfig::default()
    };
    spawn_proxy(cfg).await.expect("proxy spawn")
}

fn client() -> Client<HttpConnector, HttpBody> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// The exact envelope shape the OFFICIAL Python SDK emits for an uncaught
/// exception (pinned from the live Daytona matrix run): three lines —
/// envelope header, event item header with explicit length, event payload
/// with the trace context under `contexts.trace.trace_id`. Uncompressed,
/// `application/x-sentry-envelope`, auth in `X-Sentry-Auth`.
fn real_sdk_envelope(trace_id_hex: &str, span_id_hex: &str, event_id: &str) -> Vec<u8> {
    // Real SDK event payload with the pieces the parser must navigate.
    let event = format!(
        r#"{{"level":"error","platform":"python","environment":"production","logger":"root","sdk":{{"name":"sentry.python","version":"2.19.2","packages":[{{"name":"sentry.sdk","version":"2.19.2"}}]}},"request":{{"url":"http://127.0.0.1:8080/crash","method":"POST","headers":{{"Content-Type":"application/json"}}}},"exception":{{"values":[{{"type":"RuntimeError","value":"checkout crashed (real sdk matrix)","module":"app","stacktrace":{{"frames":[{{"filename":"app.py","lineno":13,"function":"crash","context_line":"raise RuntimeError(\"checkout crashed (real sdk matrix)\")","in_app":true}}]}}}}]}},"contexts":{{"runtime":{{"name":"CPython","version":"3.13"}},"trace":{{"trace_id":"{trace_id_hex}","span_id":"{span_id_hex}","type":"trace","origin":"auto.http.asgi"}}}}}}"#
    );
    let event_len = event.len();
    format!(
        "{{\"event_id\":\"{event_id}\",\"sent_at\":\"2026-10-25T05:30:00.000Z\",\"sdk\":{{\"name\":\"sentry.python\",\"version\":\"2.19.2\"}},\"platform\":\"python\"}}\n{{\"type\":\"event\",\"length\":{event_len}}}\n{event}\n"
    )
    .into_bytes()
}

/// POST a request through the proxy and return (status, response headers,
/// body) — plus the proxy's trace id response header.
async fn post_through_proxy(
    proxy: &ProxyHandle,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Bytes) {
    let mut builder = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{}{path}", proxy.local_addr));
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(HttpBody::new(Bytes::from(body.to_vec())))
        .unwrap();
    let res = client().request(req).await.expect("proxy request");
    let status = res.status().as_u16();
    let res_headers: Vec<(String, String)> = res
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<bin>").to_string()))
        .collect();
    let body = BodyExt::collect(res.into_body()).await.unwrap().to_bytes();
    (status, res_headers, body)
}

fn res_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The REAL SDK matrix, frozen: POST /crash with NO trace headers → the
/// proxy must inject BOTH `traceparent` (W3C) and `sentry-trace` (Sentry
/// grammar) carrying the SAME trace id as `x-blackbox-trace-id`; then the
/// app's official sentry-sdk (emulated wire-exact) reports the crash →
/// envelope ingests 200 and correlates IngressHttp + SentryCrash on ONE
/// trace, envelope stored verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn real_sdk_envelope_correlates_via_injected_sentry_trace() {
    let mock = spawn_capture_app().await;
    let proxy = spawn_proxy_for(mock.addr, "corr").await;

    // -- Act 1: the crash request (no trace headers — like any plain app).
    let (status, res_headers, _) = post_through_proxy(
        &proxy,
        "/crash",
        &[("content-type", "application/json")],
        br#"{"cart":42}"#,
    )
    .await;
    assert_eq!(status, 200, "proxy must reach upstream");
    let trace_hdr = res_header(&res_headers, "x-blackbox-trace-id")
        .expect("missing x-blackbox-trace-id")
        .to_string();

    // -- Assert 1: BOTH trace headers injected upstream, one trace id.
    let captured = mock.captured();
    assert_eq!(captured.len(), 1, "exactly one upstream request");
    let req = &captured[0];
    let tp = req.header("traceparent").expect("traceparent injected");
    assert_eq!(tp.len(), 55, "W3C 00-32hex-16hex-01: {tp}");
    let st = req.header("sentry-trace").expect("sentry-trace injected");
    assert_eq!(st.len(), 51, "Sentry 32hex-16hex-1: {st}");
    assert_eq!(
        tp.split('-').nth(1),
        st.split('-').next(),
        "W3C and Sentry trace ids must be the same 128-bit value"
    );
    assert_eq!(
        st.split('-').next(),
        Some(trace_hdr.as_str()),
        "injected trace id == x-blackbox-trace-id"
    );

    // -- Act 2: the official SDK's crash envelope (wire-exact shape),
    //    continuing the trace it received via sentry-trace.
    let span_hex = st.split('-').nth(1).unwrap().to_string();
    let event_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    let envelope = real_sdk_envelope(&trace_hdr, &span_hex, event_id);
    let (status, res_headers, resp_body) = post_through_proxy(
        &proxy,
        "/api/1/envelope/",
        &[
            ("content-type", "application/x-sentry-envelope"),
            (
                "x-sentry-auth",
                "Sentry sentry_key=public, sentry_version=7, sentry_client=sentry.python/2.19.2",
            ),
        ],
        &envelope,
    )
    .await;
    assert_eq!(status, 200, "real SDK envelope must ingest: {resp_body:?}");
    assert_eq!(
        res_header(&res_headers, "x-blackbox-trace-id"),
        Some(trace_hdr.as_str()),
        "envelope must land on the crash request's trace"
    );

    // -- Assert 2: IngressHttp + SentryCrash on ONE trace, verbatim bytes.
    let tid: TraceId = parse_trace_hex(&trace_hdr).expect("32-hex trace id");
    let records = proxy.wait_trace(&tid, 2, Duration::from_secs(10)).await;
    assert!(
        records.len() >= 2,
        "crash request + SDK envelope must share one trace (got {})",
        records.len()
    );
    let has_ingress = records
        .iter()
        .any(|r| matches!(r.payload, RecordPayload::IngressHttp(_)));
    let crash = records
        .iter()
        .find(|r| matches!(r.payload, RecordPayload::SentryCrash(_)))
        .expect("SentryCrash record must exist on the trace");
    let RecordPayload::SentryCrash(sc) = &crash.payload else {
        unreachable!()
    };
    assert_eq!(sc.project_id, "1");
    assert_eq!(sc.event_id, event_id, "event_id extracted from the SDK envelope");
    assert_eq!(
        sc.envelope, envelope,
        "SDK envelope must be stored VERBATIM (drop-in DSN replacement)"
    );
    assert!(has_ingress, "IngressHttp record must be on the same trace");

    // -- Act 3: the SDK also ships envelopes Content-Encoding: br (brotli) —
    //    the live matrix caught blackbox 415-ing them (real bug). Pin it:
    //    a brotli-compressed envelope must ingest 200 on the same trace.
    let mut br = brotli::CompressorReader::new(envelope.as_slice(), 4096, 5, 22);
    let mut br_body = Vec::new();
    std::io::Read::read_to_end(&mut br, &mut br_body).unwrap();
    let (status, res_headers, resp_body) = post_through_proxy(
        &proxy,
        "/api/1/envelope/",
        &[
            ("content-type", "application/x-sentry-envelope"),
            ("content-encoding", "br"),
            (
                "x-sentry-auth",
                "Sentry sentry_key=public, sentry_version=7, sentry_client=sentry.python/2.19.2",
            ),
        ],
        &br_body,
    )
    .await;
    assert_eq!(
        status,
        200,
        "brotli (the official SDK's default encoding) must ingest: {resp_body:?}"
    );
    assert_eq!(
        res_header(&res_headers, "x-blackbox-trace-id"),
        Some(trace_hdr.as_str()),
        "br envelope must land on the same trace"
    );
    let records = proxy.wait_trace(&tid, 3, Duration::from_secs(10)).await;
    assert!(records.len() >= 3, "plain + br envelopes must both be stored");
}

/// A caller that already speaks Sentry passes its own `sentry-trace`; the
/// proxy must forward it UNCHANGED (its trace id wins for correlation, the
/// generated W3C traceparent mirrors it for W3C consumers).
#[tokio::test(flavor = "multi_thread")]
async fn caller_supplied_sentry_trace_is_never_overridden() {
    let mock = spawn_capture_app().await;
    let proxy = spawn_proxy_for(mock.addr, "keep").await;

    let client_trace = "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0";
    let (status, _, _) = post_through_proxy(
        &proxy,
        "/work",
        &[("sentry-trace", client_trace)],
        b"{}",
    )
    .await;
    assert_eq!(status, 200);

    let captured = mock.captured();
    assert_eq!(captured.len(), 1);
    let st = captured[0].header("sentry-trace").expect("sentry-trace present");
    assert_eq!(
        st, client_trace,
        "caller-supplied sentry-trace must be forwarded untouched"
    );
}

/// W3C-only callers (OpenTelemetry SDKs) pass `traceparent` — the injected
/// `sentry-trace` must carry the SAME trace id so Sentry consumers stay
/// correlated with the W3C world.
#[tokio::test(flavor = "multi_thread")]
async fn traceparent_passthrough_also_injects_matching_sentry_trace() {
    let mock = spawn_capture_app().await;
    let proxy = spawn_proxy_for(mock.addr, "w3c").await;

    let client_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let (status, _, _) = post_through_proxy(
        &proxy,
        "/work",
        &[("traceparent", client_tp)],
        b"{}",
    )
    .await;
    assert_eq!(status, 200);

    let captured = mock.captured();
    assert_eq!(captured.len(), 1);
    let tp = captured[0].header("traceparent").expect("traceparent present");
    assert_eq!(tp, client_tp, "caller traceparent forwarded unchanged");
    let st = captured[0]
        .header("sentry-trace")
        .expect("sentry-trace must also be injected for W3C-only callers");
    assert_eq!(
        st.split('-').next(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736"),
        "injected sentry-trace continues the SAME trace id: {st}"
    );
}
