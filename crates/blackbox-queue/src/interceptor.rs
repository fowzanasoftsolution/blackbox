//! Egress interceptor — the forward-proxy listener that both RECORDS
//! outgoing calls (production) and SERVES them back (deterministic replay).
//!
//! ```text
//! production:  app --HTTP_PROXY=http://blackbox:9700--> interceptor ──► real API
//!                              │ records EgressHttpMock (trace_id from
//!                              │ the propagated `traceparent` header)
//! replay:      app --HTTP_PROXY=http://blackbox:9700--> interceptor
//!                              │ serves the RECORDED response verbatim,
//!                              │ or blocks with 428 + x-blackbox-replay-blocked
//! ```
//!
//! Requests arrive in HTTP forward-proxy form (absolute request target,
//! e.g. `POST http://api.stripe.com/v1/charges HTTP/1.1`) — exactly what
//! every HTTP client library emits when configured with an `HTTP_PROXY`.
//! Plain-HTTP targets only in Phase 3; `CONNECT` TLS tunneling arrives with
//! the Egress FinOps engine (Phase 4).
//!
//! Trace correlation: the user's app propagates the `traceparent` header it
//! received from the ingress proxy (W3C Trace Context) onto its outgoing
//! calls; the interceptor reads it to tag the EgressHttpMock record.

use crate::replay::{canonical_url, fingerprint, ReplayEngine};
use blackbox_core::schema::{
    new_id128, trace_id_to_hex, EgressHttpMock, RecordPayload, TraceId, TraceRecord,
};
use blackbox_core::StorageError;
use bytes::Bytes;
use http::{HeaderMap, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Egress request body ceiling (fingerprinting requires buffering).
pub const MAX_EGRESS_REQ_BODY: usize = 1024 * 1024;
/// Egress response body capture ceiling (recorded verbatim for replay).
pub const MAX_EGRESS_RES_BODY: usize = 1024 * 1024;
/// Hop-by-hop headers never stored / never forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Interceptor mode.
pub enum InterceptorMode {
    /// Production: forward to the real API and record the exchange. The
    /// callback receives a record with seq_no 0 and must stamp its own
    /// monotonic sequence before persisting.
    Record { emit: Arc<dyn Fn(TraceRecord) + Send + Sync> },
    /// Replay sandbox: serve recorded responses, block everything else.
    Mock { engine: Arc<ReplayEngine> },
}

#[derive(Clone)]
pub struct InterceptorConfig {
    pub listen: SocketAddr,
    pub mode: Arc<InterceptorMode>,
}

/// Handle for tests / CLI.
pub struct InterceptorHandle {
    pub local_addr: SocketAddr,
}

/// Spawn the egress interceptor server.
pub async fn spawn_interceptor(cfg: InterceptorConfig) -> Result<InterceptorHandle, StorageError> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| StorageError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let local_addr = listener.local_addr()?;

    // Per-trace egress call ordering (EgressHttpMock::seq_no) — the
    // ReplayEngine's sequence fallback matches in recorded order.
    let seqs: Arc<Mutex<HashMap<TraceId, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build_http();

    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "interceptor accept failed");
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let mode = Arc::clone(&cfg.mode);
            let client = client.clone();
            let seqs = Arc::clone(&seqs);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let mode = Arc::clone(&mode);
                    let client = client.clone();
                    let seqs = Arc::clone(&seqs);
                    async move {
                        Ok::<_, std::convert::Infallible>(handle(req, mode, client, seqs).await)
                    }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await
                {
                    tracing::debug!(error = %e, "interceptor connection ended");
                }
            });
        }
    });

    Ok(InterceptorHandle { local_addr })
}

async fn handle(
    req: hyper::Request<Incoming>,
    mode: Arc<InterceptorMode>,
    client: Client<HttpConnector, Full<Bytes>>,
    seqs: Arc<Mutex<HashMap<TraceId, u64>>>,
) -> hyper::Response<Full<Bytes>> {
    // Forward-proxy request target: absolute URI (`http://host/path?query`).
    let target = req.uri().to_string();
    let is_absolute = req.uri().scheme_str().is_some() && req.uri().host().is_some();
    let host_hdr = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if !is_absolute && host_hdr.is_none() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "blackbox egress interceptor requires an absolute-form proxy request\n",
        );
    }
    let url = if is_absolute {
        target
    } else {
        format!("http://{}{}", host_hdr.clone().unwrap_or_default(), target)
    };

    let method: String = req.method().as_str().to_string();
    let method2: hyper::Method = req.method().clone();
    let fwd_headers_snapshot: HeaderMap = req.headers().clone();
    // Trace correlation: propagate the app's traceparent.
    let trace_id = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_traceparent_trace)
        .unwrap_or_else(fresh_trace_id);

    // Buffer the request body (bounded) — fingerprinting needs exact bytes.
    let body = match read_capped(req.into_body(), MAX_EGRESS_REQ_BODY).await {
        Ok(b) => b,
        Err(status) => {
            return text_response(status, "blackbox egress interceptor: body too large\n");
        }
    };

    match &*mode {
        InterceptorMode::Mock { engine } => {
            let fp = fingerprint(&method, &url, &body);
            match engine.resolve(&method, &url, fp) {
                Some(mock) => {
                    let mut b = hyper::Response::builder().status(StatusCode::from_u16(mock.response_status).unwrap_or(StatusCode::OK));
                    for (k, v) in &mock.response_headers {
                        let lname = k.to_ascii_lowercase();
                        if HOP_BY_HOP.contains(&lname.as_str()) || lname == "content-length" {
                            continue;
                        }
                        b = b.header(k.as_str(), v.as_str());
                    }
                    b.body(Full::new(Bytes::from(mock.response_body)))
                        .unwrap_or_else(|_| text_body("mock response build failed"))
                }
                None => {
                    // Strict sandbox guard: never touch live APIs in replay.
                    let mut res = text_response(
                        StatusCode::PRECONDITION_REQUIRED,
                        format!(
                            "blackbox replay sandbox: no recorded egress for {} {} (trace {})\n",
                            method,
                            canonical_url(&url),
                            trace_id_to_hex(&trace_id)
                        ),
                    );
                    res.headers_mut().insert(
                        "x-blackbox-replay-blocked",
                        http::HeaderValue::from_static("true"),
                    );
                    res
                }
            }
        }
        InterceptorMode::Record { emit } => {
            // Rebuild the absolute target URI and forward for real.
            let fwd_uri = match Uri::try_from(url.clone()) {
                Ok(u) => u,
                Err(e) => {
                    return text_response(StatusCode::BAD_REQUEST, format!("bad target: {e}\n"));
                }
            };
            let mut builder = hyper::Request::builder().method(method2).uri(fwd_uri);
            for (name, value) in fwd_headers_snapshot.iter() {
                let lname = name.as_str();
                if HOP_BY_HOP.contains(&lname) || lname == "host" || lname == "content-length" {
                    continue;
                }
                builder = builder.header(name, value);
            }
            let fwd_req = match builder.body(Full::new(Bytes::from(body.clone()))) {
                Ok(r) => r,
                Err(e) => {
                    return text_response(StatusCode::BAD_REQUEST, format!("forward build: {e}\n"));
                }
            };

            let started = Instant::now();
            let upstream_res = match client.request(fwd_req).await {
                Ok(r) => r,
                Err(e) => {
                    return text_response(
                        StatusCode::BAD_GATEWAY,
                        format!("blackbox egress interceptor: upstream failed: {e}\n"),
                    );
                }
            };
            let _ = started.elapsed();
            let status = upstream_res.status().as_u16();
            let res_headers: Vec<(String, String)> = upstream_res
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
                .collect();
            // Buffer the response (bounded) — replay must serve exact bytes.
            let res_body = match read_capped(upstream_res.into_body(), MAX_EGRESS_RES_BODY).await {
                Ok(b) => b,
                Err(status) => {
                    return text_response(status, "blackbox egress interceptor: response too large\n");
                }
            };
            let upstream_host = Uri::try_from(url.clone())
                .ok()
                .and_then(|u| u.authority().map(|a| a.to_string()))
                .unwrap_or_default();

            // Record the exchange under the app's trace. seq_no orders the
            // call within the trace (replay's sequence fallback consumes
            // mocks in this order).
            let seq_no = {
                let mut s = seqs.lock().unwrap_or_else(|p| p.into_inner());
                let c = s.entry(trace_id).or_insert(0);
                let n = *c;
                *c += 1;
                n
            };
            let mock = EgressHttpMock {
                seq_no,
                request_fingerprint: fingerprint(&method, &url, &body),
                method,
                request_url: url.clone(),
                response_status: status,
                response_headers: res_headers.clone(),
                response_body: res_body.clone(),
                upstream_host,
                recorded_at_ms: blackbox_core::schema::now_ms(),
            };
            let rec = TraceRecord::new(trace_id, 0, RecordPayload::EgressHttpMock(mock));
            emit(rec);

            let mut b = hyper::Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));
            for (k, v) in &res_headers {
                let lname = k.to_ascii_lowercase();
                if HOP_BY_HOP.contains(&lname.as_str()) || lname == "content-length" {
                    continue;
                }
                b = b.header(k.as_str(), v.as_str());
            }
            b.body(Full::new(Bytes::from(res_body)))
                .unwrap_or_else(|_| text_body("record response build failed"))
        }
    }
}

fn text_response<S: Into<Bytes>>(status: StatusCode, msg: S) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(Full::new(msg.into()))
        .unwrap_or_else(|_| text_body("build failed"))
}

fn text_body(msg: &str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(format!("{msg}\n"))))
        .expect("static response builds")
}

async fn read_capped(body: Incoming, cap: usize) -> Result<Vec<u8>, StatusCode> {
    let mut out = Vec::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };
        if let Some(data) = frame.data_ref() {
            if out.len() + data.len() > cap {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Extract the trace id from a W3C traceparent header value.
fn parse_traceparent_trace(value: &str) -> Option<TraceId> {
    let v = value.trim();
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() != 4 || parts[1].len() != 32 {
        return None;
    }
    let tid = blackbox_core::schema::parse_trace_hex(parts[1])?;
    if tid == [0u8; 16] {
        None
    } else {
        Some(tid)
    }
}

/// Fresh random trace id for egress calls that carry no trace context
/// (recorded but not causally linked — replay matching is unaffected).
fn fresh_trace_id() -> TraceId {
    let mut out = [0u8; 16];
    // u128::to_be_bytes is 16 bytes — split two draws across the id.
    let a = new_id128().to_be_bytes();
    let b = new_id128().to_be_bytes();
    out[..8].copy_from_slice(&a[..8]);
    out[8..].copy_from_slice(&b[..8]);
    if out == [0u8; 16] {
        out[0] = 1;
    }
    out
}
