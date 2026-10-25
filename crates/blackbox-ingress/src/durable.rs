//! Durable webhook ingestion — the raw-byte-preserving 202 path.
//!
//! Routes matching the configured durable prefixes (`/webhooks/*`,
//! `/jobs/*` by default) bypass the normal proxy hot path:
//!
//! 1. the EXACT raw request bytes (headers + body) are persisted into redb
//!    via the group-commit JobStore — **the PII scrubber never touches
//!    this copy** (Stripe/Shopify/GitHub HMAC signatures must verify on the
//!    user's app!),
//! 2. the caller gets `202 Accepted` + `x-blackbox-trace-id` +
//!    `x-blackbox-job-id` in a couple of milliseconds (one group-commit),
//! 3. a SCRUBBED telemetry copy (`IngressHttp` + `QueueJob` records) is
//!    pushed to the SegmentStore sink so the flight recorder keeps a
//!    redacted timeline of the same event,
//! 4. duplicate webhooks (same `Idempotency-Key` / `X-GitHub-Delivery` /
//!    `Stripe-Signature` within the retention window) are deduplicated
//!    atomically — 202 again, no double-enqueue.
//!
//! Delivery is asynchronous: the dispatcher (blackbox-queue) claims the job
//! under a lease and POSTs the raw bytes to the upstream app, with
//! full-jitter exponential backoff and dead-lettering.

use crate::proxy::{ProxyBody, ProxyCtx};
use crate::traceparent::{Traceparent, TRACEPARENT_HEADER, TRACE_ID_RESPONSE_HEADER};
use blackbox_core::schema::{
    new_id128, now_ms, trace_id_to_hex, IngressHttp, QueueJobRecord, RecordPayload, TraceRecord,
};
use blackbox_queue::model::DurableJob;
use blackbox_queue::JobStoreHandle;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

/// Default idempotency headers, in priority order.
pub const DEFAULT_IDEM_HEADERS: &[&str] = &["idempotency-key", "x-github-delivery", "stripe-signature"];

/// Durable-route context shared by the proxy.
pub struct DurableCtx {
    /// Path prefixes that trigger durable ingestion (e.g. `/webhooks/`).
    pub prefixes: Vec<String>,
    pub store: JobStoreHandle,
    /// Hard ceiling on raw webhook bodies (413 beyond).
    pub max_body: usize,
    /// Idempotency header names (lowercase), priority order.
    pub idem_headers: Vec<String>,
    /// Default dead-letter attempt budget for new jobs.
    pub max_attempts: u32,
}

/// Parse the configured route spec (`"/webhooks/*,/jobs/*"`) into prefixes.
/// A trailing `*` is stripped; everything else matches by prefix.
pub fn parse_durable_prefixes(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let s = s.trim_end_matches('*').to_string();
            // A bare `/webhooks` must not match `/webhooks-other` — anchor
            // the trailing slash unless the user wrote a deeper prefix.
            if s.ends_with('/') || s.is_empty() {
                s
            } else {
                format!("{s}/")
            }
        })
        .collect()
}

pub fn matches_durable(prefixes: &[String], path: &str) -> bool {
    prefixes.iter().any(|p| path.starts_with(p.as_str()))
}

/// Derive the logical queue name from the request path:
/// `/webhooks/stripe` → `webhooks.stripe`.
fn queue_name(path: &str) -> String {
    let cleaned: String = path
        .split(['/', '?'])
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if cleaned.is_empty() {
        "webhooks.root".into()
    } else {
        cleaned
    }
}

/// Extract the first present idempotency header value.
fn idempotency_key(headers: &HeaderMap, names: &[String]) -> String {
    for name in names {
        if let Some(v) = headers.get(name) {
            if let Ok(s) = v.to_str() {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    String::new()
}

/// Headers persisted for delivery: everything EXCEPT hop-by-hop + framing
/// headers the delivery hop re-derives. Values are byte-exact.
const STRIP_ON_PERSIST: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// The durable ingest handler. Reads the raw body (bounded), enqueues
/// durably, emits scrubbed telemetry, answers 202.
pub(crate) async fn handle_durable(
    req: hyper::Request<Incoming>,
    ctx: &ProxyCtx,
    durable: &DurableCtx,
) -> hyper::Response<ProxyBody> {
    let started = std::time::Instant::now();
    let (head, body) = req.into_parts();
    let method = head.method.to_string();
    let url_path = head
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let path_only = head.uri.path().to_string();

    // Trace correlation: honor an incoming traceparent, else generate.
    let (tp, injected) = match head
        .headers
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(Traceparent::parse)
    {
        Some(tp) => (tp, false),
        None => (Traceparent::generate(), true),
    };
    let trace_id = tp.trace_id;
    let trace_hex = trace_id_to_hex(&trace_id);
    let _ = injected;

    // RAW header snapshot — exact values, delivery-grade (never scrubbed).
    let raw_headers: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(k, _)| !STRIP_ON_PERSIST.contains(&k.as_str()))
        .map(|(k, v)| (k.to_string(), v.to_str().map(|s| s.to_string()).unwrap_or_default()))
        .collect();

    // RAW body — exact bytes, bounded (no decompression, no scrubbing).
    let raw_body = match read_raw_body(body, durable.max_body).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let idem = idempotency_key(&head.headers, &durable.idem_headers);
    let queue = queue_name(&path_only);

    let job = DurableJob::new_pending(
        new_id128(),
        trace_id,
        queue.clone(),
        method.clone(),
        url_path.clone(),
        raw_headers.clone(),
        raw_body.clone(),
        idem,
        durable.max_attempts,
    );

    // The durability point: 202 resolves only after the group-commit fsync.
    let outcome = match durable.store.enqueue(job).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "durable enqueue failed");
            return full_response(
                StatusCode::SERVICE_UNAVAILABLE,
                vec![(TRACE_ID_RESPONSE_HEADER, trace_hex)],
                Bytes::from_static(b"blackbox queue unavailable\n"),
            );
        }
    };

    blackbox_core::audit::record(
        "queue",
        "enqueue",
        &trace_hex,
        &format!(
            "queue={} job={} dedup={}",
            queue, outcome.job_id, outcome.deduplicated
        ),
    );

    // --- Telemetry copy: SCRUBBED (this is the ONLY scrubbed copy) ---
    emit_telemetry_records(ctx, durable, &queue, &trace_id, &method, &url_path, &raw_headers, &raw_body, 202);

    let duration_ms = started.elapsed().as_millis() as u64;
    tracing::debug!(
        queue = %queue,
        job = outcome.job_id,
        dedup = outcome.deduplicated,
        "webhook enqueued in {duration_ms}ms"
    );

    let body_json = format!(
        r#"{{"job_id":"{}","deduplicated":{},"queue":"{}"}}"#,
        outcome.job_id, outcome.deduplicated, queue
    );
    full_response(
        StatusCode::ACCEPTED,
        vec![
            (TRACE_ID_RESPONSE_HEADER, trace_hex),
            ("x-blackbox-job-id", outcome.job_id.to_string()),
            ("content-type", "application/json".into()),
        ],
        Bytes::from(body_json),
    )
}

/// Emit the scrubbed `IngressHttp` + `QueueJob` records for this ingest.
#[allow(clippy::too_many_arguments)]
fn emit_telemetry_records(
    ctx: &ProxyCtx,
    durable: &DurableCtx,
    queue: &str,
    trace_id: &blackbox_core::schema::TraceId,
    method: &str,
    url_path: &str,
    raw_headers: &[(String, String)],
    raw_body: &[u8],
    status: u16,
) {
    // Scrubbed header copy for the flight recorder.
    let mut scrub_headers: Vec<(String, String)> = raw_headers.to_vec();
    ctx.scrubber.scrub_headers(&mut scrub_headers);

    // Scrubbed body copy (JSON-shaped bodies only, matching the tee policy).
    let mut scrub_body = raw_body.to_vec();
    if !scrub_body.is_empty() {
        let first = scrub_body.iter().find(|&&b| !b.is_ascii_whitespace());
        if matches!(first, Some(b'{') | Some(b'[')) {
            ctx.scrubber.scrub_json(&mut scrub_body);
        }
    }
    // Cap the telemetry copy at the capture ceiling (raw redb copy is full).
    scrub_body.truncate(crate::tee::CAPTURE_MAX_BYTES);

    let sink = &ctx.sink;
    let ingress_rec = TraceRecord::new(
        *trace_id,
        sink.next_seq(),
        RecordPayload::IngressHttp(IngressHttp {
            method: method.to_string(),
            uri: url_path.to_string(),
            status,
            req_headers: scrub_headers,
            req_body: scrub_body.clone(),
            res_body: Vec::new(),
            duration_ms: 0,
        }),
    );
    sink.try_send(ingress_rec);

    let job_rec = TraceRecord::new(
        *trace_id,
        sink.next_seq(),
        RecordPayload::QueueJob(QueueJobRecord {
            queue: queue.to_string(),
            payload: scrub_body,
            attempt: 0,
            max_attempts: durable.max_attempts,
            available_at_ms: now_ms(),
        }),
    );
    sink.try_send(job_rec);
}

/// Read the full raw body with a hard byte ceiling (no decoding).
async fn read_raw_body(
    mut body: Incoming,
    cap: usize,
) -> Result<Vec<u8>, hyper::Response<ProxyBody>> {
    let mut out: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(error = %e, "webhook body read failed");
                return Err(full_response(
                    StatusCode::BAD_REQUEST,
                    vec![],
                    Bytes::from_static(b"body read error\n"),
                ));
            }
        };
        if let Some(data) = frame.data_ref() {
            if out.len() + data.len() > cap {
                return Err(full_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    vec![],
                    Bytes::from(format!("webhook body exceeds {} byte cap\n", cap)),
                ));
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

fn full_response(
    status: StatusCode,
    headers: Vec<(&str, String)>,
    body: Bytes,
) -> hyper::Response<ProxyBody> {
    let mut b = hyper::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(ProxyBody::Full(Full::new(body)))
        .expect("static response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parsing_and_matching() {
        let prefixes = parse_durable_prefixes("/webhooks/*, /jobs/*");
        assert_eq!(prefixes, vec!["/webhooks/".to_string(), "/jobs/".to_string()]);
        assert!(matches_durable(&prefixes, "/webhooks/stripe"));
        assert!(matches_durable(&prefixes, "/jobs/render/42"));
        assert!(!matches_durable(&prefixes, "/webhooks-other"));
        assert!(!matches_durable(&prefixes, "/api/orders"));
        let bare = parse_durable_prefixes("/webhooks,/jobs");
        assert_eq!(bare, vec!["/webhooks/".to_string(), "/jobs/".to_string()]);
    }

    #[test]
    fn queue_names_derive_from_paths() {
        assert_eq!(queue_name("/webhooks/stripe"), "webhooks.stripe");
        assert_eq!(queue_name("/jobs/render/42"), "jobs.render.42");
        assert_eq!(queue_name("/"), "webhooks.root");
    }
}
