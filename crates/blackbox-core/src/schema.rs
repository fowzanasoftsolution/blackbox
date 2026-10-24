//! Unified trace schema (rkyv 0.8 high API).
//!
//! One envelope — [`TraceRecord`] — covers every engine's records so a single
//! append-only segment format stores ingress captures, egress replay mocks,
//! telemetry, Sentry crashes, and durable queue jobs side by side, correlated
//! by a global 128-bit trace id.
//!
//! ## rkyv 0.8 API contract (do not regress to 0.7 syntax)
//!
//! - Serialize: `rkyv::to_bytes::<rancor::Error>(&record)`
//! - Validate + access (bytecheck): `rkyv::access::<rkyv::Archived<TraceRecord>, rancor::Error>(&bytes)`
//! - Deserialize to owned: `rkyv::deserialize::<TraceRecord, rancor::Error>(archived)`
//!
//! The derives below also generate `bytecheck::CheckBytes` impls for the archived
//! types (rkyv default features), so every disk-loaded frame is strictly validated
//! before any zero-copy read — see blueprint §2 landmine #2.
//!
//! ## Phase 3 forward-compatibility
//!
//! [`RecordPayload::EgressHttpMock`] carries `seq_no` + `request_fingerprint` +
//! response status/headers/body. Phase 1 bakes this into the on-disk format now so
//! deterministic replay never requires a breaking disk migration.

use rkyv::{Archive, Deserialize, Serialize};

/// Schema version stamped on every record. Bump on breaking schema changes;
/// the recovery scanner refuses records with a higher major version.
pub const SCHEMA_VERSION: u16 = 1;

/// 128-bit globally unique trace id (W3C `traceparent` compatible).
pub type TraceId = [u8; 16];

/// 256-bit request fingerprint for egress cache/replay keys
/// (`SHA256(TenantID + AuthScope + Method + URL + CanonicalBody)`).
pub type Fingerprint = [u8; 32];

/// The unified trace envelope stored in every frame.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct TraceRecord {
    /// On-disk schema version (`SCHEMA_VERSION`).
    pub schema_version: u16,
    /// Reserved for future flags; must be zero.
    pub reserved: u16,
    /// Global trace id (also mirrored into the frame header for indexing).
    pub trace_id: TraceId,
    /// Wall-clock unix epoch milliseconds.
    pub timestamp_ms: u64,
    /// Monotonic per-process sequence number (replay ordering / contiguity checks).
    pub seq_no: u64,
    /// Engine-specific payload.
    pub payload: RecordPayload,
}

impl TraceRecord {
    /// Convenience constructor stamping schema version and timestamp.
    pub fn new(trace_id: TraceId, seq_no: u64, payload: RecordPayload) -> Self {
        TraceRecord {
            schema_version: SCHEMA_VERSION,
            reserved: 0,
            trace_id,
            timestamp_ms: now_ms(),
            seq_no,
            payload,
        }
    }
}

/// Engine-payload enum. One variant per engine; adding a variant later is a
/// forward-compatible change for readers (unknown variant => frame skipped and
/// reported, not fatal).
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub enum RecordPayload {
    /// Engine 1: captured ingress HTTP request/response pair (<= 64 KB body).
    IngressHttp(IngressHttp),
    /// Engine 4 (consumed by Phase 3 replay): recorded external egress call,
    /// replayed verbatim in deterministic sandbox mode.
    EgressHttpMock(EgressHttpMock),
    /// Engine 3: OTLP log record.
    TelemetryLog(TelemetryLog),
    /// Engine 3: native Sentry crash envelope (wire-compatible passthrough).
    SentryCrash(SentryCrash),
    /// Engine 2: durable queue / webhook job.
    QueueJob(QueueJobRecord),
}

/// Captured ingress HTTP exchange. Bodies larger than the 64 KB capture cap or
/// binary/multipart content-types record headers + byte counts only
/// (blueprint §2 landmine #4 — never buffer full bodies in RAM).
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct IngressHttp {
    /// HTTP method, e.g. `POST`.
    pub method: String,
    /// Request URI (path + query).
    pub uri: String,
    /// Upstream response status code (0 if the app never answered).
    pub status: u16,
    /// Request headers (already PII-scrubbed by the ingress engine).
    pub req_headers: Vec<(String, String)>,
    /// Captured request body bytes (<= 64 KB).
    pub req_body: Vec<u8>,
    /// Captured response body bytes (<= 64 KB), empty if bypassed.
    pub res_body: Vec<u8>,
    /// Total handler duration in milliseconds.
    pub duration_ms: u64,
}

/// Deterministic-replay record for outgoing HTTP/API/LLM calls (blueprint §2
/// landmine #5). During `blackbox replay <trace_id>` the egress interceptor
/// serves exactly these recorded responses instead of hitting live APIs.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct EgressHttpMock {
    /// Ordering of this egress call within the trace (0-based).
    pub seq_no: u64,
    /// `SHA256(TenantID + AuthScope + Method + URL + CanonicalBody)`.
    pub request_fingerprint: Fingerprint,
    /// HTTP method of the outgoing call (`POST`, `GET`, ...).
    pub method: String,
    /// Full request URL as called (scheme://host/path?query) — canonicalized
    /// (host lowercased, default ports stripped) before matching in replay.
    pub request_url: String,
    /// Recorded upstream response status.
    pub response_status: u16,
    /// Recorded upstream response headers.
    pub response_headers: Vec<(String, String)>,
    /// Recorded upstream response body (capped by the egress capture policy).
    pub response_body: Vec<u8>,
    /// Upstream host that served the original call (diagnostics / allowlisting).
    pub upstream_host: String,
    /// When the original call was made.
    pub recorded_at_ms: u64,
}

/// OTLP-compatible log record.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct TelemetryLog {
    /// Severity: 1=TRACE, 2=DEBUG, 3=INFO, 4=WARN, 5=ERROR.
    pub level: u8,
    /// Emitting service / app name.
    pub service: String,
    /// Log body.
    pub message: String,
    /// Resource + record attributes.
    pub attributes: Vec<(String, String)>,
}

/// Raw Sentry envelope captured wire-compatible (project id from the DSN path).
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct SentryCrash {
    /// Sentry project id from the envelope endpoint path.
    pub project_id: String,
    /// `event_id` from the envelope headers (32 hex chars when present).
    pub event_id: String,
    /// Verbatim envelope bytes (headers + item payloads).
    pub envelope: Vec<u8>,
}

/// Durable webhook / workflow job persisted through the group-commit actor.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
pub struct QueueJobRecord {
    /// Logical queue / route name, e.g. `webhooks.stripe`.
    pub queue: String,
    /// Opaque job payload (webhook body, task args...).
    pub payload: Vec<u8>,
    /// Delivery attempt counter (0 = never dispatched).
    pub attempt: u32,
    /// Give up after this many attempts (dead-letter).
    pub max_attempts: u32,
    /// Earliest dispatch time (exponential backoff w/ jitter schedules this).
    pub available_at_ms: u64,
}

/// Millisecond unix timestamp.
#[inline]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format a [`TraceId`] as 32 lowercase hex chars (W3C `traceparent` style).
pub fn trace_id_to_hex(tid: &TraceId) -> String {
    let mut s = String::with_capacity(32);
    for b in tid {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

/// Parse 32 hex chars (upper or lower case) into a [`TraceId`].
pub fn parse_trace_hex(s: &str) -> Option<TraceId> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in b.chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Monotonic 128-bit id generator (no deps): 48-bit ms timestamp in the top
/// bits + an 80-bit process-wide counter in the low bits. Strictly increasing
/// within a process and across milliseconds; used for job ids and trace ids in
/// Phase 1. The ingress engine later swaps in W3C-sampled real trace ids.
pub fn new_id128() -> u128 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    const COUNTER_MASK: u128 = (1u128 << 80) - 1; // 80 low bits
    let ms = now_ms();
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
    ((ms as u128 & 0xFFFF_FFFF_FFFF) << 80) | (n & COUNTER_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(seq: u64) -> TraceRecord {
        let payload = RecordPayload::EgressHttpMock(EgressHttpMock {
            seq_no: seq,
            request_fingerprint: [7u8; 32],
            method: "POST".into(),
            request_url: "https://api.stripe.com/v1/charges".into(),
            response_status: 200,
            response_headers: vec![("content-type".into(), "application/json".into())],
            response_body: br#"{"ok":true}"#.to_vec(),
            upstream_host: "api.openai.com".into(),
            recorded_at_ms: 1_700_000_000_000,
        });
        TraceRecord::new([9u8; 16], seq, payload)
    }

    #[test]
    fn rkyv_08_roundtrip_all_variants() {
        let records = vec![
            sample_record(0),
            TraceRecord::new(
                [1u8; 16],
                1,
                RecordPayload::IngressHttp(IngressHttp {
                    method: "POST".into(),
                    uri: "/checkout".into(),
                    status: 200,
                    req_headers: vec![("x-request-id".into(), "abc".into())],
                    req_body: vec![1u8; 4096],
                    res_body: b"charged".to_vec(),
                    duration_ms: 42,
                }),
            ),
            TraceRecord::new(
                [2u8; 16],
                2,
                RecordPayload::TelemetryLog(TelemetryLog {
                    level: 5,
                    service: "api".into(),
                    message: "db connection pool exhausted".into(),
                    attributes: vec![("span".into(), "q4f".into())],
                }),
            ),
            TraceRecord::new(
                [3u8; 16],
                3,
                RecordPayload::SentryCrash(SentryCrash {
                    project_id: "42".into(),
                    event_id: "d6e0c1e0e0c14d5e9f1a2b3c4d5e6f70".into(),
                    envelope: vec![0xde, 0xad, 0xbe, 0xef],
                }),
            ),
            TraceRecord::new(
                [4u8; 16],
                4,
                RecordPayload::QueueJob(QueueJobRecord {
                    queue: "webhooks.stripe".into(),
                    payload: b"{\"type\":\"invoice.paid\"}".to_vec(),
                    attempt: 0,
                    max_attempts: 8,
                    available_at_ms: now_ms(),
                }),
            ),
        ];

        for rec in &records {
            // rkyv 0.8 high API: to_bytes with rancor::Error
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(rec)
                .expect("to_bytes");
            assert!(bytes.as_ptr() as usize % 16 == 0, "AlignedVec must be 16-byte aligned");

            // bytecheck-validated zero-copy access
            let archived = rkyv::access::<rkyv::Archived<TraceRecord>, rkyv::rancor::Error>(
                &bytes[..],
            )
            .expect("validated access");
            assert_eq!(archived.trace_id, rec.trace_id);
            assert_eq!(archived.seq_no.to_native(), rec.seq_no);
            assert_eq!(archived.timestamp_ms.to_native(), rec.timestamp_ms);

            // deserialize back to owned — must be identical
            let owned: TraceRecord =
                rkyv::deserialize::<TraceRecord, rkyv::rancor::Error>(archived)
                    .expect("deserialize");
            assert_eq!(&owned, rec);
        }
    }

    #[test]
    fn structurally_corrupt_bytes_rejected_by_bytecheck() {
        let rec = sample_record(5);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&rec).unwrap();

        // 1) Truncated buffer: relative pointers exceed the slice bounds.
        //    bytecheck must reject instead of producing UB (landmine #2).
        let truncated = &bytes[..bytes.len() - 4];
        let res = rkyv::access::<rkyv::Archived<TraceRecord>, rkyv::rancor::Error>(truncated);
        assert!(res.is_err(), "truncated payload must fail validation");

        // 2) Flipped byte near the payload tail (discriminant/field region):
        //    either bytecheck rejects the structure, or the flip landed in a
        //    plain data byte (bytecheck-legal). What must NEVER happen is a
        //    panic or UB while validating.
        let mut flipped = bytes.to_vec();
        let off = flipped.len() * 3 / 4;
        flipped[off] ^= 0xFF;
        let _ = rkyv::access::<rkyv::Archived<TraceRecord>, rkyv::rancor::Error>(&flipped[..]);

        // 3) Content-only corruption inside a data byte is bytecheck-legal
        //    (structure still valid) — that class of damage is caught by the
        //    frame codec's CRC32C instead. Defense-in-depth split:
        //    CRC32C = content integrity, bytecheck = structural safety.
        let mut content = bytes.to_vec();
        let mid = content.len() / 2;
        content[mid] ^= 0xFF;
        let _ = rkyv::access::<rkyv::Archived<TraceRecord>, rkyv::rancor::Error>(&content[..]);
    }

    #[test]
    fn id128_is_time_ordered() {
        let a = new_id128();
        let b = new_id128();
        assert!(b > a, "ids must be strictly increasing: {a} -> {b}");
    }
}
