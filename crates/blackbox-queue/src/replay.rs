//! Deterministic time-travel replay (blueprint §2 landmine #5).
//!
//! [`ReplayEngine`] loads every `RecordPayload::EgressHttpMock` frame
//! recorded for a trace id out of the segment store and serves them back
//! during `blackbox replay <trace_id>`:
//!
//! 1. **Exact match**: `(method, canonical_url, SHA256(body))` — the app
//!    sent the same bytes as in production.
//! 2. **Sequence fallback**: `(method, canonical_url)` in recorded order —
//!    for apps that inject a dynamic timestamp/nonce into the request body.
//! 3. **Sandbox guard**: no match → the request is BLOCKED with
//!    `428 Precondition Required` + `x-blackbox-replay-blocked: true`.
//!    Live external APIs (Stripe/Twilio) can never be hit during a replay.
//!
//! ## Request fingerprint
//!
//! `SHA256("" + "\0" + "" + "\0" + method + "\0" + url + "\0" + body)` —
//! the blueprint formula `SHA256(TenantID + AuthScope + Method + URL +
//! CanonicalBody)` with the Phase 3 tenant/auth scopes empty. The
//! composition is internal and only ever compared against itself.

use blackbox_core::schema::{EgressHttpMock, RecordPayload, TraceId};
use blackbox_core::StorageError;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Mutex;

pub use blackbox_core::egress_key::{canonical_url, fingerprint};

/// `SHA256(TenantID + AuthScope + Method + URL + CanonicalBody)` and
/// `canonical_url` now live in `blackbox_core::egress_key` (shared with the
/// Phase 4 FinOps egress engine) and are re-exported above — byte-identical
/// formulas, zero replay-format change.

/// Load, index and serve recorded egress mocks for one trace.
pub struct ReplayEngine {
    mocks: Vec<EgressHttpMock>,
    exact: HashMap<(String, String, [u8; 32]), VecDeque<usize>>,
    seq: HashMap<(String, String), VecDeque<usize>>,
    used: Mutex<HashSet<usize>>,
}

impl ReplayEngine {
    /// Scan the segment directory and collect every EgressHttpMock recorded
    /// under `trace_id`, ordered by `seq_no`.
    pub fn load(dir: &Path, trace_id: &TraceId) -> Result<Self, StorageError> {
        let frames = blackbox_core::segment::read_index_all(dir)?;
        let mut mocks: Vec<EgressHttpMock> = frames
            .into_iter()
            .filter(|(_, _, rec)| rec.trace_id == *trace_id)
            .filter_map(|(_, _, rec)| match rec.payload {
                RecordPayload::EgressHttpMock(m) => Some(m),
                _ => None,
            })
            .collect();
        mocks.sort_by_key(|m| m.seq_no);

        let mut exact = HashMap::new();
        let mut seq: HashMap<(String, String), VecDeque<usize>> = HashMap::new();
        for (i, m) in mocks.iter().enumerate() {
            let url = canonical_url(&m.request_url);
            let key = (m.method.clone(), url.clone(), m.request_fingerprint);
            exact.entry(key).or_insert_with(VecDeque::new).push_back(i);
            seq.entry((m.method.clone(), url))
                .or_insert_with(VecDeque::new)
                .push_back(i);
        }
        Ok(ReplayEngine {
            mocks,
            exact,
            seq,
            used: Mutex::new(HashSet::new()),
        })
    }

    pub fn total(&self) -> usize {
        self.mocks.len()
    }

    pub fn used_count(&self) -> usize {
        self.used.lock().map(|u| u.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.mocks.is_empty()
    }

    /// Resolve a recorded response. Exact fingerprint first, then ordered
    /// `(method, canonical_url)` fallback. Marks the mock consumed.
    /// Exact keys are a subset of the seq keys, so consumed mocks are
    /// naturally skipped by the fallback (never double-served).
    pub fn resolve(&self, method: &str, url: &str, req_body_hash: [u8; 32]) -> Option<EgressHttpMock> {
        let canon = canonical_url(url);
        // 1) exact (method, url, body hash) — first unconsumed candidate
        if let Some(queue) = self.exact.get(&(method.to_string(), canon.clone(), req_body_hash)) {
            for &idx in queue {
                if self.mark_used(idx) {
                    return Some(self.mocks[idx].clone());
                }
            }
        }
        // 2) ordered (method, url) fallback — dynamic nonce/timestamp bodies
        if let Some(queue) = self.seq.get(&(method.to_string(), canon)) {
            for &idx in queue {
                if self.mark_used(idx) {
                    return Some(self.mocks[idx].clone());
                }
            }
        }
        None
    }

    fn mark_used(&self, idx: usize) -> bool {
        match self.used.lock() {
            Ok(mut u) => u.insert(idx),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackbox_core::schema::{new_id128, TraceRecord};

    fn mock_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bq-replay-{tag}-{}-{}",
            std::process::id(),
            new_id128() as u64
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(tid: TraceId, seq: u64, url: &str, method: &str, body: &[u8], status: u16, resp: &[u8]) -> TraceRecord {
        let fp = fingerprint(method, url, body);
        TraceRecord::new(
            tid,
            seq,
            RecordPayload::EgressHttpMock(EgressHttpMock {
                seq_no: seq,
                request_fingerprint: fp,
                method: method.to_string(),
                request_url: url.to_string(),
                response_status: status,
                response_headers: vec![("content-type".into(), "application/json".into())],
                response_body: resp.to_vec(),
                upstream_host: "127.0.0.1".into(),
                recorded_at_ms: blackbox_core::schema::now_ms(),
            }),
        )
    }

    #[test]
    fn canonical_url_normalizes() {
        assert_eq!(canonical_url("HTTP://Stripe.COM:80/v1/charges?a=1"), "http://stripe.com/v1/charges?a=1");
        assert_eq!(canonical_url("https://api.twilio.com:443/"), "https://api.twilio.com/");
        assert_eq!(canonical_url("api.stripe.com"), "http://api.stripe.com/");
    }

    #[test]
    fn fingerprint_is_body_sensitive() {
        let a = fingerprint("POST", "http://x/y", b"one");
        let b = fingerprint("POST", "http://x/y", b"two");
        let c = fingerprint("GET", "http://x/y", b"one");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, fingerprint("POST", "http://x/y", b"one"));
    }

    #[tokio::test]
    async fn engine_loads_matches_and_blocks() {
        let dir = mock_dir("engine");
        let tid: TraceId = [0xAB; 16];
        let url = "http://127.0.0.1:9800/v1/charges";

        {
            let mut store = blackbox_core::segment::SegmentStore::open(&dir).unwrap();
            store.append(&rec(tid, 0, url, "POST", b"charge-me", 200, br#"{"id":"ch_1"}"#)).unwrap();
            store.append(&rec(tid, 1, url, "POST", b"charge-me", 200, br#"{"id":"ch_2"}"#)).unwrap();
            store.append(&rec(tid, 2, "http://other/x", "GET", b"", 200, b"other")).unwrap();
            // A different trace — must be ignored.
            store.append(&rec([1u8; 16], 3, url, "POST", b"charge-me", 500, b"nope")).unwrap();
            store.sync().unwrap();
        }

        let engine = ReplayEngine::load(&dir, &tid).unwrap();
        assert_eq!(engine.total(), 3);

        // Exact hash hit, consumed in seq order.
        let fp = fingerprint("POST", url, b"charge-me");
        let m1 = engine.resolve("POST", url, fp).unwrap();
        assert_eq!(m1.response_body, br#"{"id":"ch_1"}"#.to_vec());
        let m2 = engine.resolve("POST", url, fp).unwrap();
        assert_eq!(m2.response_body, br#"{"id":"ch_2"}"#.to_vec());
        // Exhausted -> blocked.
        assert!(engine.resolve("POST", url, fp).is_none());
        // Unrecorded call -> blocked (sandbox guard).
        assert!(engine.resolve("POST", "http://evil.api/x", fingerprint("POST", "http://evil.api/x", b"")).is_none());
        assert_eq!(engine.used_count(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sequence_fallback_for_dynamic_bodies() {
        let dir = mock_dir("fallback");
        let tid: TraceId = [0xCD; 16];
        let url = "http://127.0.0.1:9801/v1/messages";
        {
            let mut store = blackbox_core::segment::SegmentStore::open(&dir).unwrap();
            // Same method+url, DIFFERENT bodies (nonce injected by the app).
            store.append(&rec(tid, 0, url, "POST", b"nonce-aaa", 200, b"first")).unwrap();
            store.append(&rec(tid, 1, url, "POST", b"nonce-bbb", 200, b"second")).unwrap();
            store.sync().unwrap();
        }
        let engine = ReplayEngine::load(&dir, &tid).unwrap();

        // The replayed app sends NEW bodies (different nonce): the exact
        // hash misses but the sequence fallback serves in recorded order.
        let m1 = engine.resolve("POST", url, fingerprint("POST", url, b"nonce-XXX")).unwrap();
        assert_eq!(m1.response_body, b"first".to_vec());
        let m2 = engine.resolve("POST", url, fingerprint("POST", url, b"nonce-YYY")).unwrap();
        assert_eq!(m2.response_body, b"second".to_vec());
        assert!(engine.resolve("POST", url, fingerprint("POST", url, b"nonce-ZZZ")).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
