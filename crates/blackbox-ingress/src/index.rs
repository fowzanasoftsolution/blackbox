//! In-memory trace index — roaring bitmaps + bloom fast-path + exact
//! `trace_id → (segment_id, frame_offset)` lookup.
//!
//! ## Layout
//!
//! - `frames: Vec<FrameRef>` — ordinal → location + status class + kind.
//!   The ordinal is the roaring bitmap key space.
//! - `by_trace: HashMap<TraceId, Vec<u32>>` — trace id → ordinals (append
//!   order; `get_trace` re-sorts by `seq_no` for causal order).
//! - `status_2xx/4xx/5xx: RoaringBitmap` — status-class sets over ordinals.
//! - `has_sentry_crash: RoaringBitmap` — ordinals of Sentry crash records.
//! - `bloom: Bloom` — 512 KB fixed-size filter; negative lookups (unknown
//!   trace id) never touch disk.
//!
//! The index is rebuilt from the startup recovery scan
//! ([`blackbox_core::segment::read_index_all`]) and kept live by the writer
//! task as frames are appended. All operations are O(1) amortized; the lock
//! is a plain `std::sync::RwLock` held only for memory ops.

use blackbox_core::segment::{read_record_at, FrameMeta};
use blackbox_core::schema::{TraceId, TraceRecord};
use blackbox_core::StorageError;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Status class of a captured exchange (from `IngressHttp.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    None,
    S2xx,
    S4xx,
    S5xx,
}

impl StatusClass {
    pub fn from_status(status: u16) -> Self {
        match status {
            200..=299 => StatusClass::S2xx,
            400..=499 => StatusClass::S4xx,
            500..=599 => StatusClass::S5xx,
            _ => StatusClass::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecKind {
    IngressHttp,
    EgressHttpMock,
    TelemetryLog,
    SentryCrash,
    QueueJob,
}

/// One indexed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRef {
    pub trace_id: TraceId,
    pub seq_no: u64,
    pub timestamp_ms: u64,
    pub segment_id: u32,
    pub offset: u64,
    pub class: StatusClass,
    pub kind: RecKind,
}

/// Aggregate stats for diagnostics / gates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub frames: u64,
    pub status_2xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub sentry_crashes: u64,
    pub distinct_traces: u64,
}

/// 512 KB fixed-size bloom filter over 128-bit trace ids (k = 4).
pub struct Bloom {
    bits: Vec<u64>,
    words_mask: u64,
}

impl Bloom {
    /// 2^23 bits = 1 MiB, ~4M distinct ids at 1% FP with k=4.
    pub fn new(bits_log2: u32) -> Self {
        let words = 1usize << (bits_log2 - 6).max(0);
        Bloom {
            bits: vec![0u64; words],
            words_mask: (words as u64) - 1,
        }
    }

    #[inline]
    fn hash(tid: &TraceId, salt: u64) -> u64 {
        // Two 64-bit lanes + salt, splitmix-style finalizer.
        let a = u64::from_le_bytes(tid[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(tid[8..16].try_into().unwrap());
        let mut x = a ^ b.rotate_left(17) ^ salt;
        x ^= x >> 33;
        x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        x ^= x >> 33;
        x = x.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
        x ^= x >> 33;
        x
    }

    #[inline]
    fn probe(&self, h: u64) -> (usize, u64) {
        let word = (h & self.words_mask) as usize;
        let bit = (h >> 58) & 63;
        (word, 1u64 << bit)
    }

    pub fn add(&mut self, tid: &TraceId) {
        for k in 0..4u64 {
            let h = Self::hash(tid, k.wrapping_mul(0x517C_C1B7_2722_0A95));
            let (w, bit) = self.probe(h);
            self.bits[w] |= bit;
        }
    }

    pub fn might_contain(&self, tid: &TraceId) -> bool {
        for k in 0..4u64 {
            let h = Self::hash(tid, k.wrapping_mul(0x517C_C1B7_2722_0A95));
            let (w, bit) = self.probe(h);
            if self.bits[w] & bit == 0 {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Debug for Bloom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bloom").field("bits", &(&self.bits.len() * 64)).finish()
    }
}

/// The in-memory trace index.
pub struct TraceIndex {
    dir: PathBuf,
    bloom: Bloom,
    frames: Vec<FrameRef>,
    by_trace: HashMap<TraceId, Vec<u32>>,
    status_2xx: RoaringBitmap,
    status_4xx: RoaringBitmap,
    status_5xx: RoaringBitmap,
    has_sentry_crash: RoaringBitmap,
    /// Phase 6: S3/R2 cold tier (restore evicted segments + bit-rot heal).
    cold: Option<Arc<blackbox_cold::ColdTier>>,
}

impl TraceIndex {
    /// Empty index over a segment directory.
    pub fn empty(dir: &Path) -> Self {
        TraceIndex {
            dir: dir.to_path_buf(),
            bloom: Bloom::new(23),
            frames: Vec::new(),
            by_trace: HashMap::new(),
            status_2xx: RoaringBitmap::new(),
            status_4xx: RoaringBitmap::new(),
            status_5xx: RoaringBitmap::new(),
            has_sentry_crash: RoaringBitmap::new(),
            cold: None,
        }
    }

    /// Attach the Phase 6 cold tier (S3/R2 restore + bit-rot self-heal).
    pub fn set_cold(&mut self, cold: Arc<blackbox_cold::ColdTier>) {
        self.cold = Some(cold);
    }

    pub fn cold(&self) -> Option<&Arc<blackbox_cold::ColdTier>> {
        self.cold.as_ref()
    }

    /// Rebuild from the startup scan of ALL segments on disk.
    ///
    /// Phase 5: sealed `.zst` segments with a valid `.idx` sidecar are
    /// served from the sidecar WITHOUT decompression (fast restart);
    /// everything else falls back to a full decode. Both paths produce
    /// identical index state.
    pub fn rebuild(dir: &Path) -> Result<Self, StorageError> {
        let mut idx = TraceIndex::empty(dir);
        for (segment_id, offset, meta) in blackbox_core::segment::read_meta_all(dir)? {
            idx.insert_meta(&meta, segment_id, offset);
        }
        Ok(idx)
    }

    /// Insert one appended frame. The record metadata (status/kind) is read
    /// from the payload; the frame is assumed already durable in the segment.
    pub fn insert(&mut self, record: &TraceRecord, segment_id: u32, offset: u64) {
        let meta = blackbox_core::segment::frame_meta_of(record);
        self.insert_meta(&meta, segment_id, offset);
    }

    /// Insert from payload-free metadata (the `.idx` sidecar fast path).
    pub fn insert_meta(
        &mut self,
        meta: &FrameMeta,
        segment_id: u32,
        offset: u64,
    ) {
        let class = match meta.status_class {
            blackbox_core::segment::CLASS_2XX => StatusClass::S2xx,
            blackbox_core::segment::CLASS_4XX => StatusClass::S4xx,
            blackbox_core::segment::CLASS_5XX => StatusClass::S5xx,
            _ => StatusClass::None,
        };
        let kind = match meta.kind {
            blackbox_core::segment::KIND_EGRESS => RecKind::EgressHttpMock,
            blackbox_core::segment::KIND_TELEMETRY => RecKind::TelemetryLog,
            blackbox_core::segment::KIND_SENTRY => RecKind::SentryCrash,
            blackbox_core::segment::KIND_QUEUE => RecKind::QueueJob,
            _ => RecKind::IngressHttp,
        };
        let ordinal = self.frames.len() as u32;
        self.frames.push(FrameRef {
            trace_id: meta.trace_id,
            seq_no: meta.seq_no,
            timestamp_ms: meta.timestamp_ms,
            segment_id,
            offset,
            class,
            kind,
        });
        self.by_trace.entry(meta.trace_id).or_default().push(ordinal);
        self.bloom.add(&meta.trace_id);
        match class {
            StatusClass::S2xx => {
                self.status_2xx.insert(ordinal);
            }
            StatusClass::S4xx => {
                self.status_4xx.insert(ordinal);
            }
            StatusClass::S5xx => {
                self.status_5xx.insert(ordinal);
            }
            StatusClass::None => {}
        }
        if kind == RecKind::SentryCrash {
            self.has_sentry_crash.insert(ordinal);
        }
    }

    /// Exact trace lookup: all records of `trace_id` in causal order
    /// (ascending `seq_no`). Disk reads are targeted preads via
    /// [`blackbox_core::segment::read_record_at`].
    ///
    /// Phase 6 self-healing: a frame read failure on a SEALED segment (bit-rot
    /// in a local `.zst`) triggers a verified re-fetch from the cold tier with
    /// an atomic file replace, then the read is retried — the caller never
    /// sees the corruption. A full index miss after a restart consults the
    /// cold tier's persistent trace map and transparently restores an evicted
    /// segment from S3/R2 before serving the records.
    pub fn get_trace(&self, trace_id: &TraceId) -> Option<Vec<TraceRecord>> {
        // Bloom fast-negative path: unknown ids cost one hash probe. The
        // bloom only knows LOCAL state, so fall through to the cold tier.
        if !self.bloom.might_contain(trace_id) {
            return self.get_trace_from_cold(trace_id);
        }
        let Some(ordinals) = self.by_trace.get(trace_id) else {
            return self.get_trace_from_cold(trace_id);
        };
        let mut located: Vec<(u64, u64, u32, u64)> = ordinals
            .iter()
            .map(|&o| {
                let f = &self.frames[o as usize];
                (f.seq_no, f.timestamp_ms, f.segment_id, f.offset)
            })
            .collect();
        located.sort_unstable(); // by seq_no, then ts
        let mut out = Vec::with_capacity(located.len());
        for (_, _, segment_id, offset) in located {
            match read_record_at(&self.dir, segment_id, offset) {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    // Only a SEALED segment has a cold replica to heal from;
                    // active-segment failures are logged and skipped as before.
                    let healed = self
                        .cold
                        .as_ref()
                        .map(|c| c.ensure_segment_local(&self.dir, segment_id).unwrap_or(false))
                        .unwrap_or(false);
                    if healed {
                        match read_record_at(&self.dir, segment_id, offset) {
                            Ok(rec) => {
                                out.push(rec);
                                continue;
                            }
                            Err(e2) => {
                                tracing::warn!(
                                    segment = segment_id,
                                    offset,
                                    error = %e2,
                                    "indexed frame still unreadable after cold-tier self-heal; skipping"
                                );
                                continue;
                            }
                        }
                    }
                    tracing::warn!(
                        segment = segment_id,
                        offset,
                        error = %e,
                        "indexed frame unreadable; skipping"
                    );
                }
            }
        }
        Some(out)
    }

    /// Index-miss fallback: the cold tier's persistent trace map
    /// (trace_id → segment) survives restarts AND evictions, so a trace
    /// whose segment was FIFO-evicted (or lost pre-restart) is transparently
    /// re-fetched from S3/R2 and served.
    fn get_trace_from_cold(&self, trace_id: &TraceId) -> Option<Vec<TraceRecord>> {
        let cold = self.cold.as_ref()?;
        match cold.restore_trace(&self.dir, trace_id) {
            Ok(Some(recs)) if !recs.is_empty() => {
                tracing::info!(
                    records = recs.len(),
                    "trace served from cold-tier restore (segment was evicted or unknown locally)"
                );
                Some(recs)
            }
            _ => None,
        }
    }

    /// Ordinals whose class matches (roaring set).
    pub fn status_ordinals(&self, class: StatusClass) -> &RoaringBitmap {
        match class {
            StatusClass::S2xx => &self.status_2xx,
            StatusClass::S4xx => &self.status_4xx,
            StatusClass::S5xx => &self.status_5xx,
            StatusClass::None => unreachable!("no bitmap for None class"),
        }
    }

    pub fn sentry_crash_ordinals(&self) -> &RoaringBitmap {
        &self.has_sentry_crash
    }

    pub fn stats(&self) -> IndexStats {
        IndexStats {
            frames: self.frames.len() as u64,
            status_2xx: self.status_2xx.len(),
            status_4xx: self.status_4xx.len(),
            status_5xx: self.status_5xx.len(),
            sentry_crashes: self.has_sentry_crash.len(),
            distinct_traces: self.by_trace.len() as u64,
        }
    }

    pub fn frames(&self) -> &[FrameRef] {
        &self.frames
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackbox_core::schema::{
        IngressHttp, QueueJobRecord, RecordPayload, SentryCrash, TelemetryLog,
    };
    use blackbox_core::segment::SegmentStore;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("blackbox-idx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make(store: &mut SegmentStore, tid: TraceId, seq: u64, payload: RecordPayload) -> u64 {
        let rec = TraceRecord::new(tid, seq, payload);
        store.append(&rec).unwrap()
    }

    fn tid(n: u64) -> TraceId {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&n.to_be_bytes());
        t
    }

    fn http(status: u16) -> RecordPayload {
        RecordPayload::IngressHttp(IngressHttp {
            method: "GET".into(),
            uri: "/x".into(),
            status,
            req_headers: vec![],
            req_body: vec![],
            res_body: b"ok".to_vec(),
            duration_ms: 1,
        })
    }

    #[test]
    fn insert_lookup_and_rebuild() {
        let dir = tmpdir("insert");
        let mut store = SegmentStore::open(&dir).unwrap();

        let mut offsets = Vec::new();
        offsets.push(make(&mut store, tid(1), 0, http(200)));
        offsets.push(make(&mut store, tid(1), 1, http(500)));
        offsets.push(make(&mut store, tid(2), 2, http(404)));
        offsets.push(make(
            &mut store,
            tid(3),
            3,
            RecordPayload::SentryCrash(SentryCrash {
                project_id: "1".into(),
                event_id: "e".into(),
                envelope: b"x".to_vec(),
            }),
        ));
        offsets.push(make(
            &mut store,
            tid(4),
            4,
            RecordPayload::TelemetryLog(TelemetryLog {
                level: 3,
                service: "s".into(),
                message: "m".into(),
                attributes: vec![],
            }),
        ));
        store.sync().unwrap();

        // Live index.
        let mut idx = TraceIndex::empty(&dir);
        let all = blackbox_core::segment::read_index_all(&dir).unwrap();
        for (seg, off, rec) in all {
            idx.insert(&rec, seg, off);
        }

        let st = idx.stats();
        assert_eq!(st.frames, 5);
        assert_eq!(st.status_2xx, 1);
        assert_eq!(st.status_4xx, 1);
        assert_eq!(st.status_5xx, 1);
        assert_eq!(st.sentry_crashes, 1);
        assert_eq!(st.distinct_traces, 4);

        let t1 = idx.get_trace(&tid(1)).unwrap();
        assert_eq!(t1.len(), 2);
        assert_eq!(t1[0].seq_no, 0, "causal order by seq_no");
        assert_eq!(t1[1].seq_no, 1);

        assert!(idx.get_trace(&tid(2)).is_some());
        assert!(idx.get_trace(&tid(77)).is_none(), "bloom negative");

        // Offsets must match what the store returned.
        let f2 = &idx.frames()[2];
        assert_eq!(f2.offset, offsets[2]);

        // Rebuild from disk equals live index.
        let rebuilt = TraceIndex::rebuild(&dir).unwrap();
        assert_eq!(rebuilt.stats(), st);
        assert_eq!(
            rebuilt.get_trace(&tid(1)).unwrap().len(),
            2,
            "rebuilt index serves get_trace"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_trace_survives_reopen_after_seal() {
        let dir = tmpdir("seal");
        let mut store = SegmentStore::open(&dir).unwrap();
        make(&mut store, tid(9), 0, http(200));
        make(&mut store, tid(9), 1, http(200));
        store.seal_active(true).unwrap(); // → segment_000000.log.zst
        make(&mut store, tid(9), 2, http(503));
        store.sync().unwrap();
        drop(store);

        let idx = TraceIndex::rebuild(&dir).unwrap();
        let recs = idx.get_trace(&tid(9)).unwrap();
        assert_eq!(recs.len(), 3, "records across sealed + active segments");
        assert_eq!(recs[2].seq_no, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_jobs_do_not_pollute_status_bitmaps() {
        let dir = tmpdir("queue");
        let mut store = SegmentStore::open(&dir).unwrap();
        make(
            &mut store,
            tid(5),
            0,
            RecordPayload::QueueJob(QueueJobRecord {
                queue: "q".into(),
                payload: vec![],
                attempt: 0,
                max_attempts: 3,
                available_at_ms: 0,
            }),
        );
        store.sync().unwrap();
        let mut idx = TraceIndex::empty(&dir);
        let all = blackbox_core::segment::read_index_all(&dir).unwrap();
        for (seg, off, rec) in all {
            idx.insert(&rec, seg, off);
        }
        let st = idx.stats();
        assert_eq!(st.status_2xx + st.status_4xx + st.status_5xx, 0);
        assert_eq!(st.sentry_crashes, 0);
        assert_eq!(st.frames, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bloom_never_false_negatives() {
        let mut b = Bloom::new(20);
        let ids: Vec<TraceId> = (0..1000u64).map(tid).collect();
        for t in &ids {
            b.add(t);
        }
        for t in &ids {
            assert!(b.might_contain(t));
        }
        // False-positive rate sanity (not asserted tightly; just ensure the
        // filter isn't saturating).
        let fps = (2000..3000u64)
            .map(tid)
            .filter(|t| b.might_contain(t))
            .count();
        assert!(fps < 100, "bloom FP rate too high: {fps}/1000");
    }
}
