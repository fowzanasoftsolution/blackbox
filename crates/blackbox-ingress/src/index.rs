//! In-memory trace index — v1.1.1 hot-window design.
//!
//! ## Bounds (the soak `bb-soak-6h` lesson)
//!
//! In v1.1.0 the index grew with EVERY frame ever recorded, across restarts
//! too: `frames: Vec<FrameRef>` (~56 B/frame) + `by_trace: HashMap<TraceId,
//! Vec<u32>>` per ordinal + roaring bitmaps. A 6-hour, ~330 K-frame soak
//! carried that whole history in resident memory at all times, which is a
//! large share of Node A's 68.9 MiB RSS (Node B, at ~1/3 the volume, stayed
//! under budget).
//!
//! v1.1.1 keeps in RAM only what the ACTIVE segment needs, and moves sealed
//! history to on-disk artifacts that already existed:
//!
//! - `by_trace: HashMap<TraceId, Vec<LeafLoc>>` — ACTIVE-segment frames only;
//!   cleared segment-wise the moment the writer rotates past a segment.
//! - per-segment 8 KiB Bloom filters (`Bloom(16)` = 2^16 bits) — survive
//!   every seal; ~64 KiB dozen segments ≈ nothing.
//! - `segment_XXXXXX.sidx` (v1.1.1, trace-id-SORTED, 32 B/entry) — sealed
//!   history lookups binary-search this on-disk sidecar via
//!   [`blackbox_core::compactor::lookup_sidx`] and read frames with
//!   [`blackbox_core::segment::read_records_at`] (one decompress per call).
//! - `frames/status_*/sentry/distinct` — cumulative COUNTERS (8 B each),
//!   so the admin surface keeps reporting lifetime values even after hot
//!   eviction.
//!
//! `get_trace` therefore serves: bloom hit → hot map hit (active segment);
//! else per-sealed-bloom candidates → `.sidx` binary search → batch read
//! (decompress once); else the Phase 6 cold tier. Unknown ids still die on
//! a single hash probe.
//!
//! Rebuild after restart inserts ONLY the (recovered) active segment into
//! the hot map; sealed segments contribute their blooms + counters from the
//! metadata-only startup scan. Not-yet-compacted sealed raw segments are
//! treated as hot (transient — the janitor seals them within seconds), so
//! the hot window is always bounded by `max_segment_bytes`.

use blackbox_core::compactor::lookup_sidx;
use blackbox_core::segment::{
    frame_meta_of, read_meta_all, read_records_at, FrameMeta,
};
use blackbox_core::schema::{TraceId, TraceRecord};
use blackbox_core::StorageError;
use std::collections::{BTreeMap, HashMap, HashSet};
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

/// One ACTIVE-frame location for the hot map (`trace_id → list`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafLoc {
    pub segment_id: u32,
    pub offset: u64,
    pub seq_no: u64,
}

/// Aggregate stats for diagnostics / gates. The `frames` / `status_*` /
/// `sentry_crashes` fields are exact lifetime counters (never shrink after
/// evictions or seals); `distinct_traces` is a lifetime counter deduped
/// through the 1 MiB global Bloom — bounded, so it is approximate by
/// construction (false positives only ever under-count, ~0.1 % at soak
/// volume); `hot_traces` / `hot_trace_segments` / `archived_segments`
/// describe the bounded, live window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub frames: u64,
    pub status_2xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub sentry_crashes: u64,
    pub distinct_traces: u64,
    /// Trace ids resident in the hot map (ACTIVE-segment only).
    pub hot_traces: u64,
    /// DISTINCT segment ids present in the hot map (≤ 1 after each seal;
    /// >1 only for the transient raw-compaction-backlog window).
    pub hot_trace_segments: u64,
    /// Sealed segments being served from on-disk `.sidx` + 8 KiB blooms.
    pub archived_segments: u64,
}

/// Bloom filter over 128-bit trace ids (k = 4), fixed bit size.
pub struct Bloom {
    bits: Vec<u64>,
    words_mask: u64,
}

/// Global negative-lookup bloom: 2^23 bits = 1 MiB (~4M ids at 1 % FP).
const BLOOM_GLOBAL_BITS_LOG2: u32 = 23;
/// Per-active-segment bloom AND every sealed segment's bloom: 2^16 bits
/// = 8 KiB (spec-priced oversubscription for dense segments is harmless —
/// extra false positives only trigger an `.sidx` probe; there are no
/// false negatives).
const BLOOM_SEGMENT_BITS_LOG2: u32 = 16;

impl Bloom {
    /// `bits_log2 = 16` → 8 KiB; `= 23` → 1 MiB.
    pub fn new(bits_log2: u32) -> Self {
        debug_assert!(bits_log2 >= 6);
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

impl Clone for Bloom {
    fn clone(&self) -> Self {
        Bloom { bits: self.bits.clone(), words_mask: self.words_mask }
    }
}

/// Hot-window trace index. One `std::sync::RwLock` in front (same contract
/// as v1.1.0); every op inside is O(1)-amortized or an on-disk binary search.
pub struct TraceIndex {
    dir: PathBuf,
    /// Every trace id ever inserted this boot (cheap miss filter).
    global: Bloom,
    /// Trace ids of the ACTIVE segment (sealed as the segment's archived bloom).
    hot_bloom: Bloom,
    /// The segment the hot structures currently cover (`u32::MAX` sentinel
    /// until the first insert).
    hot_seg: u32,
    /// ACTIVE-segment frames only.
    by_trace: HashMap<TraceId, Vec<LeafLoc>>,
    /// Sealed segments (oldest→newest) → their 8 KiB bloom.
    archived: BTreeMap<u32, Box<Bloom>>,
    // Lifetime counters (u64 — the admin dashboard's history view).
    frames_total: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    sentry: u64,
    distinct_total: u64,
    /// Phase 6: S3/R2 cold tier (restore evicted segments + bit-rot heal).
    cold: Option<Arc<blackbox_cold::ColdTier>>,
}

impl TraceIndex {
    /// Empty index over a segment directory.
    pub fn empty(dir: &Path) -> Self {
        TraceIndex {
            dir: dir.to_path_buf(),
            global: Bloom::new(BLOOM_GLOBAL_BITS_LOG2),
            hot_bloom: Bloom::new(BLOOM_SEGMENT_BITS_LOG2),
            hot_seg: u32::MAX,
            by_trace: HashMap::new(),
            archived: BTreeMap::new(),
            frames_total: 0,
            status_2xx: 0,
            status_4xx: 0,
            status_5xx: 0,
            sentry: 0,
            distinct_total: 0,
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

    /// Restart scan → bounded index.
    ///
    /// Sealed (non-active) segments become archived blooms + counters —
    /// their frames NEVER re-enter the hot map (that's the v1.1.0 memory
    /// leak). Not-yet-compacted sealed raw segments stay hot: the janitor
    /// seals them within one tick, after which the same seal-transition
    /// logic evicts them.
    pub fn rebuild(dir: &Path) -> Result<Self, StorageError> {
        let mut idx = TraceIndex::empty(dir);
        // Sealed-raw segments (a raw `.log` that is not the active one — the
        // janitor compacts it within one tick) are treated as HOT until the
        // live seal transition evicts them; zst artifacts are archived.
        let metas = read_meta_all(dir)?;
        let mut runs: Vec<(u32, Vec<(u64, FrameMeta)>)> = Vec::new();
        for (seg, off, meta) in metas {
            match runs.last_mut() {
                Some((cur, list)) if *cur == seg => list.push((off, meta)),
                _ => runs.push((seg, vec![(off, meta)])),
            }
        }
        for (seg, group) in runs {
            if group_is_raw(dir, seg) {
                for (off, meta) in group {
                    idx.insert_meta(&meta, seg, off);
                }
            } else {
                idx.archive_segment(seg, group);
            }
        }
        Ok(idx)
    }

    /// Insert one appended frame. The record metadata (status/kind) is read
    /// from the payload; the frame is assumed already durable in the segment.
    pub fn insert(&mut self, record: &TraceRecord, segment_id: u32, offset: u64) {
        let meta = frame_meta_of(record);
        self.insert_meta(&meta, segment_id, offset);
    }

    /// Insert from payload-free metadata (the `.idx` sidecar fast path,
    /// live hot inserts, and rebuild's active-segment path).
    pub fn insert_meta(
        &mut self,
        meta: &FrameMeta,
        segment_id: u32,
        offset: u64,
    ) {
        // Seal transition: the writer moved to a NEWER segment → everything
        // the hot window held is sealed history now.
        if self.hot_seg != u32::MAX && segment_id > self.hot_seg {
            let sealed = self.hot_seg;
            let old_bloom = std::mem::replace(&mut self.hot_bloom, Bloom::new(BLOOM_SEGMENT_BITS_LOG2));
            self.archived.insert(sealed, Box::new(old_bloom));
            // Evict: drop by_trace entries that have NO frame in a segment
            // > sealed (traces spanning seal remain hot for their live tail).
            self.by_trace.retain(|_, locs| {
                locs.iter().any(|l| l.segment_id > sealed)
            });
        } else if self.hot_seg != u32::MAX && segment_id < self.hot_seg {
            tracing::warn!(
                seg = %segment_id,
                hot = %self.hot_seg,
                "out-of-order segment insert; treating as hot"
            );
        }
        self.hot_seg = segment_id;

        let (class, _kind, crash) = classify(meta);
        self.frames_total += 1;
        match class {
            1 => self.status_2xx += 1,
            2 => self.status_4xx += 1,
            3 => self.status_5xx += 1,
            _ => {}
        }
        if crash {
            self.sentry += 1;
        }
        // Distinct dedup via the GLOBAL bloom — the same oracle
        // `archive_segment` uses. A trace whose first frames live in a
        // sealed segment (restart rebuild: archived first, hot tail
        // after) is therefore not counted twice, without keeping an
        // unbounded seen-id set. Bloom false positives can only
        // under-count (an id may look already-seen), never inflate.
        if !self.global.might_contain(&meta.trace_id) {
            self.distinct_total += 1;
        }
        match self.by_trace.get_mut(&meta.trace_id) {
            Some(locs) => locs.push(LeafLoc { segment_id, offset, seq_no: meta.seq_no }),
            None => {
                self.by_trace.insert(
                    meta.trace_id,
                    vec![LeafLoc { segment_id, offset, seq_no: meta.seq_no }],
                );
            }
        }
        self.global.add(&meta.trace_id);
        self.hot_bloom.add(&meta.trace_id);
    }

    /// Bulk-archive a NOT-hot segment's metadata run (startup scan for
    /// sealed segments). Builds the 8 KiB bloom, dedups `distinct` through
    /// the shared global bloom, and never touches the hot map.
    pub fn archive_segment(&mut self, segment_id: u32, locs: Vec<(u64, FrameMeta)>) {
        let mut bloom = Bloom::new(BLOOM_SEGMENT_BITS_LOG2);
        for (_, meta) in locs {
            let (class, _kind, crash) = classify(&meta);
            self.frames_total += 1;
            match class {
                1 => self.status_2xx += 1,
                2 => self.status_4xx += 1,
                3 => self.status_5xx += 1,
                _ => {}
            }
            if crash {
                self.sentry += 1;
            }
            // Distinct dedup via the GLOBAL bloom — shared with the hot
            // path (see insert_meta). Also feed the global bloom here so
            // sealed-only traces pass get_trace's fast-negative check
            // after a restart; without this they were invisible until the
            // cold tier. False positives only ever under-count `distinct`.
            if !self.global.might_contain(&meta.trace_id) {
                self.distinct_total += 1;
            }
            self.global.add(&meta.trace_id);
            bloom.add(&meta.trace_id);
        }
        self.archived.insert(segment_id, Box::new(bloom));
    }

    /// Exact trace lookup: all records of `trace_id` in causal order
    /// (ascending `seq_no`).
    ///
    /// Service order: hot map (active segment) → archived blooms +
    /// `.sidx` binary searches (sealed segments, one decompress per call)
    /// → Phase 6 cold tier. Unknown ids cost one hash probe.
    pub fn get_trace(&self, trace_id: &TraceId) -> Option<Vec<TraceRecord>> {
        // Global fast-negative path: unknown ids never touch disk. The
        // bloom only knows LOCAL state, so fall through to the cold tier.
        if !self.global.might_contain(trace_id) {
            return self.get_trace_from_cold(trace_id);
        }

        let mut q = Vec::new(); // (seq_no, segment_id, offset)
        if let Some(locs) = self.by_trace.get(trace_id) {
            for loc in locs {
                q.push((loc.seq_no, loc.segment_id, loc.offset));
            }
        }
        let mut sealed: Vec<SealedLoc> = Vec::new();
        if q.is_empty() {
            // Sealed history: bloom-shortlisted segments, `.sidx` probes.
            for (&seg, bloom) in &self.archived {
                if bloom.might_contain(trace_id) {
                    match lookup_sidx(&self.dir, seg, trace_id) {
                        Ok(Some(pairs)) => {
                            for (offset, seq_no) in pairs {
                                sealed.push(SealedLoc { segment_id: seg, offset, seq_no });
                            }
                        }
                        Ok(None) => {
                            // Legacy artifact without `.idx`/`.sidx`: scan
                            // the segment directly for this trace.
                            if let Some(pairs) = scan_sealed_for_trace(&self.dir, seg, trace_id) {
                                for (offset, seq_no) in pairs {
                                    sealed.push(SealedLoc { segment_id: seg, offset, seq_no });
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(segment = seg, error = %e, "sidx lookup failed");
                        }
                    }
                }
            }
        } else {
            // A trace with HOT frames may ALSO have sealed frames — probe
            // the archived segments too so the timeline stays complete.
            for (&seg, bloom) in &self.archived {
                if !bloom.might_contain(trace_id) {
                    continue;
                }
                match lookup_sidx(&self.dir, seg, trace_id) {
                    Ok(Some(pairs)) => {
                        for (offset, seq_no) in pairs {
                            sealed.push(SealedLoc { segment_id: seg, offset, seq_no });
                        }
                    }
                    Ok(None) => {
                        // Legacy (pre-sidecar) sealed segment: same zst-scan
                        // fallback as the hot-miss path — e.g. a v1.1.0-era
                        // segment sealed before an upgrade, whose trace
                        // continues into the current active segment.
                        if let Some(pairs) = scan_sealed_for_trace(&self.dir, seg, trace_id) {
                            for (offset, seq_no) in pairs {
                                sealed.push(SealedLoc { segment_id: seg, offset, seq_no });
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(segment = seg, error = %e, "sidx lookup failed");
                    }
                }
            }
        }

        let mut ordered: Vec<(u64, u32, u64)> = q
            .into_iter()
            .map(|(seq, seg, off)| (seq, seg, off))
            .collect();
        for s in sealed {
            ordered.push((s.seq_no, s.segment_id, s.offset));
        }
        if ordered.is_empty() {
            return self.get_trace_from_cold(trace_id);
        }
        ordered.sort_unstable(); // by seq_no (globally unique), then seg/off

        // Group frames per segment for the one-decompress batch reads.
        let mut out: Vec<TraceRecord> = Vec::with_capacity(ordered.len());
        let mut pending: Vec<u64> = Vec::new();
        let mut pending_seg: Option<u32> = None;
        let flush = |seg: u32, offs: &mut Vec<u64>, out: &mut Vec<TraceRecord>| {
            if offs.is_empty() {
                return;
            }
            match read_records_at(&self.dir, seg, offs) {
                Ok(recs) => {
                    for r in recs.into_iter().flatten() {
                        out.push(r);
                    }
                }
                Err(e) => {
                    // Only a SEALED segment has a cold replica to heal from;
                    // active-segment failures are logged and skipped.
                    let healed = self
                        .cold
                        .as_ref()
                        .map(|c| c.ensure_segment_local(&self.dir, seg).unwrap_or(false))
                        .unwrap_or(false);
                    if healed {
                        match read_records_at(&self.dir, seg, offs) {
                            Ok(recs) => {
                                for r in recs.into_iter().flatten() {
                                    out.push(r);
                                }
                            }
                            Err(e2) => {
                                tracing::warn!(segment = seg, error = %e2, "batch still unreadable after cold-tier self-heal; skipping");
                            }
                        }
                    } else {
                        tracing::warn!(segment = seg, error = %e, "batch frame read failed; skipping");
                    }
                }
            }
            offs.clear();
        };
        for (seq_no, seg, offset) in ordered {
            if pending_seg != Some(seg) {
                if let Some(s) = pending_seg.take() {
                    flush(s, &mut pending, &mut out);
                }
                pending_seg = Some(seg);
            }
            pending.push(offset);
            let _ = seq_no; // already used for ordering
        }
        if let Some(s) = pending_seg.take() {
            flush(s, &mut pending, &mut out);
        }

        // Causal sanity: seq_no is globally unique, so this must be sorted.
        out.sort_by_key(|r| r.seq_no);
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

    pub fn stats(&self) -> IndexStats {
        let mut segs: HashSet<u32> = HashSet::new();
        for locs in self.by_trace.values() {
            for l in locs {
                segs.insert(l.segment_id);
            }
        }
        IndexStats {
            frames: self.frames_total,
            status_2xx: self.status_2xx,
            status_4xx: self.status_4xx,
            status_5xx: self.status_5xx,
            sentry_crashes: self.sentry,
            distinct_traces: self.distinct_total,
            hot_traces: self.by_trace.len() as u64,
            hot_trace_segments: segs.len() as u64,
            archived_segments: self.archived.len() as u64,
        }
    }

    /// Numeric id of the segment the hot window currently covers.
    pub fn hot_segment(&self) -> u32 {
        self.hot_seg
    }

    /// Sealed segment ids known to this boot (ascending).
    pub fn archived_segments(&self) -> Vec<u32> {
        self.archived.keys().copied().collect()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// (status_class u8 as in `FrameMeta`, RecKind kind, is_sentry)
fn classify(meta: &FrameMeta) -> (u8, RecKind, bool) {
    let kind = match meta.kind {
        blackbox_core::segment::KIND_EGRESS => RecKind::EgressHttpMock,
        blackbox_core::segment::KIND_TELEMETRY => RecKind::TelemetryLog,
        blackbox_core::segment::KIND_SENTRY => RecKind::SentryCrash,
        blackbox_core::segment::KIND_QUEUE => RecKind::QueueJob,
        _ => RecKind::IngressHttp,
    };
    (meta.status_class, kind, kind == RecKind::SentryCrash)
}

/// Is `seg` a raw `.log` artifact at `dir` right now? (Startup-scan helper:
/// raw segments — the active one AND any sealed-but-uncompacted backlog —
/// are hot; zst artifacts are archived from their sidecar metadata.)
fn group_is_raw(dir: &Path, seg: u32) -> bool {
    blackbox_core::compactor::raw_artifact_path(dir, seg).exists()
}

struct SealedLoc {
    segment_id: u32,
    offset: u64,
    seq_no: u64,
}

/// Legacy fallback: scan a sealed segment for one trace id via the core
/// decoder (zst decompress-once or raw preads). Only reached for artifacts
/// that predate BOTH sidecars.
fn scan_sealed_for_trace(
    dir: &Path,
    seg: u32,
    trace_id: &TraceId,
) -> Option<Vec<(u64, u64)>> {
    blackbox_core::compactor::scan_sealed_for_trace(dir, seg, trace_id).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackbox_core::schema::{
        IngressHttp, QueueJobRecord, RecordPayload, SentryCrash, TelemetryLog,
    };
    use blackbox_core::segment::{read_record_at, SegmentStore};
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

    fn show(store: &mut SegmentStore, tid: TraceId, seq: u64, payload: RecordPayload) -> (u32, u64) {
        let seg = store.active_segment_id();
        let off = make(store, tid, seq, payload);
        (seg, off)
    }

    #[test]
    fn insert_lookup_and_counters() {
        let dir = tmpdir("insert");
        let mut store = SegmentStore::open(&dir).unwrap();

        let mut locs = Vec::new();
        locs.push(show(&mut store, tid(1), 0, http(200)));
        locs.push(show(&mut store, tid(1), 1, http(500)));
        locs.push(show(&mut store, tid(2), 2, http(404)));
        locs.push(show(
            &mut store,
            tid(3),
            3,
            RecordPayload::SentryCrash(SentryCrash {
                project_id: "1".into(),
                event_id: "e".into(),
                envelope: b"x".to_vec(),
            }),
        ));
        locs.push(show(
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
        assert_eq!(st.hot_traces, 4);
        assert_eq!(st.hot_trace_segments, 1);

        let t1 = idx.get_trace(&tid(1)).unwrap();
        assert_eq!(t1.len(), 2);
        assert_eq!(t1[0].seq_no, 0, "causal order by seq_no");
        assert_eq!(t1[1].seq_no, 1);

        assert!(idx.get_trace(&tid(2)).is_some());
        assert!(idx.get_trace(&tid(77)).is_none(), "bloom negative");

        // Rebuild from disk equals live counters and serves lookups.
        let rebuilt = TraceIndex::rebuild(&dir).unwrap();
        assert_eq!(rebuilt.stats(), st, "rebuild == live (all hot: one segment)");
        assert_eq!(
            rebuilt.get_trace(&tid(1)).unwrap().len(),
            2,
            "rebuilt index serves get_trace"
        );
        let loc0 = locs[0];
        assert_eq!(loc0.1, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_trace_survives_reopen_after_seal() {
        let dir = tmpdir("seal");
        let mut store = SegmentStore::open(&dir).unwrap();
        make(&mut store, tid(9), 0, http(200));
        make(&mut store, tid(9), 1, http(200));
        store.seal_active(true).unwrap(); // → segment_000000.log.zst (NO sidecars)
        make(&mut store, tid(9), 2, http(503));
        store.sync().unwrap();
        drop(store);

        // Rebuild: segment 0 is sealed → archived; segment 1 hot.
        let idx = TraceIndex::rebuild(&dir).unwrap();
        let st = idx.stats();
        assert_eq!(st.hot_trace_segments, 1, "sealed segment evicted from the hot map");
        assert_eq!(st.archived_segments, 1);
        assert_eq!(st.distinct_traces, 1);
        assert_eq!(
            st.frames, 3,
            "lifetime counters still cover sealed history"
        );
        let recs = idx.get_trace(&tid(9)).unwrap();
        assert_eq!(
            recs.len(),
            3,
            "records across sealed (zst-scan fallback) + active segments"
        );
        assert_eq!(recs[2].seq_no, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_lookup_uses_sidx_sidecars() {
        let dir = tmpdir("sidx");
        let mut store = SegmentStore::open(&dir).unwrap();
        make(&mut store, tid(1), 0, http(200));
        make(&mut store, tid(2), 1, http(503));
        make(&mut store, tid(1), 2, http(404));
        store.seal_active(true).unwrap(); // zst, then compactor writes .idx + .sidx
        blackbox_core::compactor::compact_all(&dir, u32::MAX, 3).unwrap();
        let sidx = sidx_path_of(&dir, 0);
        assert!(sidx.exists(), "compactor must write the trace-sorted sidecar");

        let idx = TraceIndex::rebuild(&dir).unwrap();
        assert_eq!(idx.stats().archived_segments, 1);
        assert!(
            idx.get_trace(&tid(1)).unwrap().len() == 2,
            "sealed lookup via .sidx binary search"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sidx_path_of(dir: &Path, seg: u32) -> PathBuf {
        blackbox_core::compactor::sidx_path(dir, seg)
    }

    #[test]
    fn seal_evicts_hot_map_but_keeps_mode_counters_and_lookups() {
        let dir = tmpdir("evict");
        let mut store = SegmentStore::open(&dir).unwrap();

        let mut locs = Vec::new();
        locs.push(show(&mut store, tid(1), 0, http(200)));
        locs.push(show(&mut store, tid(2), 1, http(200)));
        store.sync().unwrap();

        let mut idx = TraceIndex::empty(&dir);
        let all = blackbox_core::segment::read_index_all(&dir).unwrap();
        for (seg, off, rec) in all {
            idx.insert(&rec, seg, off);
        }
        let before = idx.stats();
        assert_eq!(before.hot_traces, 2);
        assert_eq!(before.hot_trace_segments, 1);

        // Writer posts new frames in segment 1 (the seal transition)…
        store.seal_active(false).unwrap(); // segment 0 seals (raw; compacted below)
        locs.push(show(&mut store, tid(3), 2, http(200)));
        store.sync().unwrap();
        let all = blackbox_core::segment::read_index_all(&dir).unwrap();
        for (seg, off, rec) in all {
            if (seg, off) != locs[2] {
                continue;
            }
            idx.insert(&rec, seg, off);
        }

        let after = idx.stats();
        assert_eq!(after.frames, 3, "counter cumulative across seals");
        assert_eq!(after.distinct_traces, 3, "distinct cumulative across seals");
        assert_eq!(after.hot_traces, 1, "only the ACTIVE segment's trace stays");
        assert_eq!(after.hot_trace_segments, 1);
        assert_eq!(after.archived_segments, 1);

        // Sealed lookups still resolve (post-seal, pre-sidecar → zst-scan).
        assert!(idx.get_trace(&tid(1)).is_some());
        assert!(idx.get_trace(&tid(2)).is_some());
        assert!(idx.get_trace(&tid(3)).is_some());
        // …and after compaction the sidx path serves them too.
        blackbox_core::compactor::compact_all(&dir, u32::MAX, 3).unwrap();
        assert_eq!(idx.get_trace(&tid(2)).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_jobs_do_not_pollute_status_counters() {
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

    #[test]
    fn read_record_pointers_match_compaction_sidecars() {
        // Point-read equivalence: frame offsets recorded by the hot insert
        // must match what compaction later puts in the sidecars.
        let dir = tmpdir("offsets");
        let mut store = SegmentStore::open(&dir).unwrap();
        make(&mut store, tid(8), 0, http(201));
        make(&mut store, tid(9), 1, http(202));
        store.seal_active(true).unwrap();
        blackbox_core::compactor::compact_all(&dir, u32::MAX, 3).unwrap();
        let (_, entries) = blackbox_core::compactor::load_idx(&dir, 0).unwrap().unwrap();
        assert_eq!(entries.len(), 2);
        let got = read_record_at(&dir, 0, entries[0].offset).unwrap();
        assert_eq!(got.seq_no, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
