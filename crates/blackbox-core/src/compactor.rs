//! Background segment compaction — the Phase 5 storage lifecycle engine.
//!
//! ## What runs when
//!
//! ```text
//! rotation (size cap)          → new segment_NNN.log, old one becomes sealed
//! compactor tick / Disk 75%    → compact_pass(): sealed .log → .log.zst (zstd-3)
//!                                + .idx sidecar, raw removed last
//! Disk 85%                     → evict_cold_fifo(): oldest .log.zst (+ .idx) deleted
//! Disk 95%                     → (ingress sheds healthy 200-OK telemetry; the
//!                                compactor keeps making room above)
//! ```
//!
//! ## Crash safety ordering (per segment)
//!
//! 1. `.idx` sidecar written + fsynced (pure metadata — harmless alone),
//! 2. `.log.zst.tmp` written + fsynced, then atomically renamed,
//! 3. raw `.log` removed LAST.
//!
//! A crash at any point leaves a state every reader already understands:
//! readers always prefer a raw `.log` over a `.log.zst` sibling (see
//! [`crate::segment::list_segment_files`]), and a `.zst` without an `.idx`
//! falls back to on-demand decompression. The next compaction pass cleans
//! up whatever intermediate state it finds.
//!
//! ## `.idx` sidecar format (BBIDX01)
//!
//! ```text
//! magic[8] = "BBIDX01\0" | segment_id: u32le | raw_len: u64le | count: u32le
//! per frame: trace_id[16] | offset: u64le | total_len: u32le
//!            | seq_no: u64le | timestamp_ms: u64le | class: u8 | kind: u8
//! ```
//!
//! Fixed 46-byte entries, checksummed implicitly by structural validation
//! on load (magic + id + exact length). The sidecar carries the SAME
//! metadata the in-memory trace index needs, so a restart rebuilds the
//! index from sidecars without decompressing a single cold segment
//! ([`crate::segment::read_meta_all`]).

use crate::error::StorageError;
use crate::frame;
use crate::schema::TraceRecord;
use crate::segment::{
    frame_meta_of, list_segment_files, parse_segment_name, parse_segment_zst_name,
    read_record_at, scan_frames, FrameMeta, IndexEntry,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// zstd level for background sealing (spec: level 3 — fast, ~3-6x on
/// telemetry frames; `seal_active` keeps its explicit level-9 path).
pub const DEFAULT_COMPRESS_LEVEL: i32 = 3;

const IDX_MAGIC: [u8; 8] = *b"BBIDX01\0";
const IDX_HEADER: usize = 8 + 4 + 8 + 4;
const IDX_ENTRY: usize = 16 + 8 + 4 + 8 + 8 + 1 + 1; // 46

/// One sidecar entry — everything the trace index needs about a frame
/// that lives inside a compressed segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdxEntry {
    pub trace_id: [u8; 16],
    pub offset: u64,
    pub total_len: u32,
    pub seq_no: u64,
    pub timestamp_ms: u64,
    pub status_class: u8,
    pub kind: u8,
}

impl IdxEntry {
    fn from_parts(entry: &IndexEntry, meta: &FrameMeta) -> Self {
        IdxEntry {
            trace_id: entry.trace_id,
            offset: entry.offset,
            total_len: entry.total_len,
            seq_no: meta.seq_no,
            timestamp_ms: meta.timestamp_ms,
            status_class: meta.status_class,
            kind: meta.kind,
        }
    }
}

/// Sidecar path for a segment id (`segment_XXXXXX.idx`).
pub fn idx_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("segment_{id:06}.idx"))
}

fn zst_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("segment_{id:06}.log.zst"))
}

/// Public `.log.zst` artifact path (the Phase 6 cold tier + janitor reuse
/// the canonical naming rule).
pub fn zst_artifact_path(dir: &Path, id: u32) -> PathBuf {
    zst_path(dir, id)
}

/// Public raw `.log` path (read-only uses: admin stats, gates).
pub fn raw_artifact_path(dir: &Path, id: u32) -> PathBuf {
    raw_path(dir, id)
}

/// Write + fsync the `.idx` sidecar for a segment.
pub fn write_idx(dir: &Path, id: u32, raw_len: u64, entries: &[IdxEntry]) -> Result<(), StorageError> {
    let mut buf = Vec::with_capacity(IDX_HEADER + entries.len() * IDX_ENTRY);
    buf.extend_from_slice(&IDX_MAGIC);
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(&raw_len.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        buf.extend_from_slice(&e.trace_id);
        buf.extend_from_slice(&e.offset.to_le_bytes());
        buf.extend_from_slice(&e.total_len.to_le_bytes());
        buf.extend_from_slice(&e.seq_no.to_le_bytes());
        buf.extend_from_slice(&e.timestamp_ms.to_le_bytes());
        buf.push(e.status_class);
        buf.push(e.kind);
    }
    let path = idx_path(dir, id);
    let mut f = File::create(&path)?;
    f.write_all(&buf)?;
    f.sync_data()?;
    Ok(())
}

/// Load + structurally validate the `.idx` sidecar. Returns
/// `Ok(None)` when absent or malformed (callers fall back to
/// decompress-on-demand — a sidecar is an optimization, never a
/// requirement). `Some((raw_len, entries))` on success.
pub fn load_idx(dir: &Path, id: u32) -> Result<Option<(u64, Vec<IdxEntry>)>, StorageError> {
    let path = idx_path(dir, id);
    let mut buf = Vec::new();
    match File::open(&path) {
        Ok(mut f) => {
            if let Err(e) = f.read_to_end(&mut buf) {
                tracing::warn!(segment = id, error = %e, "idx sidecar unreadable; ignoring");
                return Ok(None);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if buf.len() < IDX_HEADER || buf[..8] != IDX_MAGIC {
        return Ok(None);
    }
    let sid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if sid != id {
        return Ok(None);
    }
    let raw_len = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let count = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
    if buf.len() != IDX_HEADER + count * IDX_ENTRY {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let b = &buf[IDX_HEADER + i * IDX_ENTRY..IDX_HEADER + (i + 1) * IDX_ENTRY];
        entries.push(IdxEntry {
            trace_id: b[0..16].try_into().unwrap(),
            offset: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            total_len: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            seq_no: u64::from_le_bytes(b[28..36].try_into().unwrap()),
            timestamp_ms: u64::from_le_bytes(b[36..44].try_into().unwrap()),
            status_class: b[44],
            kind: b[45],
        });
    }
    Ok(Some((raw_len, entries)))
}

/// One compaction pass outcome (admin/gate reporting).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactionReport {
    /// Sealed raw segments converted to `.log.zst` (+ `.idx`).
    pub segments_compacted: u32,
    /// Raw bytes freed by compression (before → after delta).
    pub bytes_saved: u64,
    /// Frames covered by freshly written sidecars.
    pub frames_indexed: u64,
    /// Stale `.log.zst` siblings removed (raw exists = raw wins).
    pub stale_zst_removed: u32,
}

/// Compress every SEALED raw segment (`id != active_id`) into an immutable
/// `.log.zst` at `level` and write its `.idx` sidecar. Pass
/// `active_id = u32::MAX` for offline compaction (no store is running —
/// every raw segment is fair game). Idempotent: already-compacted segments
/// are skipped; a stale `.zst` next to a live raw is replaced.
///
/// Blocks the calling thread — drive it from the janitor task or a
/// `spawn_blocking`. Never touches the active segment.
pub fn compact_pass(
    dir: &Path,
    active_id: u32,
    level: i32,
) -> Result<CompactionReport, StorageError> {
    let mut report = CompactionReport::default();

    // 0) Stale sibling cleanup: a `.log.zst` whose raw `.log` still exists
    //    is dead weight (readers prefer the raw). Remove it; the raw is
    //    re-compacted below. NOTE: this cannot iterate
    //    `list_segment_files` — that helper already hides stale siblings
    //    from readers — so it scans the directory directly.
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        let Some(id) = parse_segment_zst_name(&name) else { continue };
        if id == active_id {
            continue;
        }
        if raw_path(dir, id).exists() {
            match std::fs::remove_file(zst_path(dir, id)) {
                Ok(()) => report.stale_zst_removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    // 1) Compact every sealed raw segment, oldest id first.
    for (id, _path, is_zst) in list_segment_files(dir)? {
        if is_zst || id == active_id {
            continue;
        }
        if let Some((saved, frames)) = compact_one(dir, id, level)? {
            report.segments_compacted += 1;
            report.bytes_saved += saved;
            report.frames_indexed += frames;
        }
    }
    Ok(report)
}

/// Compress one sealed raw segment + write its sidecar. Returns
/// `None` when the raw vanished (racing rotation on an empty segment —
/// benign), otherwise `(bytes_saved, frames_indexed)`.
fn compact_one(dir: &Path, id: u32, level: i32) -> Result<Option<(u64, u64)>, StorageError> {
    let raw = raw_path(dir, id);
    let mut buf = Vec::new();
    match File::open(&raw) {
        Ok(mut f) => {
            if let Err(e) = f.read_to_end(&mut buf) {
                tracing::warn!(segment = id, error = %e, "sealed raw unreadable; skipping");
                return Ok(None);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    // Index the raw stream (headers + per-frame metadata).
    let (valid_len, mut index, _events) = scan_frames(&buf);
    if valid_len != buf.len() as u64 {
        // Sealed segments are complete by construction; a torn tail here
        // means a previous process died mid-write — trim the index to the
        // valid prefix and proceed with what is durable.
        tracing::warn!(segment = id, valid_len, len = buf.len(), "sealed segment has a torn tail; indexing the valid prefix");
        index.retain(|e| e.offset + e.total_len as u64 <= valid_len);
    }

    let mut entries: Vec<IdxEntry> = Vec::with_capacity(index.len());
    if !index.is_empty() {
        // Decode each record once for its metadata (seq/ts/class/kind).
        let mut offset = 0usize;
        for entry in &index {
            let (_view, record) = match frame::decode_frame(&buf, offset) {
                Ok(x) => x,
                Err(p) => {
                    tracing::warn!(segment = id, offset = entry.offset, reason = %p.reason(), "frame decode failed during compaction; sidecar truncated here");
                    break;
                }
            };
            entries.push(IdxEntry::from_parts(entry, &frame_meta_of(&record)));
            offset = entry.offset as usize + entry.total_len as usize;
        }
    }

    if buf.is_empty() {
        // Empty segment: sidecar only, no zst artifact.
        write_idx(dir, id, 0, &entries)?;
        fsync_dir(dir);
        std::fs::remove_file(&raw)?;
        fsync_dir(dir);
        return Ok(Some((0, 0)));
    }

    // 1) sidecar, 2) zst (tmp + rename), 3) raw removal — crash-safe order.
    write_idx(dir, id, buf.len() as u64, &entries)?;
    let compressed = zstd::stream::encode_all(&buf[..], level)
        .map_err(|e| StorageError::Codec(format!("zstd compress failed: {e}")))?;
    let saved = (buf.len().saturating_sub(compressed.len())) as u64;
    let tmp = zst_path(dir, id).with_extension("zst.tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&compressed)?;
        f.sync_data()?;
    }
    std::fs::rename(&tmp, zst_path(dir, id))?;
    fsync_dir(dir);
    std::fs::remove_file(&raw)?;
    fsync_dir(dir);
    Ok(Some((saved, entries.len() as u64)))
}

/// Delete cold `.log.zst` artifacts (+ their `.idx` sidecars) oldest
/// segment-id first until `free_target` bytes have been freed. NEVER
/// touches raw `.log` files (the active segment and any not-yet-compacted
/// sealed segment stay put — data loss requires an explicit raw delete,
/// which this API does not do). Returns `(files_removed, bytes_freed)`.
pub fn evict_cold_fifo(dir: &Path, free_target: u64) -> Result<(u32, u64), StorageError> {
    if free_target == 0 {
        return Ok((0, 0));
    }
    let mut cold: Vec<(u32, u64)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = parse_segment_zst_name(&name) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            cold.push((id, size));
        }
    }
    cold.sort_by_key(|(id, _)| *id);

    let mut removed = 0u32;
    let mut freed = 0u64;
    for (id, size) in cold {
        if freed >= free_target {
            break;
        }
        let mut this = size;
        // Sidecar goes with it (same vintage).
        if let Ok(m) = std::fs::metadata(idx_path(dir, id)) {
            this += m.len();
        }
        let zst = zst_path(dir, id);
        if let Err(e) = std::fs::remove_file(&zst) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        let _ = std::fs::remove_file(idx_path(dir, id)); // optional
        removed += 1;
        freed += this;
        tracing::warn!(segment = id, bytes = this, "disk quota 85%: evicted oldest cold .zst segment (FIFO)");
    }
    fsync_dir(dir);
    Ok((removed, freed))
}

/// Tiered eviction policy — Phase 6 crash-pinned retention (blueprint §4).
///
/// `tier_of` decides whether a segment MAY be evicted at all (`None` =
/// pinned — e.g. not yet synced to the cold tier) and in which order
/// (lower tier evicted first; ties broken by oldest segment id). The
/// Phase 6 janitor passes the cold tier's classification so that:
///
///   tier 0 — healthy (no 4xx/5xx/crash) segments go first,
///   tier 1 — segments with 4xx but no 5xx/crash,
///   tier 2 — segments containing SentryCrash or 5xx (pinned longest).
///
/// Everything else about the FIFO contract is preserved: raw `.log` files
/// are never touched, `.idx` sidecars are evicted with their segment.
pub fn evict_cold_tiered(
    dir: &Path,
    free_target: u64,
    tier_of: &dyn Fn(u32) -> Option<u8>,
) -> Result<(u32, u64), StorageError> {
    if free_target == 0 {
        return Ok((0, 0));
    }
    let mut candidates: Vec<(u8, u32, u64)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = parse_segment_zst_name(&name) {
            let Some(tier) = tier_of(id) else { continue };
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            candidates.push((tier, id, size));
        }
    }
    candidates.sort_by_key(|(tier, id, _)| (*tier, *id));

    let mut removed = 0u32;
    let mut freed = 0u64;
    for (tier, id, size) in candidates {
        if freed >= free_target {
            break;
        }
        let mut this = size;
        if let Ok(m) = std::fs::metadata(idx_path(dir, id)) {
            this += m.len();
        }
        if let Err(e) = std::fs::remove_file(zst_path(dir, id)) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        let _ = std::fs::remove_file(idx_path(dir, id));
        removed += 1;
        freed += this;
        tracing::warn!(
            segment = id,
            tier,
            bytes = this,
            "disk quota 85%: evicted cold .zst segment (tiered: healthy first, crash/5xx pinned)"
        );
    }
    fsync_dir(dir);
    Ok((removed, freed))
}

/// Count cold `.zst` artifacts and their total bytes (admin stats).
pub fn cold_zst_stats(dir: &Path) -> (u32, u64) {
    let mut n = 0u32;
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(dir).into_iter().flatten() {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if parse_segment_zst_name(&name).is_some() {
            n += 1;
            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    (n, bytes)
}

/// Count sealed raw `.log` files (compaction backlog) excluding the active.
pub fn sealed_raw_stats(dir: &Path, active_id: u32) -> (u32, u64) {
    let mut n = 0u32;
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(dir).into_iter().flatten() {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = parse_segment_name(&name) {
            if id == active_id {
                continue;
            }
            n += 1;
            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    (n, bytes)
}

fn raw_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("segment_{id:06}.log"))
}

fn fsync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Decode every record across every segment artifact in order — the shared
/// implementation behind the soak/gate integrity sweeps.
pub fn read_all_records_ordered(dir: &Path) -> Result<Vec<TraceRecord>, StorageError> {
    crate::segment::read_all_records(dir)
}

/// Targeted cold read helper used by gates: reads one record from a
/// possibly-compacted segment (decompress on demand).
pub fn read_cold_record(dir: &Path, segment_id: u32, offset: u64) -> Result<TraceRecord, StorageError> {
    read_record_at(dir, segment_id, offset)
}

/// Force compaction of ALL sealed segments, looping until the directory is
/// quiescent (rotation may seal more while we run). Used by the Disk-75%
/// reaction and the offline `compact` admin path.
pub fn compact_all(dir: &Path, active_id: u32, level: i32) -> Result<CompactionReport, StorageError> {
    let mut total = CompactionReport::default();
    for _ in 0..4 {
        let r = compact_pass(dir, active_id, level)?;
        let done = r.segments_compacted == 0 && r.stale_zst_removed == 0;
        total.segments_compacted += r.segments_compacted;
        total.bytes_saved += r.bytes_saved;
        total.frames_indexed += r.frames_indexed;
        total.stale_zst_removed += r.stale_zst_removed;
        if done {
            break;
        }
    }
    Ok(total)
}

/// Aggregate compaction stats shared with the admin API.
#[derive(Debug, Default)]
pub struct CompactorStats {
    pub compactions: std::sync::atomic::AtomicU64,
    pub evictions: std::sync::atomic::AtomicU64,
    pub bytes_saved: std::sync::atomic::AtomicU64,
    pub frames_indexed: std::sync::atomic::AtomicU64,
    pub last_report: std::sync::Mutex<Option<String>>,
}

impl CompactorStats {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(CompactorStats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{IngressHttp, RecordPayload};
    use crate::segment::{SegmentConfig, SegmentStore};
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("blackbox-compact-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Compressible IngressHttp record — 4 KB of repetitive JSON so zstd-3
    /// comfortably exceeds a 4x ratio.
    fn rec(tid: [u8; 16], seq: u64) -> TraceRecord {
        let mut body = String::new();
        for i in 0..64 {
            body.push_str(&format!(
                "{{\"event\":\"synthetic\",\"pad\":\"AAAAAAAAAAAAAAAAAAAAAAAA\",\"i\":{i:04}}}"
            ));
        }
        TraceRecord::new(
            tid,
            seq,
            RecordPayload::IngressHttp(IngressHttp {
                method: "POST".into(),
                uri: "/api/events".into(),
                status: 200,
                req_headers: vec![("content-type".into(), "application/json".into())],
                req_body: body.clone().into_bytes(),
                res_body: b"{\"ok\":true,\"pad\":\"AAAAAAAAAAAAAAAAAAAA\"}".to_vec(),
                duration_ms: 3,
            }),
        )
    }

    fn tid(n: u64) -> [u8; 16] {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&n.to_be_bytes());
        t
    }

    #[test]
    fn idx_roundtrip_and_malformed_rejected() {
        let dir = tmpdir("idx-roundtrip");
        let entries = vec![
            IdxEntry { trace_id: tid(1), offset: 0, total_len: 120, seq_no: 0, timestamp_ms: 111, status_class: 1, kind: 0 },
            IdxEntry { trace_id: tid(2), offset: 120, total_len: 96, seq_no: 1, timestamp_ms: 222, status_class: 3, kind: 3 },
        ];
        write_idx(&dir, 7, 216, &entries).unwrap();
        let (raw_len, loaded) = load_idx(&dir, 7).unwrap().unwrap();
        assert_eq!(raw_len, 216);
        assert_eq!(loaded, entries);

        // Corrupt magic → treated as absent.
        let p = idx_path(&dir, 7);
        let mut raw = std::fs::read(&p).unwrap();
        raw[0] ^= 0xFF;
        std::fs::write(&p, &raw).unwrap();
        assert!(load_idx(&dir, 7).unwrap().is_none());

        // Truncated → treated as absent.
        std::fs::write(&p, &raw[..raw.len() - 5]).unwrap();
        assert!(load_idx(&dir, 7).unwrap().is_none());
        // Wrong id → treated as absent.
        write_idx(&dir, 9, 1, &[]).unwrap();
        assert!(load_idx(&dir, 8).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_pass_compresses_only_sealed_and_keeps_reads_working() {
        let dir = tmpdir("compact-sealed");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 8 * 1024 },
        )
        .unwrap();
        let mut seq = 0u64;
        while store.active_segment_id() < 4 {
            store.append(&rec(tid(seq), seq)).unwrap();
            seq += 1;
        }
        store.sync().unwrap();
        let active = store.active_segment_id();
        // Pre-compaction truth (raws still on disk).
        let pre = crate::segment::read_all_records(&dir).unwrap();
        assert_eq!(pre.len(), seq as usize);
        drop(store);

        let report = compact_pass(&dir, active, 3).unwrap();
        assert_eq!(report.segments_compacted, active as u32, "all sealed raws compact");
        assert!(report.bytes_saved > 0);

        // Ratio > 4x per compacted segment (repetitive JSON payload), and
        // the sidecars together index every sealed frame.
        let mut idx_frames = 0u64;
        for id in 0..active {
            let zst = std::fs::metadata(zst_path(&dir, id)).unwrap().len();
            let (raw_len, entries) = load_idx(&dir, id).unwrap().unwrap();
            assert!(raw_len > 0);
            assert!(raw_len / zst.max(1) > 4, "segment {id}: raw {raw_len} vs zst {zst} must exceed 4x");
            assert!(!entries.is_empty());
            idx_frames += entries.len() as u64;
            assert!(!segment_raw_exists(&dir, id), "raw must be removed after compaction");
        }
        assert!(idx_frames > 0);
        assert_eq!(
            report.frames_indexed, idx_frames,
            "report accounting matches the sidecars"
        );

        // Cold point-reads return the exact records (decompress on demand),
        // driven by the metadata scan — never by caller-tracked offsets.
        let metas = crate::segment::read_meta_all(&dir).unwrap();
        assert_eq!(metas.len(), pre.len());
        for (i, (seg, off, meta)) in metas.iter().enumerate() {
            assert_eq!(meta.seq_no, i as u64, "global order preserved");
            let got = read_cold_record(&dir, *seg, *off).unwrap();
            assert_eq!(got.seq_no, i as u64);
            assert_eq!(got.trace_id, pre[i].trace_id);
        }

        // Full read across zst + active equals the pre-compaction truth.
        let post = crate::segment::read_all_records(&dir).unwrap();
        assert_eq!(post.len(), pre.len());

        // Active segment untouched: a raw .log still exists for it.
        assert!(segment_raw_exists(&dir, active));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The active segment's own frames are not compacted — the report only
    /// counts sealed work.
    fn segment_raw_exists(dir: &Path, id: u32) -> bool {
        raw_path(dir, id).exists()
    }

    #[test]
    fn compact_pass_never_touches_active_segment() {
        let dir = tmpdir("compact-active");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 4 * 1024 },
        )
        .unwrap();
        for seq in 0..30u64 {
            store.append(&rec(tid(seq), seq)).unwrap();
        }
        store.sync().unwrap();
        let active = store.active_segment_id();
        assert!(active >= 1);
        let raw_before = std::fs::metadata(raw_path(&dir, active)).unwrap().len();
        drop(store);

        compact_pass(&dir, active, 3).unwrap();
        assert!(segment_raw_exists(&dir, active), "active raw must survive compaction");
        assert_eq!(std::fs::metadata(raw_path(&dir, active)).unwrap().len(), raw_before);
        assert!(load_idx(&dir, active).unwrap().is_none(), "no sidecar for the active segment");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_cold_fifo_removes_oldest_first() {
        let dir = tmpdir("evict-fifo");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 4 * 1024 },
        )
        .unwrap();
        for seq in 0..60u64 {
            store.append(&rec(tid(seq), seq)).unwrap();
        }
        store.sync().unwrap();
        let active = store.active_segment_id();
        drop(store);
        compact_pass(&dir, active, 3).unwrap();

        // Inventory the cold artifacts that actually exist (empty sealed
        // segments legitimately have no zst — idx-only).
        let mut cold: Vec<(u32, u64)> = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let e = entry.unwrap();
            let name = e.file_name();
            if let Some(id) = parse_segment_zst_name(&name.to_string_lossy()) {
                cold.push((id, e.metadata().unwrap().len()));
            }
        }
        cold.sort_by_key(|(id, _)| *id);
        assert!(cold.len() >= 3, "expected several cold segments, got {}", cold.len());

        // Free roughly the oldest two segments worth of bytes.
        let oldest = cold[0].0;
        let second = cold[1].0;
        let newest = cold.last().unwrap().0;
        let target = cold[0].1 + cold[1].1 + 1;
        let (removed, freed) = evict_cold_fifo(&dir, target).unwrap();
        assert!(removed >= 2, "expected >=2 evictions for target {target}, got {removed}");
        assert!(freed >= target);

        // FIFO: the OLDEST ids are gone, newer ones remain.
        assert!(!zst_path(&dir, oldest).exists());
        assert!(!idx_path(&dir, oldest).exists(), "sidecar evicted with its segment");
        assert!(!zst_path(&dir, second).exists());
        assert!(zst_path(&dir, newest).exists(), "newest cold segment survives");
        // Raw active untouched.
        assert!(segment_raw_exists(&dir, active));

        // A second pass with 0 target is a no-op.
        let (removed2, _) = evict_cold_fifo(&dir, 0).unwrap();
        assert_eq!(removed2, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_is_idempotent_and_cleans_stale_zst() {
        let dir = tmpdir("compact-idem");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 4 * 1024 },
        )
        .unwrap();
        for seq in 0..40u64 {
            store.append(&rec(tid(seq), seq)).unwrap();
        }
        store.sync().unwrap();
        let active = store.active_segment_id();
        drop(store);

        let r1 = compact_pass(&dir, active, 3).unwrap();
        assert!(r1.segments_compacted >= 1);
        // Second pass: nothing left to do.
        let r2 = compact_pass(&dir, active, 3).unwrap();
        assert_eq!(r2.segments_compacted, 0);
        assert_eq!(r2.stale_zst_removed, 0);

        // Craft a stale sibling on a COMPACTED NON-EMPTY segment (segment 0
        // may be empty under this cap — pick the first id that has a zst).
        let victim = (1..active)
            .find(|&id| zst_path(&dir, id).exists())
            .expect("at least one compacted non-empty segment");
        std::fs::write(raw_path(&dir, victim), b"").unwrap();
        let all = crate::segment::read_index_all(&dir).unwrap();
        assert_eq!(
            all.iter().filter(|(id, _, _)| *id == victim).count(),
            0,
            "raw wins over the stale zst (empty raw → zero frames)"
        );
        let r3 = compact_pass(&dir, active, 3).unwrap();
        assert_eq!(r3.stale_zst_removed, 1, "stale sibling removed");
        assert_eq!(r3.segments_compacted, 1, "empty raw re-sealed to idx-only");
        assert!(!zst_path(&dir, victim).exists(), "empty segment leaves no zst");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
