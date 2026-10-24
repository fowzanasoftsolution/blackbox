//! Append-only segment engine — the Phase 1 storage core.
//!
//! ## Design constraints honored (blueprint §2)
//!
//! - **Never `mmap` active write buffers** (landmine #1): all writes go through
//!   explicit positioned `pwrite` (`FileExt::write_at`) appends; recovery reads
//!   are plain buffered reads. No page-table locks, no TLB shootdowns, no
//!   `SIGBUS` on write-active files.
//! - **Torn-write auto-truncation** (§4.1): on open, the segment scanner walks
//!   frames from offset 0, verifying magic + header CRC + payload CRC +
//!   bytecheck. The FIRST problem encountered marks the end of valid data:
//!   the file is truncated (`set_len`) back to the last valid frame boundary,
//!   the index rebuilt, and a recovery event logged. Startup never panics and
//!   never crash-loops on a damaged tail.
//! - **Policy note**: mid-file corruption also truncates forward (the corrupt
//!   frame and everything after it is discarded). This is the correct policy
//!   for the ACTIVE segment, which has no replica; sealed segments are
//!   immutable and later get S3/R2 replica restore (Phase 1.5+, §4.1).
//!
//! ## Segment lifecycle
//!
//! ```text
//! segment_000000.log   active  (appends via SegmentStore)
//! segment_000000.log.zst  sealed (zstd-9, immutable, ready for S3 tier)
//! ```
//!
//! Rotation happens when the active segment exceeds `max_segment_bytes`
//! (default 64 MB, blueprint §3 Engine 3). Sealing is explicit
//! ([`SegmentStore::seal_active`]) so tests and callers control durability.

use crate::error::StorageError;
use crate::frame::{self, FrameProblem};
use crate::schema::{TraceId, TraceRecord};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;

/// Default active-segment rotation size (blueprint: 64 MB hot segments).
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Process-wide view of "which segment is the active one". The writer task
/// owns the [`SegmentStore`] mutably; the Phase 5 compactor / disk-quota
/// janitor and the admin API only need the monotonic active id — they
/// subscribe to this watch channel instead of touching the store.
pub struct StoreShared {
    active: watch::Sender<u32>,
}

impl Default for StoreShared {
    fn default() -> Self {
        let (tx, _rx) = watch::channel(0u32);
        StoreShared { active: tx }
    }
}

impl StoreShared {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = watch::channel(0u32);
        Arc::new(StoreShared { active: tx })
    }

    /// Current active segment id (0 until a store adopts this hub).
    pub fn active(&self) -> u32 {
        *self.active.borrow()
    }

    /// Publish an active-segment transition (rotation / seal / adoption).
    pub fn set_active(&self, id: u32) {
        let _ = self.active.send(id); // Err = no subscribers, fine
    }

    /// Subscribe to active-segment transitions (current value included).
    pub fn subscribe(&self) -> watch::Receiver<u32> {
        self.active.subscribe()
    }
}

/// Status class of an indexed frame (u8 encoding mirrors the ingress
/// index's `StatusClass` so the `.idx` sidecar can carry it cold).
pub const CLASS_NONE: u8 = 0;
pub const CLASS_2XX: u8 = 1;
pub const CLASS_4XX: u8 = 2;
pub const CLASS_5XX: u8 = 3;

/// Record-kind discriminant (u8 encoding mirrors `RecordPayload`'s order).
pub const KIND_INGRESS: u8 = 0;
pub const KIND_EGRESS: u8 = 1;
pub const KIND_TELEMETRY: u8 = 2;
pub const KIND_SENTRY: u8 = 3;
pub const KIND_QUEUE: u8 = 4;

/// Compact per-frame metadata — the payload-free summary stored in the
/// `.idx` sidecar and served by [`read_meta_all`] so the in-memory trace
/// index can be rebuilt WITHOUT decompressing sealed `.zst` segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMeta {
    pub trace_id: TraceId,
    pub seq_no: u64,
    pub timestamp_ms: u64,
    pub status_class: u8,
    pub kind: u8,
}

/// Extract the [`FrameMeta`] of a decoded record (single source of truth
/// for both the compactor and the fast index rebuild).
pub fn frame_meta_of(rec: &TraceRecord) -> FrameMeta {
    let status_class = match &rec.payload {
        crate::schema::RecordPayload::IngressHttp(h) => match h.status {
            200..=299 => CLASS_2XX,
            400..=499 => CLASS_4XX,
            500..=599 => CLASS_5XX,
            _ => CLASS_NONE,
        },
        _ => CLASS_NONE,
    };
    let kind = match &rec.payload {
        crate::schema::RecordPayload::IngressHttp(_) => KIND_INGRESS,
        crate::schema::RecordPayload::EgressHttpMock(_) => KIND_EGRESS,
        crate::schema::RecordPayload::TelemetryLog(_) => KIND_TELEMETRY,
        crate::schema::RecordPayload::SentryCrash(_) => KIND_SENTRY,
        crate::schema::RecordPayload::QueueJob(_) => KIND_QUEUE,
    };
    FrameMeta {
        trace_id: rec.trace_id,
        seq_no: rec.seq_no,
        timestamp_ms: rec.timestamp_ms,
        status_class,
        kind,
    }
}

/// One recovered frame's index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub trace_id: TraceId,
    /// Byte offset of the frame start in the segment.
    pub offset: u64,
    /// Total frame length (header + payload + padding).
    pub total_len: u32,
}

/// A recovery event for observability (logged at WARN by [`recover_file`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvent {
    pub offset: u64,
    pub reason: String,
    /// Bytes dropped from the tail (file_len_before - last_good_offset).
    pub truncated_bytes: u64,
}

/// Result of scanning + healing one segment file.
#[derive(Debug, Clone, Default)]
pub struct RecoveryReport {
    /// Number of valid frames recovered.
    pub frames: u64,
    /// Valid end-of-data offset after truncation == file length after healing.
    pub valid_len: u64,
    pub events: Vec<RecoveryEvent>,
    /// Index entries for the recovered frames.
    pub index: Vec<IndexEntry>,
}

/// Scan `buf` (contents of a segment file) frame by frame; return the valid
/// prefix length and index. Does NOT truncate the file — caller does.
/// Public: the Phase 5 compactor reuses it to index sealed segments.
pub fn scan_frames(buf: &[u8]) -> (u64, Vec<IndexEntry>, Vec<RecoveryEvent>) {
    let mut offset: usize = 0;
    let mut index = Vec::new();
    let mut events = Vec::new();

    while offset < buf.len() {
        match frame::parse_frame(buf, offset) {
            Ok(view) => {
                index.push(IndexEntry {
                    trace_id: view.trace_id,
                    offset: offset as u64,
                    total_len: view.total_len,
                });
                offset += view.total_len as usize;
            }
            Err(problem) => {
                events.push(RecoveryEvent {
                    offset: offset as u64,
                    reason: describe(&problem),
                    truncated_bytes: (buf.len() - offset) as u64,
                });
                break;
            }
        }
    }
    (offset as u64, index, events)
}

fn describe(problem: &FrameProblem) -> String {
    match problem {
        FrameProblem::PartialFrame {
            declared_total,
            available,
        } => format!(
            "partial_frame: declared {declared_total} bytes, {} available (torn write)",
            available
        ),
        other => other.reason().to_string(),
    }
}

/// Recover one segment file: scan, truncate at the first invalid frame,
/// fsync, and return the report. Idempotent — a second call finds zero
/// problems.
pub fn recover_file(path: &Path) -> Result<RecoveryReport, StorageError> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    let (valid_len, index, events) = scan_frames(&buf);

    for ev in &events {
        tracing::warn!(
            file = %path.display(),
            offset = ev.offset,
            truncated = ev.truncated_bytes,
            reason = %ev.reason,
            "segment corruption healed: truncating at last valid frame boundary"
        );
    }

    if (valid_len as usize) != buf.len() {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(valid_len)?;
        f.sync_data()?;
    }

    Ok(RecoveryReport {
        frames: index.len() as u64,
        valid_len,
        events,
        index,
    })
}

/// Active-segment writer. Single-writer by construction (owned by
/// `SegmentStore`); append-only; positioned writes, explicit fsync.
struct SegmentWriter {
    path: PathBuf,
    file: File,
    /// Next append offset — always a 16-byte-aligned frame boundary.
    offset: u64,
    id: u32,
}

impl SegmentWriter {
    /// Create a BRAND-NEW segment file (truncate is safe: no prior data).
    fn create(path: PathBuf, id: u32) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.sync_data()?;
        Ok(SegmentWriter { path, file, offset: 0, id })
    }

    /// Open an EXISTING recovered segment for continued appends. Must never
    /// truncate — recovery just validated the content we are keeping.
    fn open_existing(path: PathBuf, id: u32, offset: u64) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(&path)?;
        Ok(SegmentWriter { path, file, offset, id })
    }

    /// Append a pre-encoded frame; returns the frame's start offset.
    fn append_raw(&mut self, encoded: &[u8]) -> Result<u64, StorageError> {
        let start = self.offset;
        self.file.write_all_at(encoded, start)?;
        self.offset += encoded.len() as u64;
        Ok(start)
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.file.sync_data()?;
        Ok(())
    }
}

/// Append-only segment store managing the active segment plus sealed history.
pub struct SegmentStore {
    dir: PathBuf,
    writer: Option<SegmentWriter>,
    /// Index of the ACTIVE segment only (sealed segments are cold-tier data).
    index: Vec<IndexEntry>,
    max_segment_bytes: u64,
    /// Frames appended since the last fsync (group durability accounting).
    unsynced_frames: u64,
    /// Shared active-segment hub (compactor / janitor / admin subscribers).
    shared: Arc<StoreShared>,
}

/// Configuration for [`SegmentStore::open`].
#[derive(Debug, Clone)]
pub struct SegmentConfig {
    /// Rotate the active segment once it exceeds this size.
    pub max_segment_bytes: u64,
}

impl Default for SegmentConfig {
    fn default() -> Self {
        SegmentConfig {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
        }
    }
}

impl SegmentStore {
    /// Open (creating if needed) the segment directory, recovering the active
    /// segment: torn tails are truncated automatically before any append.
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        Self::open_with(dir, SegmentConfig::default())
    }

    pub fn open_with(dir: &Path, config: SegmentConfig) -> Result<Self, StorageError> {
        Self::open_with_shared(dir, config, StoreShared::new())
    }

    /// Open with a caller-provided [`StoreShared`] hub — the Phase 5 writer
    /// task adopts a hub it created so the compactor can subscribe BEFORE
    /// the store exists.
    pub fn open_with_shared(
        dir: &Path,
        config: SegmentConfig,
        shared: Arc<StoreShared>,
    ) -> Result<Self, StorageError> {
        std::fs::create_dir_all(dir)?;

        // Find the highest-numbered segment across BOTH artifacts. A `.log`
        // file means the segment is still writable; a `.log.zst` means it is
        // sealed-and-compacted. After a full compaction cycle the highest id
        // may exist ONLY as `.zst` — resuming at that id would create a raw
        // file that collides with the sealed one, so the fresh active
        // segment becomes max_id + 1 (Phase 5 restart-after-compaction).
        let mut max_log_id: Option<u32> = None;
        let mut max_zst_id: Option<u32> = None;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = parse_segment_name(&name) {
                max_log_id = Some(max_log_id.unwrap_or(0).max(id));
            } else if let Some(id) = parse_segment_zst_name(&name) {
                max_zst_id = Some(max_zst_id.unwrap_or(0).max(id));
            }
        }

        let (id, index, fresh) = match max_log_id {
            Some(id) => {
                // Raw wins: recover + continue appending the active segment.
                let path = segment_path(dir, id);
                let report = recover_file(&path)?;
                (id, report.index, false)
            }
            None => match max_zst_id {
                None => (0u32, Vec::new(), true),
                Some(z) => (z.checked_add(1).ok_or_else(|| {
                    StorageError::Db("segment id exhausted".into())
                })?, Vec::new(), true),
            },
        };

        // Fresh segments are created (truncate safe: no prior data); a
        // recovered active is re-opened WITHOUT truncation.
        let writer = if fresh {
            SegmentWriter::create(segment_path(dir, id), id)?
        } else {
            SegmentWriter::open_existing(
                segment_path(dir, id),
                id,
                index_last_end(&index),
            )?
        };

        shared.set_active(id);
        Ok(SegmentStore {
            dir: dir.to_path_buf(),
            writer: Some(writer),
            index,
            max_segment_bytes: config.max_segment_bytes,
            unsynced_frames: 0,
            shared,
        })
    }

    /// Append one record (encode + write). Durability is batched — call
    /// [`SegmentStore::sync`] to fsync, or drive it from the 5 ms group-commit
    /// loop. Returns the frame's start offset.
    pub fn append(&mut self, record: &TraceRecord) -> Result<u64, StorageError> {
        let encoded = frame::encode_frame(record)?;
        self.append_encoded(&encoded)
    }

    /// Append a pre-encoded frame (bench hot path reuses encode buffers).
    pub fn append_encoded(&mut self, encoded: &[u8]) -> Result<u64, StorageError> {
        // Rotate if this frame would push the active segment past the cap.
        let needs_rotate = self
            .writer
            .as_ref()
            .map(|w| w.offset + encoded.len() as u64 > self.max_segment_bytes)
            .unwrap_or(false);
        if needs_rotate {
            self.rotate()?;
        }

        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| StorageError::Db("segment writer closed".into()))?;
        let start = writer.append_raw(encoded)?;
        self.index.push(IndexEntry {
            trace_id: {
                // Header trace id sits at offset 12..28.
                let mut tid = [0u8; 16];
                tid.copy_from_slice(&encoded[12..28]);
                tid
            },
            offset: start,
            total_len: encoded.len() as u32,
        });
        self.unsynced_frames += 1;
        Ok(start)
    }

    /// fsync the active segment.
    pub fn sync(&mut self) -> Result<(), StorageError> {
        if let Some(w) = &self.writer {
            w.sync()?;
        }
        self.unsynced_frames = 0;
        Ok(())
    }

    /// Frames written since the last successful fsync.
    pub fn unsynced_frames(&self) -> u64 {
        self.unsynced_frames
    }

    /// Seal the active segment: fsync, optionally compress to `.log.zst`
    /// (zstd level 9) and remove the raw file, then start a fresh segment.
    /// Returns the sealed artifact path (`.zst` when compressed).
    pub fn seal_active(&mut self, compress: bool) -> Result<PathBuf, StorageError> {
        self.sync()?;
        let writer = self
            .writer
            .take()
            .ok_or_else(|| StorageError::Db("segment writer closed".into()))?;
        let raw_path = writer.path.clone();

        let sealed = if compress && writer.offset > 0 {
            let zst_path = raw_path.with_extension("log.zst");
            let mut raw = Vec::new();
            File::open(&raw_path)?.read_to_end(&mut raw)?;
            let compressed =
                zstd::stream::encode_all(&raw[..], 9).map_err(|e| {
                    StorageError::Codec(format!("zstd compress failed: {e}"))
                })?;
            {
                let mut out = File::create(&zst_path)?;
                out.write_all(&compressed)?;
                out.sync_data()?;
            }
            std::fs::remove_file(&raw_path)?;
            zst_path
        } else {
            raw_path
        };

        // Fresh active segment.
        let next_id = writer.id + 1;
        self.writer = Some(SegmentWriter::create(
            segment_path(&self.dir, next_id),
            next_id,
        )?);
        self.shared.set_active(next_id);
        self.index.clear();
        Ok(sealed)
    }

    /// The shared active-segment hub (clone into the compactor/janitor).
    pub fn shared(&self) -> Arc<StoreShared> {
        Arc::clone(&self.shared)
    }

    /// Subscribe to active-segment transitions.
    pub fn subscribe_active(&self) -> watch::Receiver<u32> {
        self.shared.subscribe()
    }

    fn rotate(&mut self) -> Result<(), StorageError> {
        // Rotation keeps the raw file (it becomes cold storage the Phase 5
        // compactor seals); only the index resets to the new active segment.
        self.sync()?;
        let writer = self
            .writer
            .take()
            .ok_or_else(|| StorageError::Db("segment writer closed".into()))?;
        let next_id = writer.id + 1;
        self.writer = Some(SegmentWriter::create(
            segment_path(&self.dir, next_id),
            next_id,
        )?);
        self.shared.set_active(next_id);
        self.index.clear();
        Ok(())
    }

    /// Index of the active segment (recovered + appended frames).
    pub fn index(&self) -> &[IndexEntry] {
        &self.index
    }

    /// Numeric id of the active segment (matches the `segment_%06u.log` name).
    /// The Phase 2 in-memory trace index records this alongside frame offsets.
    pub fn active_segment_id(&self) -> u32 {
        self.writer.as_ref().map(|w| w.id).unwrap_or(0)
    }

    /// Path of the active segment file.
    pub fn active_path(&self) -> Option<PathBuf> {
        self.writer.as_ref().map(|w| w.path.clone())
    }

    /// Byte size of the active segment.
    pub fn active_len(&self) -> u64 {
        self.writer.as_ref().map(|w| w.offset).unwrap_or(0)
    }
}

/// List every segment artifact under `dir` ordered by id: `(id, path,
/// is_zst)`. A raw `.log` ALWAYS wins over its `.log.zst` sibling (crash
/// between zst-write and raw-removal leaves both; the raw is authoritative
/// and the compactor re-seals it).
pub fn list_segment_files(dir: &Path) -> Result<Vec<(u32, PathBuf, bool)>, StorageError> {
    let mut raws: HashSet<u32> = HashSet::new();
    let mut out: Vec<(u32, PathBuf, bool)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if let Some(id) = parse_segment_name(&name) {
            raws.insert(id);
            out.push((id, entry.path(), false));
        } else if let Some(id) = parse_segment_zst_name(&name) {
            out.push((id, entry.path(), true));
        }
    }
    out.sort_by_key(|(id, _, is_zst)| (*id, *is_zst));
    // Drop `.zst` entries whose raw sibling exists (raw wins).
    out.retain(|(id, _, is_zst)| !is_zst || !raws.contains(id));
    Ok(out)
}

/// Read back every record of the recovered store across ALL segments
/// (sealed `.zst` decompressed, active `.log` as-is), in global order.
/// Used by tests, the crash harness, and `blackbox replay`.
pub fn read_all_records(dir: &Path) -> Result<Vec<TraceRecord>, StorageError> {
    let ids = list_segment_files(dir)?;
    let mut out = Vec::new();
    for (_, path, is_zst) in ids {
        let raw: Vec<u8> = if is_zst {
            let compressed = std::fs::read(&path)?;
            zstd::stream::decode_all(&compressed[..])
                .map_err(|e| StorageError::Codec(format!("zstd decompress failed: {e}")))?
        } else {
            std::fs::read(&path)?
        };
        append_records_from(&raw, &mut out)?;
    }
    Ok(out)
}

/// Walk frames in `buf`, fully decoding each record.
pub fn append_records_from(buf: &[u8], out: &mut Vec<TraceRecord>) -> Result<(), StorageError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let (view, record) = frame::decode_frame(buf, offset).map_err(|p| StorageError::Corrupt {
            offset: offset as u64,
            reason: p.reason().to_string(),
        })?;
        out.push(record);
        offset += view.total_len as usize;
    }
    Ok(())
}

/// Read back exactly ONE record at `(segment_id, byte_offset)` — the Phase 2
/// trace index serves `get_trace` with these targeted reads (pread header →
/// pread frame; no full-file scans). Sealed `.zst` segments are decompressed
/// on demand (cold path).
pub fn read_record_at(dir: &Path, segment_id: u32, offset: u64) -> Result<TraceRecord, StorageError> {
    let raw_path = segment_path(dir, segment_id);
    let file = match File::open(&raw_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Cold path: sealed compressed segment.
            let zst_path = raw_path.with_extension("log.zst");
            let compressed = std::fs::read(&zst_path).map_err(|_| StorageError::Corrupt {
                offset,
                reason: format!("segment {segment_id:06} not found on disk"),
            })?;
            let buf = zstd::stream::decode_all(&compressed[..]).map_err(|e| {
                StorageError::Codec(format!("zstd decompress failed: {e}"))
            })?;
            let (_view, record) = frame::decode_frame(&buf, offset as usize).map_err(|p| {
                StorageError::Corrupt { offset, reason: p.reason().to_string() }
            })?;
            return Ok(record);
        }
        Err(e) => return Err(e.into()),
    };

    // Hot path: read the 32-byte header, then exactly the frame bytes.
    let mut header = [0u8; crate::frame::HEADER_SIZE];
    use std::os::unix::fs::FileExt;
    file.read_exact_at(&mut header, offset)?;
    let payload_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if payload_len as u64 > crate::frame::MAX_PAYLOAD as u64 {
        return Err(StorageError::Corrupt {
            offset,
            reason: "bad_length in targeted read".into(),
        });
    }
    let total = frame::frame_total_len(payload_len);
    let mut frame_buf = vec![0u8; total];
    file.read_exact_at(&mut frame_buf, offset)?;
    let (_view, record) = frame::decode_frame(&frame_buf, 0).map_err(|p| {
        StorageError::Corrupt { offset, reason: p.reason().to_string() }
    })?;
    Ok(record)
}

/// Scan EVERY segment on disk (active `.log` + sealed `.zst`, ordered by id)
/// and return `(segment_id, byte_offset, decoded_record)` for all frames.
/// This is the startup recovery scan the Phase 2 in-memory trace index is
/// rebuilt from. One segment's bytes are held at a time (bounded RAM).
pub fn read_index_all(dir: &Path) -> Result<Vec<(u32, u64, TraceRecord)>, StorageError> {
    let files = list_segment_files(dir)?;

    let mut out = Vec::new();
    for (id, path, is_zst) in files {
        let raw: Vec<u8> = if is_zst {
            let compressed = std::fs::read(&path)?;
            zstd::stream::decode_all(&compressed[..])
                .map_err(|e| StorageError::Codec(format!("zstd decompress failed: {e}")))?
        } else {
            std::fs::read(&path)?
        };
        let mut offset = 0usize;
        while offset < raw.len() {
            let (view, record) = frame::decode_frame(&raw, offset).map_err(|p| {
                StorageError::Corrupt { offset: offset as u64, reason: p.reason().to_string() }
            })?;
            out.push((id, offset as u64, record));
            offset += view.total_len as usize;
        }
    }
    Ok(out)
}

/// Metadata-only startup scan. Sealed `.zst` segments with a valid `.idx`
/// sidecar are served straight from the sidecar (NO decompression — the
/// Phase 5 fast restart path); everything else falls back to a full
/// decode. Output mirrors [`read_index_all`] minus the payloads.
pub fn read_meta_all(dir: &Path) -> Result<Vec<(u32, u64, FrameMeta)>, StorageError> {
    let files = list_segment_files(dir)?;
    let mut out = Vec::new();
    for (id, path, is_zst) in files {
        if is_zst {
            // Fast path: trust only a fully valid sidecar.
            if let Some((raw_len, entries)) = crate::compactor::load_idx(dir, id)? {
                for e in entries {
                    if e.offset + e.total_len as u64 > raw_len {
                        continue; // defensive: sidecar PastEnd → ignore entry
                    }
                    out.push((
                        id,
                        e.offset,
                        FrameMeta {
                            trace_id: e.trace_id,
                            seq_no: e.seq_no,
                            timestamp_ms: e.timestamp_ms,
                            status_class: e.status_class,
                            kind: e.kind,
                        },
                    ));
                }
                continue;
            }
            // Sidecar missing/corrupt: decompress + decode (legacy).
            let compressed = std::fs::read(&path)?;
            let raw = zstd::stream::decode_all(&compressed[..])
                .map_err(|e| StorageError::Codec(format!("zstd decompress failed: {e}")))?;
            push_meta_from(&raw, id, &mut out)?;
        } else {
            let raw = std::fs::read(&path)?;
            push_meta_from(&raw, id, &mut out)?;
        }
    }
    Ok(out)
}

fn push_meta_from(buf: &[u8], segment_id: u32, out: &mut Vec<(u32, u64, FrameMeta)>) -> Result<(), StorageError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let (view, record) = frame::decode_frame(buf, offset).map_err(|p| {
            StorageError::Corrupt { offset: offset as u64, reason: p.reason().to_string() }
        })?;
        out.push((segment_id, offset as u64, frame_meta_of(&record)));
        offset += view.total_len as usize;
    }
    Ok(())
}

fn index_last_end(index: &[IndexEntry]) -> u64 {
    index.last().map(|e| e.offset + e.total_len as u64).unwrap_or(0)
}

/// Parse `segment_XXXXXX.log` → id. Public: the compactor and admin stats
/// reuse the canonical naming rule.
pub fn parse_segment_name(name: &str) -> Option<u32> {
    name.strip_prefix("segment_")
        .and_then(|s| s.strip_suffix(".log"))
        .and_then(|s| s.parse().ok())
}

/// Parse `segment_XXXXXX.log.zst` → id.
pub fn parse_segment_zst_name(name: &str) -> Option<u32> {
    name.strip_prefix("segment_")
        .and_then(|s| s.strip_suffix(".log.zst"))
        .and_then(|s| s.parse().ok())
}

fn segment_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("segment_{id:06}.log"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{QueueJobRecord, RecordPayload};

    fn rec(seq: u64, body_len: usize) -> TraceRecord {
        TraceRecord::new(
            [
                0x22u8, seq as u8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            ],
            seq,
            RecordPayload::QueueJob(QueueJobRecord {
                queue: "webhooks.test".into(),
                payload: vec![0xEEu8; body_len],
                attempt: 0,
                max_attempts: 5,
                available_at_ms: crate::schema::now_ms(),
            }),
        )
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "blackbox-seg-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_read_roundtrip_and_reopen_append() {
        let dir = tmpdir("roundtrip");
        let mut store = SegmentStore::open(&dir).unwrap();
        let n = 200usize;
        for seq in 0..n as u64 {
            store.append(&rec(seq, 64 + seq as usize)).unwrap();
        }
        store.sync().unwrap();
        let index_len = store.index().len();
        assert_eq!(index_len, n);
        drop(store);

        // Reopen: recovery finds all frames, truncates nothing.
        let store = SegmentStore::open(&dir).unwrap();
        assert_eq!(store.index().len(), n);

        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), n);
        for (seq, r) in records.iter().enumerate() {
            assert_eq!(r.seq_no, seq as u64);
        }

        // Reopen-append continuity: seq continues without gaps on disk.
        let mut store = store;
        store.append(&rec(n as u64, 100)).unwrap();
        store.sync().unwrap();
        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), n + 1);
        assert_eq!(records.last().unwrap().seq_no, n as u64);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_tail_auto_truncation() {
        let dir = tmpdir("torn");
        let mut store = SegmentStore::open(&dir).unwrap();
        let n = 50usize;
        for seq in 0..n as u64 {
            store.append(&rec(seq, 128)).unwrap();
        }
        store.sync().unwrap();
        let full_len = store.active_len();
        drop(store);

        // Tear: cut into the middle of the LAST frame.
        let path = segment_path(&dir, 0);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), full_len);

        // Walk the intact file to learn exact frame boundaries.
        let full = std::fs::read(&path).unwrap();
        let mut off = 0usize;
        let mut boundary_n2 = 0usize; // end of frame N-2 == start of frame N-1
        for i in 0..n {
            let v = frame::parse_frame(&full, off).unwrap();
            if i == n - 2 {
                boundary_n2 = off + v.total_len as usize;
            }
            off += v.total_len as usize;
        }
        assert_eq!(off, full.len());

        // Tear 8 bytes into the LAST frame's payload (past its header).
        let cut = (boundary_n2 + frame::HEADER_SIZE + 8) as u64;
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(cut).unwrap();

        // Recovery: N-1 frames survive, tail truncated, idempotent.
        let report = recover_file(&path).unwrap();
        assert_eq!(report.frames, (n - 1) as u64);
        // Valid boundary = end of the last intact frame (frame N-2).
        assert_eq!(report.valid_len, boundary_n2 as u64);
        assert_eq!(report.events.len(), 1);
        assert!(report.events[0].reason.starts_with("partial_frame"), "{}", report.events[0].reason);

        let store = SegmentStore::open(&dir).unwrap();
        assert_eq!(store.index().len(), n - 1);

        // Second recovery is a no-op (idempotent).
        let report2 = recover_file(&path).unwrap();
        assert_eq!(report2.frames, (n - 1) as u64);
        assert!(report2.events.is_empty());

        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), n - 1);
        for (seq, r) in records.iter().enumerate() {
            assert_eq!(r.seq_no, seq as u64);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bitflip_midfile_truncates_from_corrupt_frame() {
        let dir = tmpdir("bitflip");
        let mut store = SegmentStore::open(&dir).unwrap();
        let n = 100usize;
        for seq in 0..n as u64 {
            store.append(&rec(seq, 96)).unwrap();
        }
        store.sync().unwrap();
        drop(store);

        // Flip a byte inside frame #40's payload body (seq 40, deterministic).
        let path = segment_path(&dir, 0);
        let mut buf = std::fs::read(&path).unwrap();
        let entry_of_40 = {
            // Walk headers to frame 40 to find its payload start.
            let mut off = 0usize;
            let mut found = None;
            for i in 0..n {
                let v = frame::parse_frame(&buf, off).unwrap();
                if i == 40 {
                    found = Some(off);
                    break;
                }
                off += v.total_len as usize;
            }
            found.unwrap()
        };
        let payload_start = entry_of_40 + frame::HEADER_SIZE;
        buf[payload_start + 8] ^= 0xFF;
        std::fs::write(&path, &buf).unwrap();

        // Recovery: 40 frames survive (0..=39), the corrupt one and everything
        // after is dropped — conservative active-segment policy.
        let report = recover_file(&path).unwrap();
        assert_eq!(report.frames, 40, "report: {report:?}");
        assert_eq!(report.events[0].reason, "bad_payload_crc");

        let _store = SegmentStore::open(&dir).unwrap();
        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), 40);
        for (seq, r) in records.iter().enumerate() {
            assert_eq!(r.seq_no, seq as u64);
        }
        drop(_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn random_seeded_flips_always_recover_a_valid_prefix() {
        // Property test: with seeded pseudo-random single flips anywhere in
        // the file, recovery ALWAYS yields a valid contiguous prefix of
        // frames and never panics.
        let dir = tmpdir("randflip");
        for seed in 1..=25u64 {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let mut store = SegmentStore::open(&dir).unwrap();
            let n = 80usize;
            for seq in 0..n as u64 {
                store.append(&rec(seq, 72)).unwrap();
            }
            store.sync().unwrap();
            let mut state = seed.wrapping_mul(0x9E3779B97F4A7C15);
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            drop(store);

            let path = segment_path(&dir, 0);
            let mut buf = std::fs::read(&path).unwrap();
            let byte = (next() as usize) % buf.len();
            buf[byte] ^= 1u8 << (next() % 8);
            std::fs::write(&path, &buf).unwrap();

            let _store = SegmentStore::open(&dir).unwrap();
            let records = read_all_records(&dir).unwrap();
            // Contiguity: recovered records are seq 0..M with matching ids.
            for (i, r) in records.iter().enumerate() {
                assert_eq!(r.seq_no, i as u64, "seed {seed}");
                assert_eq!(r.trace_id[0], 0x22, "seed {seed}");
            }
            assert!(records.len() <= n, "seed {seed}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_and_zstd_seal_roundtrip() {
        let dir = tmpdir("rotate");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 4 * 1024 },
        )
        .unwrap();

        let mut total = 0usize;
        while store.active_path().map(|p| parse_segment_name(&p.file_name().unwrap().to_string_lossy())).unwrap() < Some(3) {
            store.append(&rec(total as u64, 200)).unwrap();
            total += 1;
        }
        store.sync().unwrap();

        // At least 3 segment files exist now (id 0,1,2,3...).
        let mut logs = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            if parse_segment_name(&entry.unwrap().file_name().to_string_lossy()).is_some() {
                logs += 1;
            }
        }
        assert!(logs >= 3, "expected >=3 segment files, got {logs}");

        // Seal the active segment with compression, then read everything back.
        let sealed = store.seal_active(true).unwrap();
        assert!(sealed.to_string_lossy().ends_with(".log.zst"));
        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), total);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.seq_no, i as u64);
        }

        // Sealed artifact decompresses to a valid frame stream, and it is
        // genuinely smaller than the raw frame stream.
        let compressed = std::fs::read(&sealed).unwrap();
        let decompressed = zstd::stream::decode_all(&compressed[..]).unwrap();
        assert!(compressed.len() < decompressed.len(), "zstd must shrink: {} vs {}", compressed.len(), decompressed.len());
        let mut count = 0;
        let mut off = 0usize;
        while off < decompressed.len() {
            let v = frame::parse_frame(&decompressed, off).unwrap();
            off += v.total_len as usize;
            count += 1;
        }
        assert!(count > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_flip_in_len_field_is_caught() {
        let dir = tmpdir("lenflip");
        let mut store = SegmentStore::open(&dir).unwrap();
        for seq in 0..30u64 {
            store.append(&rec(seq, 80)).unwrap();
        }
        store.sync().unwrap();
        drop(store);

        let path = segment_path(&dir, 0);
        let mut buf = std::fs::read(&path).unwrap();
        // Flip a bit in frame 5's payload_len header field (offset 4..8).
        let mut off = 0usize;
        for _ in 0..5 {
            let v = frame::parse_frame(&buf, off).unwrap();
            off += v.total_len as usize;
        }
        buf[off + 5] ^= 0x10; // inside payload_len LE bytes
        std::fs::write(&path, &buf).unwrap();

        // Header CRC must catch it — 5 frames survive.
        let report = recover_file(&path).unwrap();
        assert_eq!(report.frames, 5);
        assert_eq!(report.events[0].reason, "bad_header_crc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn active_segment_id_and_targeted_read() {
        let dir = tmpdir("targeted");
        let mut store = SegmentStore::open(&dir).unwrap();
        assert_eq!(store.active_segment_id(), 0);
        let mut offsets = Vec::new();
        for seq in 0..20u64 {
            offsets.push(store.append(&rec(seq, 100)).unwrap());
        }
        store.sync().unwrap();

        // Point-reads at recorded offsets return the exact records.
        for (seq, &off) in offsets.iter().enumerate() {
            let got = read_record_at(&dir, 0, off).unwrap();
            assert_eq!(got.seq_no, seq as u64);
            assert!(got.timestamp_ms > 0);
        }
        // Bad offset → clean error, no panic.
        assert!(read_record_at(&dir, 0, u64::MAX).is_err());
        // Missing segment → clean error.
        assert!(read_record_at(&dir, 99, 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_index_all_scans_active_and_sealed() {
        let dir = tmpdir("indexall");
        let mut store = SegmentStore::open(&dir).unwrap();
        for seq in 0..10u64 {
            store.append(&rec(seq, 96)).unwrap();
        }
        store.seal_active(true).unwrap(); // sealed segment 0 as .zst
        for seq in 10..16u64 {
            store.append(&rec(seq, 96)).unwrap();
        }
        store.sync().unwrap();
        drop(store);

        let all = read_index_all(&dir).unwrap();
        assert_eq!(all.len(), 16);
        // Order: segment 0 (sealed, 10 frames) then segment 1 (active, 6).
        assert_eq!(all[0].0, 0);
        assert_eq!(all[10].0, 1);
        for (i, (_, _, r)) in all.iter().enumerate() {
            assert_eq!(r.seq_no, i as u64);
        }

        // Point-read from the SEALED zst segment (cold path).
        let sealed_off = all[3].1;
        let got = read_record_at(&dir, 0, sealed_off).unwrap();
        assert_eq!(got.seq_no, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 5: after a restart where the highest artifact is a compacted
    /// `.zst` (raw removed), the store must open a FRESH active segment at
    /// max_id + 1 — never recreate the sealed id — and reads must span the
    /// sealed + new segments in order.
    #[test]
    fn restart_after_compaction_opens_fresh_next_segment() {
        let dir = tmpdir("restart-compacted");
        let mut store = SegmentStore::open(&dir).unwrap();
        for seq in 0..12u64 {
            store.append(&rec(seq, 128)).unwrap();
        }
        store.sync().unwrap();
        // seal_active(compress) → segment 0 becomes .log.zst, raw removed,
        // and a fresh raw segment 1 is created.
        let sealed = store.seal_active(true).unwrap();
        assert!(sealed.to_string_lossy().ends_with(".log.zst"));
        drop(store);

        // Offline full compaction (no active store): everything seals.
        // Segment 0 → .log.zst; the EMPTY segment 1 raw collapses to an
        // idx-only artifact (nothing to compress — no zst is produced).
        let report = crate::compactor::compact_pass(&dir, u32::MAX, 3).unwrap();
        assert_eq!(report.segments_compacted, 1);
        assert!(!segment_path(&dir, 0).exists());
        assert!(!segment_path(&dir, 1).exists());
        assert!(segment_path(&dir, 0).with_extension("log.zst").exists());
        assert!(crate::compactor::idx_path(&dir, 1).exists());

        // Restart: highest artifact is a .zst → fresh active = 1.
        let mut store = SegmentStore::open(&dir).unwrap();
        assert_eq!(store.active_segment_id(), 1, "fresh active after fully compacted dir");
        assert!(store.index().is_empty());
        store.append(&rec(12, 128)).unwrap();
        store.sync().unwrap();

        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), 13);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.seq_no, i as u64, "sealed + fresh interleave must stay ordered");
        }

        // Cold point-read straight out of a compressed segment.
        let got = read_record_at(&dir, 0, 0).unwrap();
        assert_eq!(got.seq_no, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 5: a stale `.log.zst` next to a live raw (crash between zst
    /// write and raw removal) must be ignored by every reader — the raw is
    /// authoritative — and never double-counted.
    #[test]
    fn stale_zst_sibling_is_ignored_in_favor_of_raw() {
        let dir = tmpdir("stale-zst");
        let mut store = SegmentStore::open(&dir).unwrap();
        for seq in 0..8u64 {
            store.append(&rec(seq, 96)).unwrap();
        }
        store.sync().unwrap();
        drop(store);

        // Simulate the crash window: compress the raw WITHOUT removing it.
        let raw = std::fs::read(segment_path(&dir, 0)).unwrap();
        let compressed = zstd::stream::encode_all(&raw[..], 3).unwrap();
        std::fs::write(segment_path(&dir, 0).with_extension("log.zst"), &compressed).unwrap();

        // Both readers must see exactly 8 records (raw wins, zst skipped).
        let all = read_index_all(&dir).unwrap();
        assert_eq!(all.len(), 8, "no double-count from the stale sibling");
        let metas = read_meta_all(&dir).unwrap();
        assert_eq!(metas.len(), 8);
        let records = read_all_records(&dir).unwrap();
        assert_eq!(records.len(), 8);

        // Reopen continues on the raw (it is the highest .log).
        let mut store = SegmentStore::open(&dir).unwrap();
        assert_eq!(store.active_segment_id(), 0);
        store.append(&rec(8, 96)).unwrap();
        store.sync().unwrap();
        assert_eq!(read_all_records(&dir).unwrap().len(), 9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 5: read_meta_all must agree with the full decode on every
    /// segment kind (raw, sealed zst WITH sidecar, sealed zst WITHOUT
    /// sidecar) and the fast path must actually skip decompression when a
    /// sidecar exists (validated via the id-free invariant: same output).
    #[test]
    fn read_meta_all_matches_full_scan_with_and_without_sidecar() {
        let dir = tmpdir("meta-fast");
        let mut store = SegmentStore::open_with(
            &dir,
            SegmentConfig { max_segment_bytes: 1024 },
        )
        .unwrap();
        for seq in 0..6u64 {
            store.append(&rec(seq, 96)).unwrap();
        }
        store.sync().unwrap();
        let truth_before = read_meta_all(&dir).unwrap();
        let active = store.active_segment_id();
        assert!(active >= 1, "test needs at least one sealed segment");

        // Compact WITH sidecars.
        let report = crate::compactor::compact_pass(&dir, active, 3).unwrap();
        assert_eq!(report.segments_compacted, active, "every sealed raw compacts");
        let truth_after_sidecar = read_meta_all(&dir).unwrap();
        assert_eq!(truth_before, truth_after_sidecar, "sidecar fast path == full scan");

        // Remove one NON-EMPTY sidecar: the decompress fallback must still
        // agree with the full scan.
        let with_zst = (0..active)
            .find(|&id| segment_path(&dir, id).with_extension("log.zst").exists())
            .expect("a compacted non-empty segment");
        std::fs::remove_file(crate::compactor::idx_path(&dir, with_zst)).unwrap();
        let truth_no_sidecar = read_meta_all(&dir).unwrap();
        assert_eq!(truth_before, truth_no_sidecar);
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_shared_hub_tracks_rotations() {
        let dir = tmpdir("shared-hub");
        let shared = StoreShared::new();
        let rx = shared.subscribe();
        let mut store =
            SegmentStore::open_with_shared(&dir, SegmentConfig { max_segment_bytes: 4 * 1024 }, Arc::clone(&shared))
                .unwrap();
        assert_eq!(*rx.borrow(), 0);
        for seq in 0..40u64 {
            store.append(&rec(seq, 200)).unwrap();
        }
        assert_eq!(shared.active(), store.active_segment_id(), "hub mirrors the store");
        assert!(shared.active() >= 1, "40 records at a 4 KB cap rotate at least once");
        assert_eq!(*rx.borrow(), shared.active());
        assert_eq!(*store.subscribe_active().borrow(), shared.active());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
