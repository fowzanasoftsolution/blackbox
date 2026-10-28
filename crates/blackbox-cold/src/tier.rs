//! The cold tier itself: redb-backed segment sync metadata, seal→S3
//! uploads, evicted-segment restore, bit-rot self-heal, and the
//! crash-pinned eviction classification consumed by
//! `blackbox_core::compactor::evict_cold_tiered`.
//!
//! ## Lifecycle of one segment under Phase 6
//!
//! ```text
//! rotation → sealed raw → compact (zst + .idx) ── janitor wake ──┐
//!                                                                ▼
//!                            sync_sealed(): PUT .zst + .idx (SigV4)
//!                            redb seg_meta: state = SyncedToCold
//!                            redb cold_traces: trace_id → segment id
//!                                                                │
//!      ┌─────────────────────────────────────────────────────────┘
//!      ▼
//! Evict85 (tiered): healthy 2xx-only first · 4xx next · crash/5xx PINNED
//! unsynced segments are NEVER evicted (sync-gated)
//!                                                                │
//!      ▼
//! get_trace / replay on an evicted segment:
//!   redb cold_traces → which segment → GET .zst (+ .idx) → blake3 verify
//!   → atomic re-materialize locally → serve. Caller sees a normal read.
//!
//! bit-rot (flipped byte in a local .zst):
//!   zstd/frame verification fails → GET clean replica → digest check →
//!   atomic replace → retry the read → success. No error escapes.
//! ```

use crate::client::{ColdError, S3Client, S3Config};
use blackbox_core::compactor::{idx_path, load_idx};
use blackbox_core::schema::TraceRecord;
use blackbox_core::StorageError;
use rkyv::{Archive, Deserialize as RkDeserialize, Serialize as RkSerialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SEG_META: redb::TableDefinition<'static, u32, &[u8]> = redb::TableDefinition::new("seg_meta");
const COLD_TRACES: redb::TableDefinition<'static, &[u8], u32> =
    redb::TableDefinition::new("cold_traces");

/// Eviction tiers (lower = evicted first). Unsynced segments return `None`
/// from [`ColdTier::evict_tier`] and are therefore pinned by construction.
pub const TIER_HEALTHY: u8 = 0;
pub const TIER_HAS_4XX: u8 = 1;
pub const TIER_HAS_CRASH_OR_5XX: u8 = 2;

/// Per-segment sync metadata — rkyv-encoded into the redb `seg_meta` table.
#[derive(Debug, Clone, PartialEq, Eq, Archive, RkSerialize, RkDeserialize)]
pub struct SegmentSyncMeta {
    /// BLAKE3 of the sealed `segment_XXXXXX.log.zst` replica.
    pub zst_blake3: [u8; 32],
    pub zst_len: u64,
    /// BLAKE3 of the `segment_XXXXXX.idx` sidecar replica (zeros when the
    /// segment sealed empty and has no `.zst`/`.idx` on the cold tier).
    pub idx_blake3: [u8; 32],
    pub idx_len: u64,
    /// Uncompressed segment size (from the sidecar header).
    pub raw_len: u64,
    /// Frames covered by the sidecar.
    pub frames: u32,
    /// Tiering flags (crash-pinned retention policy).
    pub has_crash: bool,
    pub has_5xx: bool,
    pub has_4xx: bool,
    pub synced_at_ms: u64,
}

impl SegmentSyncMeta {
    /// `true` when this local segment has a full verified replica in S3/R2.
    pub fn synced(&self) -> bool {
        self.zst_len > 0 || self.idx_len > 0
    }
}

/// Cumulative counters surfaced by the admin API and asserted by gates.
#[derive(Debug, Default)]
pub struct ColdStats {
    pub uploads: AtomicU64,
    pub upload_failures: AtomicU64,
    pub bytes_uploaded: AtomicU64,
    pub restores: AtomicU64,
    pub heals: AtomicU64,
    pub corrupt_detected: AtomicU64,
    pub traces_indexed: AtomicU64,
}

/// Snapshot for the admin API / gates.
#[derive(Debug, Clone, Copy, Default)]
pub struct ColdStatsSnapshot {
    pub uploads: u64,
    pub upload_failures: u64,
    pub bytes_uploaded: u64,
    pub restores: u64,
    pub heals: u64,
    pub corrupt_detected: u64,
    pub traces_indexed: u64,
}

pub struct ColdTier {
    s3: Arc<S3Client>,
    /// `Some` until Drop: the private runtime is shut down in the
    /// background (never blocking — and never panicking) even when the
    /// tier is dropped from inside an async context.
    rt: Option<tokio::runtime::Runtime>,
    db: redb::Database,
    stats: Arc<ColdStats>,
}

impl ColdTier {
    /// Drive an OWNED future on the private cold-tier runtime, safely from
    /// ANY thread:
    ///
    /// - outside any runtime (CLI paths, `spawn_blocking`, plain tests) →
    ///   plain `block_on`;
    /// - inside a foreign multi-thread runtime (the node's async workers,
    ///   gate fns) → `tokio::task::block_in_place` + our own runtime handle,
    ///   the sanctioned way to wait without killing the executor.
    ///
    /// Callers MUST pass `'static` futures — every call site clones the
    /// `Arc<S3Client>` and moves keys/buffers in (cheap pointer moves).
    fn run_on_cold_rt<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match tokio::runtime::Handle::try_current() {
            Err(_not_inside_a_runtime) => self.cold_rt().block_on(fut),
            Ok(_foreign) => {
                let cold_handle = self.cold_rt().handle().clone();
                tokio::task::block_in_place(|| cold_handle.block_on(fut))
            }
        }
    }
}

impl Drop for ColdTier {
    fn drop(&mut self) {
        // Dropping a tokio Runtime inline can block (waiting for blocking
        // tasks) and PANICS when the dropping thread is an async worker.
        // shutdown_background hands the shutdown to the background — safe
        // from any context. The redb handle drops right after us and
        // releases the file lock.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl std::fmt::Debug for ColdTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdTier")
            .field("endpoint", &self.s3.config().endpoint)
            .field("bucket", &self.s3.config().bucket)
            .finish()
    }
}

fn seg_name(id: u32) -> String {
    format!("segment_{id:06}.log.zst")
}

fn sidecar_name(id: u32) -> String {
    format!("segment_{id:06}.idx")
}

/// Local artifact path helpers (mirror the compactor's naming).
pub fn local_zst_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(seg_name(id))
}

impl ColdTier {
    /// Open (creating on first use) the cold-tier metadata DB at
    /// `<data_dir>/cold.redb` against the given S3/R2 endpoint.
    pub fn open(cfg: S3Config, data_dir: &Path) -> Result<Arc<ColdTier>, StorageError> {
        std::fs::create_dir_all(data_dir)?;
        let db_path = data_dir.join("cold.redb");
        // v1.1.1: page cache capped at 8 MiB (default is 1 GiB — soak fix #1).
        let db = if db_path.exists() {
            blackbox_core::kv::open_redb(&db_path).map_err(|e| StorageError::Db(e.to_string()))?
        } else {
            blackbox_core::kv::create_redb(&db_path)
                .map_err(|e| StorageError::Db(e.to_string()))?
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("blackbox-cold")
            .enable_all()
            .build()
            .map_err(|e| StorageError::Db(format!("cold runtime: {e}")))?;
        Ok(Arc::new(ColdTier {
            s3: Arc::new(S3Client::new(cfg)),
            rt: Some(rt),
            db,
            stats: Arc::new(ColdStats::default()),
        }))
    }

    fn cold_rt(&self) -> &tokio::runtime::Runtime {
        self.rt.as_ref().expect("runtime present until Drop")
    }

    pub fn stats(&self) -> ColdStatsSnapshot {
        let s = &*self.stats;
        ColdStatsSnapshot {
            uploads: s.uploads.load(Ordering::Relaxed),
            upload_failures: s.upload_failures.load(Ordering::Relaxed),
            bytes_uploaded: s.bytes_uploaded.load(Ordering::Relaxed),
            restores: s.restores.load(Ordering::Relaxed),
            heals: s.heals.load(Ordering::Relaxed),
            corrupt_detected: s.corrupt_detected.load(Ordering::Relaxed),
            traces_indexed: s.traces_indexed.load(Ordering::Relaxed),
        }
    }

    pub fn endpoint(&self) -> String {
        self.s3.config().endpoint.clone()
    }

    pub fn bucket(&self) -> String {
        self.s3.config().bucket.clone()
    }

    // ------------------------------------------------------------- meta --

    fn encode_meta(meta: &SegmentSyncMeta) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(meta)
            .expect("SegmentSyncMeta serializes infallibly")
            .to_vec()
    }

    /// redb AccessGuard slices are NOT 16-byte aligned — copy into an
    /// AlignedVec first (the Phase 1/4 alignment landmine, honored here).
    fn decode_meta(bytes: &[u8]) -> Option<SegmentSyncMeta> {
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let archived =
            rkyv::access::<rkyv::Archived<SegmentSyncMeta>, rkyv::rancor::Error>(&aligned[..]).ok()?;
        rkyv::deserialize::<SegmentSyncMeta, rkyv::rancor::Error>(archived).ok()
    }

    /// Sync metadata for one segment, if it has been synced.
    pub fn seg_state(&self, id: u32) -> Option<SegmentSyncMeta> {
        let read = self.db.begin_read().ok()?;
        let table = read.open_table(SEG_META).ok()?;
        let v = table.get(id).ok().flatten()?;
        Self::decode_meta(v.value())
    }

    /// Which cold segment holds `trace_id` (persisted across evictions AND
    /// restarts — the restart-after-eviction lookup path).
    pub fn cold_segment_of(&self, trace_id: &[u8; 16]) -> Option<u32> {
        let read = self.db.begin_read().ok()?;
        let table = read.open_table(COLD_TRACES).ok()?;
        table.get(trace_id.as_slice()).ok().flatten().map(|g| g.value())
    }

    /// Number of distinct synced segments (admin stats).
    pub fn synced_segment_count(&self) -> u64 {
        use redb::ReadableTable;
        let Ok(read) = self.db.begin_read() else { return 0 };
        let Ok(table) = read.open_table(SEG_META) else { return 0 };
        table.iter().map(|it| it.count() as u64).unwrap_or(0)
    }

    /// Eviction tier of a segment — `None` when the segment is NOT safely
    /// synced (never evict a segment that has no verified cold replica).
    /// Crash / 5xx segments land in the highest tier (pinned longest).
    pub fn evict_tier(&self, id: u32) -> Option<u8> {
        let m = self.seg_state(id)?;
        if !m.synced() {
            return None;
        }
        Some(if m.has_crash || m.has_5xx {
            TIER_HAS_CRASH_OR_5XX
        } else if m.has_4xx {
            TIER_HAS_4XX
        } else {
            TIER_HEALTHY
        })
    }

    // ------------------------------------------------------------- sync --

    /// Upload every sealed `.log.zst` (+ `.idx`) segment that is not yet
    /// recorded as `SyncedToCold`. Idempotent and crash-safe: metadata is
    /// written ONLY after both objects verified-uploaded, so an interrupted
    /// pass simply retries on the next janitor wake.
    ///
    /// Blocks the caller — drive from `spawn_blocking` (the janitor does).
    pub fn sync_sealed(&self, dir: &Path, active_id: u32) -> Result<SyncReport, StorageError> {
        let mut report = SyncReport::default();

        let mut candidates: Vec<u32> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = blackbox_core::segment::parse_segment_zst_name(&name) {
                if id != active_id {
                    candidates.push(id);
                }
            }
        }
        candidates.sort_unstable();

        for id in candidates {
            if self.seg_state(id).is_some() {
                report.already_synced += 1;
                continue;
            }
            let zst_path = local_zst_path(dir, id);
            let zst = match std::fs::read(&zst_path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let idx = match std::fs::read(idx_path(dir, id)) {
                Ok(b) => Some(b),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };

            // Classification straight from the sidecar (no decompression):
            // per-frame status class + kind drive the retention tiers.
            let sidecar = load_idx(dir, id)?;
            let (raw_len, frames, has_crash, has_5xx, has_4xx) = match &sidecar {
                Some((raw_len, entries)) => {
                    let has_crash = entries
                        .iter()
                        .any(|e| e.kind == blackbox_core::segment::KIND_SENTRY);
                    let has_5xx = entries
                        .iter()
                        .any(|e| e.status_class == blackbox_core::segment::CLASS_5XX);
                    let has_4xx = entries
                        .iter()
                        .any(|e| e.status_class == blackbox_core::segment::CLASS_4XX);
                    (*raw_len, entries.len() as u32, has_crash, has_5xx, has_4xx)
                }
                None => (0, 0, false, false, false),
            };

            let zst_digest = blake3::hash(&zst);
            let idx_digest = idx.as_deref().map(blake3::hash);

            // Upload .zst then .idx; record metadata only on full success.
            let zst_key = self.s3.object_key(&seg_name(id));
            let zst_len = zst.len() as u64;
            {
                let s3 = Arc::clone(&self.s3);
                let key = zst_key.clone();
                match self.run_on_cold_rt(async move { s3.put(&key, &zst).await }) {
                    Ok(_) => {
                        self.stats.uploads.fetch_add(1, Ordering::Relaxed);
                        self.stats.bytes_uploaded.fetch_add(zst_len, Ordering::Relaxed);
                    }
                    Err(e) => {
                        self.stats.upload_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(segment = id, error = %e, "cold-tier upload failed; will retry");
                        report.failures += 1;
                        continue;
                    }
                }
            }
            if let Some(idx_bytes) = &idx {
                let idx_key = self.s3.object_key(&sidecar_name(id));
                let idx_len = idx_bytes.len() as u64;
                let s3 = Arc::clone(&self.s3);
                let key = idx_key.clone();
                let bytes = idx_bytes.clone();
                match self.run_on_cold_rt(async move { s3.put(&key, &bytes).await }) {
                    Ok(_) => {
                        self.stats.uploads.fetch_add(1, Ordering::Relaxed);
                        self.stats.bytes_uploaded.fetch_add(idx_len, Ordering::Relaxed);
                    }
                    Err(e) => {
                        self.stats.upload_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(segment = id, error = %e, "cold-tier idx upload failed; will retry");
                        report.failures += 1;
                        continue;
                    }
                }
            }

            let meta = SegmentSyncMeta {
                zst_blake3: *zst_digest.as_bytes(),
                zst_len,
                idx_blake3: idx_digest
                    .as_ref()
                    .map(|d| *d.as_bytes())
                    .unwrap_or([0u8; 32]),
                idx_len: idx.as_ref().map(|b| b.len()).unwrap_or(0) as u64,
                raw_len,
                frames,
                has_crash,
                has_5xx,
                has_4xx,
                synced_at_ms: blackbox_core::schema::now_ms(),
            };

            // One redb txn: seg_meta + per-trace cold index, atomically.
            let write = self.db.begin_write().map_err(|e| StorageError::Db(e.to_string()))?;
            {
                let mut seg = write
                    .open_table(SEG_META)
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                seg.insert(id, Self::encode_meta(&meta).as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                if let Some((_, entries)) = &sidecar {
                    let mut traces = write
                        .open_table(COLD_TRACES)
                        .map_err(|e| StorageError::Db(e.to_string()))?;
                    let mut seen = std::collections::HashSet::new();
                    for e in entries.iter() {
                        if seen.insert(e.trace_id) {
                            traces
                                .insert(e.trace_id.as_slice(), id)
                                .map_err(|e| StorageError::Db(e.to_string()))?;
                            self.stats.traces_indexed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            write.commit().map_err(|e| StorageError::Db(e.to_string()))?;
            report.uploaded += 1;
            tracing::info!(
                segment = id,
                zst_bytes = meta.zst_len,
                idx_bytes = meta.idx_len,
                has_crash = meta.has_crash,
                has_5xx = meta.has_5xx,
                "segment sealed → synced to cold tier (state = SyncedToCold)"
            );
        }
        Ok(report)
    }

    // ---------------------------------------------------------- restore --

    /// GET a replica + verify its BLAKE3 digest against redb metadata.
    /// Owns its inputs so it can run on the cold runtime from any thread.
    async fn fetch_verified(
        s3: Arc<S3Client>,
        key: String,
        expected: [u8; 32],
        expect_len: u64,
    ) -> Result<Vec<u8>, ColdError> {
        let bytes = s3
            .get(&key)
            .await?
            .ok_or_else(|| ColdError::NotFound(key.clone()))?;
        let digest = blake3::hash(&bytes);
        if digest.as_bytes() != &expected {
            return Err(ColdError::DigestMismatch {
                object: key,
                expected: crate::hex::enc(&expected),
                actual: crate::hex::enc(digest.as_bytes()),
            });
        }
        if expect_len != 0 && bytes.len() as u64 != expect_len {
            return Err(ColdError::DigestMismatch {
                object: key,
                expected: format!("len {expect_len}"),
                actual: format!("len {}", bytes.len()),
            });
        }
        Ok(bytes)
    }

    /// Atomically materialize bytes at `path` (tmp file + fsync + rename).
    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        let tmp = path.with_extension("bbcold.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    /// Ensure the segment's `.zst` (+ `.idx`) exist locally and are intact:
    ///
    /// 1. absent locally  → fetch verified replica from the cold tier and
    ///    re-materialize it atomically (transparent time-travel restore),
    /// 2. present but CORRUPT (zstd/frame verification fails, or the
    ///    sidecar is gone while metadata says it should exist) → log a
    ///    self-healing event, fetch the clean replica, atomically replace
    ///    the damaged file,
    /// 3. present and healthy → no-op.
    ///
    /// Returns `Ok(false)` when the segment has no cold replica at all.
    pub fn ensure_segment_local(&self, dir: &Path, id: u32) -> Result<bool, StorageError> {
        let meta = match self.seg_state(id) {
            Some(m) => m,
            None => return Ok(false),
        };

        let zst_path = local_zst_path(dir, id);
        let local_present = zst_path.exists();
        if local_present && self.verify_local_zst(dir, id)? {
            // Healthy locally — but make sure the sidecar is intact too.
            if meta.idx_len == 0 || load_idx(dir, id)?.is_some() {
                return Ok(true);
            }
        }
        if local_present {
            self.stats.corrupt_detected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                segment = id,
                file = %zst_path.display(),
                "SELF-HEALING: local sealed segment corrupt (zstd/frame verification failed); restoring replica from cold tier"
            );
        } else {
            tracing::info!(
                segment = id,
                "segment was evicted locally; transparently restoring from cold tier"
            );
        }

        let s3 = Arc::clone(&self.s3);
        let key = self.s3.object_key(&seg_name(id));
        let zst_bytes = self
            .run_on_cold_rt(Self::fetch_verified(s3, key, meta.zst_blake3, meta.zst_len))
            .map_err(|e| StorageError::Codec(format!("cold restore: {e}")))?;
        Self::atomic_write(&zst_path, &zst_bytes)?;
        if meta.idx_len > 0 {
            let idx_key = self.s3.object_key(&sidecar_name(id));
            let s3 = Arc::clone(&self.s3);
            let idx_bytes = self
                .run_on_cold_rt(Self::fetch_verified(s3, idx_key, meta.idx_blake3, meta.idx_len))
                .map_err(|e| StorageError::Codec(format!("cold restore (idx): {e}")))?;
            Self::atomic_write(&idx_path(dir, id), &idx_bytes)?;
        }
        if !self.verify_local_zst(dir, id)? {
            return Err(StorageError::Codec(format!(
                "cold replica for segment {id} still fails verification after restore"
            )));
        }
        if local_present {
            self.stats.heals.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.restores.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(segment = id, "cold replica restored and verified");
        Ok(true)
    }

    /// Strict local-artifact health check: the `.zst` decompresses AND every
    /// frame parses with valid header/payload CRC32C over the full length
    /// (`scan_frames` walks magic + checksums + bytecheck), and — when
    /// metadata expects one — the `.idx` sidecar loads structurally valid.
    pub fn verify_local_zst(&self, dir: &Path, id: u32) -> Result<bool, StorageError> {
        let path = local_zst_path(dir, id);
        let Ok(compressed) = std::fs::read(&path) else {
            return Ok(false);
        };
        let raw = match zstd::stream::decode_all(&compressed[..]) {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };
        let (valid_len, _, events) = blackbox_core::segment::scan_frames(&raw);
        if valid_len != raw.len() as u64 || !events.is_empty() {
            return Ok(false);
        }
        let meta_present = self.seg_state(id).map(|m| m.idx_len > 0).unwrap_or(false);
        if meta_present && load_idx(dir, id)?.is_none() {
            return Ok(false);
        }
        Ok(true)
    }

    /// High-level primitive shared by `get_trace` (index-miss path) and the
    /// `blackbox replay` CLI: make the segment holding `trace_id` locally
    /// readable (restore if evicted, heal if bit-rotted), then return the
    /// trace's records read from the local artifacts.
    /// `Ok(None)` = the cold tier does not know this trace.
    pub fn restore_trace(&self, dir: &Path, trace_id: &[u8; 16]) -> Result<Option<Vec<TraceRecord>>, StorageError> {
        let Some(seg) = self.cold_segment_of(trace_id) else {
            return Ok(None);
        };
        if !self.ensure_segment_local(dir, seg)? {
            return Ok(None);
        }

        blackbox_core::audit::record(
            "cold",
            "restore",
            &blackbox_core::schema::trace_id_to_hex(trace_id),
            &format!("segment={seg}"),
        );

        // Read the trace's frames straight from the (possibly restored)
        // sidecar — no full-directory rescan.
        let mut records: Vec<TraceRecord> = Vec::new();
        match load_idx(dir, seg)? {
            Some((_raw_len, entries)) => {
                for e in entries
                    .iter()
                    .filter(|e| e.trace_id == *trace_id)
                {
                    match blackbox_core::segment::read_record_at(dir, seg, e.offset) {
                        Ok(r) => records.push(r),
                        Err(err) => {
                            tracing::warn!(segment = seg, offset = e.offset, error = %err,
                                "restored frame unreadable; skipping");
                        }
                    }
                }
            }
            None => {
                // No sidecar: decompress the whole segment and filter.
                let compressed = std::fs::read(local_zst_path(dir, seg))?;
                let raw = zstd::stream::decode_all(&compressed[..])
                    .map_err(|e| StorageError::Codec(format!("zstd decompress failed: {e}")))?;
                blackbox_core::segment::append_records_from(&raw, &mut records)?;
                records.retain(|r| r.trace_id == *trace_id);
            }
        }
        records.sort_by_key(|r| r.seq_no);
        Ok(Some(records))
    }
}

/// One `sync_sealed` pass outcome (admin/gate reporting).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Segments newly uploaded + recorded as SyncedToCold.
    pub uploaded: u32,
    /// Segments already synced (skipped).
    pub already_synced: u32,
    /// Segments whose upload failed this pass (retried next wake).
    pub failures: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock;
    use blackbox_core::compactor::compact_all;
    use blackbox_core::schema::{IngressHttp, RecordPayload, SentryCrash};
    use blackbox_core::segment::{SegmentConfig, SegmentStore};
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("blackbox-cold-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn healthy(tid: [u8; 16], seq: u64) -> TraceRecord {
        let body = "{\"pad\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".repeat(16);
        TraceRecord::new(
            tid,
            seq,
            RecordPayload::IngressHttp(IngressHttp {
                method: "POST".into(),
                uri: "/api/events".into(),
                status: 200,
                req_headers: vec![],
                req_body: body.into_bytes(),
                res_body: b"{\"ok\":true}".to_vec(),
                duration_ms: 2,
            }),
        )
    }

    fn crash(tid: [u8; 16], seq: u64) -> TraceRecord {
        TraceRecord::new(
            tid,
            seq,
            RecordPayload::SentryCrash(SentryCrash {
                project_id: "1".into(),
                event_id: format!("e{seq}"),
                envelope: b"crash".to_vec(),
            }),
        )
    }

    fn tid(n: u64) -> [u8; 16] {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&n.to_be_bytes());
        t
    }

    struct MockCold {
        dir: PathBuf,
        cold: Arc<ColdTier>,
        state: Arc<mock::MockS3State>,
        /// Keeps the mock server's runtime (and its accept loop) alive for
        /// the whole test — dropping a runtime kills its spawned tasks.
        _mock_rt: tokio::runtime::Runtime,
    }

    fn setup(tag: &str) -> MockCold {
        let dir = tmpdir(tag);
        let mut store = SegmentStore::open_with(&dir, SegmentConfig { max_segment_bytes: 4096, ..Default::default() }).unwrap();
        let mut seq = 0u64;
        // Segment 0..4: healthy 2xx only. Segment 5: contains a crash.
        while store.active_segment_id() < 6 {
            let t = tid(seq);
            let record = if store.active_segment_id() == 5 && seq % 2 == 0 {
                crash(t, seq)
            } else {
                healthy(t, seq)
            };
            store.append(&record).unwrap();
            seq += 1;
        }
        store.sync().unwrap();
        let active = store.active_segment_id();
        drop(store);
        compact_all(&dir, active, 3).unwrap();

        // Persistent runtime for the mock server (must outlive setup()).
        let mock_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (addr, state) = mock_rt
            .block_on(mock::spawn_mock_s3(
                "127.0.0.1:0",
                "blackbox-cold-test",
                "test-access",
                "test-secret",
            ))
            .unwrap();
        let cfg = S3Config {
            endpoint: format!("http://{addr}"),
            bucket: "blackbox-cold-test".into(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            prefix: "segments/".into(),
        };
        let cold = ColdTier::open(cfg, &dir).unwrap();
        MockCold { dir, cold, state, _mock_rt: mock_rt }
    }

    #[test]
    fn sync_sealed_records_digests_and_cold_traces() {
        let m = setup("sync-meta");
        let report = m.cold.sync_sealed(&m.dir, 6).unwrap();
        assert!(report.uploaded >= 5, "report {report:?}");
        assert_eq!(report.failures, 0);
        assert!(m.state.put_count() >= 10, "zst + idx per segment");

        let meta = m.cold.seg_state(0).unwrap();
        assert!(meta.synced());
        assert_eq!(meta.has_crash, false);
        assert_eq!(meta.has_5xx, false);
        let local = std::fs::read(local_zst_path(&m.dir, 0)).unwrap();
        assert_eq!(meta.zst_blake3, *blake3::hash(&local).as_bytes());
        assert_eq!(meta.zst_len, local.len() as u64);

        // Crash segment classified.
        let crash_seg = m.cold.seg_state(5).unwrap();
        assert!(crash_seg.has_crash);
        assert_eq!(m.cold.evict_tier(5).unwrap(), TIER_HAS_CRASH_OR_5XX);
        assert_eq!(m.cold.evict_tier(0).unwrap(), TIER_HEALTHY);

        // Cold trace index resolves a trace → its segment.
        let (seg0, _, meta0) = blackbox_core::segment::read_meta_all(&m.dir)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(seg0, 0);
        assert_eq!(m.cold.cold_segment_of(&meta0.trace_id), Some(0));
        assert!(m.cold.cold_segment_of(&[0xAA; 16]).is_none());

        // Idempotent second pass.
        let again = m.cold.sync_sealed(&m.dir, 6).unwrap();
        assert_eq!(again.uploaded, 0);
        assert!(again.already_synced >= 5);
        let _ = std::fs::remove_dir_all(&m.dir);
    }

    #[test]
    fn evicted_segment_restore_serves_trace() {
        let m = setup("restore");
        m.cold.sync_sealed(&m.dir, 6).unwrap();

        // Pick a trace from segment 1, then evict segment 1 locally.
        let (seg, _, meta) = blackbox_core::segment::read_meta_all(&m.dir)
            .unwrap()
            .into_iter()
            .find(|(s, _, _)| *s == 1)
            .unwrap();
        assert_eq!(seg, 1);
        let zst = local_zst_path(&m.dir, 1);
        assert!(zst.exists());
        std::fs::remove_file(&zst).unwrap();
        let _ = std::fs::remove_file(idx_path(&m.dir, 1));

        // The cold tier still knows the trace — and restores + serves it.
        let records = m.cold.restore_trace(&m.dir, &meta.trace_id).unwrap().unwrap();
        assert!(!records.is_empty());
        assert!(records.iter().all(|r| r.trace_id == meta.trace_id));
        assert!(zst.exists(), "segment re-materialized locally");
        assert!(idx_path(&m.dir, 1).exists(), "sidecar restored too");
        assert!(m.cold.stats().restores >= 1);

        // Second call: no new restore (local + healthy).
        let before = m.cold.stats().restores;
        let _ = m.cold.restore_trace(&m.dir, &meta.trace_id).unwrap();
        assert_eq!(m.cold.stats().restores, before);

        let _ = std::fs::remove_dir_all(&m.dir);
    }

    #[test]
    fn bit_rot_auto_heal_replaces_corrupt_zst() {
        let m = setup("heal");
        m.cold.sync_sealed(&m.dir, 6).unwrap();

        // Capture a trace from segment 2 BEFORE corrupting anything.
        let (_seg, _off, meta) = blackbox_core::segment::read_meta_all(&m.dir)
            .unwrap()
            .into_iter()
            .find(|(s, _, _)| *s == 2)
            .unwrap();

        // Corrupt segment 2: flip several seeded bytes inside the .zst.
        let zst = local_zst_path(&m.dir, 2);
        let mut bytes = std::fs::read(&zst).unwrap();
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pos = (state as usize) % bytes.len();
            bytes[pos] ^= 0xFF;
        }
        std::fs::write(&zst, &bytes).unwrap();
        let corrupt_hash = blake3::hash(&bytes);

        // Verification must detect it.
        assert!(!m.cold.verify_local_zst(&m.dir, 2).unwrap());

        // ensure_segment_local detects + heals + verifies.
        assert!(m.cold.ensure_segment_local(&m.dir, 2).unwrap());
        assert!(m.cold.verify_local_zst(&m.dir, 2).unwrap());
        let healed = std::fs::read(&zst).unwrap();
        let seg_meta = m.cold.seg_state(2).unwrap();
        assert_eq!(*blake3::hash(&healed).as_bytes(), seg_meta.zst_blake3, "healed file == cold replica");
        assert_ne!(*blake3::hash(&healed).as_bytes(), *corrupt_hash.as_bytes());
        assert!(m.cold.stats().heals >= 1);
        assert!(m.cold.stats().corrupt_detected >= 1);

        // restore_trace on the healed segment returns valid records.
        let records = m.cold.restore_trace(&m.dir, &meta.trace_id).unwrap().unwrap();
        assert!(!records.is_empty());
        let _ = std::fs::remove_dir_all(&m.dir);
    }

    #[test]
    fn digest_mismatch_rejected_on_tampered_replica() {
        let m = setup("digest");
        m.cold.sync_sealed(&m.dir, 6).unwrap();

        // Corrupt the LOCAL file AND the S3 replica → restore must fail
        // loudly (a poisoned replica must never be served).
        let zst = local_zst_path(&m.dir, 3);
        std::fs::remove_file(&zst).unwrap();
        // Overwrite the object in S3 with garbage via a raw client.
        let cfg = S3Config {
            endpoint: m.cold.endpoint(),
            bucket: m.cold.bucket(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            prefix: "segments/".into(),
        };
        let s3 = S3Client::new(cfg);
        let key = m.cold.s3.object_key(&seg_name(3));
        m.cold
            .run_on_cold_rt(async move { s3.put(&key, b"garbage-not-a-zstd-stream").await })
            .unwrap();

        let result = m.cold.ensure_segment_local(&m.dir, 3);
        assert!(result.is_err(), "digest mismatch must surface, not silently serve");
        let _ = std::fs::remove_dir_all(&m.dir);
    }

    #[test]
    fn unsynced_segments_have_no_tier() {
        let m = setup("tier-gate");
        // Sync only segment 0 by hand? sync_sealed syncs everything; instead
        // open a SECOND cold tier on a fresh redb (nothing synced yet) and
        // check tiering returns None for all ids.
        let cfg = S3Config {
            endpoint: m.cold.endpoint(),
            bucket: m.cold.bucket(),
            region: "us-east-1".into(),
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            prefix: "segments/".into(),
        };
        let dir2 = tmpdir("tier-gate-meta");
        let fresh = ColdTier::open(cfg, &dir2).unwrap();
        for id in 0..6u32 {
            assert!(fresh.evict_tier(id).is_none(), "unsynced segment must be pinned");
        }
        let _ = std::fs::remove_dir_all(&m.dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }
}
