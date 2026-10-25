//! Storage lifecycle janitor: disk ring-quota wiring and reaction.

use blackbox_core::compactor::{CompactorStats, DEFAULT_COMPRESS_LEVEL};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Spawn the storage janitor. Reacts to segment rotations (watch) and a
/// 2 s tick: publishes disk watermarks, compresses warm segments at 75 %,
/// FIFO-evicts the oldest cold `.zst` at 85 % (down to 80 % of quota).
/// Emergency95 shedding happens inline in the ingress Finalizer.
pub fn spawn_storage_janitor(
    dir: PathBuf,
    mut active: tokio::sync::watch::Receiver<u32>,
    disk: Arc<blackbox_supervisor::disk::DiskMonitor>,
    stats: Arc<CompactorStats>,
    cold: Option<Arc<blackbox_cold::ColdTier>>,
) -> tokio::task::JoinHandle<()> {
    use blackbox_supervisor::disk::DiskLevel;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_logged = DiskLevel::Normal;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = active.changed() => {}
            }
            let Ok(reading) = disk.poll() else { continue };
            if reading.level != last_logged {
                tracing::warn!(
                    level = ?reading.level,
                    used = reading.used_bytes,
                    quota = disk.quota_bytes,
                    "disk watermark transition"
                );
                last_logged = reading.level;
            }
            let active_id = *active.borrow();

            // Background compaction runs on EVERY wake (rotation or 2 s
            // tick): sealed segments are immutable, so compressing them is
            // always safe and a pass over an already-clean dir is one
            // read_dir. The disk watermarks only escalate urgency (75%
            // forces an immediate full pass; here the normal cadence keeps
            // the backlog near zero).
            {
                let d = dir.clone();
                let r = tokio::task::spawn_blocking(move || {
                    blackbox_core::compactor::compact_all(&d, active_id, DEFAULT_COMPRESS_LEVEL)
                })
                .await;
                if let Ok(Ok(rep)) = r {
                    if rep.segments_compacted > 0 || rep.stale_zst_removed > 0 {
                        stats.compactions.fetch_add(rep.segments_compacted as u64, Ordering::Relaxed);
                        stats.bytes_saved.fetch_add(rep.bytes_saved, Ordering::Relaxed);
                        stats.frames_indexed.fetch_add(rep.frames_indexed, Ordering::Relaxed);
                        tracing::info!(
                            segments = rep.segments_compacted,
                            saved = rep.bytes_saved,
                            level = ?reading.level,
                            "compacted sealed segments"
                        );
                    }
                }
            }

            // Sealed segments flow to the S3/R2 cold tier right after
            // compaction (sync-before-evict is enforced by the tier
            // classifier itself: unsynced segments are pinned).
            if let Some(cold) = &cold {
                let c = Arc::clone(cold);
                let d = dir.clone();
                if let Ok(Ok(rep)) =
                    tokio::task::spawn_blocking(move || c.sync_sealed(&d, active_id)).await
                {
                    if rep.uploaded > 0 || rep.failures > 0 {
                        tracing::info!(
                            uploaded = rep.uploaded,
                            failed = rep.failures,
                            "cold-tier sync pass"
                        );
                    }
                }
            }

            // 85%: evict cold .zst segments down to 80% of quota. With the
            // cold tier attached this is TIERED (healthy 2xx-only first,
            // 4xx next, crash/5xx pinned longest; unsynced never evicted);
            // without it, plain FIFO.
            if reading.level >= DiskLevel::Evict85 {
                let target = reading
                    .used_bytes
                    .saturating_sub(disk.quota_bytes / 5 * 4);
                if target > 0 {
                    let d = dir.clone();
                    let result = match &cold {
                        Some(c) => {
                            let c = Arc::clone(c);
                            tokio::task::spawn_blocking(move || {
                                let tier_of = move |id: u32| c.evict_tier(id);
                                blackbox_core::compactor::evict_cold_tiered(&d, target, &tier_of)
                            })
                            .await
                        }
                        None => tokio::task::spawn_blocking(move || {
                            blackbox_core::compactor::evict_cold_fifo(&d, target)
                        })
                        .await,
                    };
                    if let Ok(Ok((n, freed))) = result {
                        if n > 0 {
                            stats.evictions.fetch_add(n as u64, Ordering::Relaxed);
                            tracing::warn!(removed = n, freed, "disk 85%: evicted cold .zst segments");
                        }
                    }
                }
            }
            // Emergency95: no extra janitor action — CURRENT_DISK_LEVEL is
            // published by poll() and the ingress Finalizer sheds healthy
            // 200-OK telemetry (SentryCrash/5xx/queue preserved).
        }
    })
}
