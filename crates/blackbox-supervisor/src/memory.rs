//! Memory watermark monitor — tikv-jemallocator heap stats with a
//! /proc/self/status VmRSS fallback (blueprint §4.3, Anti-OOM Shield).
//!
//! Watermark levels mirror the blueprint's 75 / 85 / 95 % budget tiers:
//!
//! | Level        | Action wired in later phases                              |
//! |--------------|-----------------------------------------------------------|
//! | `Warn75`     | shrink egress API cache + read page cache to zero         |
//! | `Shed85`     | head-based adaptive sampling on telemetry ingestion       |
//! | `Backpressure95` | HTTP 429 Retry-After on non-critical telemetry paths |

use std::sync::atomic::{AtomicU8, Ordering};

/// Hard memory budget level (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RamLevel {
    Normal = 0,
    Warn75 = 1,
    Shed85 = 2,
    Backpressure95 = 3,
}

impl RamLevel {
    pub fn from_u8(v: u8) -> RamLevel {
        match v {
            1 => RamLevel::Warn75,
            2 => RamLevel::Shed85,
            3 => RamLevel::Backpressure95,
            _ => RamLevel::Normal,
        }
    }
}

/// Last observed level, shared across the process (engines poll this).
pub static CURRENT_RAM_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Process-wide level hub: every [`RamMonitor::poll`] publishes here, and
/// self-healing subscribers (egress cache purge, head sampling) wake
/// INSTANTLY on the watch channel instead of polling (Phase 4 wiring).
static RAM_HUB: std::sync::OnceLock<tokio::sync::watch::Sender<RamLevel>> =
    std::sync::OnceLock::new();

/// Publish a level to both the atomic mirror and the watch hub.
pub fn publish_ram_level(level: RamLevel) {
    CURRENT_RAM_LEVEL.store(level as u8, Ordering::Relaxed);
    let tx = RAM_HUB.get_or_init(|| tokio::sync::watch::channel(RamLevel::Normal).0);
    let _ = tx.send(level); // Err = no subscribers, fine
}

/// Subscribe to instant RAM-level transitions (watch channel, current value
/// included on subscribe). Multiple subscribers allowed.
pub fn subscribe_ram_level() -> tokio::sync::watch::Receiver<RamLevel> {
    RAM_HUB
        .get_or_init(|| tokio::sync::watch::channel(RamLevel::Normal).0)
        .subscribe()
}

pub fn current_ram_level() -> RamLevel {
    RamLevel::from_u8(CURRENT_RAM_LEVEL.load(Ordering::Relaxed))
}

/// Process RSS in bytes from `/proc/self/status` (VmRSS). Works everywhere,
/// independent of the global allocator.
pub fn rss_bytes() -> u64 {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    // Format: "    12345 kB"
                    let kb: u64 = rest
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                    return kb * 1024;
                }
            }
            0
        }
        Err(_) => 0,
    }
}

/// Precise jemalloc-allocated heap bytes (only meaningful when the process
/// uses tikv-jemallocator as its global allocator). Returns `None` when the
/// stats interface is unavailable.
pub fn jemalloc_allocated_bytes() -> Option<u64> {
    // jemalloc stats are cached — advance the epoch to refresh first.
    let _ = tikv_jemalloc_ctl::epoch::advance();
    tikv_jemalloc_ctl::stats::allocated::read().ok().map(|b| b as u64)
}

/// Best-effort "bytes the allocator is responsible for": jemalloc heap when
/// available, otherwise process RSS.
pub fn used_bytes() -> u64 {
    jemalloc_allocated_bytes().unwrap_or_else(rss_bytes).max(rss_bytes())
}

/// Map a usage figure to a watermark level for a given budget.
pub fn level_for(used: u64, budget: u64) -> RamLevel {
    if budget == 0 {
        return RamLevel::Normal;
    }
    let pct = (used as f64 / budget as f64) * 100.0;
    if pct >= 95.0 {
        RamLevel::Backpressure95
    } else if pct >= 85.0 {
        RamLevel::Shed85
    } else if pct >= 75.0 {
        RamLevel::Warn75
    } else {
        RamLevel::Normal
    }
}

/// Pollable monitor bound to a configured budget.
#[derive(Debug, Clone, Copy)]
pub struct RamMonitor {
    /// Hard memory budget for the whole sidecar (bytes).
    pub budget_bytes: u64,
}

pub struct RamReading {
    pub level: RamLevel,
    pub used_bytes: u64,
    pub rss_bytes: u64,
    pub jemalloc_bytes: Option<u64>,
}

impl RamMonitor {
    pub fn new(budget_bytes: u64) -> Self {
        RamMonitor { budget_bytes }
    }

    /// Sample now and publish the level to [`CURRENT_RAM_LEVEL`] + the hub.
    pub fn poll(&self) -> RamReading {
        let used = used_bytes();
        let level = level_for(used, self.budget_bytes);
        publish_ram_level(level);
        RamReading {
            level,
            used_bytes: used,
            rss_bytes: rss_bytes(),
            jemalloc_bytes: jemalloc_allocated_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermark_tiers() {
        let budget = 100_000u64;
        assert_eq!(level_for(74_999, budget), RamLevel::Normal);
        assert_eq!(level_for(75_000, budget), RamLevel::Warn75);
        assert_eq!(level_for(84_999, budget), RamLevel::Warn75);
        assert_eq!(level_for(85_000, budget), RamLevel::Shed85);
        assert_eq!(level_for(94_999, budget), RamLevel::Shed85);
        assert_eq!(level_for(95_000, budget), RamLevel::Backpressure95);
        assert_eq!(level_for(1_000_000, budget), RamLevel::Backpressure95);
    }

    #[test]
    fn rss_reads_and_poll_publishes() {
        let _guard = LEVEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let rss = rss_bytes();
        assert!(rss > 0, "VmRSS must be readable on linux");
        let mon = RamMonitor::new(512 * 1024 * 1024);
        let reading = mon.poll();
        assert!(reading.used_bytes > 0);
        assert_eq!(reading.level, RamLevel::Normal);
        assert_eq!(current_ram_level(), RamLevel::Normal);
    }

    /// Tests that publish process-global RAM levels must not interleave.
    static LEVEL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn hub_publish_wakes_subscribers_instantly() {
        let _guard = LEVEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut rx = subscribe_ram_level();
        publish_ram_level(RamLevel::Warn75);
        // watch::Receiver::changed resolves as soon as publish happens.
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.changed())
            .await
            .expect("subscriber must wake on publish")
            .expect("hub sender alive");
        assert_eq!(*rx.borrow(), RamLevel::Warn75);
        assert_eq!(current_ram_level(), RamLevel::Warn75);
        publish_ram_level(RamLevel::Normal);
    }
}
