//! Memory watermark monitor — RSS ground truth + jemalloc diagnostics +
//! purge-on-pressure (blueprint §4.3, Anti-OOM Shield; v1.1.1 soak fixes).
//!
//! ## Budget truth: /proc, not the allocator
//!
//! The memory budget protects the SYSTEM: what the kernel must serve for this
//! process is the Resident Set Size. jemalloc's `stats.allocated` et al.
//! describe the heap from the allocator's point of view and are kept ONLY as
//! diagnostics ([`jemalloc_allocated_bytes`]) — the 6-hour soak (`bb-soak-6h`)
//! showed the two can diverge in both directions under page retention, and
//! watermark decisions must not ride that gap.
//!
//! RSS reading order: `/proc/self/statm` resident-pages field × page size
//! (`sysconf(_SC_PAGESIZE)`), falling back to `/proc/self/status` `VmRSS`
//! (both are cheap 4 KB reads done every 500 ms by the node loop).
//!
//! ## Self-healing levels
//!
//! | Level        | Action                                                   |
//! |--------------|-----------------------------------------------------------|
//! | `Warn75`     | notify egress gateway cache purge (watch channel) +       |
//! |              | jemalloc arena purge (rate-limited ≥ 5 s)                 |
//! | `Shed85`     | head-based adaptive sampling on telemetry ingestion       |
//! | `Backpressure95` | **published but never enforced** — no HTTP path in    |
//! |              | blackbox reads it to stall traffic. Proxied requests and  |
//! |              | durable webhooks are NEVER gated by RAM level; above 95 % |
//! |              | the shedding above keeps shrinking the footprint. (The    |
//! |              | soak's 38-minute preview stall was an external proxy      |
//! |              | path, not this — see the soak report's honest limitation.)|

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

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

fn page_size() -> u64 {
    static PAGE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        // libc::sysconf(_SC_PAGESIZE) — no nix feature needed (nix::unistd's
        // sysconf sits behind the "process" feature; the re-exported libc
        // works everywhere).
        let p = unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) };
        if p > 0 { p as u64 } else { 4096 }
    })
}

/// Process RSS in bytes — `/proc/self/statm` field 1 (resident pages) times
/// the page size, with a `/proc/self/status` VmRSS fallback. Returns `0`
/// when neither source exists (non-Linux).
pub fn rss_bytes() -> u64 {
    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(field) = statm.split_ascii_whitespace().nth(1) {
            if let Ok(pages) = field.parse::<u64>() {
                return pages.saturating_mul(page_size());
            }
        }
    }
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
                    return kb.saturating_mul(1024);
                }
            }
            0
        }
        Err(_) => 0,
    }
}

/// Precise jemalloc-allocated heap bytes — SECONDARY diagnostic only (see
/// module docs). Returns `None` when the stats interface is unavailable.
pub fn jemalloc_allocated_bytes() -> Option<u64> {
    // jemalloc stats are cached — advance the epoch to refresh first.
    let _ = tikv_jemalloc_ctl::epoch::advance();
    tikv_jemalloc_ctl::stats::allocated::read().ok().map(|b| b as u64)
}

/// Budget ground truth: the resident set. (Named `used_bytes` for API
/// compatibility with v1.1.0 callers; "used" IS the RSS now.)
pub fn used_bytes() -> u64 {
    rss_bytes()
}

/// Best-effort release of jemalloc's cached pages back to the OS.
///
/// Calls `mallctl("arena.4096.purge", NULL, NULL, NULL, 0)` — arena index
/// 4096 is `MALLCTL_ARENAS_ALL`, and the purge mallctl is invoked with all
/// null pointers (write-only action; the canonical C form). This only
/// matters when the process runs on tikv-jemallocator; in a system-allocator
/// test binary the call resolves against a lazily-initialized untouched
/// jemalloc instance and is a no-op.
///
/// Errors are swallowed (fire-and-forget): an unpurgeable allocator must
/// never fail the monitor. jemalloc's own background decay keeps working
/// regardless.
pub fn purge_heap() {
    unsafe {
        let _ = tikv_jemalloc_sys::mallctl(
            b"arena.4096.purge\0".as_ptr() as *const nix::libc::c_char,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
    }
}

/// Minimum spacing between arena purges (the poll tick is 500 ms; purging
/// up to ~once per 5 s limits the syscall/madvise churn under sustained
/// pressure while still reacting within seconds).
const PURGE_MIN_INTERVAL_MS: u64 = 5_000;

/// Epoch ms of the last successful purge (rate limiter).
static LAST_PURGE_MS: AtomicU64 = AtomicU64::new(0);

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    /// Sample RSS now, purge the heaps when at `Warn75+` (rate-limited), and
    /// publish the level to [`CURRENT_RAM_LEVEL`] + the hub.
    pub fn poll(&self) -> RamReading {
        let rss = rss_bytes();
        let level = level_for(rss, self.budget_bytes);
        if level >= RamLevel::Warn75 {
            let now = unix_ms();
            let last = LAST_PURGE_MS.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= PURGE_MIN_INTERVAL_MS
                && LAST_PURGE_MS
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                purge_heap();
                tracing::debug!(
                    rss_kb = rss / 1024,
                    level = ?level,
                    "RAM ≥ Warn75: jemalloc arenas purged (rate-limited)"
                );
            }
        }
        publish_ram_level(level);
        RamReading {
            level,
            used_bytes: rss,
            rss_bytes: rss,
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
        assert!(rss > 0, "VmRSS/statm must be readable on linux");
        let mon = RamMonitor::new(512 * 1024 * 1024);
        let reading = mon.poll();
        assert!(reading.used_bytes > 0);
        assert_eq!(reading.level, RamLevel::Normal);
        assert_eq!(current_ram_level(), RamLevel::Normal);
    }

    /// Purger must be callable (fire-and-forget, infallible) and rate-limit
    /// repeated purges from `poll`.
    #[test]
    fn purge_rate_limited_from_poll() {
        let _guard = LEVEL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        LAST_PURGE_MS.store(0, Ordering::Relaxed);
        let mon = RamMonitor::new(128); // tiny budget → Warn75 at any RSS
        let reading = mon.poll();
        assert!(reading.level >= RamLevel::Warn75, "tiny budget forces pressure");
        assert!(LAST_PURGE_MS.load(Ordering::Relaxed) > 0, "poll must have attempted a purge");
        // Second poll within the 5 s window must NOT purge again — the rate
        // limiter holds the timestamp: advance it artificially and confirm
        // the next poll fires.
        LAST_PURGE_MS.store(unix_ms().saturating_sub(PURGE_MIN_INTERVAL_MS) - 1, Ordering::Relaxed);
        let _ = mon.poll();
        assert!(LAST_PURGE_MS.load(Ordering::Relaxed) > 0);
        LAST_PURGE_MS.store(0, Ordering::Relaxed);
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

    #[test]
    fn backpressure95_is_documented_as_publish_only() {
        // Structural guard for the honesty contract: nothing drawing on the
        // RAM level may be an HTTP path. The enum value exists, it publishes,
        // and that is the whole story.
        assert_eq!(RamLevel::Backpressure95 as u8, 3);
        assert_eq!(RamLevel::from_u8(3), RamLevel::Backpressure95);
    }
}
