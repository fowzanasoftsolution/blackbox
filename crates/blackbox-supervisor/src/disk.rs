//! Disk watermark monitor — statvfs + Storage Ring Quota enforcement
//! (blueprint §4.2, Disk-Full Emergency Eviction).
//!
//! The sidecar enforces its OWN quota (e.g. 4 GB) rather than waiting for the
//! disk to fill; watermarks map to the blueprint's tiers:
//!
//! | Level       | Action                                                    |
//! |-------------|-----------------------------------------------------------|
//! | `Compress75`| aggressive zstd-9 + S3/R2 upload of warm segments          |
//! | `Evict85`   | delete local cold `.zst` segments already synced to S3     |
//! | `Emergency95`| drop INFO/DEBUG ingestion; keep ERROR + durable queue 100% |

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

/// Hard disk-budget level (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DiskLevel {
    Normal = 0,
    Compress75 = 1,
    Evict85 = 2,
    Emergency95 = 3,
}

impl DiskLevel {
    pub fn from_u8(v: u8) -> DiskLevel {
        match v {
            1 => DiskLevel::Compress75,
            2 => DiskLevel::Evict85,
            3 => DiskLevel::Emergency95,
            _ => DiskLevel::Normal,
        }
    }
}

/// Last observed level, shared across the process.
pub static CURRENT_DISK_LEVEL: AtomicU8 = AtomicU8::new(0);

pub fn current_disk_level() -> DiskLevel {
    DiskLevel::from_u8(CURRENT_DISK_LEVEL.load(Ordering::Relaxed))
}

/// Absolute filesystem numbers from `statvfs(2)`.
#[derive(Debug, Clone, Copy)]
pub struct DiskStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Free bytes available to unprivileged users (bavail * frsize).
    pub available_bytes: u64,
}

/// statvfs via nix — the blueprint's 5-second poll primitive.
pub fn statvfs(path: &Path) -> Result<DiskStats, String> {
    let vfs = nix::sys::statvfs::statvfs(path).map_err(|e| e.to_string())?;
    let frsize: u64 = vfs.fragment_size();
    Ok(DiskStats {
        total_bytes: (vfs.blocks() as u64) * frsize,
        free_bytes: (vfs.blocks_free() as u64) * frsize,
        available_bytes: (vfs.blocks_available() as u64) * frsize,
    })
}

/// Pollable monitor enforcing a Storage Ring Quota over a data directory.
#[derive(Debug, Clone)]
pub struct DiskMonitor {
    /// Directory whose file usage counts against the quota.
    pub dir: std::path::PathBuf,
    /// Max bytes Blackbox may occupy on disk (blueprint: 4 GB default).
    pub quota_bytes: u64,
    /// Absolute last-resort guard: when the FILESYSTEM has fewer free bytes
    /// than this, Emergency95 is forced regardless of the quota ratio.
    /// Default 64 MB; `0` disables the guard (unit tests on packed runners).
    pub min_free_guard_bytes: u64,
}

pub struct DiskReading {
    pub level: DiskLevel,
    /// Bytes used by files under `dir`.
    pub used_bytes: u64,
    /// Quota utilization ratio (0.0-1.0+).
    pub quota_ratio: f64,
    /// Absolute filesystem availability (bytes) — the last-resort guard.
    pub filesystem_available_bytes: u64,
}

impl DiskMonitor {
    pub fn new(dir: std::path::PathBuf, quota_bytes: u64) -> Self {
        DiskMonitor {
            dir,
            quota_bytes,
            min_free_guard_bytes: 64 * 1024 * 1024,
        }
    }

    /// Override the absolute free-space last-resort guard (`0` disables it).
    pub fn with_min_free_guard(mut self, bytes: u64) -> Self {
        self.min_free_guard_bytes = bytes;
        self
    }

    /// Sum of file sizes under `dir` (shallow + recursive; small dirs only —
    /// the segment layout keeps file counts bounded).
    pub fn dir_used_bytes(&self) -> u64 {
        fn walk(p: &Path, total: &mut u64) {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    match e.file_type() {
                        Ok(ft) if ft.is_dir() => walk(&e.path(), total),
                        Ok(_) => {
                            if let Ok(m) = e.metadata() {
                                *total += m.len();
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        let mut total = 0u64;
        walk(&self.dir, &mut total);
        total
    }

    /// Sample now and publish the level to [`CURRENT_DISK_LEVEL`].
    pub fn poll(&self) -> Result<DiskReading, String> {
        let fs_stats = statvfs(&self.dir)?;
        let used = self.dir_used_bytes();
        let ratio = if self.quota_bytes == 0 {
            0.0
        } else {
            used as f64 / self.quota_bytes as f64
        };
        let level = if ratio >= 0.95 || fs_stats.available_bytes < self.min_free_guard_bytes {
            DiskLevel::Emergency95
        } else if ratio >= 0.85 {
            DiskLevel::Evict85
        } else if ratio >= 0.75 {
            DiskLevel::Compress75
        } else {
            DiskLevel::Normal
        };
        CURRENT_DISK_LEVEL.store(level as u8, Ordering::Relaxed);
        Ok(DiskReading {
            level,
            used_bytes: used,
            quota_ratio: ratio,
            filesystem_available_bytes: fs_stats.available_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statvfs_reads_root() {
        let stats = statvfs(Path::new("/")).expect("statvfs /");
        assert!(stats.total_bytes > 0);
        assert!(stats.available_bytes <= stats.free_bytes);
    }

    #[test]
    fn quota_watermarks() {
        let dir = std::env::temp_dir().join(format!("bb-disk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // The absolute-FS guard depends on the RUNNER's free space, not on
        // the quota tiers under test — disable it here (the guard itself is
        // exercised in production via the 64 MB default).
        let mon = DiskMonitor::new(dir.clone(), 1000).with_min_free_guard(0);
        // Empty dir → Normal.
        let r = mon.poll().unwrap();
        assert_eq!(r.level, DiskLevel::Normal);

        // 900 bytes = 90% of quota → Evict85.
        std::fs::write(dir.join("a.bin"), vec![0u8; 900]).unwrap();
        let r = mon.poll().unwrap();
        assert_eq!(r.used_bytes, 900);
        assert_eq!(r.level, DiskLevel::Evict85);

        // 980 bytes = 98% → Emergency95.
        std::fs::write(dir.join("b.bin"), vec![0u8; 80]).unwrap();
        let r = mon.poll().unwrap();
        assert_eq!(r.level, DiskLevel::Emergency95);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
