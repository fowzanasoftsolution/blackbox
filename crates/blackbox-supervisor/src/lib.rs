//! # blackbox-supervisor — watchdog & resource watermarks (Phase 1)
//!
//! - [`watchdog`]: parent-process supervisor with 500 ms unix-socket heartbeat,
//!   crash detection, exponential-backoff restarts.
//! - [`memory`]: RAM watermark monitor — tikv-jemallocator heap stats with a
//!   /proc/self/status VmRSS fallback, mapped to 75/85/95 % budget levels.
//! - [`disk`]: statvfs disk watermark monitor enforcing the Storage Ring Quota
//!   (75 % compress, 85 % evict cold, 95 % emergency shed).

pub mod disk;
pub mod memory;
pub mod watchdog;
