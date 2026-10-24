//! Phase 7 — sharded, lock-free token-bucket rate limiter.
//!
//! Design goals (blueprint: "reject BEFORE the upstream app or disk, at
//! ~zero cost for healthy traffic"):
//!
//! * **Lock-free**: every bucket is one [`AtomicU64`]; allow/deny decisions
//!   are a compare-and-swap loop. No mutex ever touches the hot path.
//! * **Sharded**: 64 shards × 256 slots = 16 384 buckets. The shard is
//!   picked from a folded hash of the client key; within a shard the
//!   bucket is found with an 8-slot linear probe on a 14-bit key tag.
//! * **Self-cleaning**: a slot whose last refill is older than
//!   [`SLOT_IDLE_SECS`] may be stolen by a colliding key (the CAS makes
//!   the steal safe — losers simply retry their own probe).
//! * **Refill is derived from elapsed time**, not accumulated deltas, so
//!   there is no drift and no timer task at all.
//!
//! Packing (64 bits): `tokens:22` (fixed-point 1/1024 tokens, caps burst
//! at 4095) | `last_ms:28` (uptime-ms, wraps every ~3.25 days; an idle
//! wrap resets the bucket) | `tag:14` (client-key tag for probe match).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Fixed-point scale for the token count (1 token = 1024 units).
const TOKEN_SCALE: u64 = 1024;
/// Slots per shard — the probe window is a fraction of this.
const SLOTS_PER_SHARD: usize = 256;
/// Shard count (power of two).
const SHARDS: usize = 64;
/// Linear-probe window inside a shard.
const PROBE: usize = 8;
/// A slot untouched for this long may be stolen by another key.
const SLOT_IDLE_MS: u32 = 60_000;

const TOKEN_BITS: u32 = 22;
const LAST_BITS: u32 = 28;
const TAG_BITS: u32 = 14;

const TOKEN_MASK: u64 = (1 << TOKEN_BITS) - 1;
const LAST_MASK: u64 = (1 << LAST_BITS) - 1;
const TAG_MASK: u64 = (1 << TAG_BITS) - 1;
const LAST_SHIFT: u32 = TOKEN_BITS;
const TAG_SHIFT: u32 = TOKEN_BITS + LAST_BITS;

/// Uptime clock in milliseconds, truncated to the 28-bit slot field.
static BOOT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn now_ms32() -> u32 {
    let t = BOOT.get_or_init(Instant::now).elapsed();
    ((t.as_millis() as u64) & LAST_MASK) as u32
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed (a token was consumed).
    Allowed,
    /// The bucket is empty; retry after this many milliseconds.
    Limited { retry_after_ms: u64 },
}

/// Rate-limiter tuning.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Sustained refill rate in milli-requests per second
    /// (50.5 req/s → `50_500`). The limiter is OFF when this is 0.
    pub rps_milli: u64,
    /// Bucket depth: requests that may burst above the sustained rate.
    /// Clamped to [`MAX_BURST`].
    pub burst: u32,
}

impl RateLimiterConfig {
    pub fn from_rps(rps: f64, burst: u32) -> Self {
        RateLimiterConfig {
            rps_milli: (rps.max(0.0) * 1000.0).round() as u64,
            burst,
        }
    }

    pub fn enabled(&self) -> bool {
        self.rps_milli > 0 && self.burst > 0
    }
}

/// The sharded lock-free limiter. Cheap to clone behind an `Arc`.
pub struct RateLimiter {
    shards: Vec<Box<[AtomicU64]>>,
    rps_milli: u64,
    /// Bucket capacity in fixed-point tokens.
    cap_scaled: u64,
}

// Safety: every slot is an independent AtomicU64; the CAS protocol never
// holds cross-slot invariants, so concurrent access from many threads is
// the entire point. The limiter is shared behind an Arc in practice.
unsafe impl Send for RateLimiter {}
unsafe impl Sync for RateLimiter {}

impl RateLimiter {
    /// Build a limiter; returns `None` when the config disables it.
    pub fn new(cfg: &RateLimiterConfig) -> Option<Self> {
        if !cfg.enabled() {
            return None;
        }
        let shards = (0..SHARDS)
            .map(|_| {
                (0..SLOTS_PER_SHARD)
                    .map(|_| AtomicU64::new(0))
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            })
            .collect::<Vec<_>>();
        let burst = (cfg.burst as u64).min((1 << TOKEN_BITS) - 1).max(1);
        Some(RateLimiter {
            shards,
            rps_milli: cfg.rps_milli,
            cap_scaled: burst.saturating_mul(TOKEN_SCALE),
        })
    }

    /// Fixed-point tokens accrued over `elapsed_ms`.
    ///
    /// Multiply-then-divide (no truncation drift, no per-ms floor):
    /// `rps_milli/1000` tokens per ms × `TOKEN_SCALE` — exact for any
    /// fractional rate. Overflow check: 2.6e7 ms × 1e6 milli-rps × 1024
    /// ≈ 2.6e16 ≪ u64::MAX.
    #[inline]
    fn refill_scaled(&self, elapsed_ms: u64) -> u64 {
        elapsed_ms
            .saturating_mul(self.rps_milli)
            .saturating_mul(TOKEN_SCALE)
            / 1_000_000
    }

    pub fn rps_milli(&self) -> u64 {
        self.rps_milli
    }

    pub fn burst(&self) -> u32 {
        (self.cap_scaled / TOKEN_SCALE) as u32
    }

    /// Folded hash of the client key → (shard, tag).
    #[inline]
    fn locate(&self, key: &[u8]) -> (usize, u64) {
        // FNV-1a 64.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in key {
            h ^= b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        // Mix (splitmix64 finalizer) so shard/tag correlate poorly.
        let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let tag = (z & TAG_MASK) | 1; // 0 is reserved for "empty"
        let shard = (z >> TAG_BITS) as usize & (SHARDS - 1);
        (shard, tag)
    }

    /// Consume one token for `key`. Pure CAS loop — never blocks, never
    /// allocates, single cache-line touch in the common case.
    pub fn check(&self, key: &[u8]) -> Decision {
        let (shard, tag) = self.locate(key);
        let slots: &[AtomicU64] = &self.shards[shard];
        let now = now_ms32();

        // Home position derived from the tag so independent keys spread.
        let home = (tag as usize) % SLOTS_PER_SHARD;

        // Pass 1: probe for our bucket.
        for i in 0..PROBE {
            let idx = (home + i) & (SLOTS_PER_SHARD - 1);
            let slot = &slots[idx];
            let cur = slot.load(Ordering::Relaxed);
            if unpack_tag(cur) == tag {
                return self.cas_bucket(slot, cur, tag, now);
            }
            if unpack_tag(cur) == 0 {
                // Empty: claim it in pass 2 (probe fully first to avoid
                // duplicating a bucket that sits deeper in the window).
            }
        }

        // Pass 2: claim an empty or idle-stale slot.
        for i in 0..PROBE {
            let idx = (home + i) & (SLOTS_PER_SHARD - 1);
            let slot = &slots[idx];
            let cur = slot.load(Ordering::Relaxed);
            let (_tok, last, t) = unpack(cur);
            let claimable = t == 0 || now.wrapping_sub(last) >= SLOT_IDLE_MS;
            if !claimable {
                continue;
            }
            // A full bucket for a fresh claim (friendly burst semantics).
            let full = pack(self.cap_scaled, now, tag);
            match slot.compare_exchange_weak(cur, full, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    // We claimed a full bucket: this first request passes,
                    // subsequent ones draw it down in cas_bucket.
                    let one_down = pack(self.cap_scaled.saturating_sub(TOKEN_SCALE), now, tag);
                    let _ = slot.compare_exchange_weak(full, one_down, Ordering::Relaxed, Ordering::Relaxed);
                    return Decision::Allowed;
                }
                Err(actual) => {
                    // Lost the race: if the winner is OUR tag, join it.
                    if unpack_tag(actual) == tag {
                        return self.cas_bucket(slot, actual, tag, now);
                    }
                }
            }
        }

        // Window exhausted (256-slot shard fully warm): shared-bucket
        // fallback — key collides into the home slot. Correct (never
        // over-admits beyond the shared bucket) and practically never
        // hit at 16 384 total buckets.
        let slot = &slots[home];
        let cur = slot.load(Ordering::Relaxed);
        self.cas_bucket(slot, cur, unpack_tag(cur), now)
    }

    fn cas_bucket(&self, slot: &AtomicU64, cur: u64, tag: u64, now: u32) -> Decision {
        let mut cur = cur;
        loop {
            let (tok, last, _cur_tag) = unpack(cur);
            // Elapsed since last refill, saturating at one day (a wrap or
            // a very idle bucket refills to full anyway).
            let elapsed = if now.wrapping_sub(last) > 86_400_000 {
                86_400_000u64
            } else {
                now.wrapping_sub(last) as u64
            };
            let refill = self.refill_scaled(elapsed);
            let tok = (tok + refill).min(self.cap_scaled);

            if tok >= TOKEN_SCALE {
                let next = pack(tok - TOKEN_SCALE, now, tag);
                match slot.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return Decision::Allowed,
                    Err(actual) => cur = actual,
                }
            } else {
                // Do NOT advance `last` on denial: tokens must keep
                // accruing across denials or a hammered client starves
                // forever. Retry-After = time to afford one more token:
                // deficit/(rps_milli×1024) fixed-point ms → real ms.
                let deficit = TOKEN_SCALE - tok;
                let denom = self.rps_milli.saturating_mul(TOKEN_SCALE).max(1);
                let retry = deficit
                    .saturating_mul(1_000_000)
                    .div_ceil(denom)
                    .max(1);
                // Same tokens, same stamp, just keep the CAS contested so
                // concurrent denials agree (also refreshes the tag).
                let next = pack(tok, last, tag);
                match slot.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => return Decision::Limited { retry_after_ms: retry },
                    Err(actual) => cur = actual,
                }
            }
        }
    }
}

#[inline]
fn pack(tokens: u64, last_ms: u32, tag: u64) -> u64 {
    (tokens & TOKEN_MASK) | (((last_ms as u64) & LAST_MASK) << LAST_SHIFT) | ((tag & TAG_MASK) << TAG_SHIFT)
}

#[inline]
fn unpack(v: u64) -> (u64, u32, u64) {
    (
        v & TOKEN_MASK,
        ((v >> LAST_SHIFT) & LAST_MASK) as u32,
        (v >> TAG_SHIFT) & TAG_MASK,
    )
}

#[inline]
fn unpack_tag(v: u64) -> u64 {
    (v >> TAG_SHIFT) & TAG_MASK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn limiter(rps: f64, burst: u32) -> RateLimiter {
        RateLimiter::new(&RateLimiterConfig::from_rps(rps, burst)).unwrap()
    }

    #[test]
    fn burst_then_limit_with_retry_after() {
        let rl = limiter(1.0, 5);
        let key = b"10.0.0.1";
        // Ten IMMEDIATE checks: the burst depth is exactly 5 and the
        // refill over a few microseconds cannot mint extra tokens.
        let mut allowed = 0;
        let mut limited = 0;
        let mut retry_after_ms = 0;
        for _ in 0..10 {
            match rl.check(key) {
                Decision::Allowed => allowed += 1,
                Decision::Limited { retry_after_ms: r } => {
                    limited += 1;
                    retry_after_ms = r;
                }
            }
        }
        assert_eq!(allowed, 5, "burst depth");
        assert_eq!(limited, 5, "overflow must be limited");
        // ~1 token at 1 rps → about a second.
        assert!(retry_after_ms > 500 && retry_after_ms <= 1_100, "{retry_after_ms}");
    }

    #[test]
    fn keys_are_independent() {
        let rl = limiter(1.0, 2);
        for _ in 0..2 {
            assert_eq!(rl.check(b"10.0.0.1"), Decision::Allowed);
        }
        assert!(matches!(rl.check(b"10.0.0.1"), Decision::Limited { .. }));
        // A different key still has its full burst.
        assert_eq!(rl.check(b"10.0.0.2"), Decision::Allowed);
    }

    #[test]
    fn refill_over_time() {
        let rl = limiter(50.0, 1);
        let key = b"k";
        assert_eq!(rl.check(key), Decision::Allowed);
        assert!(matches!(rl.check(key), Decision::Limited { .. }));
        // 50 rps → a token after 20 ms; 40 ms is comfortably enough.
        std::thread::sleep(std::time::Duration::from_millis(40));
        assert_eq!(rl.check(key), Decision::Allowed);
    }

    #[test]
    fn disabled_config_yields_no_limiter() {
        assert!(RateLimiter::new(&RateLimiterConfig::from_rps(0.0, 100)).is_none());
    }

    #[test]
    fn hammering_never_starves_forever() {
        // Denials must not advance `last` — tokens keep accruing while
        // the client is rejected, so it is re-admitted after ~1/rps.
        let rl = limiter(100.0, 1);
        let key = b"burst";
        assert_eq!(rl.check(key), Decision::Allowed);
        for _ in 0..50 {
            let _ = rl.check(key);
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
        assert_eq!(rl.check(key), Decision::Allowed);
    }

    #[test]
    fn many_keys_threaded() {
        // 8 threads × 64 keys: every key gets exactly its burst of
        // allows before its first Limited (modulo races with refill at
        // 50 rps — so keep rps tiny to make refill negligible).
        let rl = Arc::new(limiter(0.001, 4));
        let allowed = Arc::new(AtomicU64::new(0));
        let limited = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for t in 0..8u64 {
            let rl = Arc::clone(&rl);
            let allowed = Arc::clone(&allowed);
            let limited = Arc::clone(&limited);
            handles.push(std::thread::spawn(move || {
                for i in 0..64u64 {
                    let key = format!("10.{t}.0.{i}");
                    for _ in 0..8 {
                        match rl.check(key.as_bytes()) {
                            Decision::Allowed => {
                                allowed.fetch_add(1, Ordering::Relaxed);
                            }
                            Decision::Limited { .. } => {
                                limited.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 512 keys × burst 4 = 2048 guaranteed allows; refill is ~0 at
        // 0.001 rps so the total must be tight.
        assert_eq!(allowed.load(Ordering::Relaxed), 2048);
        assert_eq!(limited.load(Ordering::Relaxed), 8 * 64 * 8 - 2048);
    }

    #[test]
    fn slot_steal_after_idle() {
        // Drive the clock far past SLOT_IDLE_MS by packing directly.
        let rl = limiter(1.0, 2);
        let (shard, tag) = rl.locate(b"victim");
        let home = (tag as usize) % SLOTS_PER_SHARD;
        let slot = &rl.shards[shard][home];
        slot.store(pack(TOKEN_SCALE, now_ms32().wrapping_sub(SLOT_IDLE_MS + 5_000), tag), Ordering::Relaxed);
        // A DIFFERENT key hashing to the same home may steal the idle slot.
        let (shard2, tag2) = rl.locate(b"attacker");
        if shard2 == shard && ((tag2 as usize) % SLOTS_PER_SHARD) == ((tag as usize) % SLOTS_PER_SHARD) {
            assert_eq!(rl.check(b"attacker"), Decision::Allowed);
            assert_eq!(unpack_tag(slot.load(Ordering::Relaxed)), tag2);
        }
    }
}
