//! Durable job model — the lease-based delivery state machine.
//!
//! ```text
//!  enqueue ──► Pending ──claim(lease)──► InFlight ──2xx──► Delivered (row deleted)
//!                ▲                          │
//!                │ reap expired lease       ├─429/5xx/connect──► Pending (backoff+jitter)
//!                │ or dispatch failure      │
//!                └──────────────────── DeadLetter ◄──attempt >= max── (full payload
//!                                        ▲                        retained for
//!                              other 4xx ┘                        1-click retry)
//! ```
//!
//! ## Raw-byte preservation (HMAC safety)
//!
//! [`DurableJob::headers`] and [`DurableJob::body`] hold the **exact, unmodified**
//! request bytes as received from the caller. The PII scrubber is NEVER run on
//! these fields — Stripe/Shopify/GitHub HMAC signature verification on the user's
//! app would fail if a single byte changed. Scrubbing happens only on the
//! telemetry copy handed to the SegmentStore (see the ingress durable route).
//!
//! ## Adaptive backoff (full jitter, AWS style)
//!
//! `delay = uniform(0, min(base * 2^failed_attempts, max))` — full jitter spreads
//! retry storms out instead of synchronizing them into thundering herds.

use blackbox_core::schema::{now_ms, TraceId};

/// Durable job id (monotonic u128 from `blackbox_core::schema::new_id128`).
pub type JobId = u128;

/// Lease-based job lifecycle state (persisted in redb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum JobState {
    /// Waiting for `available_at_ms`; picked up by the dispatcher.
    Pending,
    /// Claimed by a delivery attempt; protected by `lease_until_ms`.
    InFlight,
    /// Delivered with 2xx — the row is deleted (retained in stats only).
    Delivered,
    /// Exhausted `max_attempts` or rejected with a permanent 4xx.
    DeadLetter,
}

/// A durable webhook / workflow job. Serialized with rkyv into the redb
/// `bq_jobs` table.
#[derive(Debug, Clone, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DurableJob {
    pub job_id: JobId,
    /// Trace id of the original ingest request (0s when the caller sent no
    /// correlation context) — deliveries and telemetry stay causally linked.
    pub trace_id: TraceId,
    /// Logical queue derived from the route, e.g. `webhooks.stripe`.
    pub queue: String,
    /// HTTP method for delivery (usually the ingest method).
    pub method: String,
    /// Path + query to deliver at the upstream app (e.g. `/webhooks/stripe`).
    pub url_path: String,
    /// **Raw, unscrubbed** request headers (HMAC safety — see crate docs).
    pub headers: Vec<(String, String)>,
    /// **Raw, unscrubbed** request body bytes (HMAC safety — see crate docs).
    pub body: Vec<u8>,
    /// Idempotency key (`Idempotency-Key` / `X-GitHub-Delivery` /
    /// `Stripe-Signature`), empty when the caller supplied none.
    pub idem_key: String,
    pub state: JobState,
    /// Number of FAILED delivery attempts so far.
    pub attempt: u32,
    /// Dead-letter after this many failed attempts.
    pub max_attempts: u32,
    /// While InFlight: dispatch lease expiry (reaper recovers on crash).
    pub lease_until_ms: u64,
    /// Earliest next dispatch time (backoff with jitter).
    pub available_at_ms: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
    /// Last upstream HTTP status (0 = never answered / connect error).
    pub last_status: u16,
    /// Last failure reason (delivery diagnostics).
    pub last_error: String,
}

impl DurableJob {
    /// Build a fresh Pending job.
    pub fn new_pending(
        job_id: JobId,
        trace_id: TraceId,
        queue: String,
        method: String,
        url_path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        idem_key: String,
        max_attempts: u32,
    ) -> Self {
        let now = now_ms();
        DurableJob {
            job_id,
            trace_id,
            queue,
            method,
            url_path,
            headers,
            body,
            idem_key,
            state: JobState::Pending,
            attempt: 0,
            max_attempts,
            lease_until_ms: 0,
            available_at_ms: now,
            created_ms: now,
            updated_ms: now,
            last_status: 0,
            last_error: String::new(),
        }
    }
}

/// Retry backoff tuning.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// Delay cap after the first failure: `base * 2^0`.
    pub base_ms: u64,
    /// Hard delay cap (`min(base * 2^attempt, max)`).
    pub max_ms: u64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        BackoffConfig { base_ms: 100, max_ms: 60_000 }
    }
}

impl BackoffConfig {
    /// Full-jitter exponential backoff (AWS architecture blog formula):
    /// `uniform(0, min(base * 2^failed_attempts, max))`.
    pub fn delay_ms(&self, failed_attempts: u32) -> u64 {
        let exp = failed_attempts.min(20) as u64;
        let cap = self
            .base_ms
            .saturating_mul(1u64 << exp)
            .min(self.max_ms);
        // fastrand takes exclusive ranges; `..cap` yields [0, cap).
        let d = fastrand::u64(..cap.saturating_add(1));
        d.min(cap)
    }
}

/// Classify an upstream delivery outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryVerdict {
    /// 2xx — mark Delivered.
    Success,
    /// 429 / 5xx / connect error / timeout — retry with backoff.
    Retryable,
    /// Other 4xx — permanent rejection, dead-letter immediately.
    Permanent,
}

impl DeliveryVerdict {
    pub fn from_status(status: u16) -> Self {
        if (200..300).contains(&status) {
            DeliveryVerdict::Success
        } else if status == 408 || status == 425 || status == 429 || status >= 500 {
            DeliveryVerdict::Retryable
        } else {
            DeliveryVerdict::Permanent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_jitter_stays_within_cap() {
        let cfg = BackoffConfig::default();
        for attempt in 0..12u32 {
            for _ in 0..50 {
                let d = cfg.delay_ms(attempt);
                let cap = cfg.base_ms.saturating_mul(1u64 << attempt.min(20)).min(cfg.max_ms);
                assert!(d <= cap, "delay {d} exceeds cap {cap}");
            }
        }
        // attempt 0 => cap == base (100 ms)
        assert!(cfg.delay_ms(0) <= 100);
    }

    #[test]
    fn backoff_caps_at_max() {
        let cfg = BackoffConfig { base_ms: 100, max_ms: 1_000 };
        for _ in 0..100 {
            assert!(cfg.delay_ms(30) <= 1_000);
        }
    }

    #[test]
    fn verdict_classification() {
        assert_eq!(DeliveryVerdict::from_status(200), DeliveryVerdict::Success);
        assert_eq!(DeliveryVerdict::from_status(202), DeliveryVerdict::Success);
        assert_eq!(DeliveryVerdict::from_status(299), DeliveryVerdict::Success);
        assert_eq!(DeliveryVerdict::from_status(429), DeliveryVerdict::Retryable);
        assert_eq!(DeliveryVerdict::from_status(500), DeliveryVerdict::Retryable);
        assert_eq!(DeliveryVerdict::from_status(503), DeliveryVerdict::Retryable);
        assert_eq!(DeliveryVerdict::from_status(408), DeliveryVerdict::Retryable);
        assert_eq!(DeliveryVerdict::from_status(400), DeliveryVerdict::Permanent);
        assert_eq!(DeliveryVerdict::from_status(404), DeliveryVerdict::Permanent);
    }
}
