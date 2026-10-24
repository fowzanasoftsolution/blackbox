//! Shared upstream circuit breaker — the self-healing backbone (Phase 3).
//!
//! One atomic [`UpstreamHealth`] instance is shared between the ingress
//! proxy (synchronous requests) and the queue dispatcher (webhook delivery),
//! so both engines react to the same upstream reality:
//!
//! ```text
//!  Closed ──threshold consecutive failures──► Open
//!     ▲                                       │ probe TCP connect every 50 ms
//!     │ first real success                    ▼
//!  Closed ◄──first success── HalfOpen ◄──probe OK── (held requests released)
//!                 │
//!                 └──any failure──► Open
//! ```
//!
//! ## Connection hold (invisible app restarts)
//!
//! While `Open`, synchronous ingress requests do NOT get an instant 502 —
//! they park on a `tokio::sync::watch` channel ([`UpstreamHealth::wait_available`])
//! for up to the configured hold window while the prober task TCP-connects to
//! the upstream every ~50 ms. A brief app restart therefore costs the client
//! a few hundred ms of latency instead of an error, and the held requests are
//! replayed upstream the moment the socket accepts again.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Circuit is healthy: traffic flows normally.
pub const STATE_CLOSED: u8 = 0;
/// Circuit tripped: dispatch paused, sync requests held.
pub const STATE_OPEN: u8 = 1;
/// Probe succeeded: limited traffic allowed to confirm recovery.
pub const STATE_HALF_OPEN: u8 = 2;

/// Human-readable state name (`closed` / `open` / `half_open`).
pub fn state_name(state: u8) -> &'static str {
    match state {
        STATE_CLOSED => "closed",
        STATE_OPEN => "open",
        STATE_HALF_OPEN => "half_open",
        _ => "unknown",
    }
}

/// Shared atomic circuit breaker around the upstream application.
pub struct UpstreamHealth {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    /// Failures (in Closed state) required to trip.
    threshold: u32,
    opened_at_ms: AtomicU64,
    transitions: AtomicU64,
    tx: watch::Sender<u8>,
    prober_started: AtomicBool,
}

impl UpstreamHealth {
    /// Create a shared breaker. `threshold` consecutive failures (connection
    /// refused, 502/503/504, dispatch timeout) trip the circuit.
    pub fn new(threshold: u32) -> Arc<Self> {
        let (tx, _rx) = watch::channel(STATE_CLOSED);
        Arc::new(UpstreamHealth {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            threshold: threshold.max(1),
            opened_at_ms: AtomicU64::new(0),
            transitions: AtomicU64::new(0),
            tx,
            prober_started: AtomicBool::new(false),
        })
    }

    #[inline]
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    /// Consecutive failure count (diagnostics).
    #[inline]
    pub fn failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::SeqCst)
    }

    /// Millis since the circuit last tripped (0 if closed).
    pub fn open_for_ms(&self) -> u64 {
        let opened = self.opened_at_ms.load(Ordering::SeqCst);
        if opened == 0 {
            return 0;
        }
        crate::schema::now_ms().saturating_sub(opened)
    }

    pub fn transitions(&self) -> u64 {
        self.transitions.load(Ordering::SeqCst)
    }

    #[inline]
    fn set_state(&self, next: u8) {
        if self.state.swap(next, Ordering::SeqCst) != next {
            self.transitions.fetch_add(1, Ordering::SeqCst);
            if next == STATE_OPEN {
                self.opened_at_ms.store(crate::schema::now_ms(), Ordering::SeqCst);
            }
            let _ = self.tx.send(next); // wake all held requests
        }
    }

    /// A request/dispatch succeeded — heal to Closed (if not already).
    #[inline]
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        if self.state() != STATE_CLOSED {
            tracing::info!("circuit breaker: {} -> closed (upstream healthy)", state_name(self.state()));
            self.set_state(STATE_CLOSED);
        }
    }

    /// A CONNECT-phase failure (connection refused/reset, dial timeout):
    /// the upstream is unreachable right now — trip IMMEDIATELY (blueprint:
    /// "connection refused → trip to Open"), unlike consecutive-5xx trips.
    pub fn record_connect_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::SeqCst);
        if self.state() != STATE_OPEN {
            tracing::warn!(
                "circuit breaker: {} -> open (upstream connection refused)",
                state_name(self.state())
            );
            self.trip_open();
        }
    }

    /// A request/dispatch failed with an HTTP-level error (502/503/504/429).
    /// In Closed: trip after `threshold` consecutive failures.
    /// In HalfOpen: trip immediately (recovery unconfirmed).
    pub fn record_failure(&self) {
        if self.state() == STATE_HALF_OPEN {
            tracing::warn!("circuit breaker: half_open -> open (recovery probe failed)");
            self.trip_open();
            return;
        }
        let f = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if f >= self.threshold && self.state() == STATE_CLOSED {
            tracing::warn!("circuit breaker: closed -> open after {f} consecutive upstream failures");
            self.trip_open();
        }
    }

    fn trip_open(&self) {
        self.set_state(STATE_OPEN);
    }

    /// Called by the prober when a TCP connect succeeds while Open.
    pub fn try_half_open(&self) {
        if self.state() == STATE_OPEN {
            tracing::info!("circuit breaker: open -> half_open (probe connected)");
            self.set_state(STATE_HALF_OPEN);
        }
    }

    /// Park until the circuit admits traffic or `deadline` passes.
    /// Returns `true` = proceed upstream, `false` = hold window expired.
    pub async fn wait_available(&self, deadline: Instant) -> bool {
        let mut rx = self.tx.subscribe();
        loop {
            match self.state() {
                STATE_CLOSED | STATE_HALF_OPEN => return true,
                _ => {}
            }
            if Instant::now() >= deadline {
                return false;
            }
            match tokio::time::timeout_at(tokio::time::Instant::from(deadline), rx.changed()).await {
                Ok(Ok(_)) => continue,          // state changed — re-check
                Ok(Err(_)) => return true,      // breaker dropped: fail open
                Err(_) => return false,         // deadline hit
            }
        }
    }

    /// Spawn the 50 ms TCP-connect prober (once per breaker). The prober
    /// flips Open -> HalfOpen when the upstream accepts a connection again,
    /// and re-trips if a HalfOpen probe fails.
    pub fn spawn_prober(self: &Arc<Self>, upstream: &str, interval: Duration) -> bool {
        if self
            .prober_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false; // already running
        }
        // Resolve once at spawn; the upstream of a co-located sidecar is a
        // stable localhost/lan socket. (HTTP health probes land in Phase 4.)
        let addr: SocketAddr = match upstream.to_socket_addrs_ok() {
            Some(a) => a,
            None => {
                self.prober_started.store(false, Ordering::SeqCst);
                tracing::error!("prober: cannot resolve upstream {upstream}");
                return false;
            }
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // first tick is immediate — skip
            loop {
                tick.tick().await;
                match this.state() {
                    STATE_CLOSED => continue,
                    STATE_OPEN => {
                        if probe_connect(addr).await {
                            this.try_half_open();
                        }
                    }
                    STATE_HALF_OPEN => {
                        if !probe_connect(addr).await {
                            tracing::warn!("circuit breaker: half_open -> open (probe refused)");
                            this.trip_open();
                        }
                    }
                    _ => {}
                }
            }
        });
        true
    }
}

trait ResolveOnce {
    fn to_socket_addrs_ok(&self) -> Option<SocketAddr>;
}

impl ResolveOnce for str {
    fn to_socket_addrs_ok(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

async fn probe_connect(addr: SocketAddr) -> bool {
    match tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trips_after_threshold_and_heals_on_success() {
        let h = UpstreamHealth::new(3);
        h.record_failure();
        h.record_failure();
        assert_eq!(h.state(), STATE_CLOSED, "below threshold");
        h.record_failure();
        assert_eq!(h.state(), STATE_OPEN, "trips at threshold");
        assert!(h.open_for_ms() < 100);

        h.record_success();
        assert_eq!(h.state(), STATE_CLOSED);
        assert_eq!(h.failures(), 0);
    }

    #[tokio::test]
    async fn connect_failure_trips_immediately() {
        let h = UpstreamHealth::new(3);
        h.record_connect_failure();
        assert_eq!(h.state(), STATE_OPEN, "connection refused must trip at once");
        h.record_success();
        assert_eq!(h.state(), STATE_CLOSED);
    }

    #[tokio::test]
    async fn half_open_failure_retrips_immediately() {
        let h = UpstreamHealth::new(3);
        for _ in 0..3 {
            h.record_failure();
        }
        assert_eq!(h.state(), STATE_OPEN);
        h.try_half_open();
        assert_eq!(h.state(), STATE_HALF_OPEN);
        h.record_failure();
        assert_eq!(h.state(), STATE_OPEN, "half-open failure must re-trip");
    }

    #[tokio::test]
    async fn wait_available_deadline_when_open() {
        let h = UpstreamHealth::new(1);
        h.record_failure();
        let started = Instant::now();
        let ok = h.wait_available(started + Duration::from_millis(80)).await;
        assert!(!ok, "open circuit must not admit traffic");
        assert!(started.elapsed() >= Duration::from_millis(70));
    }

    #[tokio::test]
    async fn wait_available_wakes_on_recovery() {
        let h = UpstreamHealth::new(1);
        h.record_failure();
        let h2 = h.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            h2.record_success();
        });
        let ok = h.wait_available(Instant::now() + Duration::from_secs(2)).await;
        assert!(ok, "held request must be released on healing");
    }

    #[tokio::test]
    async fn prober_flips_open_to_half_open_when_upstream_returns() {
        let h = UpstreamHealth::new(1);
        h.record_failure();
        assert_eq!(h.state(), STATE_OPEN);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        h.spawn_prober(&addr.to_string(), Duration::from_millis(20));

        let ok = h.wait_available(Instant::now() + Duration::from_secs(2)).await;
        assert!(ok, "prober must detect the listener and release waiters");
        assert_eq!(h.state(), STATE_HALF_OPEN);
    }
}
