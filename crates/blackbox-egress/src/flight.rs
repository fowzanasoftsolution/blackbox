//! Detached singleflight request coalescing.
//!
//! Concurrent identical cacheable requests share ONE upstream call:
//!
//! ```text
//! caller #1 ──join(key)──► leader ─► tokio::spawn(execute_upstream)
//! caller #2..N ─join(key)─► waiter ─► watch::Receiver ─┐
//!                                                      ├─► same outcome
//! leader's HTTP caller DISCONNECTS ────────────────────┘
//! (the spawned task is detached — it publishes regardless)
//! ```
//!
//! The **detached leader rule**: the upstream request runs in an
//! independent `tokio::spawn` task that publishes to a
//! `tokio::sync::watch` channel. If the first caller's connection drops
//! and hyper cancels its request future, the flight task survives and
//! every remaining coalesced waiter still receives the response.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// A completed upstream outcome shared with every coalesced waiter.
#[derive(Debug)]
pub struct UpstreamOutcome {
    pub status: u16,
    /// Filtered response headers (hop-by-hop + content-length stripped).
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Parsed token usage (prompt+completion / input+output), 0 if absent.
    pub tokens: u64,
    /// Parsed `x-api-cost-micros` response header, 0 if absent.
    pub cost_micros: u64,
}

/// Terminal flight result.
pub type FlightResult = Result<Arc<UpstreamOutcome>, Arc<String>>;

struct Flight {
    tx: watch::Sender<Option<FlightResult>>,
}

impl Flight {
    fn new() -> (Arc<Flight>, watch::Receiver<Option<FlightResult>>) {
        let (tx, rx) = watch::channel(None);
        (Arc::new(Flight { tx }), rx)
    }

    fn publish(&self, result: FlightResult) {
        let _ = self.tx.send(Some(result));
    }
}

/// The in-flight map. Key = composite cache key.
#[derive(Default)]
pub struct FlightTable {
    inner: Mutex<HashMap<[u8; 32], Arc<Flight>>>,
}

/// Result of joining a flight.
pub enum Join {
    /// An upstream call is already in flight — wait on this receiver.
    Wait(watch::Receiver<Option<FlightResult>>),
    /// You are the leader: spawn the detached upstream task, then wait on
    /// the receiver like everyone else (your client may disconnect freely).
    Lead(watch::Receiver<Option<FlightResult>>),
}

impl FlightTable {
    pub fn new() -> Self {
        FlightTable::default()
    }

    /// Join (or start) the flight for `key`. Leaders get a fresh flight;
    /// the table entry lives until [`FlightTable::finish`] removes it,
    /// AFTER the outcome is published — so late joiners coalesce onto the
    /// completed result instead of re-executing upstream.
    pub fn join(&self, key: [u8; 32]) -> Join {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(f) = guard.get(&key) {
            return Join::Wait(f.tx.subscribe());
        }
        let (f, rx) = Flight::new();
        guard.insert(key, Arc::clone(&f));
        Join::Lead(rx)
    }

    /// Publish the outcome (leader side). The flight stays visible for
    /// late joiners until [`FlightTable::finish`].
    pub fn publish(&self, key: [u8; 32], result: FlightResult) {
        let guard = self.inner.lock();
        if let Ok(g) = &guard {
            if let Some(f) = g.get(&key) {
                f.publish(result);
            }
        }
    }

    /// Remove the flight entry (after cache insert completed).
    pub fn finish(&self, key: [u8; 32]) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(&key);
        }
    }

    /// Coalesced-waiter count currently in flight (diagnostics).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Await a flight result (leaders and waiters use the same wait).
pub async fn wait(mut rx: watch::Receiver<Option<FlightResult>>) -> FlightResult {
    loop {
        if let Some(res) = rx.borrow().as_ref() {
            return res.clone();
        }
        if rx.changed().await.is_err() {
            // Sender dropped without publishing (bug): fail closed.
            return Err(Arc::new("flight dropped without publishing".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn leader_and_waiters_share_one_outcome() {
        let table = Arc::new(FlightTable::new());
        let key = [5u8; 32];

        let lead_rx = match table.join(key) {
            Join::Lead(rx) => rx,
            Join::Wait(_) => panic!("first joiner must lead"),
        };
        let waiter_rx = match table.join(key) {
            Join::Wait(rx) => rx,
            Join::Lead(_) => panic!("second joiner must wait"),
        };

        // Detached leader task: publishes even if the leader caller cancels.
        let t2 = {
            let table = Arc::clone(&table);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                table.publish(
                    key,
                    Ok(Arc::new(UpstreamOutcome {
                        status: 200,
                        headers: vec![("content-type".into(), "application/json".into())],
                        body: Bytes::from_static(b"shared"),
                        tokens: 10,
                        cost_micros: 5,
                    })),
                );
                table.finish(key);
            })
        };

        // Leader caller disconnects instantly (its future is dropped).
        drop(lead_rx);

        let res = waiter_rx.clone();
        let outcome = crate::flight::wait(res).await.unwrap();
        assert_eq!(outcome.body, Bytes::from_static(b"shared"));
        t2.await.unwrap();

        // Late joiner after finish() leads a NEW flight (no stale entry).
        assert!(matches!(table.join(key), Join::Lead(_)));
    }

    #[tokio::test]
    async fn failure_is_shared_then_entry_cleared() {
        let table = FlightTable::new();
        let key = [6u8; 32];
        let rx = match table.join(key) {
            Join::Lead(rx) => rx,
            Join::Wait(_) => panic!("first joiner must lead"),
        };
        table.publish(key, Err(Arc::new("connect refused".into())));
        table.finish(key);
        let err = crate::flight::wait(rx).await.unwrap_err();
        assert_eq!(&*err, "connect refused");
    }
}
