//! Tenant-scoped response cache — byte-budgeted LRU with live stats and
//! supervisor-driven emergency purge.
//!
//! - Keys are the composite BLAKE3 keys from [`crate::key`]; the map is
//!   process-global but every key embeds the tenant + auth, so there is no
//!   way for one tenant to read another's entries.
//! - Budget: `max_entries` AND `max_bytes` (default 256 entries / 4 MiB —
//!   the sidecar's total RSS budget is 35 MB, so the cache must stay small).
//! - [`ResponseCache::purge_all`] drops the cache to **0 bytes** instantly;
//!   it is wired to the supervisor's 75 % RAM watermark via the watch hub.

use crate::validate::Verdict;
use bytes::Bytes;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// One cached upstream response (shared refcounted body).
pub struct CachedEntry {
    pub status: u16,
    /// Filtered headers (hop-by-hop + content-length stripped).
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Parsed token usage (0 when absent) — FinOps savings accounting.
    pub tokens: u64,
    /// Parsed `x-api-cost-micros` (0 when absent).
    pub cost_micros: u64,
}

impl CachedEntry {
    /// Approximate resident bytes (body + header text overhead).
    pub fn ram_bytes(&self) -> usize {
        self.body.len()
            + self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len() + 4)
                .sum::<usize>()
    }
}

/// Insertion outcome (feeds ledger counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Stored,
    Rejected(Verdict),
    OverBudget,
}

pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub purges: u64,
    pub entries: u64,
    pub bytes: u64,
    pub last_purge_reason: Option<String>,
}

pub struct ResponseCache {
    inner: Mutex<LruCache<[u8; 32], std::sync::Arc<CachedEntry>>>,
    max_bytes: usize,
    bytes: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    purges: AtomicU64,
    last_purge_reason: Mutex<Option<String>>,
}

impl ResponseCache {
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        ResponseCache {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(max_entries.max(1)).unwrap(),
            )),
            max_bytes,
            bytes: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            purges: AtomicU64::new(0),
            last_purge_reason: Mutex::new(None),
        }
    }

    /// LRU get — refreshes recency.
    pub fn get(&self, key: &[u8; 32]) -> Option<std::sync::Arc<CachedEntry>> {
        let found = self.inner.lock().ok()?.get(key).cloned();
        if found.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    /// Leader/miss counter (a cacheable request that went upstream).
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Validate + insert. Returns the verdict even when not stored.
    pub fn insert(&self, key: [u8; 32], entry: CachedEntry) -> InsertOutcome {
        let verdict = crate::validate::validate(entry.status, header(&entry.headers, "content-type"), &entry.body);
        if verdict != Verdict::Cacheable {
            return InsertOutcome::Rejected(verdict);
        }
        let entry = std::sync::Arc::new(entry);
        let ram = entry.ram_bytes();
        if ram > self.max_bytes {
            return InsertOutcome::OverBudget;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return InsertOutcome::OverBudget;
        };
        // Evict LRU entries until the new entry fits the byte budget.
        while self.bytes.load(Ordering::Relaxed) + ram as u64 > self.max_bytes as u64 {
            let Some((_k, evicted)) = guard.pop_lru() else { break };
            self.bytes.fetch_sub(evicted.ram_bytes() as u64, Ordering::Relaxed);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        // Replace-if-present bookkeeping (same key re-inserted OR LRU
        // capacity eviction — lru::push returns the evicted pair).
        if let Some(old) = guard.push(key, entry.clone()) {
            self.bytes.fetch_sub(old.1.ram_bytes() as u64, Ordering::Relaxed);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes.fetch_add(ram as u64, Ordering::Relaxed);
        InsertOutcome::Stored
    }

    /// Supervisor self-healing: drop to 0 entries / 0 bytes immediately.
    /// Returns the number of entries evicted.
    pub fn purge_all(&self, reason: &str) -> usize {
        let Ok(mut guard) = self.inner.lock() else { return 0 };
        let n = guard.len();
        guard.clear();
        self.bytes.store(0, Ordering::Relaxed);
        self.purges.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut r) = self.last_purge_reason.lock() {
            *r = Some(reason.to_string());
        }
        if n > 0 {
            tracing::warn!("egress cache PURGED to 0 ({n} entries): {reason}");
        }
        n
    }

    pub fn stats(&self) -> CacheStats {
        let entries = self
            .inner
            .lock()
            .map(|g| g.len() as u64)
            .unwrap_or(0);
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            purges: self.purges.load(Ordering::Relaxed),
            entries,
            bytes: self.bytes.load(Ordering::Relaxed),
            last_purge_reason: self.last_purge_reason.lock().ok().and_then(|r| r.clone()),
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

/// Case-insensitive header lookup in a (String, String) list.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(status: u16, body: &[u8], ct: Option<&str>) -> CachedEntry {
        CachedEntry {
            status,
            headers: ct.map(|c| vec![("content-type".into(), c.into())]).unwrap_or_default(),
            body: Bytes::copy_from_slice(body),
            tokens: 0,
            cost_micros: 0,
        }
    }

    #[test]
    fn hit_miss_and_lru_eviction() {
        let c = ResponseCache::new(2, 1 << 20);
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let k3 = [3u8; 32];
        assert_eq!(c.insert(k1, entry(200, br#"{"v":1}"#, Some("application/json"))), InsertOutcome::Stored);
        assert_eq!(c.insert(k2, entry(200, br#"{"v":2}"#, Some("application/json"))), InsertOutcome::Stored);
        assert!(c.get(&k1).is_some());
        // k1 is now MRU; inserting k3 evicts k2 (LRU).
        assert_eq!(c.insert(k3, entry(200, br#"{"v":3}"#, Some("application/json"))), InsertOutcome::Stored);
        assert!(c.get(&k2).is_none(), "LRU entry must be evicted");
        assert!(c.get(&k1).is_some());
        let s = c.stats();
        assert_eq!(s.evictions, 1);
        assert_eq!(s.entries, 2);
    }

    #[test]
    fn soft_error_never_stored() {
        let c = ResponseCache::new(8, 1 << 20);
        let out = c.insert([9u8; 32], entry(200, br#"{"error":{"m":"rate_limit_exceeded"}}"#, Some("application/json")));
        assert_eq!(out, InsertOutcome::Rejected(Verdict::SoftError));
        assert_eq!(c.stats().entries, 0);
    }

    #[test]
    fn byte_budget_enforced() {
        let c = ResponseCache::new(64, 100);
        assert_eq!(c.insert([1u8; 32], entry(200, &[b'a'; 90], None)), InsertOutcome::Stored);
        assert_eq!(c.insert([2u8; 32], entry(200, &[b'b'; 90], None)), InsertOutcome::Stored);
        let s = c.stats();
        assert!(s.bytes <= 100, "byte budget must hold: {}", s.bytes);
        assert_eq!(s.entries, 1);
    }

    #[test]
    fn purge_to_zero() {
        let c = ResponseCache::new(8, 1 << 20);
        for i in 0..5u8 {
            c.insert([i; 32], entry(200, br#"{"ok":true}"#, Some("application/json")));
        }
        assert_eq!(c.stats().entries, 5);
        let n = c.purge_all("test: 75% watermark");
        assert_eq!(n, 5);
        let s = c.stats();
        assert_eq!(s.entries, 0);
        assert_eq!(s.bytes, 0);
        assert_eq!(s.purges, 1);
        assert_eq!(s.last_purge_reason.as_deref(), Some("test: 75% watermark"));
        // Re-population after purge is allowed (self-healing is transient).
        assert_eq!(c.insert([7u8; 32], entry(200, br#"{"ok":2}"#, Some("application/json"))), InsertOutcome::Stored);
        assert_eq!(c.stats().entries, 1);
    }
}
