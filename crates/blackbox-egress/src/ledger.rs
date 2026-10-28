//! Real-time FinOps cost & token ledger.
//!
//! One row per `(tenant_id, provider, model)`:
//!
//! | field                 | meaning                                            |
//! |-----------------------|----------------------------------------------------|
//! | `total_requests`      | every observed request (hits included)             |
//! | `cache_hits`          | served from the LRU cache                          |
//! | `coalesced_hits`      | served by singleflight coalescing                  |
//! | `tokens_used`         | tokens billed on REAL upstream calls               |
//! | `tokens_saved`        | tokens NOT billed (hits × the cached usage)        |
//! | `cost_micros_spent`   | `x-api-cost-micros` summed over real calls         |
//! | `cost_micros_saved`   | the cost those saved calls WOULD have incurred     |
//!
//! Hot path is a locked `HashMap` (microseconds); a single-writer flush
//! task persists dirty rows to `finops.redb` every second (group-commit
//! style) and on explicit flush — restart-safe without ever blocking
//! egress.

use rkyv::{Archive, Deserialize, Serialize};
use redb::ReadableTable;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Parsed token usage from a response body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub tokens: u64,
}

/// OpenAI: `usage.prompt_tokens + usage.completion_tokens`.
/// Anthropic: `usage.input_tokens + usage.output_tokens`.
pub fn parse_usage(body: &[u8]) -> Usage {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Usage::default();
    };
    let Some(u) = v.get("usage") else {
        return Usage::default();
    };
    let num = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    let openai = num("prompt_tokens") + num("completion_tokens");
    let anthropic = num("input_tokens") + num("output_tokens");
    Usage {
        tokens: openai.max(anthropic),
    }
}

/// `x-api-cost-micros` custom cost header (micro-USD).
pub fn parse_cost_header(headers: &[(String, String)]) -> u64 {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-api-cost-micros"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// One ledger row (rkyv-persisted).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub coalesced_hits: u64,
    pub tokens_used: u64,
    pub tokens_saved: u64,
    pub cost_micros_spent: u64,
    pub cost_micros_saved: u64,
}

impl LedgerEntry {
    /// Cost savings fraction in percent (0-100), based on micros when the
    /// cost header is present, else on tokens.
    pub fn savings_pct(&self) -> f64 {
        let spent_would = self.cost_micros_spent + self.cost_micros_saved;
        if spent_would > 0 {
            return (self.cost_micros_saved as f64 / spent_would as f64) * 100.0;
        }
        let tok_would = self.tokens_used + self.tokens_saved;
        if tok_would > 0 {
            return (self.tokens_saved as f64 / tok_would as f64) * 100.0;
        }
        0.0
    }
}

/// Ledger dimension key: `(tenant_id, provider, model)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerKey {
    pub tenant: String,
    pub provider: String,
    pub model: String,
}

impl LedgerKey {
    pub fn new(tenant: impl Into<String>, provider: impl Into<String>, model: impl Into<String>) -> Self {
        LedgerKey {
            tenant: tenant.into(),
            provider: provider.into(),
            model: model.into(),
        }
    }

    fn redb_key(&self) -> String {
        format!("{}\u{1f}{}\u{1f}{}", self.tenant, self.provider, self.model)
    }

    fn from_redb_key(s: &str) -> Option<LedgerKey> {
        let mut it = s.split('\u{1f}');
        Some(LedgerKey {
            tenant: it.next()?.to_string(),
            provider: it.next()?.to_string(),
            model: it.next()?.to_string(),
        })
    }
}

struct Inner {
    rows: Mutex<HashMap<LedgerKey, (LedgerEntry, bool)>>, // value + dirty
}

/// The shared ledger: in-memory rows + background redb flusher.
/// Drop stops the flush task and releases the redb file lock.
pub struct CostLedger {
    inner: Arc<Inner>,
    /// Held for the redb file lock lifetime (flushes run through the task).
    #[allow(dead_code)]
    db: Arc<redb::Database>,
    #[allow(dead_code)]
    db_path: std::path::PathBuf,
    flush_tx: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<u64>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    flush_task: tokio::task::JoinHandle<()>,
    flushes: AtomicU64,
}

impl Drop for CostLedger {
    fn drop(&mut self) {
        // Signal the flush task to exit AND cancel it, so the redb file
        // lock is released deterministically when this handle goes away.
        let _ = self.shutdown_tx.send(true);
        self.flush_task.abort();
    }
}

impl CostLedger {
    /// Open (or create) `dir/finops.redb`, load persisted rows, and spawn
    /// the 1 s single-writer flush task.
    pub fn open(dir: &Path) -> Result<Arc<Self>, blackbox_core::StorageError> {
        let db_path = dir.join("finops.redb");
        // v1.1.1: page cache capped at 8 MiB (default is 1 GiB — soak fix #1).
        let db = Arc::new(blackbox_core::kv::create_redb(&db_path).map_err(redb_err)?);
        let persisted = load_all(&db)?;

        let inner = Arc::new(Inner {
            rows: Mutex::new(persisted.into_iter().map(|(k, v)| (k, (v, false))).collect()),
        });
        let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<u64>>(16);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        // Single-writer flush task: owns Inner + the Database handle (NOT the
        // CostLedger — so Drop can shut it down and release the file lock).
        let flush_task = {
            let inner = Arc::clone(&inner);
            let db = Arc::clone(&db);
            tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(1_000));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => return,
                    reply = flush_rx.recv() => {
                        let Some(reply) = reply else { return };
                        let n = flush_dirty(&inner, &db);
                        let _ = reply.send(n);
                        continue;
                    }
                    _ = tick.tick() => {}
                }
                let _ = flush_dirty(&inner, &db);
            }
            })
        };

        let ledger = Arc::new(CostLedger {
            inner,
            db,
            db_path: db_path.clone(),
            flush_tx,
            shutdown_tx,
            flush_task,
            flushes: AtomicU64::new(0),
        });

        Ok(ledger)
    }

    /// Count one handled request. `saved_tokens`/`saved_cost` describe what
    /// the request did NOT consume (hit paths pass the cached usage/cost).
    pub fn record(
        &self,
        key: LedgerKey,
        kind: RequestKind,
        tokens_used: u64,
        tokens_saved: u64,
        cost_spent: u64,
        cost_saved: u64,
    ) {
        let mut guard = match self.inner.rows.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let (e, dirty) = guard.entry(key).or_insert_with(|| (LedgerEntry::default(), false));
        e.total_requests += 1;
        e.tokens_used += tokens_used;
        e.tokens_saved += tokens_saved;
        e.cost_micros_spent += cost_spent;
        e.cost_micros_saved += cost_saved;
        match kind {
            RequestKind::Upstream => {}
            RequestKind::CacheHit => e.cache_hits += 1,
            RequestKind::Coalesced => e.coalesced_hits += 1,
        }
        *dirty = true;
    }

    /// Force-flush dirty rows now; returns rows written. Used by gates and
    /// graceful shutdown (the periodic task covers normal operation).
    pub async fn flush(&self) -> u64 {
        let n = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if self.flush_tx.send(tx).await.is_err() {
                return 0;
            }
            let n = rx.await.unwrap_or(0);
            self.flushes.fetch_add(1, Ordering::Relaxed);
            n
        };
        n
    }

    /// Snapshot for the admin API (sorted by tenant, provider, model).
    pub fn snapshot(&self) -> Vec<(LedgerKey, LedgerEntry)> {
        let guard = match self.inner.rows.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut out: Vec<(LedgerKey, LedgerEntry)> =
            guard.iter().map(|(k, (v, _))| (k.clone(), *v)).collect();
        out.sort_by(|a, b| {
            (&a.0.tenant, &a.0.provider, &a.0.model).cmp(&(&b.0.tenant, &b.0.provider, &b.0.model))
        });
        out
    }

    /// Aggregated totals across all rows.
    pub fn totals(&self) -> LedgerEntry {
        let mut t = LedgerEntry::default();
        for (_, e) in self.snapshot() {
            t.total_requests += e.total_requests;
            t.cache_hits += e.cache_hits;
            t.coalesced_hits += e.coalesced_hits;
            t.tokens_used += e.tokens_used;
            t.tokens_saved += e.tokens_saved;
            t.cost_micros_spent += e.cost_micros_spent;
            t.cost_micros_saved += e.cost_micros_saved;
        }
        t
    }

    pub fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    /// Persistence path (admin diagnostics).
    pub fn db_path(&self) -> &std::path::Path {
        &self.db_path
    }
}

fn flush_dirty(inner: &Inner, db: &redb::Database) -> u64 {
    let dirty: Vec<(String, LedgerEntry)> = {
        let mut guard = match inner.rows.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard
            .iter_mut()
            .filter(|(_, (_, d))| *d)
            .map(|(k, (v, d))| {
                *d = false;
                (k.redb_key(), *v)
            })
            .collect()
    };
    if dirty.is_empty() {
        return 0;
    }
    let n = dirty.len() as u64;
    let res = (|| -> Result<(), blackbox_core::StorageError> {
        let txn = db.begin_write().map_err(redb_err)?;
        {
            let mut table = txn.open_table(LEDGER_TABLE).map_err(redb_err)?;
            for (k, v) in &dirty {
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(v).expect("ledger rkyv encode");
                table.insert(k.as_str(), &bytes[..]).map_err(redb_err)?;
            }
        }
        txn.commit().map_err(redb_err)
    })();
    if let Err(e) = res {
        // Re-mark dirty so the next pass retries.
        let mut guard = inner.rows.lock().unwrap_or_else(|p| p.into_inner());
        for (k, _v) in dirty {
            if let Some(row) = guard.iter_mut().find(|(lk, _)| lk.redb_key() == k) {
                row.1 .1 = true;
            }
        }
        tracing::error!("finops ledger flush failed: {e}");
    }
    n
}

/// What kind of request this ledger entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Real upstream call (leader / bypass path).
    Upstream,
    /// Served from the LRU cache.
    CacheHit,
    /// Served via singleflight coalescing.
    Coalesced,
}

const LEDGER_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("finops_ledger");

fn redb_err<E: std::fmt::Display>(e: E) -> blackbox_core::StorageError {
    blackbox_core::StorageError::Db(e.to_string())
}

fn load_all(db: &redb::Database) -> Result<Vec<(LedgerKey, LedgerEntry)>, blackbox_core::StorageError> {
    let txn = db.begin_read().map_err(redb_err)?;
    let Ok(table) = txn.open_table(LEDGER_TABLE) else {
        return Ok(Vec::new()); // first boot: table not created yet
    };
    let mut out = Vec::new();
    for row in table.iter().map_err(redb_err)? {
        let (k, v) = row.map_err(redb_err)?;
        let Some(key) = LedgerKey::from_redb_key(k.value()) else { continue };
        // redb value slices sit at arbitrary page alignment — copy into an
        // AlignedVec before rkyv::access (same class of bug as the Phase 1
        // redb AccessGuard fix in the queue actor).
        let raw = v.value();
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(raw.len());
        aligned.extend_from_slice(&raw);
        let Some(arch) = rkyv::access::<rkyv::Archived<LedgerEntry>, rkyv::rancor::Error>(&aligned).ok() else {
            continue; // corrupt row: skip, don't poison startup
        };
        let entry: LedgerEntry = rkyv::deserialize::<LedgerEntry, rkyv::rancor::Error>(arch)
            .map_err(|e| blackbox_core::StorageError::Codec(e.to_string()))?;
        out.push((key, entry));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bq-ledger-{tag}-{}-{}",
            std::process::id(),
            blackbox_core::schema::new_id128() as u64
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn usage_parsing_openai_and_anthropic() {
        let openai = parse_usage(br#"{"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#);
        assert_eq!(openai.tokens, 46);
        let anthropic = parse_usage(br#"{"usage":{"input_tokens":100,"output_tokens":50}}"#);
        assert_eq!(anthropic.tokens, 150);
        assert_eq!(parse_usage(b"not json").tokens, 0);
        assert_eq!(parse_usage(br#"{"no_usage":true}"#).tokens, 0);
    }

    #[test]
    fn cost_header_parsing() {
        let h = vec![("content-type".to_string(), "application/json".to_string()),
                     ("X-Api-Cost-Micros".to_string(), "750".to_string())];
        assert_eq!(parse_cost_header(&h), 750);
        assert_eq!(parse_cost_header(&[("x".to_string(), "y".to_string())]), 0);
    }

    #[tokio::test]
    async fn ledger_records_flushes_and_survives_restart() {
        let dir = tmpdir("roundtrip");
        let l = CostLedger::open(&dir).unwrap();
        let k = LedgerKey::new("tenant-a", "openai", "gpt-4o-mini");
        l.record(k.clone(), RequestKind::Upstream, 46, 0, 750, 0);
        for _ in 0..24 {
            l.record(k.clone(), RequestKind::Coalesced, 0, 46, 0, 750);
        }
        let snap = l.snapshot();
        assert_eq!(snap.len(), 1);
        let (lk, e) = &snap[0];
        assert_eq!(lk.tenant, "tenant-a");
        assert_eq!(e.total_requests, 25);
        assert_eq!(e.coalesced_hits, 24);
        assert_eq!(e.tokens_used, 46);
        assert_eq!(e.tokens_saved, 24 * 46);
        assert_eq!(e.cost_micros_spent, 750);
        assert_eq!(e.cost_micros_saved, 24 * 750);
        // 96 % savings: 18000 / (18000 + 750)
        assert!((e.savings_pct() - 96.0).abs() < 1e-9);
        let n = l.flush().await;
        assert_eq!(n, 1);
        assert!(l.flush_count() >= 1);
        drop(l);
        // The abort + shutdown need one scheduler tick to release the lock.
        tokio::time::sleep(Duration::from_millis(120)).await;
        // Restart: reload from redb.
        let l2 = CostLedger::open(&dir).unwrap();
        let rows = l2.snapshot();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.total_requests, 25, "persistence across restart");
        assert_eq!(rows[0].1.coalesced_hits, 24);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
