//! Shared `redb` open helper — bounds the embedded store's page cache.
//!
//! ## Why (v1.1.1, soak `bb-soak-6h`)
//!
//! `redb::Database::create/open` uses the crate default of **1 GiB** read /
//! write page-cache budget (`Builder::new` seeds exactly that). As the B-tree
//! expands, jemalloc happily keeps every touched cached page resident — node A
//! of the 6-hour soak drifted to 68.9 MiB RSS (81.2 MB `ram.used`) with the
//! queue B-tree contributing the bulk of it. A sidecar on a 48 MiB budget must
//! never hand the KV layer 1 GiB of cache: this helper caps it at
//! [`REDB_CACHE_BYTES`] for EVERY database this process opens (queue store,
//! Phase-1 actor, offline admin probes).
//!
//! A capped cache is a pure *eviction* bound — correctness, durability and
//! fsync behavior are unaffected; hot keys simply miss the cache and hit disk.

use std::path::Path;

/// Fixed page-cache budget per open `redb` database (8 MiB).
pub const REDB_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// Open or CREATE a database with the capped page cache.
pub fn create_redb(path: impl AsRef<Path>) -> Result<redb::Database, redb::DatabaseError> {
    redb::Database::builder().set_cache_size(REDB_CACHE_BYTES).create(path)
}

/// Open (no create) a database with the capped page cache.
pub fn open_redb(path: impl AsRef<Path>) -> Result<redb::Database, redb::DatabaseError> {
    redb::Database::builder().set_cache_size(REDB_CACHE_BYTES).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_reopen_with_capped_cache() {
        let dir = std::env::temp_dir().join(format!(
            "bb-kv-{}-{}",
            std::process::id(),
            crate::schema::new_id128()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.redb");
        {
            let db = create_redb(&path).unwrap();
            let mut txn = db.begin_write().unwrap();
            txn.set_durability(redb::Durability::Immediate);
            let t: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("k");
            txn.open_table(t)
                .unwrap()
                .insert(b"a".as_slice(), b"1".as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
        let db = open_redb(&path).unwrap();
        let txn = db.begin_read().unwrap();
        let t: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("k");
        assert_eq!(
            txn.open_table(t)
                .unwrap()
                .get(b"a".as_slice())
                .unwrap()
                .unwrap()
                .value(),
            b"1"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
