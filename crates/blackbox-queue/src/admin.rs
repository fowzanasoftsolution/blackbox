//! Offline administrative access to the JobStore database (`blackbox queue
//! status | retry-dlq`). Opens redb directly — use these when the serve
//! process is stopped; a running serve holds the writer lock.

use crate::model::JobState;
use crate::store::{decode_job, JobCounts};
use redb::ReadableTable;
use blackbox_core::schema::now_ms;
use blackbox_core::StorageError;
use std::path::Path;

use crate::store::{T_DLQ, T_DUE, T_IDEM, T_JOBS, T_LEASE};

/// Read job-state counts straight from the database file.
pub fn read_counts_blocking(db_path: &Path) -> Result<JobCounts, StorageError> {
    let db = redb::Database::open(db_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let txn = db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
    let mut c = JobCounts::default();
    if let Ok(table) = txn.open_table(T_JOBS) {
        for row in table.range::<&[u8]>(..).map_err(|e| StorageError::Db(e.to_string()))? {
            let (_, v) = row.map_err(|e| StorageError::Db(e.to_string()))?;
            let job = decode_job(v.value())?;
            match job.state {
                JobState::Pending => c.pending += 1,
                JobState::InFlight => c.in_flight += 1,
                JobState::DeadLetter => c.dead_letter += 1,
                JobState::Delivered => {}
            }
        }
    }
    Ok(c)
}

/// Retry every dead-lettered job offline (attempt reset, due now).
pub fn retry_dlq_blocking(db_path: &Path) -> Result<u64, StorageError> {
    let db = redb::Database::open(db_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let now = now_ms();
    let mut requeued = 0u64;
    {
        let mut txn = db
            .begin_write()
            .map_err(|e| StorageError::Db(e.to_string()))?;
        txn.set_durability(redb::Durability::Immediate);
        {
            let mut jobs = txn.open_table(T_JOBS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut due = txn.open_table(T_DUE).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut dlq = txn.open_table(T_DLQ).map_err(|e| StorageError::Db(e.to_string()))?;
            let _ = txn.open_table(T_LEASE).map_err(|e| StorageError::Db(e.to_string()))?;
            let _ = txn.open_table(T_IDEM).map_err(|e| StorageError::Db(e.to_string()))?;
            let entries: Vec<Vec<u8>> = dlq
                .range::<&[u8]>(..)
                .map_err(|e| StorageError::Db(e.to_string()))?
                .filter_map(|row| row.ok())
                .map(|(k, _)| k.value().to_vec())
                .collect();
            for jk in entries {
                if jk.len() != 16 {
                    continue;
                }
                let existing = jobs
                    .get(jk.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?
                    .map(|v| decode_job(v.value()))
                    .transpose()?;
                if let Some(mut job) = existing {
                    job.state = JobState::Pending;
                    job.attempt = 0;
                    job.available_at_ms = now;
                    job.lease_until_ms = 0;
                    job.last_error.clear();
                    job.updated_ms = now;
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                        .map_err(|e| StorageError::Codec(e.to_string()))?;
                    jobs.insert(jk.as_slice(), bytes.as_slice())
                        .map_err(|e| StorageError::Db(e.to_string()))?;
                    let mut dk = Vec::with_capacity(24);
                    dk.extend_from_slice(&now.to_be_bytes());
                    dk.extend_from_slice(jk.as_slice());
                    due.insert(dk.as_slice(), &b""[..])
                        .map_err(|e| StorageError::Db(e.to_string()))?;
                    requeued += 1;
                }
                let _ = dlq.remove(jk.as_slice());
            }
        }
        txn.commit().map_err(|e| StorageError::Db(e.to_string()))?;
    }
    Ok(requeued)
}

/// Per-queue breakdown for the status surface.
pub fn queue_breakdown(db_path: &Path) -> Result<Vec<(String, u64, u64, u64)>, StorageError> {
    // (queue, pending, in_flight, dead_letter)
    let db = redb::Database::open(db_path).map_err(|e| StorageError::Db(e.to_string()))?;
    let txn = db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
    let mut map: std::collections::BTreeMap<String, [u64; 3]> = Default::default();
    if let Ok(table) = txn.open_table(T_JOBS) {
        for row in table.range::<&[u8]>(..).map_err(|e| StorageError::Db(e.to_string()))? {
            let (_, v) = row.map_err(|e| StorageError::Db(e.to_string()))?;
            let job = decode_job(v.value())?;
            let slot = map.entry(job.queue).or_insert([0; 3]);
            match job.state {
                JobState::Pending => slot[0] += 1,
                JobState::InFlight => slot[1] += 1,
                JobState::DeadLetter => slot[2] += 1,
                JobState::Delivered => {}
            }
        }
    }
    Ok(map
        .into_iter()
        .map(|(q, s)| (q, s[0], s[1], s[2]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DurableJob;
    use crate::store::spawn_job_store;
    use crate::store::JobStoreConfig;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_admin_sees_live_data() {
        let dir = std::env::temp_dir().join(format!(
            "bq-admin-{}-{}",
            std::process::id(),
            blackbox_core::schema::new_id128() as u64
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("jobs.redb");

        {
            let (h, _s, j) = spawn_job_store(&db, JobStoreConfig::default()).await.unwrap();
            let mk = |id: u128, dead: bool| {
                DurableJob::new_pending(
                    id,
                    [3u8; 16],
                    "webhooks.stripe".into(),
                    "POST".into(),
                    "/webhooks/stripe".into(),
                    vec![],
                    b"body".to_vec(),
                    String::new(),
                    10,
                )
            };
            let mut j1 = mk(1, false);
            h.enqueue(j1.clone()).await.unwrap();
            let mut j2 = mk(2, true);
            j2.max_attempts = 1;
            h.enqueue(j2).await.unwrap();
            // Fail j2 once -> dead-letter.
            h.fail(2, 1, 0, true, 400, "bad request".into()).await.unwrap();
            drop(h);
            j.await.unwrap();
        }

        // Offline (serve "stopped"): counts + breakdown + retry.
        let c = read_counts_blocking(&db).unwrap();
        assert_eq!(c.pending, 1);
        assert_eq!(c.dead_letter, 1);
        let breakdown = queue_breakdown(&db).unwrap();
        assert_eq!(breakdown.len(), 1);
        assert_eq!(breakdown[0].0, "webhooks.stripe");
        let n = retry_dlq_blocking(&db).unwrap();
        assert_eq!(n, 1);
        let c2 = read_counts_blocking(&db).unwrap();
        assert_eq!(c2.pending, 2);
        assert_eq!(c2.dead_letter, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
