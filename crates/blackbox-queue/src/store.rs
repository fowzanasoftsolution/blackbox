//! JobStore — single-writer group-commit actor over `redb` for the durable
//! queue (Phase 3 Engine 2).
//!
//! Same discipline as the Phase 1 [`blackbox_core::queue_actor`]: ONE task
//! owns the database; writers funnel through a bounded mpsc; every batch is
//! a single `Durability::Immediate` ACID transaction (one fsync), and replies
//! fan out strictly post-commit. The 202 Accepted for a webhook resolves
//! only once its job row is fsynced.
//!
//! ## Tables (all `&[u8] -> &[u8]`)
//!
//! | table      | key                                 | value               |
//! |------------|-------------------------------------|---------------------|
//! | `bq_jobs`  | job_id BE(16)                       | rkyv(DurableJob)    |
//! | `bq_due`   | available_at BE(8) ++ job_id BE(16) | — (Pending index)   |
//! | `bq_lease` | lease_until BE(8) ++ job_id BE(16)  | — (InFlight index)  |
//! | `bq_dlq`   | job_id BE(16)                       | failed_at BE(8)     |
//! | `bq_idem`  | idempotency key bytes               | job_id ++ expires   |
//!
//! Composite big-endian keys keep lexicographic == numeric order, so "due
//! jobs" is a bounded range scan. Every index update happens inside the same
//! transaction as its job row — state and indexes can never diverge.
//!
//! ## Idempotency (webhook retry dedup)
//!
//! The `bq_idem` lookup and the job insert commit atomically in one
//! transaction, so concurrent duplicate deliveries cannot double-enqueue.
//! Keys are retained for the configured retention window (dedup survives
//! caller retry storms well past the job's delivery).

use crate::model::{DurableJob, JobId, JobState};
use blackbox_core::StorageError;
use redb::ReadableTable;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

pub(crate) const T_JOBS: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bq_jobs");
pub(crate) const T_DUE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bq_due");
pub(crate) const T_LEASE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bq_lease");
pub(crate) const T_DLQ: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bq_dlq");
pub(crate) const T_IDEM: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("bq_idem");

/// Actor tuning (group-commit window kept tight — webhook ingest latency is
/// the product: blueprint target "<1.5 ms 202", Phase 3 gate "p99 < 2 ms").
#[derive(Debug, Clone)]
pub struct JobStoreConfig {
    pub batch_window: Duration,
    pub max_batch: usize,
    pub channel_cap: usize,
    pub reader_timeout: Duration,
    /// How long idempotency keys survive after enqueue (dedup window).
    pub idem_retention: Duration,
}

impl Default for JobStoreConfig {
    fn default() -> Self {
        JobStoreConfig {
            // Latency-first profile (see actor loop: no artificial window).
            batch_window: Duration::from_micros(500),
            max_batch: 1_000,
            channel_cap: 8_192,
            reader_timeout: Duration::from_millis(250),
            idem_retention: Duration::from_secs(24 * 3600),
        }
    }
}

/// Cumulative counters (atomics; live state counts are scanned from disk).
#[derive(Debug, Default)]
pub struct JobStoreStats {
    pub enqueued_total: AtomicU64,
    pub deduped_total: AtomicU64,
    pub delivered_total: AtomicU64,
    pub deadletted_total: AtomicU64,
    pub reaped_total: AtomicU64,
    pub batches_committed: AtomicU64,
    pub ops_committed: AtomicU64,
    pub commit_ms_total: AtomicU64,
}

impl JobStoreStats {
    /// (batches, ops, avg_batch, avg_commit_ms, total_commit_ms)
    pub fn snapshot_stats(&self) -> (u64, u64, f64, f64, u64) {
        let b = self.batches_committed.load(Ordering::Relaxed);
        let o = self.ops_committed.load(Ordering::Relaxed);
        let ms = self.commit_ms_total.load(Ordering::Relaxed);
        (
            b,
            o,
            if b > 0 { o as f64 / b as f64 } else { 0.0 },
            if b > 0 { ms as f64 / b as f64 } else { 0.0 },
            ms,
        )
    }
}

/// Disk-truth state counts + lifetime totals.
#[derive(Debug, Clone, Copy, Default)]
pub struct JobCounts {
    pub pending: u64,
    pub in_flight: u64,
    pub dead_letter: u64,
    pub enqueued_total: u64,
    pub deduped_total: u64,
    pub delivered_total: u64,
    pub deadletted_total: u64,
    pub reaped_total: u64,
}

/// Result of an (idempotent) enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueueOutcome {
    pub job_id: JobId,
    /// True when a job with the same idempotency key already existed inside
    /// the retention window — the caller gets 202 (deduplicated), the
    /// original job is NOT re-enqueued.
    pub deduplicated: bool,
}

// ------------------------------------------------------------- requests ----

/// Pre-encoded enqueue op: rkyv encoding happens on the CALLER's task
/// (parallel across clients) so the actor only inserts bytes.
pub(crate) struct EnqueueOp {
    pub job_id: JobId,
    pub idem_key: String,
    pub available_at_ms: u64,
    pub encoded: rkyv::util::AlignedVec<16>,
}

/// Write op payload (replies travel beside it in [`ReplySlot`]).
pub(crate) enum WriteKind {
    Enqueue(EnqueueOp),
    Claim { job_id: JobId, lease_until_ms: u64 },
    /// Atomically claim up to `limit` due jobs (one write op per dispatch
    /// wave instead of one op per job).
    ClaimBatch { limit: usize, lease_until_ms: u64 },
    Succeed { job_id: JobId },
    Fail {
        job_id: JobId,
        attempt: u32,
        available_at_ms: u64,
        dead: bool,
        last_status: u16,
        last_error: String,
    },
    Reap { now_ms: u64 },
    RetryDlq { now_ms: u64 },
}

pub(crate) struct WriteRequest {
    pub kind: WriteKind,
    pub reply: ReplySlot,
}

/// Post-commit reply channel, position-aligned with its op.
pub(crate) enum ReplySlot {
    Enqueue(oneshot::Sender<Result<EnqueueOutcome, StorageError>>),
    Bool(oneshot::Sender<Result<bool, StorageError>>),
    Count(oneshot::Sender<Result<u64, StorageError>>),
    ClaimBatch(oneshot::Sender<Result<Vec<DurableJob>, StorageError>>),
}

impl ReplySlot {
    fn send_enqueue(self, outcome: EnqueueOutcome) {
        if let ReplySlot::Enqueue(tx) = self {
            let _ = tx.send(Ok(outcome));
        }
    }
    fn send_bool(self, v: bool) {
        if let ReplySlot::Bool(tx) = self {
            let _ = tx.send(Ok(v));
        }
    }
    fn send_count(self, v: u64) {
        if let ReplySlot::Count(tx) = self {
            let _ = tx.send(Ok(v));
        }
    }
    fn send_err(self, msg: &str) {
        let msg = StorageError::Db(msg.to_string());
        match self {
            ReplySlot::Enqueue(tx) => {
                let _ = tx.send(Err(msg));
            }
            ReplySlot::Bool(tx) => {
                let _ = tx.send(Err(msg));
            }
            ReplySlot::Count(tx) => {
                let _ = tx.send(Err(msg));
            }
            ReplySlot::ClaimBatch(tx) => {
                let _ = tx.send(Err(msg));
            }
        }
    }
}

enum Request {
    Write(WriteRequest),
    Due { now_ms: u64, limit: usize, reply: oneshot::Sender<Result<Vec<DurableJob>, StorageError>> },
    Counts { reply: oneshot::Sender<Result<JobCounts, StorageError>> },
    Dlq { limit: usize, reply: oneshot::Sender<Result<Vec<DurableJob>, StorageError>> },
    Idem { key: String, reply: oneshot::Sender<Result<Option<JobId>, StorageError>> },
}

/// Outcome of one write op, position-aligned with the ops of its batch.
enum Outcome {
    Enqueue(EnqueueOutcome),
    Claimed(bool),
    ClaimedBatch(Vec<DurableJob>),
    Succeeded(bool),
    Failed { applied: bool, dead: bool },
    Reaped(u64),
    Requeued(u64),
}

/// Cloneable producer handle to the JobStore actor.
#[derive(Clone)]
pub struct JobStoreHandle {
    tx: mpsc::Sender<Request>,
    pub stats: Arc<JobStoreStats>,
    reader_timeout: Duration,
}

impl JobStoreHandle {
    /// Durably enqueue a job (returns after the batch fsyncs). Idempotent
    /// when `job.idem_key` is non-empty. The rkyv encoding runs on the
    /// caller's task so the actor's commit path stays insert-only.
    pub async fn enqueue(&self, job: DurableJob) -> Result<EnqueueOutcome, StorageError> {
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        self.send_write(
            WriteKind::Enqueue(EnqueueOp {
                job_id: job.job_id,
                idem_key: job.idem_key,
                available_at_ms: job.available_at_ms,
                encoded,
            }),
            ReplySlot::Enqueue(tx),
        )
        .await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Atomically claim a Pending job into InFlight under a dispatch lease.
    /// Returns false when the job is not claimable (raced / wrong state).
    pub async fn claim(&self, job_id: JobId, lease_until_ms: u64) -> Result<bool, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(WriteKind::Claim { job_id, lease_until_ms }, ReplySlot::Bool(tx)).await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Atomically claim up to `limit` due jobs under a dispatch lease —
    /// one ACID write op per dispatch wave.
    pub async fn claim_batch(
        &self,
        limit: usize,
        lease_until_ms: u64,
    ) -> Result<Vec<DurableJob>, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(WriteKind::ClaimBatch { limit, lease_until_ms }, ReplySlot::ClaimBatch(tx))
            .await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Mark delivered (2xx): the job row is deleted.
    pub async fn succeed(&self, job_id: JobId) -> Result<bool, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(WriteKind::Succeed { job_id }, ReplySlot::Bool(tx)).await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Record a failed attempt: reschedule with backoff or dead-letter.
    #[allow(clippy::too_many_arguments)]
    pub async fn fail(
        &self,
        job_id: JobId,
        attempt: u32,
        available_at_ms: u64,
        dead: bool,
        last_status: u16,
        last_error: String,
    ) -> Result<bool, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(
            WriteKind::Fail { job_id, attempt, available_at_ms, dead, last_status, last_error },
            ReplySlot::Bool(tx),
        )
        .await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Recover expired InFlight leases back to Pending. Returns the count.
    pub async fn reap_expired(&self, now_ms: u64) -> Result<u64, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(WriteKind::Reap { now_ms }, ReplySlot::Count(tx)).await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    /// 1-click DLQ retry: move every DeadLetter job back to Pending
    /// (attempt reset to 0). Returns the number of jobs requeued.
    pub async fn retry_dlq(&self, now_ms: u64) -> Result<u64, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.send_write(WriteKind::RetryDlq { now_ms }, ReplySlot::Count(tx)).await?;
        rx.await.map_err(|_| StorageError::Closed)?
    }

    async fn send_write(
        &self,
        kind: WriteKind,
        reply: ReplySlot,
    ) -> Result<(), StorageError> {
        self.tx
            .send(Request::Write(WriteRequest { kind, reply }))
            .await
            .map_err(|_| StorageError::Closed)
    }

    /// Jobs with `state == Pending && available_at_ms <= now` (FIFO by due
    /// time then job id).
    pub async fn due_jobs(&self, now_ms: u64, limit: usize) -> Result<Vec<DurableJob>, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Request::Due { now_ms, limit, reply: tx })
            .await
            .map_err(|_| StorageError::Closed)?;
        self.await_read(rx).await
    }

    /// Disk-truth state counts + lifetime totals.
    pub async fn counts(&self) -> Result<JobCounts, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Request::Counts { reply: tx }).await.map_err(|_| StorageError::Closed)?;
        self.await_read(rx).await
    }

    /// Dead-lettered jobs (full payloads retained for 1-click retry).
    pub async fn list_dlq(&self, limit: usize) -> Result<Vec<DurableJob>, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Request::Dlq { limit, reply: tx }).await.map_err(|_| StorageError::Closed)?;
        self.await_read(rx).await
    }

    /// Look up the job id bound to an idempotency key (diagnostics/tests).
    pub async fn idem_lookup(&self, key: &str) -> Result<Option<JobId>, StorageError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Request::Idem { key: key.to_string(), reply: tx })
            .await
            .map_err(|_| StorageError::Closed)?;
        self.await_read(rx).await
    }

    async fn await_read<T>(
        &self,
        rx: oneshot::Receiver<Result<T, StorageError>>,
    ) -> Result<T, StorageError> {
        match tokio::time::timeout(self.reader_timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(StorageError::Closed),
            Err(_) => Err(StorageError::Timeout(self.reader_timeout.as_millis() as u64)),
        }
    }
}

/// Spawn the actor. Creates or opens the database file.
pub async fn spawn_job_store(
    db_path: &Path,
    config: JobStoreConfig,
) -> Result<(JobStoreHandle, Arc<JobStoreStats>, tokio::task::JoinHandle<()>), StorageError> {
    let path: PathBuf = db_path.to_path_buf();
    let db = tokio::task::spawn_blocking(move || redb::Database::create(&path))
        .await
        .map_err(|e| StorageError::Db(format!("join error: {e}")))?
        .map_err(|e| StorageError::Db(e.to_string()))?;
    let db = Arc::new(db);

    let (tx, rx) = mpsc::channel::<Request>(config.channel_cap);
    let stats = Arc::new(JobStoreStats::default());
    let handle = JobStoreHandle {
        tx,
        stats: Arc::clone(&stats),
        reader_timeout: config.reader_timeout,
    };
    let join = tokio::spawn(actor_loop(db, rx, config, Arc::clone(&stats)));
    Ok((handle, stats, join))
}

async fn actor_loop(
    db: Arc<redb::Database>,
    mut rx: mpsc::Receiver<Request>,
    config: JobStoreConfig,
    stats: Arc<JobStoreStats>,
) {
    let mut shutdown = false;
    while !shutdown {
        let mut batch: Vec<WriteRequest> = Vec::new();
        match rx.recv().await {
            Some(Request::Write(w)) => batch.push(w),
            Some(Request::Due { now_ms, limit, reply }) => {
                let _ = reply.send(read_due(&db, now_ms, limit));
                continue;
            }
            Some(Request::Counts { reply }) => {
                let _ = reply.send(read_counts(&db, &stats));
                continue;
            }
            Some(Request::Dlq { limit, reply }) => {
                let _ = reply.send(read_dlq(&db, limit));
                continue;
            }
            Some(Request::Idem { key, reply }) => {
                let _ = reply.send(read_idem(&db, &key));
                continue;
            }
            None => break,
        }

        // Group-commit collection, latency-first: drain everything already
        // queued WITHOUT waiting (the common case under load — the whole
        // in-flight set is waiting in the channel), then only arm the
        // batch window when the drain came up nearly empty (low traffic:
        // amortize one fsync across a few more ops).
        while batch.len() < config.max_batch {
            match rx.try_recv() {
                Ok(Request::Write(w)) => batch.push(w),
                Ok(Request::Due { now_ms, limit, reply }) => {
                    let _ = reply.send(read_due(&db, now_ms, limit));
                }
                Ok(Request::Counts { reply }) => {
                    let _ = reply.send(read_counts(&db, &stats));
                }
                Ok(Request::Dlq { limit, reply }) => {
                    let _ = reply.send(read_dlq(&db, limit));
                }
                Ok(Request::Idem { key, reply }) => {
                    let _ = reply.send(read_idem(&db, &key));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    shutdown = true;
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
            }
        }
        // NOTE: no artificial batch window. Drain-first self-batching gives
        // the fsync amortization under load (batches grow to the backlog, up
        // to max_batch), while single ops commit immediately — the 202 path
        // never pays a timer tick. On slow-storage deployments the group
        // commit still collapses concurrent webhooks into one fsync.
        let _ = config.batch_window; // retained for config compatibility

        commit_batch(&db, batch, &stats, config.idem_retention.as_millis() as u64).await;
    }
    tracing::info!("job store actor shut down cleanly");
}

// ------------------------------------------------------------ read path ----

fn read_counts(db: &redb::Database, stats: &JobStoreStats) -> Result<JobCounts, StorageError> {
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
    c.enqueued_total = stats.enqueued_total.load(Ordering::Relaxed);
    c.deduped_total = stats.deduped_total.load(Ordering::Relaxed);
    c.delivered_total = stats.delivered_total.load(Ordering::Relaxed);
    c.deadletted_total = stats.deadletted_total.load(Ordering::Relaxed);
    c.reaped_total = stats.reaped_total.load(Ordering::Relaxed);
    Ok(c)
}

fn read_due(db: &redb::Database, now_ms: u64, limit: usize) -> Result<Vec<DurableJob>, StorageError> {
    let txn = db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
    let due = match txn.open_table(T_DUE) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]), // table not created yet
    };
    let jobs = match txn.open_table(T_JOBS) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]),
    };
    // (now, any job id] — exclusive upper bound one ms past `now`.
    let end_key = due_key(now_ms.saturating_add(1), 0);
    let mut out = Vec::new();
    for row in due
        .range::<&[u8]>(..end_key.as_slice())
        .map_err(|e| StorageError::Db(e.to_string()))?
    {
        if out.len() >= limit {
            break;
        }
        let (k, _) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let kb: &[u8] = k.value();
        if kb.len() != 24 {
            continue;
        }
        let job_id = u128::from_be_bytes(kb[8..24].try_into().unwrap());
        if let Some(v) = jobs
            .get(job_id.to_be_bytes().as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?
        {
            let job = decode_job(v.value())?;
            if job.state == JobState::Pending && job.available_at_ms <= now_ms {
                out.push(job);
            }
        }
    }
    Ok(out)
}

fn read_dlq(db: &redb::Database, limit: usize) -> Result<Vec<DurableJob>, StorageError> {
    let txn = db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
    let dlq = match txn.open_table(T_DLQ) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]),
    };
    let jobs = match txn.open_table(T_JOBS) {
        Ok(t) => t,
        Err(_) => return Ok(vec![]),
    };
    let mut out = Vec::new();
    for row in dlq.range::<&[u8]>(..).map_err(|e| StorageError::Db(e.to_string()))? {
        if out.len() >= limit {
            break;
        }
        let (k, _) = row.map_err(|e| StorageError::Db(e.to_string()))?;
        let kb: &[u8] = k.value();
        if kb.len() != 16 {
            continue;
        }
        let job_id = u128::from_be_bytes(kb.try_into().unwrap());
        if let Some(v) = jobs
            .get(job_id.to_be_bytes().as_slice())
            .map_err(|e| StorageError::Db(e.to_string()))?
        {
            out.push(decode_job(v.value())?);
        }
    }
    Ok(out)
}

fn read_idem(db: &redb::Database, key: &str) -> Result<Option<JobId>, StorageError> {
    let txn = db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
    let table = match txn.open_table(T_IDEM) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    match table.get(key.as_bytes()).map_err(|e| StorageError::Db(e.to_string()))? {
        Some(v) => {
            let b: &[u8] = v.value();
            if b.len() != 24 {
                return Ok(None);
            }
            Ok(Some(u128::from_be_bytes(b[0..16].try_into().unwrap())))
        }
        None => Ok(None),
    }
}

/// Alignment-safe rkyv decode of a job value stored in redb (Phase 1 bug #1:
/// never `rkyv::access` an arbitrarily aligned in-page slice directly).
pub(crate) fn decode_job(bytes: &[u8]) -> Result<DurableJob, StorageError> {
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(bytes);
    let archived = rkyv::access::<rkyv::Archived<DurableJob>, rkyv::rancor::Error>(&aligned[..])
        .map_err(|e| StorageError::Codec(e.to_string()))?;
    rkyv::deserialize::<DurableJob, rkyv::rancor::Error>(archived)
        .map_err(|e| StorageError::Codec(e.to_string()))
}

// ------------------------------------------------------------ key codec ----

#[inline]
fn due_key(available_at_ms: u64, job_id: JobId) -> Vec<u8> {
    let mut k = Vec::with_capacity(24);
    k.extend_from_slice(&available_at_ms.to_be_bytes());
    k.extend_from_slice(&job_id.to_be_bytes());
    k
}

#[inline]
fn lease_key(lease_until_ms: u64, job_id: JobId) -> Vec<u8> {
    let mut k = Vec::with_capacity(24);
    k.extend_from_slice(&lease_until_ms.to_be_bytes());
    k.extend_from_slice(&job_id.to_be_bytes());
    k
}

#[inline]
fn idem_value(job_id: JobId, expires_ms: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&job_id.to_be_bytes());
    v.extend_from_slice(&expires_ms.to_be_bytes());
    v
}

// ----------------------------------------------------------- write path ----

async fn commit_batch(
    db: &Arc<redb::Database>,
    batch: Vec<WriteRequest>,
    stats: &Arc<JobStoreStats>,
    idem_retention_ms: u64,
) {
    // Split ops from replies: kinds go into the blocking task, slots stay on
    // the async side so replies fan out only after the commit resolves.
    let mut slots: Vec<ReplySlot> = Vec::with_capacity(batch.len());
    let kinds: Vec<WriteKind> = batch
        .into_iter()
        .map(|w| {
            slots.push(w.reply);
            w.kind
        })
        .collect();
    let db = Arc::clone(db);
    let stats = Arc::clone(stats);
    let started = Instant::now();

    let _done: () = tokio::task::spawn_blocking(move || {
        let mut txn = match db.begin_write() {
            Ok(t) => t,
            Err(e) => {
                for slot in slots {
                    slot.send_err(&e.to_string());
                }
                return;
            }
        };
        txn.set_durability(redb::Durability::Immediate);

        let outcome = (|| -> Result<Vec<Outcome>, String> {
            let mut jobs = txn.open_table(T_JOBS).map_err(|e| e.to_string())?;
            let mut due = txn.open_table(T_DUE).map_err(|e| e.to_string())?;
            let mut lease = txn.open_table(T_LEASE).map_err(|e| e.to_string())?;
            let mut dlq = txn.open_table(T_DLQ).map_err(|e| e.to_string())?;
            let mut idem = txn.open_table(T_IDEM).map_err(|e| e.to_string())?;
            let now = blackbox_core::schema::now_ms();
            let mut outcomes = Vec::with_capacity(kinds.len());

            for op in &kinds {
                match op {
                    WriteKind::Enqueue(op) => {
                        // Atomic idempotency check + insert (same txn).
                        let mut dedup: Option<JobId> = None;
                        if !op.idem_key.is_empty() {
                            if let Some(existing) = idem
                                .get(op.idem_key.as_bytes())
                                .map_err(|e| e.to_string())?
                            {
                                let eb: &[u8] = existing.value();
                                if eb.len() == 24 {
                                    let existing_id =
                                        u128::from_be_bytes(eb[0..16].try_into().unwrap());
                                    let expires =
                                        u64::from_be_bytes(eb[16..24].try_into().unwrap());
                                    if expires > now {
                                        dedup = Some(existing_id);
                                    }
                                }
                            }
                        }
                        if let Some(existing_id) = dedup {
                            outcomes.push(Outcome::Enqueue(EnqueueOutcome {
                                job_id: existing_id,
                                deduplicated: true,
                            }));
                            continue;
                        }
                        let jk = op.job_id.to_be_bytes().to_vec();
                        jobs.insert(jk.as_slice(), op.encoded.as_slice())
                            .map_err(|e| e.to_string())?;
                        let dk = due_key(op.available_at_ms, op.job_id);
                        due.insert(dk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                        if !op.idem_key.is_empty() {
                            let iv = idem_value(op.job_id, now + idem_retention_ms);
                            idem
                                .insert(op.idem_key.as_bytes(), iv.as_slice())
                                .map_err(|e| e.to_string())?;
                        }
                        outcomes.push(Outcome::Enqueue(EnqueueOutcome {
                            job_id: op.job_id,
                            deduplicated: false,
                        }));
                    }
                    WriteKind::Claim { job_id, lease_until_ms } => {
                        let jk = job_id.to_be_bytes().to_vec();
                        let mut claimed = false;
                        let existing = jobs
                            .get(jk.as_slice())
                            .map_err(|e| e.to_string())?
                            .map(|v| decode_job(v.value()))
                            .transpose()
                            .map_err(|e| e.to_string())?;
                        if let Some(mut job) = existing {
                            if job.state == JobState::Pending && job.available_at_ms <= now {
                                let old_due = due_key(job.available_at_ms, job.job_id);
                                let _ = due.remove(old_due.as_slice());
                                job.state = JobState::InFlight;
                                job.lease_until_ms = *lease_until_ms;
                                job.updated_ms = now;
                                let value = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                                    .map_err(|e| e.to_string())?;
                                jobs.insert(jk.as_slice(), value.as_slice())
                                    .map_err(|e| e.to_string())?;
                                let lk = lease_key(*lease_until_ms, job.job_id);
                                lease.insert(lk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                                claimed = true;
                            }
                        }
                        outcomes.push(Outcome::Claimed(claimed));
                    }
                    WriteKind::ClaimBatch { limit, lease_until_ms } => {
                        // Claim every due Pending job atomically: scan the
                        // due index, flip states, rebuild the lease entries.
                        let end_key = due_key(now.saturating_add(1), 0);
                        let candidates: Vec<Vec<u8>> = due
                            .range::<&[u8]>(..end_key.as_slice())
                            .map_err(|e| e.to_string())?
                            .filter_map(|row| row.ok())
                            .map(|(k, _)| k.value().to_vec())
                            .take(*limit)
                            .collect();
                        let mut claimed = Vec::with_capacity(candidates.len());
                        for dk in candidates {
                            if dk.len() != 24 {
                                let _ = due.remove(dk.as_slice());
                                continue;
                            }
                            let job_id = u128::from_be_bytes(dk[8..24].try_into().unwrap());
                            let jk = job_id.to_be_bytes().to_vec();
                            let existing = jobs
                                .get(jk.as_slice())
                                .map_err(|e| e.to_string())?
                                .map(|v| decode_job(v.value()))
                                .transpose()
                                .map_err(|e| e.to_string())?;
                            let Some(mut job) = existing else {
                                let _ = due.remove(dk.as_slice());
                                continue;
                            };
                            if job.state != JobState::Pending {
                                let _ = due.remove(dk.as_slice());
                                continue;
                            }
                            let _ = due.remove(dk.as_slice());
                            job.state = JobState::InFlight;
                            job.lease_until_ms = *lease_until_ms;
                            job.updated_ms = now;
                            let value = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                                .map_err(|e| e.to_string())?;
                            jobs.insert(jk.as_slice(), value.as_slice())
                                .map_err(|e| e.to_string())?;
                            let lk = lease_key(*lease_until_ms, job.job_id);
                            lease.insert(lk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                            claimed.push(job);
                        }
                        outcomes.push(Outcome::ClaimedBatch(claimed));
                    }
                    WriteKind::Succeed { job_id } => {
                        let jk = job_id.to_be_bytes().to_vec();
                        let mut existed = false;
                        let existing = jobs
                            .get(jk.as_slice())
                            .map_err(|e| e.to_string())?
                            .map(|v| decode_job(v.value()))
                            .transpose()
                            .map_err(|e| e.to_string())?;
                        if let Some(job) = existing {
                            let lk = lease_key(job.lease_until_ms, job.job_id);
                            let _ = lease.remove(lk.as_slice());
                            let dk = due_key(job.available_at_ms, job.job_id);
                            let _ = due.remove(dk.as_slice());
                            existed = true;
                        }
                        jobs.remove(jk.as_slice()).map_err(|e| e.to_string())?;
                        outcomes.push(Outcome::Succeeded(existed));
                    }
                    WriteKind::Fail { job_id, attempt, available_at_ms, dead, last_status, last_error } => {
                        let jk = job_id.to_be_bytes().to_vec();
                        let mut applied = false;
                        let existing = jobs
                            .get(jk.as_slice())
                            .map_err(|e| e.to_string())?
                            .map(|v| decode_job(v.value()))
                            .transpose()
                            .map_err(|e| e.to_string())?;
                        if let Some(mut job) = existing {
                            let lk = lease_key(job.lease_until_ms, job.job_id);
                            let _ = lease.remove(lk.as_slice());
                            // Drop the stale due entry (if any) before
                            // rescheduling / dead-lettering — otherwise the
                            // due index accumulates one entry per attempt.
                            let old_due = due_key(job.available_at_ms, job.job_id);
                            let _ = due.remove(old_due.as_slice());
                            job.state = if *dead { JobState::DeadLetter } else { JobState::Pending };
                            job.attempt = *attempt;
                            job.available_at_ms = *available_at_ms;
                            job.lease_until_ms = 0;
                            job.last_status = *last_status;
                            job.last_error = last_error.clone();
                            job.updated_ms = now;
                            let value = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                                .map_err(|e| e.to_string())?;
                            jobs.insert(jk.as_slice(), value.as_slice())
                                .map_err(|e| e.to_string())?;
                            if *dead {
                                let dv = now.to_be_bytes().to_vec();
                                dlq.insert(jk.as_slice(), dv.as_slice())
                                    .map_err(|e| e.to_string())?;
                            } else {
                                let dk = due_key(*available_at_ms, job.job_id);
                                due.insert(dk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                            }
                            applied = true;
                        }
                        outcomes.push(Outcome::Failed { applied, dead: *dead });
                    }
                    WriteKind::Reap { now_ms: reap_now } => {
                        // Expired InFlight leases -> Pending (crash recovery).
                        let end_key = lease_key(reap_now.saturating_add(1), 0);
                        let expired: Vec<Vec<u8>> = lease
                            .range::<&[u8]>(..end_key.as_slice())
                            .map_err(|e| e.to_string())?
                            .filter_map(|row| row.ok())
                            .map(|(k, _)| k.value().to_vec())
                            .collect();
                        let mut reaped = 0u64;
                        for lk in expired {
                            if lk.len() != 24 {
                                let _ = lease.remove(lk.as_slice());
                                continue;
                            }
                            let job_id = u128::from_be_bytes(lk[8..24].try_into().unwrap());
                            let jk = job_id.to_be_bytes().to_vec();
                            let existing = jobs
                                .get(jk.as_slice())
                                .map_err(|e| e.to_string())?
                                .map(|v| decode_job(v.value()))
                                .transpose()
                                .map_err(|e| e.to_string())?;
                            let Some(mut job) = existing else {
                                let _ = lease.remove(lk.as_slice());
                                continue;
                            };
                            let _ = lease.remove(lk.as_slice());
                            job.state = JobState::Pending;
                            job.available_at_ms = *reap_now;
                            job.lease_until_ms = 0;
                            job.updated_ms = *reap_now;
                            let value = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                                .map_err(|e| e.to_string())?;
                            jobs.insert(jk.as_slice(), value.as_slice())
                                .map_err(|e| e.to_string())?;
                            let dk = due_key(*reap_now, job.job_id);
                            due.insert(dk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                            reaped += 1;
                        }
                        outcomes.push(Outcome::Reaped(reaped));
                    }
                    WriteKind::RetryDlq { now_ms: retry_now } => {
                        let entries: Vec<Vec<u8>> = dlq
                            .range::<&[u8]>(..)
                            .map_err(|e| e.to_string())?
                            .filter_map(|row| row.ok())
                            .map(|(k, _)| k.value().to_vec())
                            .collect();
                        let mut requeued = 0u64;
                        for jk in entries {
                            let existing = jobs
                                .get(jk.as_slice())
                                .map_err(|e| e.to_string())?
                                .map(|v| decode_job(v.value()))
                                .transpose()
                                .map_err(|e| e.to_string())?;
                            let Some(mut job) = existing else {
                                let _ = dlq.remove(jk.as_slice());
                                continue;
                            };
                            job.state = JobState::Pending;
                            job.attempt = 0;
                            job.available_at_ms = *retry_now;
                            job.lease_until_ms = 0;
                            job.last_error.clear();
                            job.updated_ms = *retry_now;
                            let value = rkyv::to_bytes::<rkyv::rancor::Error>(&job)
                                .map_err(|e| e.to_string())?;
                            jobs.insert(jk.as_slice(), value.as_slice())
                                .map_err(|e| e.to_string())?;
                            let _ = dlq.remove(jk.as_slice());
                            let dk = due_key(*retry_now, job.job_id);
                            due.insert(dk.as_slice(), &b""[..]).map_err(|e| e.to_string())?;
                            requeued += 1;
                        }
                        outcomes.push(Outcome::Requeued(requeued));
                    }
                }
            }
            Ok(outcomes)
        })();

        // Replies fan out INSIDE the closure, strictly after commit — the
        // caller wakes one hop earlier than an async-side fanout.
        let stats_fanout = Arc::clone(&stats);
        match outcome {
            Ok(outcomes) => match txn.commit() {
                Ok(()) => {
                    let commit_ms = started.elapsed().as_millis() as u64;
                    stats_fanout.commit_ms_total.fetch_add(commit_ms, Ordering::Relaxed);
                    stats_fanout.batches_committed.fetch_add(1, Ordering::Relaxed);
                    stats_fanout.ops_committed.fetch_add(kinds.len() as u64, Ordering::Relaxed);
                    for (slot, outcome) in slots.into_iter().zip(outcomes.into_iter()) {
                        match outcome {
                            Outcome::Enqueue(o) => {
                                if o.deduplicated {
                                    stats_fanout.deduped_total.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    stats_fanout.enqueued_total.fetch_add(1, Ordering::Relaxed);
                                }
                                slot.send_enqueue(o);
                            }
                            Outcome::Claimed(v) => slot.send_bool(v),
                            Outcome::ClaimedBatch(jobs) => {
                                if let ReplySlot::ClaimBatch(tx) = slot {
                                    let _ = tx.send(Ok(jobs));
                                }
                            }
                            Outcome::Succeeded(v) => {
                                if v {
                                    stats_fanout.delivered_total.fetch_add(1, Ordering::Relaxed);
                                }
                                slot.send_bool(v);
                            }
                            Outcome::Failed { applied, dead } => {
                                if applied && dead {
                                    stats_fanout.deadletted_total.fetch_add(1, Ordering::Relaxed);
                                }
                                slot.send_bool(applied);
                            }
                            Outcome::Reaped(n) => {
                                stats_fanout.reaped_total.fetch_add(n, Ordering::Relaxed);
                                slot.send_count(n);
                            }
                            Outcome::Requeued(n) => slot.send_count(n),
                        }
                    }
                }
                Err(e) => {
                    for slot in slots {
                        slot.send_err(&e.to_string());
                    }
                }
            },
            Err(e) => {
                let _ = txn.abort();
                for slot in slots {
                    slot.send_err(&e);
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        // join error: the closure died — slots dropped, callers see Closed.
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BackoffConfig, DurableJob};
    use std::time::Duration;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bq-store-{tag}-{}-{}",
            std::process::id(),
            blackbox_core::schema::new_id128() as u64
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn job(id: JobId, idem: &str, body: &[u8]) -> DurableJob {
        DurableJob::new_pending(
            id,
            [9u8; 16],
            "webhooks.stripe".into(),
            "POST".into(),
            "/webhooks/stripe".into(),
            vec![("stripe-signature".into(), "t=1,v1=abc".into())],
            body.to_vec(),
            idem.into(),
            10,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enqueue_claim_succeed_lifecycle() {
        let dir = tmpdir("lifecycle");
        let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), JobStoreConfig::default())
            .await
            .unwrap();

        // 2 000 concurrent enqueues — group commit must batch them.
        const N: JobId = 2_000;
        let mut tasks = Vec::new();
        for i in 0..N {
            let h = h.clone();
            tasks.push(tokio::spawn(async move {
                let body = format!(r#"{{"i":{i}}}"#);
                h.enqueue(job(i, &format!("idem-{i}"), body.as_bytes()))
                    .await
                    .unwrap()
            }));
        }
        for t in tasks {
            let o = t.await.unwrap();
            assert!(!o.deduplicated);
        }
        assert_eq!(h.counts().await.unwrap().pending, N as u64);

        // Claim -> InFlight; claim again must fail (state moved).
        let due = h.due_jobs(blackbox_core::schema::now_ms(), 100).await.unwrap();
        assert_eq!(due.len(), 100);
        let jid = due[0].job_id;
        let lease = blackbox_core::schema::now_ms() + 30_000;
        assert!(h.claim(jid, lease).await.unwrap());
        assert!(!h.claim(jid, lease).await.unwrap(), "double claim must fail");
        let c = h.counts().await.unwrap();
        assert_eq!(c.in_flight, 1);

        // Succeed deletes the row.
        assert!(h.succeed(jid).await.unwrap());
        assert!(!h.succeed(jid).await.unwrap(), "double succeed must be false");
        let c = h.counts().await.unwrap();
        assert_eq!(c.in_flight, 0);
        assert_eq!(c.delivered_total, 1);

        drop(h);
        j.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idempotency_dedup_is_atomic() {
        let dir = tmpdir("idem");
        let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), JobStoreConfig::default())
            .await
            .unwrap();

        // 64 racing duplicates of the SAME idempotency key: exactly one insert.
        let mut tasks = Vec::new();
        for i in 0..64 {
            let h = h.clone();
            tasks.push(tokio::spawn(async move {
                h.enqueue(job(1_000_000 + i as JobId, "dup-key", b"x")).await.unwrap()
            }));
        }
        let mut outcomes = Vec::new();
        for t in tasks {
            outcomes.push(t.await.unwrap());
        }
        let fresh: Vec<_> = outcomes.iter().filter(|o| !o.deduplicated).collect();
        let dedups: Vec<_> = outcomes.iter().filter(|o| o.deduplicated).collect();
        assert_eq!(fresh.len(), 1, "exactly one insert for 64 racing duplicates");
        assert_eq!(dedups.len(), 63);
        for d in dedups {
            assert_eq!(d.job_id, fresh[0].job_id, "dedup must return the original id");
        }
        assert_eq!(h.counts().await.unwrap().pending, 1);

        // Distinct keys are never deduped against each other.
        h.enqueue(job(2, "k1", b"a")).await.unwrap();
        let o = h.enqueue(job(3, "k2", b"b")).await.unwrap();
        assert!(!o.deduplicated);

        drop(h);
        j.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fail_reschedules_then_dead_letters() {
        let dir = tmpdir("dlq");
        let cfg = JobStoreConfig {
            idem_retention: Duration::from_millis(150),
            ..JobStoreConfig::default()
        };
        let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), cfg).await.unwrap();
        let backoff = BackoffConfig { base_ms: 10, max_ms: 50 };

        h.enqueue(job(7, "", b"payload")).await.unwrap();

        // Attempts 1..9: rescheduled each time.
        for attempt in 1..10u32 {
            let delay = backoff.delay_ms(attempt - 1);
            let avail = blackbox_core::schema::now_ms() + delay;
            let ok = h
                .fail(7, attempt, avail, attempt >= 10, 503, "upstream 503".into())
                .await
                .unwrap();
            assert!(ok);
            if attempt < 10 {
                // Not available before its scheduled time.
                let due_before = h
                    .due_jobs(avail.saturating_sub(1), 10)
                    .await
                    .unwrap();
                assert!(due_before.is_empty(), "job must wait out its backoff");
            }
            tokio::time::sleep(Duration::from_millis(delay + 15)).await;
        }
        // Attempt 10 -> DeadLetter (full payload retained).
        let ok = h
            .fail(7, 10, 0, true, 500, "connection refused".into())
            .await
            .unwrap();
        assert!(ok);
        let c = h.counts().await.unwrap();
        assert_eq!(c.dead_letter, 1);
        assert_eq!(c.deadletted_total, 1);

        let dlq = h.list_dlq(10).await.unwrap();
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq[0].body, b"payload", "DLQ retains the full raw payload");
        assert_eq!(dlq[0].attempt, 10);

        // 1-click retry: back to Pending, attempts reset.
        let n = h.retry_dlq(blackbox_core::schema::now_ms()).await.unwrap();
        assert_eq!(n, 1);
        let c = h.counts().await.unwrap();
        assert_eq!(c.pending, 1);
        assert_eq!(c.dead_letter, 0);
        let due = h.due_jobs(blackbox_core::schema::now_ms(), 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempt, 0);

        drop(h);
        j.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lease_reaper_recovers_inflight() {
        let dir = tmpdir("reap");
        let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), JobStoreConfig::default())
            .await
            .unwrap();

        h.enqueue(job(11, "", b"job")).await.unwrap();
        h.enqueue(job(12, "", b"job2")).await.unwrap();

        // Claim both with a SHORT lease, simulating a crash mid-delivery.
        let now = blackbox_core::schema::now_ms();
        assert!(h.claim(11, now + 60).await.unwrap());
        assert!(h.claim(12, now + 60).await.unwrap());
        assert_eq!(h.counts().await.unwrap().in_flight, 2);

        // Not yet expired: nothing reaped.
        assert_eq!(h.reap_expired(now).await.unwrap(), 0);
        // Expired: both recovered to Pending.
        tokio::time::sleep(Duration::from_millis(90)).await;
        let n = h
            .reap_expired(blackbox_core::schema::now_ms())
            .await
            .unwrap();
        assert_eq!(n, 2);
        let c = h.counts().await.unwrap();
        assert_eq!(c.in_flight, 0);
        assert_eq!(c.pending, 2);

        drop(h);
        j.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_durability_and_raw_bytes() {
        let dir = tmpdir("restart");
        let body = vec![0xFAu8; 4096]; // raw webhook bytes — HMAC safety
        {
            let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), JobStoreConfig::default())
                .await
                .unwrap();
            h.enqueue(job(42, "stripe-retry-1", &body)).await.unwrap();
            drop(h);
            j.await.unwrap();
        }
        // Reopen: the job (and its idempotency binding) must survive.
        {
            let (h, _s, j) = spawn_job_store(&dir.join("q.redb"), JobStoreConfig::default())
                .await
                .unwrap();
            assert_eq!(h.counts().await.unwrap().pending, 1);
            assert_eq!(h.idem_lookup("stripe-retry-1").await.unwrap(), Some(42));
            // Re-enqueue with the same key after restart: deduped.
            let o = h.enqueue(job(43, "stripe-retry-1", &body)).await.unwrap();
            assert!(o.deduplicated);
            assert_eq!(o.job_id, 42);
            let due = h.due_jobs(blackbox_core::schema::now_ms(), 10).await.unwrap();
            assert_eq!(due[0].body, body, "raw body bytes must round-trip EXACTLY");
            assert_eq!(due[0].headers[0].0, "stripe-signature");
            drop(h);
            j.await.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
