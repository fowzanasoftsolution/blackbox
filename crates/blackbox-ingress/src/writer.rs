//! Background segment writer — the disk-I/O decoupling point.
//!
//! The proxy hot path pushes completed `TraceRecord`s into a **bounded
//! channel** ([`WriterConfig::channel_cap`], default 16 384) via
//! [`RecordSink::try_send`] — a non-blocking clone of the record. A single
//! dedicated task owns the [`SegmentStore`]:
//!
//! 1. drains the channel in batches (append is ~700 K frames/s in Phase 1
//!    benchmarks — the writer is never the bottleneck at 8 K req/s),
//! 2. fsyncs on the 5 ms group-commit tick when frames are pending,
//! 3. updates the shared [`TraceIndex`] after every append
//!    (`trace_id → (segment_id, offset)` + status counters),
//! 4. answers [`WriterMsg::Flush`] with an ack once the queue is drained
//!    and synced (used by tests and graceful shutdown).
//!
//! Backpressure: when the channel is full, records are DROPPED and counted
//! (the proxy never blocks on disk — blueprint §4.2 shed-under-load policy;
//! a full 16 384-record buffer means the disk is catastrophically behind).

use crate::index::TraceIndex;
use blackbox_core::segment::{SegmentConfig, SegmentStore, StoreShared, DEFAULT_MAX_SEGMENT_BYTES};
use blackbox_core::schema::TraceRecord;
use blackbox_core::StorageError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;

/// Channel capacity (blueprint: 16 384 completed frames in flight).
pub const DEFAULT_CHANNEL_CAP: usize = 16_384;
/// Group-commit fsync cadence (matches the redb actor's 5 ms window).
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_millis(5);
/// Max records appended per drain pass (bounds lock hold time).
const DRAIN_BATCH: usize = 512;

#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub data_dir: PathBuf,
    pub channel_cap: usize,
    pub sync_interval: Duration,
    /// Rotate the active segment once it exceeds this size (Phase 5:
    /// configurable down to 1 MB for tests; default 64 MB).
    pub max_segment_bytes: u64,
    /// v1.1.2 RAM budget (bytes) for the segment rollover guard
    /// (`min(max_segment_bytes, ram_budget_bytes / 6)`). 0 = disabled.
    pub ram_budget_bytes: u64,
}

impl Default for WriterConfig {
    fn default() -> Self {
        WriterConfig {
            data_dir: PathBuf::from("./data"),
            channel_cap: DEFAULT_CHANNEL_CAP,
            sync_interval: DEFAULT_SYNC_INTERVAL,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            ram_budget_bytes: 48 * 1024 * 1024,
        }
    }
}

/// Messages into the writer task.
pub enum WriterMsg {
    Record(TraceRecord),
    /// Drain + fsync + ack with the total appended count.
    Flush(tokio::sync::oneshot::Sender<u64>),
}

/// Clone-able handle to push records at the writer task.
#[derive(Clone)]
pub struct RecordSink {
    tx: mpsc::Sender<WriterMsg>,
    seq: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl RecordSink {
    /// Global monotonic sequence number for a new record.
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Non-blocking push. Returns false (and counts a drop) when the
    /// bounded channel is full — never blocks the caller.
    pub fn try_send(&self, record: TraceRecord) -> bool {
        match self.tx.try_send(WriterMsg::Record(record)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("writer channel full; record dropped (disk behind)");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Wait until every record pushed before this call is appended + synced.
    pub async fn flush(&self) -> u64 {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(WriterMsg::Flush(tx)).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn channel_len(&self) -> usize {
        self.tx.max_capacity().saturating_sub(self.tx.capacity())
    }
}

/// Spawn the writer task. Returns the sink, the shared index and the task
/// handle. The index is pre-rebuilt from the on-disk recovery scan.
pub fn spawn_writer(
    cfg: WriterConfig,
) -> (RecordSink, Arc<RwLock<TraceIndex>>, tokio::task::JoinHandle<u64>) {
    let (sink, index, join, _active) = spawn_writer_full(cfg);
    (sink, index, join)
}

/// Like [`spawn_writer`] but also hands out the active-segment watch
/// receiver — the Phase 5 compactor/janitor subscribes to it.
pub fn spawn_writer_full(
    cfg: WriterConfig,
) -> (
    RecordSink,
    Arc<RwLock<TraceIndex>>,
    tokio::task::JoinHandle<u64>,
    tokio::sync::watch::Receiver<u32>,
) {
    // 1) Recovery pass: torn tails are truncated BEFORE the index scan so
    //    `read_index_all` only sees valid frames. (SegmentStore::open does
    //    this; it is idempotent and cheap.)
    let shared = StoreShared::new();
    let _store_probe = SegmentStore::open_with_shared(
        &cfg.data_dir,
        SegmentConfig { 
            max_segment_bytes: cfg.max_segment_bytes,
            ram_budget_bytes: cfg.ram_budget_bytes,
            ..Default::default()
        },
        Arc::clone(&shared),
    )
    .expect("segment recovery on startup must not fail");

    // 2) Index rebuild from the (now clean) disk contents.
    let index = Arc::new(RwLock::new(
        TraceIndex::rebuild(&cfg.data_dir).expect("index rebuild must not fail"),
    ));

    // 3) Channel + task.
    let (tx, rx) = mpsc::channel::<WriterMsg>(cfg.channel_cap);
    let sink = RecordSink {
        tx,
        seq: Arc::new(AtomicU64::new(0)),
        dropped: Arc::new(AtomicU64::new(0)),
    };
    let index_for_task = index.clone();
    let dir = cfg.data_dir.clone();
    let sync_interval = cfg.sync_interval;
    let max_segment_bytes = cfg.max_segment_bytes;
    let ram_budget_bytes = cfg.ram_budget_bytes;
    let shared_for_task = Arc::clone(&shared);
    let join = tokio::spawn(async move {
        match run_writer(dir, sync_interval, max_segment_bytes, ram_budget_bytes, rx, index_for_task, shared_for_task).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("writer task failed: {e}");
                0
            }
        }
    });
    (sink, index, join, shared.subscribe())
}

async fn run_writer(
    dir: PathBuf,
    sync_interval: Duration,
    max_segment_bytes: u64,
    ram_budget_bytes: u64,
    mut rx: mpsc::Receiver<WriterMsg>,
    index: Arc<RwLock<TraceIndex>>,
    shared: Arc<StoreShared>,
) -> Result<u64, StorageError> {
    let mut store = SegmentStore::open_with_shared(
        &dir,
        SegmentConfig { 
            max_segment_bytes,
            ram_budget_bytes,
            ..Default::default()
        },
        shared,
    )?;
    let mut tick = tokio::time::interval(sync_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut appended_total: u64 = 0;

    loop {
        tokio::select! {
            biased;
            msg = rx.recv() => match msg {
                Some(WriterMsg::Record(rec)) => {
                    append_one(&mut store, &index, rec, &mut appended_total);
                    // Drain the rest of what's queued (append is cheap;
                    // batching amortizes the index lock acquisition).
                    let mut drained = 0;
                    while drained < DRAIN_BATCH {
                        match rx.try_recv() {
                            Ok(WriterMsg::Record(rec)) => {
                                append_one(&mut store, &index, rec, &mut appended_total);
                                drained += 1;
                            }
                            Ok(WriterMsg::Flush(ack)) => {
                                store.sync()?;
                                let _ = ack.send(appended_total);
                            }
                            Err(_) => break,
                        }
                    }
                }
                Some(WriterMsg::Flush(ack)) => {
                    store.sync()?;
                    let _ = ack.send(appended_total);
                }
                None => {
                    // All senders dropped: final sync and exit.
                    store.sync()?;
                    return Ok(appended_total);
                }
            },
            _ = tick.tick() => {
                if store.unsynced_frames() > 0 {
                    store.sync()?;
                }
            }
        }
    }
}

fn append_one(
    store: &mut SegmentStore,
    index: &RwLock<TraceIndex>,
    rec: TraceRecord,
    appended_total: &mut u64,
) {
    let segment_id = store.active_segment_id();
    match store.append(&rec) {
        Ok(offset) => {
            *appended_total += 1;
            if let Ok(mut idx) = index.write() {
                idx.insert(&rec, segment_id, offset);
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "segment append failed; record lost");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::TraceIndex;
    use blackbox_core::schema::{
        IngressHttp, RecordPayload, TelemetryLog, TraceRecord,
    };
    use std::time::Duration;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("blackbox-writer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(tid: [u8; 16], seq: u64) -> TraceRecord {
        TraceRecord::new(
            tid,
            seq,
            RecordPayload::IngressHttp(IngressHttp {
                method: "GET".into(),
                uri: "/w".into(),
                status: 200,
                req_headers: vec![],
                req_body: vec![],
                res_body: b"ok".to_vec(),
                duration_ms: 1,
            }),
        )
    }

    #[tokio::test]
    async fn records_flow_to_index_and_disk() {
        let dir = tmpdir("flow");
        let cfg = WriterConfig {
            data_dir: dir.clone(),
            ..WriterConfig::default()
        };
        let (sink, index, writer) = spawn_writer(cfg);

        for seq in 0..100u64 {
            let mut tid = [7u8; 16];
            tid[0] = seq as u8;
            sink.try_send(rec(tid, seq));
        }
        sink.flush().await;

        // Index must see all 100 records under 100 distinct trace ids.
        let st = index.read().unwrap().stats();
        assert_eq!(st.frames, 100);
        assert_eq!(st.distinct_traces, 100);
        assert_eq!(st.status_2xx, 100);

        // get_trace serves them from disk.
        let mut tid = [7u8; 16];
        tid[0] = 41u8;
        let got = index.read().unwrap().get_trace(&tid).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq_no, 41);

        drop(sink);
        writer.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn flush_acks_after_drain() {
        let dir = tmpdir("flush");
        let cfg = WriterConfig {
            data_dir: dir.clone(),
            channel_cap: 1024,
            sync_interval: Duration::from_millis(5),
            ..WriterConfig::default()
        };
        let (sink, index, writer) = spawn_writer(cfg);
        for seq in 0..500u64 {
            sink.try_send(rec([3u8; 16], seq));
        }
        let total = sink.flush().await;
        assert_eq!(total, 500);
        let st = index.read().unwrap().stats();
        assert_eq!(st.frames, 500);
        assert_eq!(sink.dropped(), 0);
        drop(sink);
        writer.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn log_records_indexed_as_telemetry() {
        let dir = tmpdir("telemetry");
        let cfg = WriterConfig {
            data_dir: dir.clone(),
            ..WriterConfig::default()
        };
        let (sink, index, writer) = spawn_writer(cfg);
        let log = TraceRecord::new(
            [11u8; 16],
            sink.next_seq(),
            RecordPayload::TelemetryLog(TelemetryLog {
                level: 5,
                service: "api".into(),
                message: "boom".into(),
                attributes: vec![],
            }),
        );
        sink.try_send(log);
        sink.flush().await;
        let idx = index.read().unwrap();
        assert_eq!(idx.stats().sentry_crashes, 0);
        assert_eq!(idx.stats().frames, 1);
        drop(idx);
        drop(sink);
        writer.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
