//! Internal child modes: `write-loop` (crash harness victim) and
//! `heartbeat-child` (watchdog demo subject).

use anyhow::Result;
use blackbox_core::schema::{new_id128, now_ms, QueueJobRecord, RecordPayload, TraceRecord};
use blackbox_core::segment::SegmentStore;
use std::path::PathBuf;
use std::time::Instant;

/// Append `records` frames to a fresh segment store as fast as possible,
/// fsyncing every `sync_every` frames. Never exits early — the harness
/// SIGKILLs it mid-flight; whatever lands on disk is the crash artifact.
pub fn write_loop(dir: PathBuf, records: u64, sync_every: u64) -> Result<()> {
    let mut store = SegmentStore::open(&dir)?;
    let t0 = Instant::now();
    for seq in 0..records {
        let payload = RecordPayload::QueueJob(QueueJobRecord {
            queue: "webhooks.kill9".into(),
            payload: vec![0x99u8; 160],
            attempt: 0,
            max_attempts: 8,
            available_at_ms: now_ms(),
        });
        let rec = TraceRecord::new(new_id128().to_be_bytes(), seq, payload);
        store.append(&rec)?;
        if seq % sync_every == sync_every - 1 {
            store.sync()?;
        }
    }
    store.sync()?;
    eprintln!(
        "write-loop done: {records} records in {}ms",
        t0.elapsed().as_millis()
    );
    Ok(())
}

/// Child-side heartbeat: connect to the supervisor socket and beat forever.
pub async fn heartbeat_child(socket: PathBuf) -> Result<()> {
    blackbox_supervisor::watchdog::heartbeat_client(
        socket,
        std::time::Duration::from_millis(500),
    )
    .await?;
    Ok(())
}
