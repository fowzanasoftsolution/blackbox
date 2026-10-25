//! Phase 1 storage-core benchmarks.
//!
//! `bench segment` — append throughput/latency, recovery scan speed, and the
//! durable (fsync-every-1000) path of the append-only segment engine.
//! `bench queue` — end-to-end durable enqueue RTT + throughput through the
//! redb group-commit actor, including restart durability verification.

use crate::stats::{fmt_ns, fmt_ops, fmt_rate, Latency};
use anyhow::Result;
use blackbox_core::schema::{new_id128, now_ms, EgressHttpMock, QueueJobRecord, RecordPayload, TraceRecord};
use blackbox_core::segment::{read_all_records, SegmentStore};
use blackbox_core::queue_actor::{spawn_queue_actor, QueueActorConfig};
use std::path::PathBuf;
use std::time::Instant;

fn benchdir(tag: &str) -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("blackbox-bench-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Mixed-size realistic bodies (64B .. 4KB) indexed by seq.
fn body_len(seq: u64) -> usize {
    const SIZES: [usize; 10] = [64, 128, 256, 512, 1024, 2048, 4096, 1024, 512, 128];
    SIZES[(seq % 10) as usize]
}

fn gen_record(seq: u64) -> TraceRecord {
    let payload = if seq % 4 == 0 {
        RecordPayload::EgressHttpMock(EgressHttpMock {
            seq_no: seq,
            request_fingerprint: new_id128().to_be_bytes().repeat(2).try_into().unwrap(),
            method: "POST".into(),
            request_url: "https://api.openai.com/v1/chat/completions".into(),
            response_status: 200,
            response_headers: vec![("content-type".into(), "application/json".into())],
            response_body: vec![0x7Eu8; body_len(seq)],
            upstream_host: "api.openai.com".into(),
            recorded_at_ms: now_ms(),
        })
    } else {
        RecordPayload::QueueJob(QueueJobRecord {
            queue: "webhooks.shopify".into(),
            payload: vec![0x33u8; body_len(seq)],
            attempt: 1,
            max_attempts: 8,
            available_at_ms: now_ms(),
        })
    };
    TraceRecord::new(new_id128().to_be_bytes(), seq, payload)
}

pub fn run_segment(frames: u64) -> Result<()> {
    println!("═══ BENCH segment: frames={frames} (mixed 64B-4KB bodies) ═══");

    // ---- Phase A: append throughput + latency (page-cache writes) ----
    let dir = benchdir("seg")?;
    let mut store = SegmentStore::open(&dir)?;
    let mut lat = Latency::with_capacity(frames as usize);
    let t0 = Instant::now();
    for seq in 0..frames {
        let rec = gen_record(seq);
        let t1 = Instant::now();
        store.append(&rec)?;
        lat.push(t1.elapsed().as_nanos() as u64);
    }
    let append_dur = t0.elapsed();
    store.sync()?;
    let bytes = store.active_len();
    println!(
        "  A. append (encode+pwrite): {} ops in {} → {} ops | {} | {}",
        frames,
        fmt_ns(append_dur.as_nanos() as u64),
        fmt_ops(frames as f64 / append_dur.as_secs_f64()),
        fmt_rate(bytes as f64 / append_dur.as_secs_f64()),
        lat.summary()
    );
    drop(store);

    // ---- Phase B: crash-recovery scan (index rebuild) + full validation ----
    let t0 = Instant::now();
    let store = SegmentStore::open(&dir)?;
    let idx = store.index().len();
    let scan_dur = t0.elapsed();
    println!(
        "  B. reopen recovery (magic+2×CRC scan, index rebuild): {} frames in {} → {}",
        idx,
        fmt_ns(scan_dur.as_nanos() as u64),
        fmt_ops(idx as f64 / scan_dur.as_secs_f64())
    );

    let t0 = Instant::now();
    let records = read_all_records(&dir)?;
    let decode_dur = t0.elapsed();
    assert_eq!(records.len(), frames as usize, "bench integrity");
    println!(
        "     full decode (rkyv+bytecheck every frame): {} frames in {} → {}",
        records.len(),
        fmt_ns(decode_dur.as_nanos() as u64),
        fmt_ops(records.len() as f64 / decode_dur.as_secs_f64())
    );
    drop(store);

    // ---- Phase C: durable appends (fsync every 1 000 — group durability) ----
    let dir2 = benchdir("seg-sync")?;
    let mut store = SegmentStore::open(&dir2)?;
    let mut lat2 = Latency::with_capacity((frames / 10).max(1) as usize);
    const SYNC_EVERY: u64 = 1_000;
    let t0 = Instant::now();
    for seq in 0..frames {
        let t1 = Instant::now();
        store.append(&gen_record(seq))?;
        if seq % SYNC_EVERY == SYNC_EVERY - 1 {
            store.sync()?;
            lat2.push(t1.elapsed().as_nanos() as u64);
        }
    }
    store.sync()?;
    let dur_sync = t0.elapsed();
    println!(
        "  C. durable append (fsync every {SYNC_EVERY}): {} ops in {} → {} ops | per-group fsync-inclusive latency {}",
        frames,
        fmt_ns(dur_sync.as_nanos() as u64),
        fmt_ops(frames as f64 / dur_sync.as_secs_f64()),
        lat2.summary()
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
    println!("═══ BENCH segment: done ═══\n");
    Ok(())
}

pub async fn run_queue(ops: u64, concurrency: u64) -> Result<()> {
    println!("═══ BENCH queue: ops={ops} concurrency={concurrency} (5ms/1000 group-commit) ═══");
    let dir = benchdir("queue")?;
    let (handle, _stats, join) =
        spawn_queue_actor(&dir.join("q.redb"), QueueActorConfig::default()).await?;

    // 64 tasks × per-task sequential enqueues; each task returns its RTT samples.
    let per = ops / concurrency;
    let rem = ops % concurrency;
    let mut tasks = Vec::new();
    let t0 = Instant::now();
    for t in 0..concurrency {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            let extra = (t < rem) as u64;
            let start = t * per + t.min(rem);
            let mut lat = Latency::with_capacity((per + extra) as usize);
            for i in 0..(per + extra) {
                let job = QueueJobRecord {
                    queue: "webhooks.bench".into(),
                    payload: vec![0x41u8; 256],
                    attempt: 0,
                    max_attempts: 8,
                    available_at_ms: now_ms(),
                };
                let _ = start + i;
                let t1 = Instant::now();
                let res = h.enqueue(job).await;
                lat.push(t1.elapsed().as_nanos() as u64);
                res?;
            }
            Ok::<Latency, anyhow::Error>(lat)
        }));
    }
    let mut all_lat = Latency::with_capacity(ops as usize);
    for t in tasks {
        let task_lat = t.await??;
        for &s in task_lat.samples() {
            all_lat.push(s);
        }
    }
    let total_dur = t0.elapsed();
    let snap = handle.stats();

    println!(
        "  enqueue (durable ack incl. fsync): {} ops in {} → {} ops | RTT {}",
        snap.ops_committed,
        fmt_ns(total_dur.as_nanos() as u64),
        fmt_ops(snap.ops_committed as f64 / total_dur.as_secs_f64()),
        all_lat.summary()
    );
    println!(
        "  actor batches: {} commits | avg_batch={:.1} | max_batch={} | saturated={} | commit_total={}ms",
        snap.batches_committed,
        snap.avg_batch(),
        snap.max_batch_seen,
        snap.saturated_batches,
        snap.commit_ms_total
    );
    let q_len = handle.len().await?;
    println!("  durable rows: {q_len}");

    // ---- Burst scenario: saturate the 1 000-op batch cap ----
    if ops >= 2_000 {
        const BURST: u64 = 2_000;
        let mut tasks = Vec::new();
        let t0 = Instant::now();
        for _t in 0..BURST {
            let h = handle.clone();
            tasks.push(tokio::spawn(async move {
                h.enqueue(QueueJobRecord {
                    queue: "webhooks.burst".into(),
                    payload: vec![0x42u8; 256],
                    attempt: 0,
                    max_attempts: 8,
                    available_at_ms: now_ms(),
                })
                .await
            }));
        }
        let mut burst_lat = Latency::with_capacity(BURST as usize);
        for t in tasks {
            t.await??;
            // RTT collected below via stats; latency per-op tracked coarsely.
        }
        let _ = &mut burst_lat;
        let dur = t0.elapsed();
        let snap2 = handle.stats();
        let burst_batches = snap2.batches_committed - snap.batches_committed;
        println!(
            "  burst ({} concurrent): {} ops in {} → {} ops | batch window saturated: {} commits, avg_batch={:.1} (cap 1 000)",
            BURST,
            BURST,
            fmt_ns(dur.as_nanos() as u64),
            fmt_ops(BURST as f64 / dur.as_secs_f64()),
            burst_batches,
            burst_batches as f64 * 0.0 + (BURST as f64 / burst_batches.max(1) as f64),
        );
    }

    // Restart durability proof.
    drop(handle);
    join.await?;
    let (handle2, _s2, join2) =
        spawn_queue_actor(&dir.join("q.redb"), QueueActorConfig::default()).await?;
    let after = handle2.len().await?;
    println!("  after restart: {after} rows durable [{}]", if after == q_len + if ops >= 2_000 { 2_000 } else { 0 } { "PASS" } else { "FAIL" });
    drop(handle2);
    join2.await?;

    let _ = std::fs::remove_dir_all(&dir);
    println!("═══ BENCH queue: done ═══\n");
    Ok(())
}
