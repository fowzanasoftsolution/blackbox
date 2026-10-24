//! Closed-loop enqueue latency bench (isolates the JobStore actor).

use blackbox_queue::model::DurableJob;
use blackbox_queue::{spawn_job_store, JobStoreConfig};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_loop_enqueue_latency() {
    let dir = std::env::temp_dir().join(format!("bq-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (h, stats, join) = spawn_job_store(
        &dir.join("q.redb"),
        JobStoreConfig { batch_window: Duration::from_millis(1), ..Default::default() },
    )
    .await
    .unwrap();

    let tasks_env: u64 = std::env::var("BENCH_TASKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);
    let rounds_env: u64 = std::env::var("BENCH_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let (TASKS, ROUNDS) = (tasks_env, rounds_env);
    let mut lats = Vec::new();
    let mut tasks = Vec::new();
    for t in 0..TASKS {
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            let mut lats = Vec::new();
            for i in 0..ROUNDS {
                let n = t * ROUNDS + i;
                let job = DurableJob::new_pending(
                    blackbox_core::schema::new_id128(),
                    [7u8; 16],
                    "webhooks.stripe".into(),
                    "POST".into(),
                    "/webhooks/stripe".into(),
                    vec![("stripe-signature".into(), "t=1,v1=deadbeef".into())],
                    format!(r#"{{"event":{n},"type":"invoice.paid","amount":1234}}"#).into_bytes(),
                    format!("evt-{n}"),
                    10,
                );
                let t0 = Instant::now();
                h.enqueue(job).await.unwrap();
                lats.push(t0.elapsed().as_micros() as u64);
            }
            lats
        }));
    }
    for task in tasks {
        lats.extend(task.await.unwrap());
    }
    lats.sort_unstable();
    let n = lats.len();
    println!(
        "enqueue closed-loop: n={n} p50={}us p99={}us p999={}us max={}us",
        lats[n / 2],
        lats[(n as f64 * 0.99) as usize],
        lats[(n as f64 * 0.999) as usize],
        lats[n - 1]
    );
    let (b, o, avg_b, avg_ms, total_ms) = stats.snapshot_stats();
    println!(
        "actor: batches={b} ops={o} avg_batch={avg_b:.0} avg_commit_ms={avg_ms:.2} total_commit_ms={total_ms}"
    );
    drop(h);
    join.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
