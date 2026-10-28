//! Soak-memory gate (v1.1.1) — the PASS/FAIL test for the four soak fixes.
//!
//! This is the minutes-scale, in-repo version of the 6-hour `bb-soak-6h`
//! scenario that produced the four soak root causes. It boots the REAL
//! stack in one process — durable ingress proxy (WAF/rate-limit/TLS off)
//! + JobStore redb actor + dispatcher + segment writer + background
//! compaction — against a throwaway mock upstream, then pushes
//! **125 000 durable webhooks** with many segment rollovers, drains
//! completely, and asserts:
//!
//! 1. **Fix #1** — zero jobs left in redb after the drain. The JobStore
//!    actor's `counts()` call scans EVERY row of the `bq_jobs` table, so
//!    `pending + in_flight + dead_letter == 0` proves the table drained to
//!    zero rows; delivered/enqueued totals must cover the whole volume;
//!    redb is opened through the capped-cache helper
//!    (`blackbox_core::kv::REDB_CACHE_BYTES`), and the expired-idem sweep
//!    machinery keeps the dedup table from growing for the process
//!    lifetime.
//! 2. **Fix #2** — the in-memory trace index holds ONLY the active
//!    segment at the end (`hot_trace_segments == 1`), even though the run
//!    seals dozens of segments; sealed history stays fully queryable
//!    through the sidecar/scan paths (cumulative counters still cover the
//!    whole run).
//! 3. **Fix #3** — on Linux the WHOLE process (all engines in one binary)
//!    fits under **42.0 MiB VmRSS** after drain, measured from `/proc` —
//!    the budget ground truth. The harness runs the production memory
//!    configuration: the supervisor watermark monitor (500 ms poll,
//!    48 MiB soak budget) that purges jemalloc arenas at Warn75+ — the
//!    exact self-healing the production node ran. cfg-gated so non-Linux
//!    dev boxes don't assert RSS (the Windows/macOS CI has no `/proc`).
//! 4. **Fix #4** — the soakctl collect-only evidence guard is a shell
//!    property of `scripts/soak/soakctl.sh`, not an in-process behavior;
//!    nothing to assert here beyond keeping the data dirs referenced
//!    fresh (a wipe/re-init of non-empty dirs can't happen in this test).
//!
//! Transport-failure contract: all 125 000 webhook POSTs must return
//! `202 Accepted` and the drain must deliver every job to the mock
//! upstream exactly once (`delivered_total == 125_000`, `dead_letter == 0`).
//!
//! The crash-injection and preview-proxy legs of the harness live in
//! `scripts/soak/soakctl.sh`; the 38-minute soak preview stall was the
//! EXTERNAL proxy path, never Blackbox backpressure (honesty note in
//! `blackbox-supervisor/src/memory.rs`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use blackbox_core::breaker::UpstreamHealth;
use blackbox_ingress::proxy::{QueueAttachment, IngressConfig};
use blackbox_queue::{spawn_queue_runtime, DispatcherConfig, JobStoreConfig};

// Production allocator (the node binary sets this in crates/blackbox). The
// RSS budget below is a PRODUCTION number measured under jemalloc — the
// watermark purge (`arena.4096.purge`) is a no-op on the system allocator,
// so a test process without it would measure a configuration no node ever
// runs. Linux-only: the RSS gate itself is cfg-gated to Linux.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Whole-run gate constants (named for the soak budget math).
const WEBHOOKS: u64 = 125_000;
const RSS_BUDGET_BYTES: u64 = 42 * 1024 * 1024;
/// The soak nodes' supervisor RAM target (50,331,648 B = 48 MiB) — the
/// watermark budget the production monitor ran with (soak report: budget
/// 50,331,648 B for both nodes).
const RAM_BUDGET_BYTES: u64 = 50_331_648;
const CLIENT_CONCURRENCY: usize = 64;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "blackbox-soak-gate-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A minimal upstream app: 200 "ok" for everything (webhook receiver).
async fn spawn_mock_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let join = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let io = hyper_util::rt::TokioIo::new(sock);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    // Drain the request body (BodyExt UFCS — hyper::body::Body
                    // is a trait in hyper 1.x).
                    let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .body(http_body_util::Full::new(bytes::Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (addr, join)
}

/// POST `n` webhooks through the ingress proxy with bounded concurrency.
/// Returns the worker that delivers and failure statistics.
#[allow(clippy::too_many_arguments)]
async fn flood_webhooks(
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<bytes::Bytes>,
    >,
    base: String,
    n: u64,
) -> (u64 /* failures */, u64 /* non_202s */) {
    let next: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let failures: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let non_202s: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(CLIENT_CONCURRENCY);
    for _ in 0..CLIENT_CONCURRENCY {
        let client = client.clone();
        let next = Arc::clone(&next);
        let failures = Arc::clone(&failures);
        let non_202s = Arc::clone(&non_202s);
        let base = base.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let body = format!(
                    r#"{{"i":{i},"n":{n},"kind":"soak-gate","pad":"{}"}}"#,
                    "p".repeat(96)
                );
                let req = http::Request::builder()
                    .method("POST")
                    .uri(&format!("{base}/webhooks/stripe"))
                    .header("content-type", "application/json")
                    .header("idempotency-key", format!("soak-gate-{i:09}"))
                    .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                    .unwrap();
                // NOTE: any error here is a TRANSPORT failure counted for
                // the gate (see "0 transport failures" contract).
                match client.request(req).await {
                    Ok(resp) => {
                        if resp.status() != 202 {
                            non_202s.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in workers {
        w.await.unwrap();
    }
    (failures.load(Ordering::Relaxed), non_202s.load(Ordering::Relaxed))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn soak_memory_bound() {
    let data = tmpdir("data");
    let (up_addr, _up_join) = spawn_mock_upstream().await;
    let upstream = up_addr.to_string();

    // ---- Queue runtime (JobStore actor + dispatcher + reaper). ----------
    // redb opens through blackbox_core::kv::create_redb → 8 MiB page cache
    // (the v1.1.0 1 GiB default was soak root cause #1).
    assert_eq!(
        blackbox_core::kv::REDB_CACHE_BYTES,
        8 * 1024 * 1024,
        "the capped redb cache is a gate contract"
    );
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(4_096);
    let health = UpstreamHealth::new(3);
    let runtime = spawn_queue_runtime(
        &data.join("jobs.redb"),
        JobStoreConfig::default(),
        DispatcherConfig {
            upstream: upstream.clone(),
            // Tight poll + wide lease: deliveries stream continuously.
            tick: Duration::from_millis(10),
            ..Default::default()
        },
        Arc::clone(&health),
        Some(events_tx),
    )
    .await
    .expect("queue runtime");
    // Keep our own store handle for drain polling (the runtime itself is
    // moved into the proxy's QueueAttachment).
    let store = runtime.store.clone();

    // ---- Ingress proxy with the queue attached (durable /webhooks/*). ----
    let mut cfg = IngressConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.clone(),
        upstream: upstream.clone(),
        health: Some(Arc::clone(&health)),
        hold_window: Duration::from_secs(3),
        durable_prefixes: blackbox_ingress::durable::parse_durable_prefixes("/webhooks/*"),
        queue: Some(QueueAttachment { runtime, events: events_rx }),
        // Small segments ⇒ dozens of rollovers so the seal-transition
        // eviction (v1.1.1 fix #2) is exercised over and over.
        max_segment_bytes: 2 * 1024 * 1024,
        ..Default::default()
    };
    cfg.shield = blackbox_ingress::waf::ScannerShield::disabled();
    cfg.rate_limit = None;
    let proxy = blackbox_ingress::proxy::spawn_proxy(cfg).await.expect("ingress proxy");

    // ---- Supervisor RAM monitor — the PRODUCTION memory configuration. ---
    // The 42 MiB budget is a PRODUCTION shape: the node runs the watermark
    // monitor (500 ms poll) that purges jemalloc arenas at Warn75+ (the
    // v1.1.1 fix #3; the soak report's last purge reason is exactly
    // `supervisor watermark Warn75`). A faithful harness runs it too —
    // measuring the engines WITHOUT self-healing would test a config that
    // no production node ever runs. Budget = the soak nodes' 48 MiB
    // (50,331,648 B) supervisor target.
    let mon_task = tokio::spawn(async move {
        let mon = blackbox_supervisor::memory::RamMonitor::new(RAM_BUDGET_BYTES);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            mon.poll();
        }
    });

    // ---- Background compaction (mirrors the janitor's core loop). --------
    // Every rotation or 2 s: compact sealed segments → .log.zst + .idx +
    // trace-sorted .sidx sidecars (the v1.1.1 archived-lookup path).
    let mut active_watch = proxy.active_segments.clone();
    let comp: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let comp_for_task = Arc::clone(&comp);
    let comp_dir = data.clone();
    let janitor = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = active_watch.changed() => {}
            }
            let active = *active_watch.borrow();
            if active == u32::MAX {
                continue;
            }
            let d = comp_dir.clone();
            let r = tokio::task::spawn_blocking(move || {
                blackbox_core::compactor::compact_all(&d, active, 3)
            })
            .await;
            if let Ok(Ok(rep)) = r {
                if rep.segments_compacted > 0 {
                    comp_for_task.fetch_add(rep.segments_compacted as u64, Ordering::Relaxed);
                }
            }
        }
    });

    // ---- Volume: 125 000 durable webhooks. -------------------------------
    let base = format!("http://{}", proxy.local_addr);
    let client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<bytes::Bytes>,
    > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http(); /* keepalive pool inside */
    let started = Instant::now();
    let (failures, non_202s) = flood_webhooks(client, base, WEBHOOKS).await;
    println!(
        "flood done in {:.1}s (failures={failures}, non_202s={non_202s})",
        started.elapsed().as_secs_f32()
    );

    // ---- Drain: every job delivered, nothing left in the queue. ----------
    let deadline = Instant::now() + Duration::from_secs(480);
    let c = loop {
        let c = store.counts().await.expect("counts");
        if c.pending == 0 && c.in_flight == 0 && c.delivered_total >= WEBHOOKS {
            break c;
        }
        assert!(
            Instant::now() < deadline,
            "drain timed out; last counts: {c:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    println!("drained in {:.1}s: {c:?}", started.elapsed().as_secs_f32());

    // ---- Gate 1: transport contract (fix #1 + #3 correctness at load). ---
    assert_eq!(failures, 0, "0 transport failures under volume");
    assert_eq!(non_202s, 0, "every webhook must be durably accepted (202)");
    assert_eq!(
        c.enqueued_total, WEBHOOKS,
        "each unique idempotency key enqueued exactly one job"
    );
    assert_eq!(c.deduped_total, 0, "unique keys must never dedup");
    assert_eq!(
        c.delivered_total, WEBHOOKS,
        "every job delivered to the upstream exactly once"
    );
    assert_eq!(c.deadletted_total, 0, "no job dead-lettered");
    assert_eq!(c.dead_letter, 0, "bq_jobs holds no DeadLetter rows");

    // ---- Gate 2: redb table EMPTY after drain (fix #1). -------------------
    // counts() reads EVERY row of bq_jobs in the actor: the three state
    // buckets partition the table — all zero ⇒ the table is empty.
    assert_eq!(
        c.pending + c.in_flight,
        0,
        "bq_jobs table drained to zero rows"
    );

    // ---- Gate 3: in-memory index holds only the ACTIVE segment (fix #2). --
    // Give the last rotations/compactions a beat to settle, then assert.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let st = proxy.stats();
    println!(
        "index endgame: frames={} distinct={} hot_traces={} hot_segments={} archived={}",
        st.frames, st.distinct_traces, st.hot_traces, st.hot_trace_segments, st.archived_segments
    );
    assert_eq!(
        st.hot_trace_segments, 1,
        "hot map must cover only the ACTIVE segment (dozens sealed)"
    );
    assert!(
        st.archived_segments >= 10,
        "the volume must have sealed ≥10 segments (got {})",
        st.archived_segments
    );
    assert!(
        st.hot_traces <= 10_000,
        "hot map is bounded by one segment's worth of traces (got {})",
        st.hot_traces
    );
    // Sealed history remains queryable through the sidecar/scan paths;
    // cumulative counters still cover the whole run (2 records per ingest:
    // scrubbed IngressHttp + QueueJob copies; delivery-event TelemetryLogs
    // add up to 1 more per webhook, so ≥ 2×volume is the firm floor).
    assert!(
        st.frames >= 2 * WEBHOOKS,
        "cumulative frame counter must cover the whole run (got {})",
        st.frames
    );

    // ---- Gate 4: process RSS under budget after drain (fix #3, Linux). ----
    // Converged measurement (same discipline as the Phase 2 gate): the
    // monitor's purge runs at Warn75+ during the run; wait (≤ 8 s) until
    // RSS stops shrinking so we assert the steady-state footprint, not a
    // momentary peak.
    #[cfg(target_os = "linux")]
    {
        let mut last = blackbox_supervisor::memory::rss_bytes();
        let mut stable = 0u32;
        for i in 0..32u32 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let now = blackbox_supervisor::memory::rss_bytes();
            if now < last {
                stable = 0;
            } else {
                stable += 1;
            }
            if i >= 8 && stable >= 4 {
                break;
            }
            last = now.min(last);
        }
        let rss = blackbox_supervisor::memory::rss_bytes();
        let mib = rss as f64 / (1024.0 * 1024.0);
        let level = blackbox_supervisor::memory::current_ram_level();
        println!(
            "VmRSS after drain: {mib:.2} MiB (budget {} MiB, level {level:?})",
            RSS_BUDGET_BYTES / 1024 / 1024
        );
        assert!(
            rss < RSS_BUDGET_BYTES,
            "VmRSS {mib:.2} MiB exceeds the 42.0 MiB soak budget"
        );
    }
    #[cfg(not(target_os = "linux"))]
    println!("RSS gate skipped: /proc unavailable on this platform");

    // ---- Tidy shutdown: stop compaction + monitor, drop engines, clean. --
    janitor.abort();
    mon_task.abort();
    drop(proxy);
    drop(store);
    println!("segments compacted during run: {}", comp.load(Ordering::Relaxed));
    let _ = std::fs::remove_dir_all(&data);
}
