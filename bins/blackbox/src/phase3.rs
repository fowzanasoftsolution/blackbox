//! Phase 3 CLI plumbing: full node assembly for `serve`, the deterministic
//! replay launcher, and the offline queue admin commands.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// One shared circuit breaker across ingress + queue + interceptor.
pub fn shared_breaker(threshold: u32) -> Arc<blackbox_core::breaker::UpstreamHealth> {
    blackbox_core::breaker::UpstreamHealth::new(threshold)
}

/// (Superseded by phase4::serve — kept for reference / quick rollback.)
#[allow(dead_code)]
pub async fn serve(
    listen: String,
    upstream: String,
    data: PathBuf,
    webhooks: String,
    hold_ms: u64,
    egress_listen: String,
) -> Result<()> {
    let health = shared_breaker(3);

    // Queue runtime (dispatcher + reaper + JobStore actor).
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(4_096);
    let dispatcher_cfg = blackbox_queue::DispatcherConfig {
        upstream: upstream.clone(),
        ..Default::default()
    };
    let runtime = blackbox_queue::spawn_queue_runtime(
        &data.join("jobs.redb"),
        blackbox_queue::JobStoreConfig::default(),
        dispatcher_cfg,
        Arc::clone(&health),
        Some(events_tx),
    )
    .await
    .context("spawn queue runtime")?;

    // Egress record interceptor (forward-proxy listener).
    let sink_ref: Arc<dyn Fn(blackbox_core::schema::TraceRecord) + Send + Sync> = {
        // The interceptor is spawned by replay/serve via blackbox_queue; here we
        // only print its address — recording goes through the ingress writer.
        // (Records are emitted by the interceptor's emit callback below.)
        Arc::new(|_| {})
    };
    let _ = sink_ref; // placeholder — the real emit is wired to the proxy sink below

    let proxy_cfg = blackbox_ingress::proxy::IngressConfig {
        listen: listen.parse()?,
        data_dir: data.clone(),
        upstream: upstream.clone(),
        health: Some(Arc::clone(&health)),
        hold_window: Duration::from_millis(hold_ms),
        durable_prefixes: blackbox_ingress::durable::parse_durable_prefixes(&webhooks),
        queue: Some(blackbox_ingress::proxy::QueueAttachment {
            runtime,
            events: events_rx,
        }),
        ..Default::default()
    };

    // The egress interceptor records into the SAME segment store through the
    // proxy's writer sink. The proxy handle exposes it only after spawn — so
    // spawn the proxy first, then attach the interceptor with a closure over
    // the sink.
    let handle = blackbox_ingress::proxy::spawn_proxy(proxy_cfg).await?;
    let interceptor = blackbox_queue::interceptor::spawn_interceptor(blackbox_queue::interceptor::InterceptorConfig {
        listen: egress_listen.parse()?,
        mode: Arc::new(blackbox_queue::interceptor::InterceptorMode::Record {
            emit: {
                let sink = handle.sink.clone();
                Arc::new(move |mut rec: blackbox_core::schema::TraceRecord| {
                    rec.seq_no = sink.next_seq();
                    sink.try_send(rec);
                })
            },
        }),
    })
    .await
    .context("spawn egress interceptor")?;

    println!(
        "blackbox node listening on http://{} (upstream {})",
        handle.local_addr, upstream
    );
    println!("  telemetry:  /api/{{project}}/envelope/  /v1/traces  /v1/logs");
    println!("  durable:    webhook routes get 202 + x-blackbox-job-id (dispatcher armed)");
    println!(
        "  egress:     set HTTP_PROXY=http://{} on your app to record outgoing calls",
        interceptor.local_addr
    );
    println!("  data:       {} (segments + jobs.redb)", data.display());
    println!("  Ctrl-C to stop");
    std::future::pending::<()>().await;
    Ok(())
}

/// `blackbox replay <trace_id> --target <url>` — deterministic sandbox.
pub async fn replay(
    trace_hex: String,
    target: String,
    data: PathBuf,
    listen: String,
    egress: String,
) -> Result<()> {
    let trace_id = blackbox_core::schema::parse_trace_hex(trace_hex.trim())
        .context("trace id must be 32 hex chars")?;

    // Phase 6: when the cold tier is configured, transparently restore the
    // trace's segment if it was FIFO-evicted (or bit-rotted) BEFORE loading
    // the replay engine — time-travel replay reads through S3/R2.
    if let Some(cfg) = blackbox_cold::S3Config::from_env() {
        if let Ok(cold) = blackbox_cold::ColdTier::open(cfg, &data) {
            match cold.restore_trace(&data, &trace_id) {
                Ok(Some(records)) => println!(
                    "cold tier: {} record(s) for {} restored from S3/R2 (or already local)",
                    records.len(),
                    trace_hex.trim()
                ),
                _ => {}
            }
        }
    }

    let engine = blackbox_queue::ReplayEngine::load(&data, &trace_id)
        .context("load recorded egress mocks")?;
    if engine.is_empty() {
        anyhow::bail!(
            "no recorded EgressHttpMock frames for trace {} in {}",
            trace_hex,
            data.display()
        );
    }
    println!(
        "replay trace {}: {} recorded egress call(s) loaded",
        trace_hex,
        engine.total()
    );

    // Sandbox interceptor: serves recorded responses, blocks the rest (428).
    let interceptor = blackbox_queue::interceptor::spawn_interceptor(blackbox_queue::interceptor::InterceptorConfig {
        listen: egress.parse()?,
        mode: Arc::new(blackbox_queue::interceptor::InterceptorMode::Mock {
            engine: Arc::new(engine),
        }),
    })
    .await?;

    // Replay ingress: forces every request onto the replay trace id.
    let proxy_cfg = blackbox_ingress::proxy::IngressConfig {
        listen: listen.parse()?,
        data_dir: data.clone(),
        upstream: target.clone(),
        health: Some(shared_breaker(3)),
        replay_trace: Some(trace_id),
        ..Default::default()
    };
    let handle = blackbox_ingress::proxy::spawn_proxy(proxy_cfg).await?;

    println!("replay proxy listening on http://{} (target {})", handle.local_addr, target);
    println!("  1) restart your app with the bug fixed, pointed at the replay proxy");
    println!(
        "  2) route its outgoing calls through HTTP_PROXY=http://{} (mock Stripe/Twilio...)",
        interceptor.local_addr
    );
    println!("  3) re-send the original request — unrecorded egress gets 428-blocked");
    println!("  Ctrl-C to stop");
    std::future::pending::<()>().await;
    Ok(())
}

/// `blackbox queue status` — offline redb inspection.
pub async fn queue_status(data: PathBuf) -> Result<()> {
    let db = data.join("jobs.redb");
    if !db.exists() {
        anyhow::bail!("no queue database at {} — is the data dir right?", db.display());
    }
    let counts = tokio::task::spawn_blocking(move || {
        blackbox_queue::admin::read_counts_blocking(&db)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))??;

    let db2 = data.join("jobs.redb");
    let breakdown = tokio::task::spawn_blocking(move || {
        blackbox_queue::admin::queue_breakdown(&db2)
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))??;

    println!("blackbox queue status ({})", data.display());
    println!(
        "  pending: {} | in_flight: {} | dead_letter: {}",
        counts.pending, counts.in_flight, counts.dead_letter
    );
    println!(
        "  lifetime: enqueued {} (deduped {}) | delivered {} | dead-lettered {} | reaped {}",
        counts.enqueued_total, counts.deduped_total, counts.delivered_total,
        counts.deadletted_total, counts.reaped_total
    );
    if !breakdown.is_empty() {
        println!("  per-queue:");
        for (q, p, f, d) in breakdown {
            println!("    {q}: pending={p} in_flight={f} dead_letter={d}");
        }
    }
    Ok(())
}

/// `blackbox queue retry-dlq` — 1-click requeue of every dead-lettered job.
pub async fn queue_retry_dlq(data: PathBuf) -> Result<()> {
    let db = data.join("jobs.redb");
    if !db.exists() {
        anyhow::bail!("no queue database at {} — is the data dir right?", db.display());
    }
    let n = tokio::task::spawn_blocking(move || blackbox_queue::admin::retry_dlq_blocking(&db))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    println!("requeued {n} dead-lettered job(s) from the DLQ");
    Ok(())
}
