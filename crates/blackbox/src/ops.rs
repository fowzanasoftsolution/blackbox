//! Operational command plumbing: the deterministic replay launcher, the
//! offline queue administration commands, the shared circuit breaker and
//! the injectable-env stand-in app behind `blackbox env-child`.

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use std::sync::Arc;

/// One shared circuit breaker across ingress + queue + interceptor.
pub fn shared_breaker(threshold: u32) -> Arc<blackbox_core::breaker::UpstreamHealth> {
    blackbox_core::breaker::UpstreamHealth::new(threshold)
}

/// `blackbox replay <trace_id> --target <url>` — deterministic sandbox.
///
/// v1.0.3 concurrent-replay hardening: this runs WHILE `blackbox serve` /
/// `blackbox run` is live and holding the redb locks, because the developer
/// is single-terminal. When the data dir is locked by a live node (probe:
/// `DatabaseAlreadyOpen` on any `*.redb`) — or whenever `--data-copy` is
/// passed — the whole dir is cloned into an ephemeral scratch copy:
/// immutable cold artifacts (`.zst` / `.idx`) are HARDLINKED, everything the
/// replay may mutate (the active `.log` segments, every `*.redb`) is really
/// copied, and every replay-side touch (cold-tier restore for FIFO-evicted
/// traces, the replay proxy's own segment recording) happens in that scratch
/// dir. The live node is never written and is never asked for the lock.
pub async fn replay(
    trace_hex: String,
    target: String,
    data: PathBuf,
    listen: String,
    egress: String,
    data_copy: bool,
) -> Result<()> {
    let trace_id = blackbox_core::schema::parse_trace_hex(trace_hex.trim())
        .context("trace id must be 32 hex chars")?;

    let locked = !data_copy && blackbox_queue::admin::data_dir_locked(&data);
    let data = if data_copy || locked {
        let scratch = copy_data_dir_scratch(&data)
            .context("data-copy: cloning the data dir for an isolated replay")?;
        let why = if locked {
            "live node redb lock detected — automatic fallback"
        } else {
            "--data-copy requested"
        };
        println!(
            "data-copy: cloned {} -> {} ({})",
            data.display(),
            scratch.display(),
            why
        );
        println!("  (replay-side heals/records go here — delete any time)");
        scratch
    } else {
        data
    };

    // Audit chain: for a live-locked replay this is the SCRATCH copy — every
    // replay event extends the copied chain there; the live node is never
    // touched (v1.0.3 discipline, now v1.1-compliant audit records too).
    let _ = blackbox_core::audit::init(&data);
    blackbox_core::audit::record(
        "replay",
        "start",
        &blackbox_core::schema::trace_id_to_hex(&trace_id),
        &format!("target={target}"),
    );

    // Phase 6: when the cold tier is configured, transparently restore the
    // trace's segment if it was FIFO-evicted (or bit-rotted) BEFORE loading
    // the replay engine — time-travel replay reads through S3/R2. With the
    // scratch copy in place this heals the SCRATCH dir only.
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

/// Ephemeral scratch clone of a data dir for isolated replay.
///
/// File classification:
/// * `.zst` / `.idx` — sealed, immutable cold artifacts → HARDLINK (unix;
///   versions of this path copy when a hardlink is unavailable, e.g. across
///   filesystems). A later cold-tier heal REPLACES such a file via atomic
///   rename, breaking the link — never the live node's inode.
/// * `.log` — the active append-only segment: real copy. The replay proxy's
///   own recording appends here (and may rotate) without touching the live
///   file's offsets.
/// * `.redb` — snapshot state (`jobs`, `finops`, `cold`): real copy. redb's
///   on-disk format recovers to the last valid commit on open, so a copy
///   taken while the node commits concurrently stays loadable.
/// * everything else (`tls/`, `update.pub`, `.sig`, subdirs) is not needed
///   by the replay path and is skipped.
pub fn copy_data_dir_scratch(src: &PathBuf) -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dst = std::env::temp_dir().join(format!("blackbox-replay-{}-{nanos:x}", std::process::id()));
    std::fs::create_dir_all(&dst)
        .with_context(|| format!("create scratch dir {}", dst.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry.context("data-copy: read entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue; // `tls/`, `…/parts` etc. — replay never needs them
        }
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        let dst_path = dst.join(entry.file_name());
        match ext {
            "zst" | "idx" => {
                // Sealed artifacts: hardlink so a later cold-tier heal's
                // atomic rename breaks the link instead of the live inode
                // (falls back to a real copy — e.g. across filesystems).
                if std::fs::hard_link(&path, &dst_path).is_err() {
                    std::fs::copy(&path, &dst_path).with_context(|| {
                        format!("data-copy: copy {} -> {}", path.display(), dst_path.display())
                    })?;
                }
            }
            "log" | "redb" => {
                std::fs::copy(&path, &dst_path).with_context(|| {
                    format!("data-copy: copy {} -> {}", path.display(), dst_path.display())
                })?;
            }
            _ => {} // update.pub, *.sig, metadata relics — replay does not read them
        }
    }
    Ok(dst)
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

// ---------------------------------------------------------------------------
// env-child — the injectable-env stand-in app (used by `blackbox env-child`
// in demos/sims; the app is unsupervised, the supervisor wants a real one)
// ---------------------------------------------------------------------------

/// INTERNAL subcommand body: dump the injected Blackbox env vars to a JSON
/// file, then serve HTTP 200 "ok" on every path/port (GET, POST, anything).
pub async fn env_child(port: u16, env_file: PathBuf) -> Result<()> {
    const VARS: &[&str] = &[
        "SENTRY_DSN",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "BLACKBOX_EGRESS_URL",
    ];
    let mut map = serde_json::Map::new();
    for k in VARS {
        if let Ok(v) = std::env::var(k) {
            map.insert((*k).to_string(), serde_json::Value::String(v));
        }
    }
    let json = serde_json::Value::Object(map).to_string();
    std::fs::write(&env_file, json).with_context(|| format!("write {}", env_file.display()))?;

    // SO_REUSEADDR is mandatory for a supervised app: after a SIGKILL the
    // previous incarnation's accepted sockets sit in TIME_WAIT for up to a
    // minute, and without reuseaddr the respawn EADDRINUSE-crash-loops.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into())
        .with_context(|| format!("env-child bind 127.0.0.1:{port}"))?;
    socket.listen(1024)?;
    let listener = tokio::net::TcpListener::from_std(std::net::TcpListener::from(socket))?;
    let addr = listener.local_addr()?;
    eprintln!("env-child serving http://{addr} (env file {})", env_file.display());
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let _ = tcp.set_nodelay(true);
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_string();
                    // Drain the body (keep-alive hygiene), answer 200.
                    let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                    let body = format!("ok {path}");
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from(body)))
                            .expect("env-child response builds"),
                    )
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), svc)
                .await;
        });
    }
}
