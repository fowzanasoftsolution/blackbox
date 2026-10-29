//! Phase 4/5 CLI plumbing: the full v1.0+ node assembly (ingress shield +
//! durable queue + egress FinOps proxy + supervisor RAM monitor + Phase 5
//! storage janitor) and the embedded Admin API / dashboard.

use anyhow::{Context, Result};
use blackbox_egress::EgressHandle;
use blackbox_ingress::proxy::ProxyHandle;
use blackbox_ingress::rate_limit::{RateLimiter, RateLimiterConfig};
use blackbox_ingress::tls;
use blackbox_ingress::waf::ScannerShield;
use blackbox_queue::QueueRuntime;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Phase 7: how the ingress listener terminates TLS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TlsOptions {
    /// Plain HTTP (behind your own edge, or the Phase 2 bench default).
    #[default]
    Off,
    /// Terminate TLS with these PEM files; hot-reloaded on change.
    Files { cert: PathBuf, key: PathBuf },
    /// Generate (or reuse) a self-signed cert under `<data>/tls/`.
    SelfSigned,
}

impl TlsOptions {
    /// CLI flag resolution: explicit cert+key wins, else self-signed, else
    /// plain HTTP. Errors when the pair is half-specified.
    pub fn from_flags(
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
        self_signed: bool,
    ) -> anyhow::Result<Self> {
        match (cert, key) {
            (Some(cert), Some(key)) => Ok(TlsOptions::Files { cert, key }),
            (Some(_), None) => anyhow::bail!("--tls-cert given without --tls-key"),
            (None, Some(_)) => anyhow::bail!("--tls-key given without --tls-cert"),
            (None, None) => Ok(if self_signed {
                TlsOptions::SelfSigned
            } else {
                TlsOptions::Off
            }),
        }
    }
}

/// Full-node configuration (Phase 5 adds segment + disk-quota knobs,
/// Phase 7 adds the request guard + native TLS).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub listen: String,
    pub upstream: String,
    pub data: PathBuf,
    pub webhooks: String,
    pub hold_ms: u64,
    pub egress_listen: String,
    pub admin_listen: String,
    pub mem_budget_mb: u64,
    /// Active-segment rotation cap in MB (default 64; 1 for tests).
    pub max_segment_mb: u64,
    /// Storage Ring Quota for the data dir in MB (default 4096).
    pub disk_quota_mb: u64,
    /// Phase 6: S3/R2 cold tier (None = local-only retention).
    pub cold: Option<Arc<blackbox_cold::ColdTier>>,
    /// Phase 7: scanner/WAF shield on the ingress (default ON).
    pub shield: bool,
    /// Phase 7: sustained rate limit (requests/sec; 0 = unlimited).
    pub rate_rps: f64,
    /// Phase 7: token-bucket burst depth (default 100).
    pub rate_burst: u32,
    /// Phase 7: native TLS termination on the ingress listener.
    pub tls: TlsOptions,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            listen: "127.0.0.1:8080".into(),
            upstream: "127.0.0.1:3000".into(),
            data: PathBuf::from("./data"),
            webhooks: "/webhooks/*,/jobs/*".into(),
            hold_ms: 3_000,
            egress_listen: "127.0.0.1:0".into(),
            admin_listen: "127.0.0.1:9690".into(),
            mem_budget_mb: 48,
            max_segment_mb: 64,
            disk_quota_mb: 4096,
            cold: None,
            shield: true,
            rate_rps: 0.0,
            rate_burst: 100,
            tls: TlsOptions::Off,
        }
    }
}

/// Live handles for `blackbox run`, gates and the admin API.
pub struct NodeHandle {
    pub proxy: ProxyHandle,
    pub health: Arc<blackbox_core::breaker::UpstreamHealth>,
    pub egress: EgressHandle,
    pub queue: QueueRuntime,
    pub admin_addr: std::net::SocketAddr,
    pub data_dir: PathBuf,
    pub ram_budget: u64,
    pub max_segment_bytes: u64,
    pub disk: Arc<blackbox_supervisor::disk::DiskMonitor>,
    pub compactor: Arc<blackbox_core::compactor::CompactorStats>,
    pub cold: Option<Arc<blackbox_cold::ColdTier>>,
    /// Phase 7: live TLS state (None = plain HTTP ingress).
    pub tls: Option<Arc<tls::TlsState>>,
    /// Phase 7: the live rate limiter (None = unlimited).
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Phase 7: whether the scanner shield is active.
    pub shield_enabled: bool,
}

/// Everything the admin API reports on.
pub struct AdminState {
    pub started: Instant,
    pub proxy: ProxyHandle,
    pub health: Arc<blackbox_core::breaker::UpstreamHealth>,
    pub egress: Option<EgressHandle>,
    pub queue: Option<QueueRuntime>,
    pub data_dir: PathBuf,
    pub ram_budget: u64,
    pub disk: Option<Arc<blackbox_supervisor::disk::DiskMonitor>>,
    pub disk_quota: u64,
    pub max_segment_bytes: u64,
    pub compactor: Option<Arc<blackbox_core::compactor::CompactorStats>>,
    pub cold: Option<Arc<blackbox_cold::ColdTier>>,
    /// Phase 7: guard telemetry for /api/stats.
    pub shield_enabled: bool,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub tls_enabled: bool,
    pub tls_reload_paths: Option<(PathBuf, PathBuf)>,
}

/// Spawn the whole node (returns as soon as every listener is bound).
pub async fn spawn_node(cfg: NodeConfig) -> Result<NodeHandle> {
    // The data dir must exist before redb opens jobs.redb (first-run UX:
    // `blackbox run --data ./fresh` must just work).
    std::fs::create_dir_all(&cfg.data).context("create data dir")?;
    // Audit chain (v1.1, ON by default — `BLACKBOX_AUDIT=0` disables): every
    // queue/env/gateway/cold state-touch is appended + hash-chained here.
    if std::env::var("BLACKBOX_AUDIT").as_deref() != Ok("0") {
        let _ = blackbox_core::audit::init(&cfg.data);
    }
    let health = blackbox_core::breaker::UpstreamHealth::new(3);

    // ---- Phase 7: native TLS termination (before the ingress boots). ---
    let tls_state: Option<Arc<tls::TlsState>> = match &cfg.tls {
        TlsOptions::Off => None,
        TlsOptions::Files { cert, key } => {
            let s = tls::from_files(cert, key).context("load TLS cert/key")?;
            tls::spawn_hot_reload(Arc::clone(&s));
            Some(s)
        }
        TlsOptions::SelfSigned => {
            let s = tls::from_self_signed(&cfg.data).context("generate self-signed TLS")?;
            Some(s)
        }
    };
    let rate_limiter = RateLimiter::new(&RateLimiterConfig::from_rps(cfg.rate_rps, cfg.rate_burst)).map(Arc::new);

    // ---- Queue runtime (dispatcher + reaper + JobStore actor). ----------
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(4_096);
    let runtime = blackbox_queue::spawn_queue_runtime(
        &cfg.data.join("jobs.redb"),
        blackbox_queue::JobStoreConfig::default(),
        blackbox_queue::DispatcherConfig {
            upstream: cfg.upstream.clone(),
            ..Default::default()
        },
        Arc::clone(&health),
        Some(events_tx),
    )
    .await
    .context("spawn queue runtime")?;

    // ---- Ingress shield (durable routes + telemetry ingestion). ---------
    let proxy_cfg = blackbox_ingress::proxy::IngressConfig {
        listen: cfg.listen.parse()?,
        data_dir: cfg.data.clone(),
        upstream: cfg.upstream.clone(),
        health: Some(Arc::clone(&health)),
        hold_window: Duration::from_millis(cfg.hold_ms),
        durable_prefixes: blackbox_ingress::durable::parse_durable_prefixes(&cfg.webhooks),
        queue: Some(blackbox_ingress::proxy::QueueAttachment {
            runtime: blackbox_queue::QueueRuntime {
                store: runtime.store.clone(),
                cfg: runtime.cfg.clone(),
            },
            events: events_rx,
        }),
        max_segment_bytes: cfg.max_segment_mb.saturating_mul(1024 * 1024),
        ram_budget_bytes: cfg.mem_budget_mb.saturating_mul(1024 * 1024),
        cold: cfg.cold.clone(),
        shield: if cfg.shield { ScannerShield::enabled() } else { ScannerShield::disabled() },
        rate_limit: rate_limiter.clone(),
        tls: tls_state.clone(),
        ..Default::default()
    };
    let proxy = blackbox_ingress::proxy::spawn_proxy(proxy_cfg).await?;

    // ---- Egress FinOps proxy (records into the SAME segment store). -----
    let emit: blackbox_egress::EmitFn = {
        let sink = proxy.sink.clone();
        Arc::new(move |mut rec: blackbox_core::schema::TraceRecord| {
            rec.seq_no = sink.next_seq();
            sink.try_send(rec);
        })
    };
    let egress = blackbox_egress::spawn_egress(
        blackbox_egress::EgressConfig {
            listen: cfg.egress_listen.parse()?,
            data_dir: cfg.data.clone(),
            ..Default::default()
        },
        emit,
    )
    .await
    .context("spawn egress finops proxy")?;
    egress.attach_self_healing();

    // ---- Supervisor RAM monitor: publishes 75/85/95 watermarks to the
    //      process-wide hub (egress purge + ingress head sampling react
    //      instantly via the watch channel).
    let budget = cfg.mem_budget_mb * 1024 * 1024;
    tokio::spawn(async move {
        let mon = blackbox_supervisor::memory::RamMonitor::new(budget);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            mon.poll();
        }
    });

    // ---- Phase 5 storage janitor: compaction + DiskMonitor watermarks.
    let disk = Arc::new(blackbox_supervisor::disk::DiskMonitor::new(
        cfg.data.clone(),
        cfg.disk_quota_mb.saturating_mul(1024 * 1024),
    ));
    let compactor = blackbox_core::compactor::CompactorStats::new();
    crate::janitor::spawn_storage_janitor(
        cfg.data.clone(),
        proxy.active_segments.clone(),
        Arc::clone(&disk),
        Arc::clone(&compactor),
        cfg.cold.clone(),
    );

    // ---- Embedded Admin API + dashboard. --------------------------------
    let admin_addr: std::net::SocketAddr = cfg.admin_listen.parse()?;
    let cold_for_handle = cfg.cold.clone();
    let admin_state = Arc::new(AdminState {
        started: Instant::now(),
        proxy: proxy.clone(),
        health: Arc::clone(&health),
        egress: Some(blackbox_egress::EgressHandle {
            local_addr: egress.local_addr,
            cache: Arc::clone(&egress.cache),
            near: Arc::clone(&egress.near),
            ledger: Arc::clone(&egress.ledger),
            flights: Arc::clone(&egress.flights),
            recorded: Arc::clone(&egress.recorded),
            coalesced_served: Arc::clone(&egress.coalesced_served),
            bypass_served: Arc::clone(&egress.bypass_served),
        }),
        queue: Some(blackbox_queue::QueueRuntime {
            store: runtime.store.clone(),
            cfg: runtime.cfg.clone(),
        }),
        data_dir: cfg.data.clone(),
        ram_budget: budget,
        disk: Some(Arc::clone(&disk)),
        disk_quota: cfg.disk_quota_mb.saturating_mul(1024 * 1024),
        max_segment_bytes: cfg.max_segment_mb.saturating_mul(1024 * 1024),
        compactor: Some(Arc::clone(&compactor)),
        cold: cfg.cold.clone(),
        shield_enabled: cfg.shield,
        rate_limiter: rate_limiter.clone(),
        tls_enabled: tls_state.is_some(),
        tls_reload_paths: tls_state.as_ref().and_then(|t| t.watch_paths().cloned()),
    });
    let admin_bind = admin::spawn(admin_addr, admin_state)
        .await
        .context("spawn admin server")?;

    Ok(NodeHandle {
        proxy,
        health,
        egress,
        queue: runtime,
        admin_addr: admin_bind,
        data_dir: cfg.data,
        ram_budget: budget,
        max_segment_bytes: cfg.max_segment_mb.saturating_mul(1024 * 1024),
        disk,
        compactor,
        cold: cold_for_handle,
        tls: tls_state,
        rate_limiter,
        shield_enabled: cfg.shield,
    })
}

/// `blackbox serve` — full node (foreground; Ctrl-C to stop).
pub async fn serve(cfg: NodeConfig) -> Result<()> {
    // v1.1.2: install BOTH signal handlers BEFORE any listener binds, and use
    // eager `signal()` registration (not `ctrl_c()`, which only registers its
    // handler on first poll — i.e. after `spawn_node` had already opened the
    // port). With this order there is no window in which the node is reachable
    // yet still dies on the default disposition, and an inherited SIG_IGN
    // (detached/background launcher) is overridden up front.
    let mut sig_int =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sig_term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Phase 6: S3/R2 cold tier from BLACKBOX_COLD_* env when the caller
    // did not attach one explicitly.
    let cold = cfg.cold.clone().or_else(|| {
        blackbox_cold::S3Config::from_env().and_then(|s3| blackbox_cold::ColdTier::open(s3, &cfg.data).ok())
    });
    let upstream = cfg.upstream.clone();
    let tls_opts = cfg.tls.clone();
    let node = spawn_node(NodeConfig { cold, ..cfg }).await?;

    let scheme = if node.tls.is_some() { "https" } else { "http" };
    println!(
        concat!("blackbox ", concat!("v", env!("CARGO_PKG_VERSION")), " node listening on {}://{} (upstream {})"),
        scheme, node.proxy.local_addr, upstream
    );
    println!("  ingress:    reverse proxy + /webhooks,/jobs durable 202s + Sentry/OTLP ingestion");
    match (&node.tls, &tls_opts) {
        (Some(_), TlsOptions::Files { cert, key }) => println!(
            "  tls:        ON (cert {} · key {} · hot reload every 2s)",
            cert.display(),
            key.display()
        ),
        (Some(_), TlsOptions::SelfSigned) => println!(
            "  tls:        ON (self-signed, persisted under {}/tls/ — clients must trust or skip verify)",
            node.data_dir.display()
        ),
        _ => {}
    }
    if node.shield_enabled {
        println!("  shield:     scanner/WAF filter ON (blocks /.env /.git wp-admin traversal) — disable with --no-shield");
    }
    match &node.rate_limiter {
        Some(rl) => println!(
            "  rate limit: {:.1} req/s sustained · burst {} · 429 + Retry-After",
            rl.rps_milli() as f64 / 1000.0,
            rl.burst()
        ),
        None => println!("  rate limit: OFF (--rps N --burst M to enable)"),
    }
    println!(
        "  egress:     set OPENAI_BASE_URL=http://{} (aliases /v1/*), X-Blackbox-Target, or HTTP_PROXY",
        node.egress.local_addr
    );
    println!(
        "  admin:      http://{}  (dashboard + trace inspector + 1-click replay)",
        node.admin_addr
    );
    println!(
        "  self-heal:  RAM (RSS) budget {} MB → 75% purge caches (egress + jemalloc arenas) · 85% head sampling · 95% published only (never gates traffic)",
        node.ram_budget / 1024 / 1024
    );
    println!(
        "  storage:    segment cap {} MB · disk quota {} MB · zstd-3 compaction + .idx/.sidx sidecars",
        node.max_segment_bytes / 1024 / 1024,
        node.disk.quota_bytes / 1024 / 1024
    );
    match &node.cold {
        Some(c) => println!(
            "  cold tier:  S3/R2 sync ON → {} bucket \"{}\" · evicted-segment restore + bit-rot self-heal",
            c.endpoint(),
            c.bucket()
        ),
        None => println!("  cold tier:  OFF (set BLACKBOX_COLD_ENDPOINT/BUCKET/ACCESS_KEY_ID/SECRET_ACCESS_KEY to enable)"),
    }
    println!("  data:       {} (segments + jobs.redb + finops.redb + cold.redb)", node.data_dir.display());
    println!("  Ctrl-C to stop");
    // v1.1.2: wait on the ALREADY-registered handlers (registered at the
    // top of `serve`, before any listener bound). `ctrl_c()` here would only
    // register on first poll — i.e. after the node was reachable — leaving a
    // window where a signal lands on the default disposition and kills the
    // process without a drain. Drain + fsync the writer before returning so
    // rc is always a clean 0.
    tokio::select! {
        _ = sig_int.recv() => { println!("\nblackbox serve: SIGINT — shutting down"); }
        _ = sig_term.recv() => { println!("\nblackbox serve: SIGTERM — shutting down"); }
    }
    // v1.1.2 graceful stop: finish in-flight connections (their Finalizers
    // push the last ACKNOWLEDGED records), then drain + fsync the writer.
    // rc is always a clean 0.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), node.proxy.shutdown()).await;
    println!("blackbox serve: stopped — writer flushed");
    Ok(())
}

/// Tiny embedded admin HTTP server (hyper 1.x, zero extra deps).
pub mod admin {
    use super::AdminState;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper_util::rt::TokioIo;
    use std::net::SocketAddr;
    use std::sync::Arc;

    type Resp = hyper::Response<Full<Bytes>>;

    pub async fn spawn(
        listen: SocketAddr,
        state: Arc<AdminState>,
    ) -> anyhow::Result<SocketAddr> {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        let local = listener.local_addr()?;
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let _ = tcp.set_nodelay(true);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, std::convert::Infallible>(route(req, state).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        Ok(local)
    }

    fn json_resp(v: serde_json::Value) -> Resp {
        hyper::Response::builder()
            .status(hyper::StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .body(Full::new(Bytes::from(v.to_string())))
            .expect("json response builds")
    }

    fn text_resp(status: hyper::StatusCode, body: &str) -> Resp {
        hyper::Response::builder()
            .status(status)
            .body(Full::new(Bytes::from(body.to_string())))
            .expect("text response builds")
    }

    async fn route(req: hyper::Request<Incoming>, state: Arc<AdminState>) -> Resp {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // Optional token gate (set BLACKBOX_ADMIN_TOKEN to lock the API down).
        if let Ok(token) = std::env::var("BLACKBOX_ADMIN_TOKEN") {
            let ok = req
                .headers()
                .get("x-admin-token")
                .and_then(|v| v.to_str().ok())
                .map(|v| v == token)
                .unwrap_or(false);
            if !ok {
                return text_resp(hyper::StatusCode::UNAUTHORIZED, "admin token required\n");
            }
        }

        match (method.as_str(), path.as_str()) {
            ("GET", "/") => hyper::Response::builder()
                .status(hyper::StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from_static(super::DASHBOARD_HTML.as_bytes())))
                .expect("dashboard builds"),
            ("GET", "/api/stats") => json_resp(stats(&state).await),
            ("GET", "/api/finops") => json_resp(finops(&state)),
            ("GET", "/api/queue") => json_resp(queue(&state).await),
            ("POST", "/api/egress/purge") => {
                if let Some(eg) = &state.egress {
                    let n = eg.cache.purge_all("manual admin purge");
                    json_resp(serde_json::json!({ "purged": n }))
                } else {
                    json_resp(serde_json::json!({ "purged": 0 }))
                }
            }
            ("GET", p) if p.starts_with("/api/trace/") => {
                json_resp(trace(&state, &p["/api/trace/".len()..]))
            }
            _ => text_resp(hyper::StatusCode::NOT_FOUND, "not found\n"),
        }
    }

    async fn stats(state: &Arc<AdminState>) -> serde_json::Value {
        use blackbox_supervisor::memory::{jemalloc_allocated_bytes, rss_bytes, used_bytes};
        use blackbox_supervisor::disk;

        let version = concat!("v", env!("CARGO_PKG_VERSION"));

        let idx = state.proxy.stats();
        let used = used_bytes();
        let level = blackbox_supervisor::memory::current_ram_level();
        let disk_stats = disk::statvfs(&state.data_dir).unwrap_or(disk::DiskStats {
            total_bytes: 0,
            free_bytes: 0,
            available_bytes: 0,
        });
        let q = queue(&state).await;
        let (eg_cache, eg_ledger, eg_recorded) = match &state.egress {
            Some(eg) => {
                let s = eg.cache.stats();
                (
                    serde_json::json!({
                        "entries": s.entries, "bytes": s.bytes,
                        "hits": s.hits, "misses": s.misses,
                        "evictions": s.evictions, "purges": s.purges,
                        "last_purge_reason": s.last_purge_reason,
                    }),
                    {
                        let t = eg.ledger.totals();
                        serde_json::json!({
                            "total_requests": t.total_requests,
                            "cache_hits": t.cache_hits,
                            "coalesced_hits": t.coalesced_hits,
                            "tokens_used": t.tokens_used,
                            "tokens_saved": t.tokens_saved,
                            "cost_micros_spent": t.cost_micros_spent,
                            "cost_micros_saved": t.cost_micros_saved,
                        })
                    },
                    eg.recorded.load(std::sync::atomic::Ordering::Relaxed),
                )
            }
            None => (
                serde_json::json!({}),
                serde_json::json!({}),
                0,
            ),
        };

        // Phase 5: disk watermark + storage lifecycle stats.
        let disk_level = blackbox_supervisor::disk::current_disk_level();
        let dir_used = state
            .disk
            .as_ref()
            .map(|d| d.dir_used_bytes())
            .unwrap_or(0);
        use std::sync::atomic::Ordering as AtomicOrdering;
        let ord = AtomicOrdering::Relaxed;
        let storage = match &state.compactor {
            Some(c) => {
                let active = state.proxy.active_segment_id();
                let (sealed_raw_n, sealed_raw_b) =
                    blackbox_core::compactor::sealed_raw_stats(&state.data_dir, active);
                let (zst_n, zst_b) = blackbox_core::compactor::cold_zst_stats(&state.data_dir);
                serde_json::json!({
                    "active_segment": active,
                    "max_segment_bytes": state.max_segment_bytes,
                    "sealed_raw_segments": sealed_raw_n,
                    "sealed_raw_bytes": sealed_raw_b,
                    "cold_zst_segments": zst_n,
                    "cold_zst_bytes": zst_b,
                    "compactions": c.compactions.load(ord),
                    "evictions": c.evictions.load(ord),
                    "bytes_saved": c.bytes_saved.load(ord),
                    "frames_indexed": c.frames_indexed.load(ord),
                    "sampled_out": state.proxy.sampled_out(),
                    "disk_shed_out": state.proxy.disk_shed_out(),
                })
            }
            None => serde_json::json!({}),
        };

        serde_json::json!({
            "version": version,
            "uptime_secs": state.started.elapsed().as_secs(),
            "ingress": {
                "total_requests": state.proxy.total_requests(),
                "sampled_out": state.proxy.sampled_out(),
                "disk_shed_out": state.proxy.disk_shed_out(),
                "dropped": state.proxy.dropped(),
                "frames": idx.frames,
                "status_2xx": idx.status_2xx,
                "status_4xx": idx.status_4xx,
                "status_5xx": idx.status_5xx,
                "sentry_crashes": idx.sentry_crashes,
                "distinct_traces": idx.distinct_traces,
            },
            "guard": {
                "shield": state.shield_enabled,
                "blocked_attacks": blackbox_ingress::waf::blocked_attacks(),
                "rate_limited": blackbox_ingress::proxy::RATE_LIMITED.load(std::sync::atomic::Ordering::Relaxed),
                "rate_rps_milli": state.rate_limiter.as_ref().map(|r| r.rps_milli()).unwrap_or(0),
                "rate_burst": state.rate_limiter.as_ref().map(|r| r.burst()).unwrap_or(0),
                "tls": state.tls_enabled,
                "tls_reload_paths": state.tls_reload_paths.as_ref().map(|(c, k)| serde_json::json!({"cert": c.display().to_string(), "key": k.display().to_string()})),
            },
            "ram": {
                "level": format!("{level:?}"),
                "pct": if state.ram_budget > 0 { (used as f64 / state.ram_budget as f64) * 100.0 } else { 0.0 },
                "used": used,
                "budget": state.ram_budget,
                "rss": rss_bytes(),
                // Diagnostic only (module docs): allocator-view heap bytes.
                "jemalloc": jemalloc_allocated_bytes(),
            },
            "disk": {
                "level": format!("{disk_level:?}"),
                "used": dir_used,
                "quota": state.disk_quota,
                "pct": if state.disk_quota > 0 { (dir_used as f64 / state.disk_quota as f64) * 100.0 } else { 0.0 },
                "total": disk_stats.total_bytes,
                "free": disk_stats.free_bytes,
                "available": disk_stats.available_bytes,
            },
            "storage": storage,
            "cold": match &state.cold {
                Some(c) => {
                    let s = c.stats();
                    serde_json::json!({
                        "enabled": true,
                        "endpoint": c.endpoint(),
                        "bucket": c.bucket(),
                        "synced_segments": c.synced_segment_count(),
                        "uploads": s.uploads,
                        "upload_failures": s.upload_failures,
                        "bytes_uploaded": s.bytes_uploaded,
                        "restores": s.restores,
                        "heals": s.heals,
                        "corrupt_detected": s.corrupt_detected,
                        "traces_indexed": s.traces_indexed,
                    })
                }
                None => serde_json::json!({ "enabled": false }),
            },
            "breaker": {
                "state": blackbox_core::breaker::state_name(state.health.state()),
                "failures": state.health.failures(),
                "open_for_ms": state.health.open_for_ms(),
                "transitions": state.health.transitions(),
            },
            "egress": {
                "cache": eg_cache,
                "ledger": eg_ledger,
                "recorded": eg_recorded,
            },
            "queue": q,
        })
    }

    async fn queue(state: &Arc<AdminState>) -> serde_json::Value {
        match &state.queue {
            Some(rt) => match rt.store.counts().await {
                Ok(c) => serde_json::json!({
                    "pending": c.pending, "in_flight": c.in_flight,
                    "dead_letter": c.dead_letter,
                    "enqueued_total": c.enqueued_total, "deduped_total": c.deduped_total,
                    "delivered_total": c.delivered_total, "deadletted_total": c.deadletted_total,
                    "reaped_total": c.reaped_total,
                    "idem_swept_total": c.idem_swept_total,
                }),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            },
            None => serde_json::json!({ "error": "queue engine not attached" }),
        }
    }

    fn finops(state: &Arc<AdminState>) -> serde_json::Value {
        let Some(eg) = &state.egress else {
            return serde_json::json!({ "rows": [] });
        };
        let rows: Vec<serde_json::Value> = eg
            .ledger
            .snapshot()
            .into_iter()
            .map(|(k, e)| {
                serde_json::json!({
                    "tenant": k.tenant, "provider": k.provider, "model": k.model,
                    "total_requests": e.total_requests,
                    "cache_hits": e.cache_hits,
                    "coalesced_hits": e.coalesced_hits,
                    "tokens_used": e.tokens_used,
                    "tokens_saved": e.tokens_saved,
                    "cost_micros_spent": e.cost_micros_spent,
                    "cost_micros_saved": e.cost_micros_saved,
                    "savings_pct": e.savings_pct(),
                })
            })
            .collect();
        serde_json::json!({ "rows": rows })
    }

    fn trace(state: &Arc<AdminState>, hex: &str) -> serde_json::Value {
        let Some(tid) = blackbox_core::schema::parse_trace_hex(hex) else {
            return serde_json::json!({ "error": "trace id must be 32 hex chars" });
        };
        let Some(records) = state.proxy.get_trace(&tid) else {
            return serde_json::json!({ "error": "trace not found in the index (bloom-filtered)" });
        };
        let items: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                use blackbox_core::schema::RecordPayload;
                let (kind, status, detail, cls) = match &r.payload {
                    RecordPayload::IngressHttp(i) => (
                        "IngressHttp",
                        Some(i.status),
                        format!("{} {} · {}ms", i.method, i.uri, i.duration_ms),
                        if i.status < 400 { "t2xx" } else if i.status < 500 { "t4xx" } else { "t5xx" },
                    ),
                    RecordPayload::EgressHttpMock(m) => (
                        "EgressHttpMock",
                        Some(m.response_status),
                        format!("{} {} ({}B)", m.method, m.request_url, m.response_body.len()),
                        "tinf",
                    ),
                    RecordPayload::TelemetryLog(l) => (
                        "TelemetryLog",
                        None,
                        format!("L{} {} · {}", l.level, l.service, l.message),
                        "tinf",
                    ),
                    RecordPayload::SentryCrash(c) => (
                        "SentryCrash",
                        None,
                        format!("project {} event {}", c.project_id, c.event_id),
                        "t5xx",
                    ),
                    RecordPayload::QueueJob(j) => (
                        "QueueJob",
                        None,
                        format!("{} attempt {}/{}", j.queue, j.attempt, j.max_attempts),
                        "tinf",
                    ),
                };
                serde_json::json!({
                    "seq_no": r.seq_no, "kind": kind, "status": status,
                    "detail": detail, "cls": cls,
                    "at": format!("{}s", (r.timestamp_ms % 100000) as f64 / 1000.0),
                    "timestamp_ms": r.timestamp_ms,
                })
            })
            .collect();
        serde_json::json!({
            "trace_id": hex,
            "records": items,
            "replay_command": format!("blackbox replay {hex} --target http://APP:PORT --data {}", state.data_dir.display()),
        })
    }
}
