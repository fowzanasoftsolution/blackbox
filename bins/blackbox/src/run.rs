//! Phase 5: `blackbox run` — the zero-config child process wrapper.
//!
//! `blackbox run --upstream-port 3000 -- python3 app.py` boots the full
//! Blackbox node (ingress shield + durable queue + egress FinOps proxy +
//! admin) and then launches the wrapped application with five environment
//! variables injected, so ANY existing app becomes observable without a
//! single line of code or config:
//!
//! ```text
//! SENTRY_DSN                    = http://public@127.0.0.1:<ingress>/1
//! OTEL_EXPORTER_OTLP_ENDPOINT   = http://127.0.0.1:<ingress>
//! OPENAI_BASE_URL               = http://127.0.0.1:<egress>/egress/https/api.openai.com/v1
//! ANTHROPIC_BASE_URL            = http://127.0.0.1:<egress>/egress/https/api.anthropic.com
//! BLACKBOX_EGRESS_URL           = http://127.0.0.1:<egress>
//! ```
//!
//! The child is then SUPERVISED (`supervise_forever`): crash (SIGSEGV /
//! SIGABRT / exit != 0), startup timeout, or hang (port stops accepting)
//! → the UpstreamHealth breaker trips immediately (in-flight requests are
//! HELD, not 502'd), the child is respawned with a full-jitter exponential
//! backoff guard (100 ms → 5 s cap), and the held requests release the
//! moment the child port accepts connections again.

use anyhow::{Context, Result};
use blackbox_core::breaker::UpstreamHealth;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Supervision tunables (`blackbox run` + Phase 5 gates).
pub struct SupervisionArgs {
    /// argv for the child: [program, args...].
    pub command: Vec<String>,
    /// Environment variables injected into EVERY (re)spawn.
    pub env: Vec<(String, String)>,
    /// The port the child is expected to accept HTTP on.
    pub upstream_port: u16,
    /// Max time from spawn to first successful port accept.
    pub startup_timeout_ms: u64,
    /// Max respawns (0 = unlimited).
    pub max_restarts: u64,
    /// Child pid is written here on EVERY spawn (respawn-aware).
    pub pid_file: Option<PathBuf>,
}

/// Default backoff ladder: full-jitter exponential, 100 ms base, 5 s cap.
pub const BACKOFF_BASE_MS: u64 = 100;
pub const BACKOFF_CAP_MS: u64 = 5_000;
/// A child alive this long resets the backoff attempt counter.
const STABILITY_RESET: Duration = Duration::from_secs(30);
/// Consecutive failed port probes (while the child process is alive) that
/// declare a HANG and trigger a SIGKILL + respawn.
const HANG_PROBES: u32 = 4;

/// Outcome of a supervision session (gates + diagnostics).
#[derive(Debug, Clone, Copy, Default)]
pub struct SupervisionStats {
    pub spawns: u64,
    pub crashes: u64,
    pub hangs: u64,
}

/// The five zero-config environment variables injected into every child.
pub fn injected_env(ingress: SocketAddr, egress: SocketAddr) -> Vec<(String, String)> {
    vec![
        (
            "SENTRY_DSN".into(),
            format!("http://public@127.0.0.1:{}/1", ingress.port()),
        ),
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT".into(),
            format!("http://127.0.0.1:{}", ingress.port()),
        ),
        (
            "OPENAI_BASE_URL".into(),
            format!(
                "http://127.0.0.1:{}/egress/https/api.openai.com/v1",
                egress.port()
            ),
        ),
        (
            "ANTHROPIC_BASE_URL".into(),
            format!(
                "http://127.0.0.1:{}/egress/https/api.anthropic.com",
                egress.port()
            ),
        ),
        (
            "BLACKBOX_EGRESS_URL".into(),
            format!("http://127.0.0.1:{}", egress.port()),
        ),
    ]
}

fn jitter_backoff(attempt: u32) -> Duration {
    let shift = attempt.min(6);
    let base = BACKOFF_BASE_MS
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_CAP_MS);
    Duration::from_millis(fastrand::u64(0..base.max(2)))
}

async fn port_accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

fn spawn_child(args: &SupervisionArgs) -> tokio::io::Result<tokio::process::Child> {
    let (program, rest) = args.command.split_first().expect("non-empty command");
    tokio::process::Command::new(program)
        .args(rest)
        .envs(args.env.clone())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
}

/// Spawn + monitor + respawn the wrapped child until `shutdown` fires.
/// Every crash/hang trips the shared breaker IMMEDIATELY so the ingress
/// holds requests instead of erroring; the breaker releases them as soon
/// as the respawned child accepts connections.
pub async fn supervise_forever(
    args: SupervisionArgs,
    health: Arc<UpstreamHealth>,
    mut shutdown: watch::Receiver<bool>,
) -> SupervisionStats {
    let mut stats = SupervisionStats::default();
    if args.command.is_empty() {
        tracing::error!("supervision needs a command (use `-- <cmd> <args...>`)");
        return stats;
    }
    let mut attempt: u32 = 0;

    loop {
        if shutdown.has_changed().unwrap_or(true) {
            break;
        }
        if args.max_restarts > 0 && stats.spawns >= args.max_restarts + 1 {
            tracing::error!("max restarts ({}) exhausted; giving up", args.max_restarts);
            break;
        }
        stats.spawns += 1;

        // EXACTLY ONE spawn per supervision iteration. Spawn errors retry
        // in-place (inside the same iteration) so the loop head never
        // double-spawns — a ghost child nobody monitors would hold the
        // upstream port and send every real respawn into an EADDRINUSE
        // crash loop.
        let mut child = loop {
            match spawn_child(&args) {
                Ok(c) => break c,
                Err(e) => {
                    stats.crashes += 1;
                    tracing::error!("spawn failed: {e}; breaker OPEN, backing off");
                    health.record_connect_failure();
                    tokio::time::sleep(jitter_backoff(attempt)).await;
                    attempt += 1;
                    if shutdown.has_changed().unwrap_or(true) {
                        return stats;
                    }
                }
            }
        };
        if let Some(pf) = &args.pid_file {
            let _ = std::fs::write(pf, child.id().map(|p| p.to_string()).unwrap_or_default());
        }
        let pid_note = child.id().map(|p| p.to_string()).unwrap_or("?".into());
        println!("  child pid {pid_note} spawned (attempt {})", attempt + 1);

        // ---- Startup window: the child MUST accept on its port. ----------
        let deadline = Instant::now() + Duration::from_millis(args.startup_timeout_ms);
        let mut up = false;
        let mut died_at_startup = false;
        while Instant::now() < deadline {
            if shutdown.has_changed().unwrap_or(true) {
                let _ = child.start_kill();
                return stats;
            }
            if port_accepts(args.upstream_port).await {
                up = true;
                break;
            }
            if let Ok(Some(_)) = child.try_wait() {
                died_at_startup = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !up {
            if died_at_startup {
                stats.crashes += 1;
                tracing::warn!("child crashed during startup");
            } else {
                stats.hangs += 1;
                tracing::warn!(
                    "child did not accept on :{} within {} ms — declaring startup hang, SIGKILL",
                    args.upstream_port,
                    args.startup_timeout_ms
                );
                let _ = child.start_kill();
            }
            health.record_connect_failure(); // trip immediately: HOLD requests
            tokio::time::sleep(jitter_backoff(attempt)).await;
            attempt += 1;
            continue;
        }

        // Port is up: release held traffic NOW (the prober would also flip
        // the breaker within ~50 ms; this makes it deterministic).
        health.record_success();
        println!("  child healthy on :{} — blackbox is shielding it", args.upstream_port);

        // ---- Runtime monitor: exit status + hang detection. --------------
        let mut stable_since = Instant::now();
        let mut dead_probes = 0u32;
        let exit_status: Option<std::process::ExitStatus>;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                _ = shutdown.changed() => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    return stats;
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("try_wait failed: {e}");
                    exit_status = None;
                    break;
                }
            }
            // Hang probe: a live process whose port stopped accepting.
            if !port_accepts(args.upstream_port).await {
                dead_probes += 1;
                if dead_probes >= HANG_PROBES {
                    stats.hangs += 1;
                    tracing::warn!(
                        "child alive but port :{} unresponsive {dead_probes}x — HANG, SIGKILL",
                        args.upstream_port
                    );
                    let _ = child.start_kill();
                }
            } else {
                dead_probes = 0;
            }
            if stable_since.elapsed() >= STABILITY_RESET {
                attempt = 0;
                stable_since = Instant::now();
            }
        }

        // ---- The child DIED: describe, trip, back off, and fall through
        // to the loop head — which performs the SINGLE next spawn.
        stats.crashes += 1;
        match exit_status {
            Some(status) => tracing::warn!("child exited: {status} — breaker OPEN (holding requests)"),
            None => tracing::warn!("child wait failed after death — treating as crash"),
        }
        health.record_connect_failure(); // immediate trip → hold, no 502s
        tokio::time::sleep(jitter_backoff(attempt)).await;
        attempt += 1;
    }
    stats
}

/// `blackbox run` — full node + zero-config child supervision (foreground).
pub struct RunArgs {
    pub upstream_port: u16,
    pub listen: String,
    pub egress_listen: String,
    pub admin_listen: String,
    pub data: PathBuf,
    pub webhooks: String,
    pub hold_ms: u64,
    pub mem_budget_mb: u64,
    pub startup_timeout_ms: u64,
    pub max_restarts: u64,
    pub pid_file: Option<PathBuf>,
    pub status_file: Option<PathBuf>,
    pub command: Vec<String>,
}

pub async fn run_node(args: RunArgs) -> Result<()> {
    anyhow::ensure!(
        !args.command.is_empty(),
        "`blackbox run` needs a command after `--` (e.g. `blackbox run --upstream-port 3000 -- python3 app.py`)"
    );

    let node = crate::phase4::spawn_node(crate::phase4::NodeConfig {
        listen: args.listen.clone(),
        upstream: format!("127.0.0.1:{}", args.upstream_port),
        data: args.data.clone(),
        webhooks: args.webhooks.clone(),
        hold_ms: args.hold_ms,
        egress_listen: args.egress_listen.clone(),
        admin_listen: args.admin_listen.clone(),
        mem_budget_mb: args.mem_budget_mb,
        max_segment_mb: 64,
        disk_quota_mb: 4096,
        cold: blackbox_cold::S3Config::from_env().and_then(|cfg| {
            blackbox_cold::ColdTier::open(cfg, &args.data).ok()
        }),
    })
    .await
    .context("boot blackbox node")?;

    // Machine-readable status (orchestrators + the Phase 5 gate).
    if let Some(sf) = &args.status_file {
        let status = serde_json::json!({
            "ingress": node.proxy.local_addr.to_string(),
            "egress": node.egress.local_addr.to_string(),
            "admin": node.admin_addr.to_string(),
            "upstream": format!("127.0.0.1:{}", args.upstream_port),
            "pid": std::process::id(),
        });
        std::fs::write(sf, status.to_string())
            .with_context(|| format!("write status file {}", sf.display()))?;
    }

    println!(
        "blackbox run: node up — ingress http://{} · egress http://{} · admin http://{}",
        node.proxy.local_addr, node.egress.local_addr, node.admin_addr
    );
    println!(
        "  supervising: {} (upstream port {}, startup timeout {} ms, max restarts {})",
        args.command.join(" "),
        args.upstream_port,
        args.startup_timeout_ms,
        args.max_restarts
    );

    let env = injected_env(node.proxy.local_addr, node.egress.local_addr);
    println!(
        "  injected env: SENTRY_DSN, OTEL_EXPORTER_OTLP_ENDPOINT, OPENAI_BASE_URL, ANTHROPIC_BASE_URL, BLACKBOX_EGRESS_URL"
    );

    let sup_args = SupervisionArgs {
        command: args.command.clone(),
        env,
        upstream_port: args.upstream_port,
        startup_timeout_ms: args.startup_timeout_ms,
        max_restarts: args.max_restarts,
        pid_file: args.pid_file.clone(),
    };
    let health = Arc::clone(&node.health);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let monitor = tokio::spawn(supervise_forever(sup_args, health, shutdown_rx));

    // Foreground: wait for SIGINT / SIGTERM, then tear down cleanly.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { println!("\nblackbox run: SIGINT — shutting down"); }
        _ = term.recv() => { println!("\nblackbox run: SIGTERM — shutting down"); }
    }
    let _ = shutdown_tx.send(true);
    let stats = monitor.await.unwrap_or_default();
    println!(
        "blackbox run: stopped — {} spawn(s), {} crash(es), {} hang(s)",
        stats.spawns, stats.crashes, stats.hangs
    );
    Ok(())
}
