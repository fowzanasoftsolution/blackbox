//! Project Blackbox — the Rust "Omni-Sidecar" CLI.
//!
//! Phase 1 deliverables live here: the crash & corruption harness
//! (`harness corrupt|kill9|rss`) and the storage-core benchmarks
//! (`bench segment|queue`).

mod bench;
mod child;
mod demo;
mod harness;
mod phase3;
mod phase4;
mod phase5;
mod phase6;
mod phase7;
mod run;
mod selfupdate;
mod stats;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// jemalloc as the global allocator — the supervisor reads its stats for the
/// RAM watermark monitor, and background purging keeps idle RSS tight.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Keep load-time RSS near the idle floor: jemalloc's default 8 s dirty /
/// 10 s muzzy page decay retains tens of MB after a 38 K req/s burst.
/// 1 s / 1 s returns purgeable pages to the OS ~8× sooner — the Phase 2
/// gate's 35 MB load budget stays honest with the v1.0 TLS stack linked in.
fn tune_jemalloc_decay() {
    use std::sync::atomic::AtomicBool;
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    unsafe {
        let _ = tikv_jemalloc_ctl::raw::update(b"arenas.dirty_decay_ms\0", 1_000i64);
        let _ = tikv_jemalloc_ctl::raw::update(b"arenas.muzzy_decay_ms\0", 1_000i64);
    }
}

#[derive(Parser)]
#[command(
    name = "blackbox",
    version,
    about = "Project Blackbox — Rust Omni-Sidecar & Self-Healing Architecture (v1.2: rate-limit shield + WAF + native TLS + one-command demo)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Zero-config child supervisor: wrap ANY app (no code/config edits).
    /// Injects SENTRY_DSN / OTEL / OPENAI / ANTHROPIC / BLACKBOX_EGRESS_URL
    /// and auto-resurrects the app after crashes or hangs.
    Run {
        /// Port the wrapped app will serve HTTP on (Blackbox proxies to it).
        #[arg(long, default_value_t = 3000)]
        upstream_port: u16,
        /// Ingress shield bind (your app's users hit THIS).
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        egress_listen: String,
        #[arg(long, default_value = "127.0.0.1:9690")]
        admin_listen: String,
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        /// Durable route spec (prefix match; `*` suffix cosmetic).
        #[arg(long, default_value = "/webhooks/*,/jobs/*")]
        webhooks: String,
        /// Connection-hold window while the app is down (ms).
        #[arg(long, default_value_t = 10_000)]
        hold_ms: u64,
        #[arg(long, default_value_t = 48)]
        mem_budget_mb: u64,
        /// Scanner/WAF shield on the ingress (default on).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        shield: bool,
        /// Sustained rate limit (requests/sec, 0 = unlimited).
        #[arg(long, default_value_t = 0.0)]
        rps: f64,
        /// Token-bucket burst depth (used with --rps).
        #[arg(long, default_value_t = 100)]
        burst: u32,
        /// TLS cert PEM (enables native TLS termination on the ingress).
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS key PEM (requires --tls-cert).
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Generate (and persist) a self-signed cert for instant HTTPS.
        #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
        tls_self_signed: bool,
        /// Max time the app gets to bind its port after spawn (ms).
        #[arg(long, default_value_t = 15_000)]
        startup_timeout_ms: u64,
        /// Max respawns before giving up (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        max_restarts: u64,
        /// Child pid is (re)written here on every spawn.
        #[arg(long)]
        pid_file: Option<PathBuf>,
        /// Node addresses JSON {ingress, egress, admin, upstream, pid}.
        #[arg(long)]
        status_file: Option<PathBuf>,
        /// The wrapped command (`--` separated).
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// INTERNAL: injectable-env HTTP stand-in app (gates / demos).
    EnvChild {
        #[arg(long, default_value_t = 3000)]
        port: u16,
        #[arg(long)]
        env_file: PathBuf,
    },
    /// Phase 1 crash & corruption harness (the verification gate).
    Harness {
        #[command(subcommand)]
        mode: HarnessMode,
    },
    /// Storage-core benchmarks.
    Bench {
        #[command(subcommand)]
        mode: BenchMode,
    },
    /// Run the full co-located node: ingress shield + durable queue +
    /// egress FinOps proxy + supervisor self-healing + admin dashboard.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Upstream app `host:port` the proxy forwards to.
        #[arg(long)]
        upstream: String,
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        /// Durable route spec (prefix match; `*` suffix cosmetic).
        #[arg(long, default_value = "/webhooks/*,/jobs/*")]
        webhooks: String,
        /// Connection-hold window while the upstream is down (ms).
        #[arg(long, default_value_t = 3_000)]
        hold_ms: u64,
        /// Egress FinOps proxy bind (set OPENAI_BASE_URL / HTTP_PROXY on your app).
        #[arg(long, default_value = "127.0.0.1:0")]
        egress_listen: String,
        /// Embedded admin dashboard + API bind.
        #[arg(long, default_value = "127.0.0.1:9690")]
        admin_listen: String,
        /// Process RAM budget for the supervisor watermarks (MB).
        #[arg(long, default_value_t = 48)]
        mem_budget_mb: u64,
        /// Active-segment rotation cap (MB). 1 for tests, 64 default.
        #[arg(long, default_value_t = 64)]
        max_segment_mb: u64,
        /// Storage Ring Quota for the data dir (MB): 75% compress /
        /// 85% evict oldest .zst FIFO / 95% survival shedding.
        #[arg(long, default_value_t = 4096)]
        disk_quota_mb: u64,
        /// Scanner/WAF shield on the ingress (default on).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        shield: bool,
        /// Sustained rate limit (requests/sec, 0 = unlimited).
        #[arg(long, default_value_t = 0.0)]
        rps: f64,
        /// Token-bucket burst depth (used with --rps).
        #[arg(long, default_value_t = 100)]
        burst: u32,
        /// TLS cert PEM (enables native TLS termination on the ingress).
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS key PEM (requires --tls-cert).
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Generate (and persist) a self-signed cert for instant HTTPS.
        #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
        tls_self_signed: bool,
    },
    /// Deterministic time-travel replay of a recorded trace.
    Replay {
        /// 32-hex trace id (from x-blackbox-trace-id or the index).
        trace_id: String,
        /// Upstream app URL the replayed requests are proxied to.
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        /// Replay proxy bind.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Egress mock interceptor bind.
        #[arg(long, default_value = "127.0.0.1:0")]
        egress: String,
        /// Force an isolated scratch copy of the data dir (also happens
        /// automatically when a live serve/run node holds the redb locks).
        #[arg(long, default_value_t = false)]
        data_copy: bool,
    },
    /// Durable queue administration (run while `serve` is stopped).
    Queue {
        #[command(subcommand)]
        mode: QueueMode,
    },
    /// Phase 3 verification gates: 1 = zero-lost-webhooks chaos,
    /// 2 = invisible app restart (connection hold), 3 = replay sandbox.
    P3Gate { n: u8 },
    /// Phase 4 verification gates: 1 = singleflight/FinOps savings,
    /// 2 = cache poisoning guard, 3 = self-healing RAM shed + audit.
    P4Gate { n: u8 },
    /// Phase 5 verification gates: 1 = hot-to-cold .zst rollover + cold
    /// replay + 85% eviction, 2 = zero-config auto-resurrection,
    /// 3 = zero-leak 100K-op soak (flat RSS).
    P5Gate { n: u8 },
    /// Phase 6 verification gates: 1 = evicted cold-tier time-travel
    /// replay, 2 = bit-rot self-healing, 3 = bad-update canary rollback.
    P6Gate { n: u8 },
    /// Phase 7 verification gates: 1 = shield (rate limit + WAF),
    /// 2 = native TLS + hot reload, 3 = `blackbox demo --once`.
    P7Gate { n: u8 },
    /// The whole architecture in one shot: a self-contained demo node
    /// (embedded app + LLM provider + mock S3 cold tier) driven through
    /// normal traffic → coalesced LLM calls → webhook burst → a checkout
    /// bug with a Sentry crash → automatic bit-rot self-heal, then the
    /// 4-engine ANSI summary. Without --once the dashboard stays up.
    Demo {
        /// Run the scenario, print the summary and exit 0 (verification).
        #[arg(long)]
        once: bool,
        /// Ingress bind (0 port = ephemeral).
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Admin dashboard bind (falls back to an ephemeral port when busy).
        #[arg(long, default_value = "127.0.0.1:9690")]
        admin_listen: String,
        /// Data dir (default: a fresh temp dir).
        #[arg(long)]
        data: Option<PathBuf>,
        /// Keep the data dir after --once exits.
        #[arg(long)]
        keep: bool,
    },
    /// Ed25519-verified canary self-update with automatic rollback
    /// (signature verify → redb snapshot → isolated canary → promote/rollback).
    SelfUpdate {
        /// Candidate binary (local path or http:// URL).
        #[arg(long)]
        from: String,
        /// Detached signature file (128 hex chars, Ed25519 over SHA-256).
        #[arg(long)]
        sig: PathBuf,
        /// Verifying key (64 hex). Falls back to BLACKBOX_VERIFY_PUBKEY,
        /// legacy BLACKBOX_UPDATE_PUBKEY, <data>/update.pub, then the
        /// compiled-in official release key.
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long, default_value = "./data")]
        data: PathBuf,
        #[arg(long, default_value_t = selfupdate::DEFAULT_CANARY_WINDOW_MS)]
        canary_window_ms: u64,
    },
    /// Generate an Ed25519 update-signing keypair.
    Keygen {
        #[arg(long, default_value = "./keys")]
        out_dir: PathBuf,
    },
    /// Sign an update candidate (Ed25519 over SHA-256 of the binary).
    SignUpdate {
        /// Hex seed, or @path/to/blackbox_ed25519.key
        #[arg(long)]
        key: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// INTERNAL: canary payload spawned by `self-update` (boots the engines
    /// on a scratch data dir and serves /healthz until probed).
    SelfTest {
        #[arg(long)]
        canary_port: u16,
        #[arg(long, default_value = "./data")]
        data: PathBuf,
    },
    /// Restore the *.redb.bak snapshot taken by self-update (run OFFLINE,
    /// before starting the node).
    RestoreSnapshot {
        #[arg(long, default_value = "./data")]
        data: PathBuf,
    },
    /// Phase 2 verification gates: 1 = causal link, 2 = stream/bomb safety,
    /// 3 = 2-vCPU throughput & overhead.
    Gate { n: u8 },
    /// INTERNAL: append records until killed (crash-harness child process).
    WriteLoop {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value_t = 200_000)]
        records: u64,
        #[arg(long, default_value_t = 512)]
        sync_every: u64,
    },
    /// INTERNAL: heartbeat client for watchdog demos/tests.
    HeartbeatChild {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum QueueMode {
    /// Pending / in-flight / dead-letter counts + per-queue breakdown.
    Status {
        #[arg(long, default_value = "./data")]
        data: PathBuf,
    },
    /// Requeue every dead-lettered job (attempt reset).
    RetryDlq {
        #[arg(long, default_value = "./data")]
        data: PathBuf,
    },
}

#[derive(Subcommand)]
enum HarnessMode {
    /// Deterministic torn-write + bit-flip injection and recovery verification.
    Corrupt {
        #[arg(long, default_value_t = 500)]
        frames: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// torn | flip | both
        #[arg(long, default_value = "both")]
        mode: String,
    },
    /// Real SIGKILL mid-append against a child writer, then recovery checks.
    Kill9 {
        #[arg(long, default_value_t = 200_000)]
        records: u64,
        #[arg(long, default_value_t = 5)]
        iterations: u32,
        #[arg(long, default_value_t = 7)]
        seed: u64,
    },
    /// Idle RSS budget check (<25 MB gate) with supervisor monitor output.
    Rss {
        #[arg(long, default_value_t = 25)]
        budget_mb: u64,
    },
}

#[derive(Subcommand)]
enum BenchMode {
    /// Append-only segment engine: throughput, recovery scan, durable path.
    Segment {
        #[arg(long, default_value_t = 50_000)]
        frames: u64,
    },
    /// redb group-commit actor: durable enqueue RTT + throughput.
    Queue {
        #[arg(long, default_value_t = 50_000)]
        ops: u64,
        #[arg(long, default_value_t = 64)]
        concurrency: u64,
    },
    /// Phase 2 ingress proxy: keep-alive throughput + added latency + RSS.
    Proxy {
        #[arg(long, default_value_t = 30_000)]
        requests: u64,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tune_jemalloc_decay();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .without_time()
        .init();

    match Cli::parse().cmd {
        Cmd::Run {
            upstream_port,
            listen,
            egress_listen,
            admin_listen,
            data,
            webhooks,
            hold_ms,
            mem_budget_mb,
            shield,
            rps,
            burst,
            tls_cert,
            tls_key,
            tls_self_signed,
            startup_timeout_ms,
            max_restarts,
            pid_file,
            status_file,
            command,
        } => {
            let tls = phase4::TlsOptions::from_flags(tls_cert, tls_key, tls_self_signed)?;
            run::run_node(run::RunArgs {
                upstream_port,
                listen,
                egress_listen,
                admin_listen,
                data,
                webhooks,
                hold_ms,
                mem_budget_mb,
                startup_timeout_ms,
                max_restarts,
                pid_file,
                status_file,
                command,
                shield,
                rate_rps: rps,
                rate_burst: burst,
                tls,
            })
            .await?;
        }
        Cmd::EnvChild { port, env_file } => {
            phase5::env_child(port, env_file).await?;
        }
        Cmd::Harness { mode } => match mode {
            HarnessMode::Corrupt { frames, seed, mode } => {
                if !matches!(mode.as_str(), "torn" | "flip" | "both") {
                    anyhow::bail!("--mode must be torn|flip|both");
                }
                harness::run_corrupt(frames, seed, &mode)?;
            }
            HarnessMode::Kill9 { records, iterations, seed } => {
                harness::run_kill9(records, iterations, seed)?;
            }
            HarnessMode::Rss { budget_mb } => {
                harness::run_rss(budget_mb)?;
            }
        },
        Cmd::Bench { mode } => match mode {
            BenchMode::Segment { frames } => bench::run_segment(frames)?,
            BenchMode::Queue { ops, concurrency } => bench::run_queue(ops, concurrency).await?,
            BenchMode::Proxy {
                requests,
                concurrency,
            } => blackbox_ingress::verify::gate3(requests, concurrency)
                .await
                .map_err(|e| anyhow::anyhow!(e))?,
        },
        Cmd::Serve {
            listen,
            upstream,
            data,
            webhooks,
            hold_ms,
            egress_listen,
            admin_listen,
            mem_budget_mb,
            max_segment_mb,
            disk_quota_mb,
            shield,
            rps,
            burst,
            tls_cert,
            tls_key,
            tls_self_signed,
        } => {
            let tls = phase4::TlsOptions::from_flags(tls_cert, tls_key, tls_self_signed)?;
            phase4::serve(phase4::NodeConfig {
                listen,
                upstream,
                data,
                webhooks,
                hold_ms,
                egress_listen,
                admin_listen,
                mem_budget_mb,
                max_segment_mb,
                disk_quota_mb,
                cold: None,
                shield,
                rate_rps: rps,
                rate_burst: burst,
                tls,
            })
            .await?;
        }
        Cmd::Replay {
            trace_id,
            target,
            data,
            listen,
            egress,
            data_copy,
        } => {
            phase3::replay(trace_id, target, data, listen, egress, data_copy).await?;
        }
        Cmd::Queue { mode } => match mode {
            QueueMode::Status { data } => phase3::queue_status(data).await?,
            QueueMode::RetryDlq { data } => phase3::queue_retry_dlq(data).await?,
        },
        Cmd::P3Gate { n } => match n {
            1 => blackbox_ingress::verify3::gate1().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            2 => blackbox_ingress::verify3::gate2().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            3 => blackbox_ingress::verify3::gate3().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            _ => anyhow::bail!("p3gate must be 1, 2 or 3"),
        },
        Cmd::P4Gate { n } => match n {
            1 => blackbox_egress::gate1().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            2 => blackbox_egress::gate2().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            3 => blackbox_egress::gate3().await.map_err(|e| anyhow::anyhow!("{e}"))?,
            _ => anyhow::bail!("p4gate must be 1, 2 or 3"),
        },
        Cmd::P5Gate { n } => match n {
            1 => phase5::gate1().await?,
            2 => phase5::gate2().await?,
            3 => phase5::gate3().await?,
            _ => anyhow::bail!("p5gate must be 1, 2 or 3"),
        },
        Cmd::P6Gate { n } => match n {
            1 => phase6::gate1().await?,
            2 => phase6::gate2().await?,
            3 => phase6::gate3().await?,
            _ => anyhow::bail!("p6gate must be 1, 2 or 3"),
        },
        Cmd::P7Gate { n } => match n {
            1 => phase7::gate1().await?,
            2 => phase7::gate2().await?,
            3 => phase7::gate3().await?,
            _ => anyhow::bail!("p7gate must be 1, 2 or 3"),
        },
        Cmd::Demo {
            once,
            listen,
            admin_listen,
            data,
            keep,
        } => {
            let code = demo::run_demo(demo::DemoArgs {
                once,
                listen,
                admin_listen,
                data,
                keep,
            })
            .await?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Cmd::SelfUpdate {
            from,
            sig,
            pubkey,
            data,
            canary_window_ms,
        } => {
            let outcome = selfupdate::run_self_update(
                &from,
                &sig,
                pubkey.as_deref(),
                &data,
                canary_window_ms,
            )
            .await?;
            match outcome {
                selfupdate::UpdateOutcome::RejectedSignature(why) => {
                    eprintln!("self-update REJECTED: {why}");
                    std::process::exit(2);
                }
                selfupdate::UpdateOutcome::RolledBack { .. } => std::process::exit(3),
                selfupdate::UpdateOutcome::Promoted { .. } => {}
            }
        }
        Cmd::Keygen { out_dir } => {
            selfupdate::keygen(&out_dir)?;
        }
        Cmd::SignUpdate { key, input, out } => {
            let sk = selfupdate::load_signing_key(&key)?;
            let bytes = std::fs::read(&input)
                .with_context(|| format!("read candidate {}", input.display()))?;
            let sig = selfupdate::sign_bytes(&sk, &bytes);
            std::fs::write(&out, sig).with_context(|| format!("write {}", out.display()))?;
            println!("signed {} → {} (128-hex Ed25519 over SHA-256)", input.display(), out.display());
            // Release CI signs with a secret seed and publishes this line as the
            // public verifying key operators can pin for `blackbox self-update`.
            println!("verifying-key: {}", crate::phase6::hex_of(&sk.verifying_key().to_bytes()));
        }
        Cmd::SelfTest {
            canary_port,
            data,
        } => {
            selfupdate::self_test(canary_port, data).await?;
        }
        Cmd::RestoreSnapshot { data } => {
            let n = selfupdate::restore_redb_snapshot(&data)?;
            println!("restored {n} snapshot file(s) over their live databases");
        }
        Cmd::Gate { n } => match n {
            1 => blackbox_ingress::verify::gate1().await.map_err(|e| anyhow::anyhow!(e))?,
            2 => blackbox_ingress::verify::gate2().await.map_err(|e| anyhow::anyhow!(e))?,
            3 => {
                blackbox_ingress::verify::gate3(30_000, 8)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?
            }
            _ => anyhow::bail!("gate must be 1, 2 or 3"),
        },
        Cmd::WriteLoop {
            dir,
            records,
            sync_every,
        } => child::write_loop(dir, records, sync_every)?,
        Cmd::HeartbeatChild { socket } => child::heartbeat_child(socket).await?,
    }
    Ok(())
}
