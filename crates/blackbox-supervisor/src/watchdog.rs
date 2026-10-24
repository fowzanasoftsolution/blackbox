//! Process watchdog with unix-socket heartbeat (blueprint §4, Supervisor).
//!
//! The parent [`Watchdog`] binds a unix socket, spawns the child with
//! `BLACKBOX_HEARTBEAT_SOCKET` in its environment, and expects a beat every
//! `beat_every` (500 ms default). Three strikes (no beat for `timeout`)
//! or an unexpected child exit triggers a kill + exponential-backoff restart
//! — turning a hung app PID into a 200 ms blip instead of a 10-minute outage.
//!
//! The child side helper [`heartbeat_client`] is used by `blackbox run`
//! workers (and the harness) to stay supervised.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;

/// Watchdog lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WatchState {
    Starting = 0,
    Healthy = 1,
    Suspect = 2,
    Restarting = 3,
    Stopped = 4,
}

impl WatchState {
    pub fn as_str(&self) -> &'static str {
        match self {
            WatchState::Starting => "starting",
            WatchState::Healthy => "healthy",
            WatchState::Suspect => "suspect",
            WatchState::Restarting => "restarting",
            WatchState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Program to supervise.
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Heartbeat socket path (parent binds, child connects).
    pub socket_path: PathBuf,
    /// Expected beat interval (blueprint: 500 ms).
    pub beat_every: Duration,
    /// Kill + restart after silence of this duration (default 3 beats).
    pub timeout: Duration,
    /// Initial restart backoff (doubles up to `backoff_max`).
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    /// Give up after this many restarts (u32::MAX = always).
    pub max_restarts: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        WatchdogConfig {
            program: String::new(),
            args: vec![],
            socket_path: std::env::temp_dir().join("blackbox-heartbeat.sock"),
            beat_every: Duration::from_millis(500),
            timeout: Duration::from_millis(1_500),
            backoff_start: Duration::from_millis(100),
            backoff_max: Duration::from_secs(5),
            max_restarts: u32::MAX,
        }
    }
}

/// Atomic status snapshot for admin API / CLI.
#[derive(Debug)]
pub struct WatchdogStatus {
    pub state: AtomicU8,
    pub pid: AtomicU32,
    pub restarts: AtomicU32,
    /// Milliseconds since the last healthy beat (0 = never).
    pub last_beat_age_ms: AtomicU64,
}

impl WatchdogStatus {
    fn new() -> Self {
        WatchdogStatus {
            state: AtomicU8::new(WatchState::Starting as u8),
            pid: AtomicU32::new(0),
            restarts: AtomicU32::new(0),
            last_beat_age_ms: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> (WatchState, u32, u32, u64) {
        (
            match self.state.load(Ordering::Relaxed) {
                1 => WatchState::Healthy,
                2 => WatchState::Suspect,
                3 => WatchState::Restarting,
                4 => WatchState::Stopped,
                _ => WatchState::Starting,
            },
            self.pid.load(Ordering::Relaxed),
            self.restarts.load(Ordering::Relaxed),
            self.last_beat_age_ms.load(Ordering::Relaxed),
        )
    }
}

/// A running supervision loop. Cloneable; `shutdown` terminates the child
/// and stops the loop.
#[derive(Clone)]
pub struct WatchdogHandle {
    status: Arc<WatchdogStatus>,
    stop_tx: watch::Sender<bool>,
    #[allow(dead_code)] // consumed implicitly; kept for future cancel semantics
    join: Arc<tokio::task::JoinHandle<()>>,
}

impl WatchdogHandle {
    pub fn status(&self) -> Arc<WatchdogStatus> {
        Arc::clone(&self.status)
    }

    /// Terminate child + loop (idempotent).
    pub async fn shutdown(&self) {
        let _ = self.stop_tx.send(true);
        // Join happens on drop of the arc'd task handle; give it a beat.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Spawn the supervision loop.
pub fn spawn_watchdog(config: WatchdogConfig) -> WatchdogHandle {
    let status = Arc::new(WatchdogStatus::new());
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let status_for_task = Arc::clone(&status);
    let join = tokio::spawn(async move {
        supervise(config, &mut stop_rx, status_for_task).await;
    });
    WatchdogHandle {
        status,
        stop_tx,
        join: Arc::new(join),
    }
}

async fn supervise(
    config: WatchdogConfig,
    stop_rx: &mut watch::Receiver<bool>,
    status: Arc<WatchdogStatus>,
) {
    let mut backoff = config.backoff_start;
    loop {
        if *stop_rx.borrow() {
            break;
        }

        // Bind the heartbeat socket BEFORE spawning the child so the child
        // can connect immediately on boot.
        let _ = std::fs::remove_file(&config.socket_path);
        let listener = match UnixListener::bind(&config.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, path = %config.socket_path.display(), "cannot bind heartbeat socket");
                break;
            }
        };

        status
            .state
            .store(WatchState::Starting as u8, Ordering::Relaxed);
        let mut child = match Command::new(&config.program)
            .args(&config.args)
            .env("BLACKBOX_HEARTBEAT_SOCKET", &config.socket_path)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, program = %config.program, "cannot spawn child");
                break;
            }
        };
        let pid = child.id().unwrap_or(0);
        status.pid.store(pid, Ordering::Relaxed);
        tracing::info!(pid, program = %config.program, "child spawned, awaiting heartbeat");

        // Race: healthy heartbeat flow vs child exit vs watchdog stop.
        let outcome = run_one_generation(&config, &listener, &mut child, stop_rx, &status).await;

        // Clean up this generation.
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&config.socket_path);

        match outcome {
            Generation::Stopped => {
                status
                    .state
                    .store(WatchState::Stopped as u8, Ordering::Relaxed);
                break;
            }
            Generation::Crashed(reason) => {
                let restarts = status.restarts.fetch_add(1, Ordering::Relaxed) + 1;
                status
                    .state
                    .store(WatchState::Restarting as u8, Ordering::Relaxed);
                tracing::warn!(pid, restarts, %reason, "child unhealthy — restarting with backoff");
                if restarts > config.max_restarts {
                    status
                        .state
                        .store(WatchState::Stopped as u8, Ordering::Relaxed);
                    tracing::error!("max restarts exceeded — giving up");
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            status.state.store(WatchState::Stopped as u8, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                backoff = (backoff * 2).min(config.backoff_max);
            }
            Generation::HealthyForever => unreachable!(),
        }
    }
    let _ = std::fs::remove_file(&config.socket_path);
}

enum Generation {
    Stopped,
    Crashed(String),
    #[allow(dead_code)]
    HealthyForever,
}

async fn run_one_generation(
    config: &WatchdogConfig,
    listener: &UnixListener,
    child: &mut Child,
    stop_rx: &mut watch::Receiver<bool>,
    status: &Arc<WatchdogStatus>,
) -> Generation {
    // Accept the child's heartbeat connection (with a grace period), then
    // pump beats; ANY deviation (exit, silence) crashes the generation.
    let accept = listener.accept();
    let conn = tokio::select! {
        r = accept => match r {
            Ok((stream, _addr)) => stream,
            Err(e) => return Generation::Crashed(format!("accept failed: {e}")),
        },
        res = child.wait() => {
            return match res {
                Ok(code) => Generation::Crashed(format!("exited before first beat: {code:?}")),
                Err(e) => Generation::Crashed(format!("wait failed: {e}")),
            };
        }
        _ = stop_rx.changed() => {
            if *stop_rx.borrow() { return Generation::Stopped; }
            return Generation::Crashed("stop signal during accept".into());
        }
        // The child must connect within one timeout window too — a boot-frozen
        // app that never heartbeats is exactly as dead as a hung one.
        _ = tokio::time::sleep(config.timeout) => {
            status.state.store(WatchState::Suspect as u8, Ordering::Relaxed);
            return Generation::Crashed(format!("child never connected within {:?}", config.timeout));
        }
    };

    status
        .state
        .store(WatchState::Healthy as u8, Ordering::Relaxed);
    let healthy_at = std::time::Instant::now();
    status.last_beat_age_ms.store(0, Ordering::Relaxed);

    let mut stream = conn;
    let mut buf = [0u8; 8];
    loop {
        tokio::select! {
            res = stream.read(&mut buf) => {
                match res {
                    Ok(8) => {
                        status.last_beat_age_ms.store(0, Ordering::Relaxed);
                        status.state.store(WatchState::Healthy as u8, Ordering::Relaxed);
                    }
                    Ok(0) => return Generation::Crashed("heartbeat stream closed".into()),
                    Ok(_) => return Generation::Crashed("short heartbeat frame".into()),
                    Err(e) => return Generation::Crashed(format!("heartbeat read error: {e}")),
                }
            }
            _ = tokio::time::sleep(config.timeout) => {
                let age = healthy_at.elapsed().as_millis() as u64;
                status.last_beat_age_ms.store(age, Ordering::Relaxed);
                status.state.store(WatchState::Suspect as u8, Ordering::Relaxed);
                return Generation::Crashed(format!("no beat within {:?}", config.timeout));
            }
            res = child.wait() => {
                return match res {
                    Ok(code) => Generation::Crashed(format!("exited: {code:?}")),
                    Err(e) => Generation::Crashed(format!("wait failed: {e}")),
                };
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() { return Generation::Stopped; }
            }
        }
    }
}

/// Child-side heartbeat loop: connect to the supervisor socket and send a
/// u64 counter beat every `beat_every` until the process is killed.
pub async fn heartbeat_client(socket: PathBuf, beat_every: Duration) -> std::io::Result<()> {
    let mut stream = loop {
        match UnixStream::connect(&socket).await {
            Ok(s) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let mut counter: u64 = 0;
    loop {
        counter += 1;
        stream.write_all(&counter.to_le_bytes()).await?;
        tokio::time::sleep(beat_every).await;
    }
}

use tokio::io::AsyncWriteExt;

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bb-wd-{tag}-{}.sock", std::process::id()))
    }

    fn cfg(tag: &str, program: &str, args: &[&str], timeout_ms: u64, max_restarts: u32) -> WatchdogConfig {
        WatchdogConfig {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            socket_path: sock(tag),
            beat_every: Duration::from_millis(100),
            timeout: Duration::from_millis(timeout_ms),
            backoff_start: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
            max_restarts,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restarts_on_crash_then_stops_at_max() {
        let wd = spawn_watchdog(cfg("crash", "/bin/sh", &["-c", "exit 0"], 800, 2));
        tokio::time::sleep(Duration::from_millis(900)).await;
        let (state, _pid, restarts, _age) = wd.status().snapshot();
        assert!(restarts >= 2, "expected >=2 restarts, got {restarts}");
        assert_eq!(state, WatchState::Stopped);
        wd.shutdown().await;
        let _ = std::fs::remove_file(sock("crash"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heartbeat_beats_keep_child_healthy() {
        let config = cfg("beat", "/bin/sh", &["-c", "sleep 30"], 500, 10);
        let path = config.socket_path.clone();
        let wd = spawn_watchdog(config);

        // Simulate the child's heartbeat from the test itself.
        let beater = tokio::spawn(heartbeat_client(path, Duration::from_millis(100)));

        tokio::time::sleep(Duration::from_millis(1_000)).await;
        let (state, _pid, restarts, _age) = wd.status().snapshot();
        assert_eq!(state, WatchState::Healthy, "beats must keep it healthy");
        assert_eq!(restarts, 0);

        beater.abort();
        wd.shutdown().await;
        let _ = std::fs::remove_file(sock("beat"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silent_child_is_killed_and_restarted() {
        // Child sleeps forever and never beats → watchdog must kill+restart.
        let wd = spawn_watchdog(cfg("silent", "/bin/sh", &["-c", "sleep 30"], 300, 1));
        tokio::time::sleep(Duration::from_millis(900)).await;
        let (_state, _pid, restarts, _age) = wd.status().snapshot();
        assert!(restarts >= 1, "silent child must be restarted, got {restarts}");
        wd.shutdown().await;
        let _ = std::fs::remove_file(sock("silent"));
    }
}
