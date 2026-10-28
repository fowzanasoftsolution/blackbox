//! v1.1.2 verification gate — SIGINT / SIGTERM clean shutdown (rc = 0).
//!
//! Regression for the v1.1.1 30-minute soak (`bb-soak-30m`): Node B was
//! stopped with `rc = -15` because a detached/backgrounded launcher leaves
//! `SIGINT` inherited as `SIG_IGN` and only `SIGTERM` is delivered — with
//! no handler installed, `serve` was killed outright (no writer drain, no
//! fsync, no chance to persist the group-commit tail).
//!
//! v1.1.2 installs explicit `tokio::signal::ctrl_c()` + `SIGTERM` handlers
//! in BOTH `blackbox serve` and `blackbox run`, drains + fsyncs the segment
//! writer, and returns exit code 0. This gate boots the real binary and
//! asserts:
//!
//! 1. `serve` + SIGTERM → exit code 0 (was rc = -15),
//! 2. `serve` + SIGINT  → exit code 0 (was silently ignored / killed),
//! 3. `run`   + SIGTERM → exit code 0 with the supervised child reaped,
//! 4. every record accepted BEFORE the signal is durable on disk after
//!    shutdown (the drain actually flushed — no lost tail).
#![cfg(unix)]

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use blackbox_core::segment::read_all_records;

const BIN: &str = env!("CARGO_BIN_EXE_blackbox");

// -- child management ------------------------------------------------------

/// Soak-parity environment: the 30-minute soak runs every node with
/// `TOKIO_WORKER_THREADS=2`. On a many-core CI/Docker host the default
/// (one worker per visible core) inflates baseline RSS far past the 48 MiB
/// budget, which would falsely trip the `Shed85`/`Backpressure95` samplers
/// and hide real flush behavior — so the gate pins the same thread count.
fn soak_env() -> std::collections::HashMap<String, String> {
    let mut env: std::collections::HashMap<String, String> =
        std::env::vars().collect();
    env.insert("TOKIO_WORKER_THREADS".into(), "2".into());
    env
}

fn spawn_capture(args: &[&str]) -> Child {
    Command::new(BIN)
        .args(args)
        .envs(soak_env())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child")
}

/// Detach + drain the pipes on background threads so a chatty child never
/// blocks on a full pipe buffer during the test.
fn drain_pipes(child: &mut Child) {
    let pipes: Vec<Box<dyn std::io::Read + Send>> = vec![
        Box::new(child.stdout.take().expect("stdout")),
        Box::new(child.stderr.take().expect("stderr")),
    ];
    for mut pipe in pipes {
        std::thread::spawn(move || {
            let mut sink = std::io::sink();
            let _ = std::io::copy(&mut pipe, &mut sink);
        });
    }
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = l.local_addr().unwrap().port();
    drop(l);
    std::thread::sleep(Duration::from_millis(20));
    port
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "blackbox-shutdown-{tag}-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Minimal blocking HTTP/1.1 POST — returns the response status.
fn post(port: u16, path: &str, body: &[u8]) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// Signal the child by pid (SIGTERM/SIGINT via `kill(2)` — the `nix` crate
/// is already a workspace dependency with the `signal` feature).
fn signal_child(child: &Child, sig: i32) {
    let pid = child.id() as i32;
    let signal = match sig {
        15 => nix::sys::signal::Signal::SIGTERM,
        2 => nix::sys::signal::Signal::SIGINT,
        _ => unreachable!("test only sends SIGTERM/SIGINT"),
    };
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal)
        .unwrap_or_else(|e| panic!("kill({pid}, {sig}): {e}"));
}

/// Wait for exit; assert rc == 0 within the timeout. Kills on timeout.
fn expect_clean_exit(child: &mut Child, timeout: Duration, ctx: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "{ctx}: exit must be clean rc=0 (got {status})"
                );
                return;
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{ctx}: did not exit within {timeout:?}");
            }
        }
    }
}

// -- the gate ---------------------------------------------------------------

/// Serialize the tests in this file: each boots real listeners on ephemeral
/// ports and delivers a real signal, so parallel runs can race the
/// bind/signal window across tests. One lock at each test entry makes them
/// run one at a time. `into_inner()` recovers if a prior test panicked, so
/// one failure does not poison (and dead-lock) the rest.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Shared body: boot `serve`, send traffic, deliver `sig`, assert rc=0 and
/// that every accepted record survived the drain.
fn serve_survives_signal_with_durable_records(tag: &str, sig: i32) {
    let _serial = serial_guard();
    let dir = tmpdir(tag);
    let app_port = free_port();
    let serve_port = free_port();

    // Upstream app (env-child stand-in).
    let env_file = dir.join("env.json");
    let mut app = spawn_capture(&[
        "env-child",
        "--port",
        &app_port.to_string(),
        "--env-file",
        env_file.to_str().unwrap(),
    ]);
    drain_pipes(&mut app);
    assert!(wait_port(app_port, Duration::from_secs(5)), "env-child up");

    // The node.
    let mut server = spawn_capture(&[
        "serve",
        "--upstream",
        &format!("127.0.0.1:{app_port}"),
        "--listen",
        &format!("127.0.0.1:{serve_port}"),
        "--admin-listen",
        "127.0.0.1:0",
        "--egress-listen",
        "127.0.0.1:0",
        "--data",
        dir.to_str().unwrap(),
        // This gate verifies the SIGTERM/SIGINT drain (rc=0 + acknowledged
        // records durable), NOT the Shed85 sampler. With the default 48 MB
        // budget on a THP=always host (Docker Desktop; several runner
        // images) the process VmRSS reads past the 40.8 MB Shed85 watermark
        // while fully idle, and the finalizer legitimately head-samples
        // away ~99 % of healthy fast 2xx traffic — the gate then flaked as
        // "0 records durable" with a perfectly-working drain (a lost round
        // measured sampled_out=8, frames=0 in the admin stats). The demo
        // node makes the same adjustment (NodeConfig in demo.rs).
        "--mem-budget-mb",
        "256",
    ]);
    drain_pipes(&mut server);
    assert!(wait_port(serve_port, Duration::from_secs(15)), "serve up");

    // Accepted traffic (each 200 through the proxy to env-child).
    let n = 8;
    for i in 0..n {
        let st = post(serve_port, "/api/events", format!("{{\"i\":{i}}}").as_bytes());
        assert_eq!(st, 200, "traffic {i} through serve");
    }

    // Deliver the signal and demand a clean exit.
    signal_child(&server, sig);
    expect_clean_exit(&mut server, Duration::from_secs(20), tag);

    // The drain must have persisted every accepted record.
    let records = read_all_records(&dir).expect("reopen after clean shutdown");
    assert!(
        records.len() >= n,
        "{tag}: {n} accepted records must be durable after shutdown (got {})",
        records.len()
    );

    // Upstream app no longer needed.
    let _ = app.kill();
    let _ = app.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// v1.1.2: `blackbox serve` + SIGTERM must exit rc=0 (v1.1.1: rc=-15).
#[test]
fn serve_sigterm_exits_zero_and_flushes() {
    serve_survives_signal_with_durable_records("serve-sigterm", 15);
}

/// v1.1.2: `blackbox serve` + SIGINT must exit rc=0 (v1.1.1: inherited
/// SIG_IGN made it unkillable-by-int; only SIGTERM worked, and even that
/// killed without a flush).
#[test]
fn serve_sigint_exits_zero_and_flushes() {
    serve_survives_signal_with_durable_records("serve-sigint", 2);
}

/// v1.1.2: `blackbox run` (supervisor mode) + SIGTERM must reap the
/// supervised child and exit rc=0.
#[test]
fn run_sigterm_exits_zero() {
    let _serial = serial_guard();
    let dir = tmpdir("run-sigterm");
    let app_port = free_port();
    let serve_port = free_port();
    let env_file = dir.join("env.json");

    let mut runner = spawn_capture(&[
        "run",
        "--upstream-port",
        &app_port.to_string(),
        "--listen",
        &format!("127.0.0.1:{serve_port}"),
        "--admin-listen",
        "127.0.0.1:0",
        "--egress-listen",
        "127.0.0.1:0",
        "--data",
        dir.to_str().unwrap(),
        // Drain gate, not sampler gate — see the serve leg's note.
        "--mem-budget-mb",
        "256",
        "--",
        BIN,
        "env-child",
        "--port",
        &app_port.to_string(),
        "--env-file",
        env_file.to_str().unwrap(),
    ]);
    drain_pipes(&mut runner);
    assert!(wait_port(serve_port, Duration::from_secs(20)), "run node up");
    // The supervised child binds its own port after the first spawn.
    assert!(wait_port(app_port, Duration::from_secs(15)), "supervised child up");

    let st = post(serve_port, "/api/events", b"{\"run\":true}");
    assert_eq!(st, 200, "traffic through run");

    signal_child(&runner, 15);
    expect_clean_exit(&mut runner, Duration::from_secs(30), "run-sigterm");

    let records = read_all_records(&dir).expect("reopen after clean run shutdown");
    assert!(
        !records.is_empty(),
        "run: accepted record must be durable after shutdown"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
