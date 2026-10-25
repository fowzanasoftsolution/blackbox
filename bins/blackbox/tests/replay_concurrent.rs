//! v1.0.3 verification gate — CONCURRENT replay against a LIVE server.
//!
//! Boots `blackbox serve` (with an env-child upstream app) on a seeded
//! data dir, then — while the server is live, serving traffic and holding
//! the `jobs.redb` writer lock — launches `blackbox replay <trace_id>`
//! as a separate subprocess against the SAME `--data` dir.
//!
//! Assertions:
//! 1. The replay boot DETECTS the live node's lock and clones the dir into
//!    an ephemeral scratch copy (the automatic fallback, no `--data-copy`).
//! 2. The replay sandbox serves recorded egress calls verbatim (200 with
//!    the recorded bytes) and blocks unrecorded ones (428 +
//!    `x-blackbox-replay-blocked: true`).
//! 3. Zero redb lock errors anywhere ("already open" never appears).
//! 4. The live server never dies and keeps answering throughout the
//!    replay window.
//! 5. The live data dir is untouched by replay: `*.redb` + sealed
//!    `*.zst`/`*.idx` byte-sizes are identical before/after, and no new
//!    files appear. (`.log` may legitimately grow — it carries the live
//!    node's own ingress traffic.)

use std::io::Read as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_blackbox");

// -- child management ------------------------------------------------------

fn spawn_capture(args: &[&str]) -> (Child, Arc<Mutex<String>>) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let drain = |pipe: Box<dyn std::io::Read + Send>, tag: &'static str, sink: Arc<Mutex<String>>| {
        std::thread::spawn(move || {
            let mut pipe = pipe;
            // Incremental reads: the node children run indefinitely, so we
            // must not wait for EOF — push whatever arrives, as it arrives.
            let mut pending = String::new();
            let mut chunk = [0u8; 8 * 1024];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break, // EOF — child closed the pipe
                    Ok(n) => {
                        pending.push_str(&String::from_utf8_lossy(&chunk[..n]));
                        if let Ok(mut s) = sink.lock() {
                            s.push_str(&format!("[{tag}] {pending}"));
                            pending.clear();
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    };
    drain(Box::new(child.stdout.take().expect("stdout")), "out", Arc::clone(&buf));
    drain(Box::new(child.stderr.take().expect("stderr")), "err", buf.clone());
    (child, buf)
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn free_port(_tag: &str) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = l.local_addr().unwrap().port();
    drop(l);
    std::thread::sleep(Duration::from_millis(20)); // let the freelist settle
    port
}

// -- raw HTTP client (the test IS the app) ---------------------------------

/// One HTTP/1.1 request over a fresh connection. `target` may be
/// absolute-form (`http://host/path`) for the egress interceptor or
/// origin-form (`/path`) for a direct listener. Returns (status, body).
async fn raw_http(
    port: u16,
    target: &str,
    method: &str,
    body: &[u8],
) -> (u16, Vec<u8>, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (req_target, host) = if let Some(rest) = target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or(rest).to_string();
        (target.to_string(), authority)
    } else {
        (target.to_string(), format!("127.0.0.1:{port}"))
    };

    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let req = format!(
        "{method} {req_target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).await.expect("write header");
    s.write_all(body).await.expect("write body");

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split(' ')
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    (status, buf[sep..].to_vec(), text[..text.len().min(sep)].to_string())
}

// -- data dir helpers ------------------------------------------------------

fn dir_map(dir: &Path) -> std::collections::BTreeMap<String, u64> {
    let mut map = std::collections::BTreeMap::new();
    for e in std::fs::read_dir(dir).expect("read dir") {
        let e = e.unwrap();
        if e.path().is_file() {
            map.insert(
                e.file_name().to_string_lossy().to_string(),
                e.metadata().expect("meta").len(),
            );
        }
    }
    map
}

// -- the gate --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_against_a_live_server_uses_the_scratch_copy() {
    use blackbox_core::schema::{EgressHttpMock, RecordPayload, TraceRecord};
    use blackbox_core::segment::SegmentStore;

    let rnd = blackbox_core::schema::new_id128() as u64;
    let dir = std::env::temp_dir().join(format!("bb-gate-live-{rnd}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create data dir");

    // The replayed trace: one recorded payment call + one recorded balance
    // call under TID, on a blackhole authority (the mock interceptor never
    // forwards, so the host is arbitrary).
    let tid: blackbox_core::schema::TraceId = [0xB1u8; 16];
    let tid_hex = blackbox_core::schema::trace_id_to_hex(&tid);
    let pay_url = "http://blackbox-gate.test/v1/pay";
    let bal_url = "http://blackbox-gate.test/v1/balance";
    let pay_body = br#"{"order":1}"#.to_vec();
    let pay_resp = br#"{"pay":"ch_ok","status":"captured"}"#.to_vec();
    let bal_resp = br#"{"balance":4200}"#.to_vec();
    {
        let mut store = SegmentStore::open(&dir).expect("seed store open");
        let seeds: [(u64, &str, &str, Vec<u8>, Vec<u8>); 2] = [
            (0, pay_url, "POST", pay_body.clone(), pay_resp.clone()),
            (1, bal_url, "GET", Vec::new(), bal_resp.clone()),
        ];
        for (seq, url, method, body, resp) in seeds {
            let fp = blackbox_core::egress_key::fingerprint(method, url, &body);
            let rec = TraceRecord::new(
                tid,
                seq,
                RecordPayload::EgressHttpMock(EgressHttpMock {
                    seq_no: seq,
                    request_fingerprint: fp,
                    method: method.into(),
                    request_url: url.into(),
                    response_status: 200,
                    response_headers: vec![("content-type".into(), "application/json".into())],
                    response_body: resp,
                    upstream_host: "blackbox-gate.test".into(),
                    recorded_at_ms: blackbox_core::schema::now_ms(),
                }),
            );
            store.append(&rec).expect("seed append");
        }
        store.sync().expect("seed sync");
    }

    // Free ports (snap, pass explicit).
    let app_port = free_port("app");
    let serve_port = free_port("serve");
    let replay_port = free_port("repl");
    let egress_port = free_port("egr");

    // 1) The upstream app.
    let env_file = std::env::temp_dir().join(format!("bb-gate-live-env-{rnd}.json"));
    let (mut app, _app_log) = spawn_capture(&[
        "env-child",
        "--port",
        &app_port.to_string(),
        "--env-file",
        env_file.to_str().unwrap(),
    ]);
    assert!(
        wait_port(app_port, Duration::from_secs(5)),
        "env-child must come up"
    );

    // 2) The live node — jobs.redb (writer lock) held for the whole gate.
    let data_arg = dir.to_string_lossy().to_string();
    let (mut server, _serve_log) = spawn_capture(&[
        "serve",
        "--upstream",
        &format!("127.0.0.1:{app_port}"),
        "--listen",
        &format!("127.0.0.1:{serve_port}"),
        "--admin-listen",
        "127.0.0.1:0",
        "--data",
        &data_arg,
    ]);
    assert!(
        wait_port(serve_port, Duration::from_secs(15)),
        "serve must come up"
    );
    std::thread::sleep(Duration::from_millis(500)); // let redb settle its boot commit

    // 3) Traffic through the live node.
    for _ in 0..3 {
        let (st, _, _) = raw_http(serve_port, "/api/events", "POST", b"{\"load\":true}").await;
        assert_eq!(st, 200, "live traffic through serve must be 200");
    }

    // Zero-touch baseline (after serving's startup writes settle).
    let before = dir_map(&dir);

    // 4) The CONCURRENT replay — no --data-copy: the fallback must detect
    //    the live node and clone the dir by itself.
    let (mut replay, replay_log) = spawn_capture(&[
        "replay",
        &tid_hex,
        "--target",
        &format!("http://127.0.0.1:{app_port}"),
        "--data",
        &data_arg,
        "--listen",
        &format!("127.0.0.1:{replay_port}"),
        "--egress",
        &format!("127.0.0.1:{egress_port}"),
    ]);
    assert!(
        wait_port(replay_port, Duration::from_secs(15)),
        "replay proxy must come up beside the live node"
    );

    // 5) Zero disruption: probe the live node WHILE the replay is up.
    for _ in 0..5 {
        let (st, _, _) = raw_http(serve_port, "/api/events", "POST", b"{\"load\":true}").await;
        assert_eq!(st, 200, "serve must keep answering during replay");
    }

    // 6) The recorded sandbox: exact 200s with the recorded bytes.
    let (st, body, _) =
        raw_http(egress_port, pay_url, "POST", &pay_body).await;
    assert_eq!(st, 200, "recorded payment must resolve 200");
    assert_eq!(body, pay_resp, "recorded response must be verbatim");
    let (st, body, _) = raw_http(egress_port, bal_url, "GET", b"").await;
    assert_eq!(st, 200, "recorded balance must resolve 200");
    assert_eq!(body, bal_resp, "recorded response must be verbatim");

    // 7) The unrecorded guard: 428 + x-blackbox-replay-blocked: true.
    let (st, _, head) =
        raw_http(egress_port, "http://blackbox-gate.test/v1/unrecorded", "POST", b"{}").await;
    assert_eq!(st, 428, "unrecorded egress must be 428-blocked");
    assert!(
        head.to_ascii_lowercase().contains("x-blackbox-replay-blocked: true"),
        "428 must carry the replay-blocked header, got: {head}"
    );

    // 8) The replayed request itself (through the replay proxy → the app).
    let (st, body, _) =
        raw_http(replay_port, "/api/replayed", "POST", b"{\"fix\":\"hot\"}").await;
    assert_eq!(st, 200, "the replayed request must round-trip");
    assert_eq!(body, b"ok /api/replayed".to_vec(), "upstream app must answer through the replay proxy");

    // 9) Still alive? Live traffic once more.
    let (st, _, _) = raw_http(serve_port, "/api/events", "POST", b"{\"load\":true}").await;
    assert_eq!(st, 200, "serve survives the whole concurrent-replay gate");
    assert!(server.try_wait().unwrap().is_none(), "serve must still be running");
    assert!(replay.try_wait().unwrap().is_none(), "replay must still be running");

    // 10) Zero lock errors in the replay's own output.
    std::thread::sleep(Duration::from_millis(200));
    let log = replay_log.lock().unwrap().to_lowercase();
    assert!(
        !log.contains("alreadyopen") && !log.contains("already open"),
        "replay must never hit a redb lock error, log: {log}"
    );
    assert!(
        log.contains("data-copy: cloned"),
        "replay must clone the dir when the node is live, log: {log}"
    );
    assert!(
        log.contains("live node redb lock detected"),
        "the automatic fallback must report the live-lock detection, log: {log}"
    );

    // 11) Zero-touch: redb + sealed artifacts identical, no new files.
    std::thread::sleep(Duration::from_millis(200));
    let after = dir_map(&dir);
    for (name, len) in &before {
        match after.get(name) {
            Some(&l2) => {
                let is_redb = name.ends_with(".redb");
                let is_sealed = name.ends_with(".zst") || name.ends_with(".idx");
                if is_redb || is_sealed {
                    assert_eq!(
                        &l2, len,
                        "{name} must not change while replay runs against the scratch copy"
                    );
                }
                // .log may grow with the live node's own traffic — untouched
            }
            None => panic!("replay must never delete live files: {name} vanished"),
        }
    }
    for name in after.keys() {
        assert!(
            before.contains_key(name),
            "replay must never create files in the live dir: {name}"
        );
    }

    // Teardown.
    replay.kill().ok();
    server.kill().ok();
    app.kill().ok();
    std::thread::sleep(Duration::from_millis(100));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&env_file);
}
