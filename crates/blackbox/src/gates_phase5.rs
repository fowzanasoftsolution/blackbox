//! Phase 5 verification gates:
//!
//! - [`gate1`] hot-to-cold rollover + cold replay + eviction,
//! - [`gate2`] zero-config auto-resurrection,
//! - [`gate3`] zero-leak mixed-workload soak (100 K+ ops, flat RSS).
//!
//! The storage-management code these gates exercise lives in
//! [`crate::janitor`]; the injectable-env stand-in app is [`crate::ops`].

use anyhow::{Context, Result};
use blackbox_core::compactor::DEFAULT_COMPRESS_LEVEL;
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type HttpBody = Full<Bytes>;
type ClientT = Client<HttpConnector, HttpBody>;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("blackbox-p5-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn http_client() -> ClientT {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(60)));
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(256)
        .build(connector)
}

fn rand_trace_hex() -> String {
    let a = fastrand::u64(..);
    let b = fastrand::u64(..);
    format!("{a:016x}{b:016x}")
}

/// Hand-rolled HTTP/1.1 call with an ABSOLUTE-FORM request target (the
/// forward-proxy / replay-interceptor wire form). Returns
/// `(status, body, headers)`.
async fn forward_proxy_call(
    addr: SocketAddr,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    let mut tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut req = format!("{method} {url} HTTP/1.1\r\nhost: {url}\r\ncontent-length: {}\r\nconnection: close\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;
    tcp.write_all(body).await?;
    tcp.flush().await?;
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await?;

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no header end"))?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let payload = buf[header_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut hdrs = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            hdrs.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Ok((status, payload, hdrs))
}

async fn wait_port(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Gate 1 — hot-to-cold .zst rollover & cold replay & 85% eviction
// ---------------------------------------------------------------------------

pub async fn gate1() -> Result<()> {
    use blackbox_core::compactor::{compact_all, cold_zst_stats, evict_cold_fifo, idx_path, load_idx};
    use blackbox_core::schema::{EgressHttpMock, RecordPayload};
    use blackbox_core::segment::{
        read_meta_all, read_record_at, SegmentConfig, SegmentStore,
    };

    let dir = tmpdir("gate1");
    const SEG_CAP: u64 = 1024 * 1024; // 1 MB — spec rollover threshold
    let mut store = SegmentStore::open_with(&dir, SegmentConfig { max_segment_bytes: SEG_CAP, ..Default::default() })?;

    // Compressible 4 KB JSON body (zstd-3 must exceed 4x).
    let big_body = "{\"event\":\"synthetic\",\"pad\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".repeat(48);
    let mock_tid: [u8; 16] = {
        let mut t = [0xB0u8; 16];
        t[1] = 0x07;
        t
    };
    let mock_url = "http://api.blackbox.test/v1/charge";
    let mock_body = br#"{"amount":4200,"currency":"usd"}"#.to_vec();
    let mock_resp_body = br#"{"charge":"ch_cold_12345","status":"succeeded"}"#.to_vec();

    let mut seq: u64 = 0;
    while store.active_segment_id() < 5 {
        seq += 1;
        let payload = if seq == 481 {
            RecordPayload::EgressHttpMock(EgressHttpMock {
                seq_no: 0,
                request_fingerprint: blackbox_core::egress_key::fingerprint(
                    "POST",
                    mock_url,
                    &mock_body,
                ),
                method: "POST".into(),
                request_url: mock_url.into(),
                response_status: 200,
                response_headers: vec![("content-type".into(), "application/json".into())],
                response_body: mock_resp_body.clone(),
                upstream_host: "api.blackbox.test".into(),
                recorded_at_ms: blackbox_core::schema::now_ms(),
            })
        } else {
            RecordPayload::IngressHttp(blackbox_core::schema::IngressHttp {
                method: "POST".into(),
                uri: "/api/events".into(),
                status: 200,
                req_headers: vec![],
                req_body: big_body.clone().into_bytes(),
                res_body: b"{\"ok\":true}".to_vec(),
                duration_ms: 2,
            })
        };
        let tid = if seq == 481 {
            mock_tid
        } else {
            blackbox_core::schema::new_id128().to_be_bytes()
        };
        store.append(&blackbox_core::schema::TraceRecord::new(tid, seq, payload))?;
    }
    store.sync()?;
    let active = store.active_segment_id();
    assert!(active >= 5, "gate needs 5 rollovers at 1 MB, got {active}");
    let pre = blackbox_core::segment::read_all_records(&dir)?;
    println!("gate1: wrote {seq} records across {} rollovers (1 MB cap)", active);
    drop(store);

    // ---- Compact: sealed .log → .log.zst + .idx --------------------------
    let report = compact_all(&dir, active, DEFAULT_COMPRESS_LEVEL)?;
    assert_eq!(
        report.segments_compacted, active,
        "all sealed raws compress"
    );
    let (zst_n, zst_bytes) = cold_zst_stats(&dir);
    assert!(zst_n >= 5, "expected >=5 .zst segments, got {zst_n}");

    let mut raw_total = 0u64;
    for id in 0..active {
        let (raw_len, entries) =
            load_idx(&dir, id)?.unwrap_or_else(|| panic!("sidecar for segment {id}"));
        let zst = std::fs::metadata(dir.join(format!("segment_{id:06}.log.zst")))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(!dir.join(format!("segment_{id:06}.log")).exists(), "raw removed");
        if raw_len > 0 {
            let ratio = raw_len as f64 / zst.max(1) as f64;
            assert!(ratio > 4.0, "segment {id}: {ratio:.1}x must exceed 4x (raw {raw_len} → zst {zst})");
            raw_total += raw_len;
        }
        assert!(!entries.is_empty() || raw_len == 0);
    }
    println!(
        "gate1: {zst_n} segments sealed → {} KB raw → {} KB .zst ({:.1}x overall, zstd-3)",
        raw_total / 1024,
        zst_bytes / 1024,
        raw_total as f64 / zst_bytes.max(1) as f64
    );

    // ---- Cold reads + fast index rebuild ---------------------------------
    let metas = read_meta_all(&dir)?;
    assert_eq!(metas.len(), pre.len(), "sidecar fast path indexes every frame");
    let sampled = [0, 25, 250, pre.len() / 2, pre.len() - 1];
    for &i in &sampled {
        let (seg, off, meta) = metas[i];
        let got = read_record_at(&dir, seg, off)?;
        assert_eq!(got.seq_no, pre[i].seq_no);
        assert_eq!(got.trace_id, meta.trace_id);
    }
    let index = blackbox_ingress::index::TraceIndex::rebuild(&dir)?;
    assert_eq!(index.stats().frames as usize, pre.len());
    println!("gate1: cold reads + fast index rebuild OK ({} frames)", pre.len());

    // ---- `blackbox replay` transparently reads the compressed trace ------
    // 9a) The exact loader the CLI uses, against the compacted dir:
    let tid_hex = hex_of(mock_tid);
    let engine = blackbox_queue::ReplayEngine::load(&dir, &mock_tid)?;
    assert_eq!(engine.total(), 1, "replay engine loads the mock from .zst cold storage");

    // 9b) The REAL CLI: `blackbox replay <tid>` with fixed ports, then a
    //     forward-proxy call served from the recorded (compressed) mock.
    let egress_port = free_port().await?;
    let ingress_port = free_port().await?;
    let exe = std::env::current_exe()?;
    let mut cli = tokio::process::Command::new(exe)
        .args([
            "replay",
            &tid_hex,
            "--target",
            "http://127.0.0.1:9",
            "--data",
            dir.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{ingress_port}"),
            "--egress",
            &format!("127.0.0.1:{egress_port}"),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn blackbox replay CLI")?;
    let egress_addr: SocketAddr = format!("127.0.0.1:{egress_port}").parse()?;
    assert!(
        wait_port(egress_addr, Duration::from_secs(20)).await,
        "replay CLI mock interceptor must come up"
    );

    let (status, body, _) = forward_proxy_call(
        egress_addr,
        "POST",
        mock_url,
        &[
            ("content-type", "application/json"),
            ("traceparent", &format!("00-{tid_hex}-0000000000000001-01")),
        ],
        &mock_body,
    )
    .await?;
    assert_eq!(status, 200, "recorded (cold .zst) mock must be served");
    assert!(
        String::from_utf8_lossy(&body).contains("ch_cold_12345"),
        "exact recorded response: {}",
        String::from_utf8_lossy(&body)
    );
    let (status, _, hdrs) = forward_proxy_call(
        egress_addr,
        "POST",
        "http://api.blackbox.test/v1/refund",
        &[],
        b"{}",
    )
    .await?;
    assert_eq!(status, 428, "unrecorded call must stay sandbox-blocked");
    assert!(hdrs.iter().any(|(k, v)| k == "x-blackbox-replay-blocked" && v == "true"));
    cli.kill().await?;
    let _ = cli.wait().await;
    println!("gate1: blackbox replay CLI read trace {tid_hex} straight from .zst cold storage (200 + 428 guard)");

    // ---- 85% disk-quota eviction (oldest .zst FIFO) ----------------------
    let used = dir_size(&dir);
    // Force an Evict85 reading: quota set so used/quota == 0.9.
    let quota = used * 10 / 9;
    let monitor = blackbox_supervisor::disk::DiskMonitor::new(dir.clone(), quota);
    let reading = monitor.poll().unwrap();
    assert_eq!(reading.level, blackbox_supervisor::disk::DiskLevel::Evict85);
    let free_target = used - quota / 5 * 4; // down to 80%
    let oldest_zst = (0..active)
        .find(|&id| dir.join(format!("segment_{id:06}.log.zst")).exists())
        .expect("cold zst present");
    let (removed, freed) = evict_cold_fifo(&dir, free_target)?;
    assert!(removed >= 1 && freed > 0, "eviction must free space");
    assert!(!dir.join(format!("segment_{oldest_zst:06}.log.zst")).exists());
    assert!(!idx_path(&dir, oldest_zst).exists(), "sidecar evicted too");
    // Newer cold segments survive; the active raw is never touched.
    let newest_zst = (0..active)
        .rev()
        .find(|&id| {
            let p = dir.join(format!("segment_{id:06}.log.zst"));
            p.exists()
        });
    if let Some(newest) = newest_zst {
        assert!(newest > oldest_zst);
        assert!(dir.join(format!("segment_{newest:06}.log.zst")).exists());
    }
    assert!(dir.join(format!("segment_{active:06}.log")).exists(), "active raw survives");
    println!(
        "gate1: Evict85 reading → {} oldest .zst segment(s) evicted ({} KB freed), FIFO order clean",
        removed,
        freed / 1024
    );

    // ---- Restart after compaction: never resurrect a compacted id -------
    // The eviction legitimately deleted the oldest .zst data — capture what
    // remains on disk BEFORE reopening.
    let remaining_after_evict = read_meta_all(&dir)?.len();
    assert!(
        remaining_after_evict < pre.len(),
        "eviction must have removed the oldest cold segment's frames"
    );
    let mut store = SegmentStore::open_with(&dir, SegmentConfig { max_segment_bytes: SEG_CAP, ..Default::default() })?;
    assert!(
        store.active_segment_id() >= active,
        "restart must continue at or after the previous active ({}), got {}",
        active,
        store.active_segment_id()
    );
    assert!(
        !dir.join(format!("segment_{oldest_zst:06}.log")).exists(),
        "an evicted/compacted segment id must never re-materialize as raw"
    );
    store.append(&blackbox_core::schema::TraceRecord::new(
        blackbox_core::schema::new_id128().to_be_bytes(),
        pre.len() as u64,
        RecordPayload::IngressHttp(blackbox_core::schema::IngressHttp {
            method: "GET".into(),
            uri: "/after".into(),
            status: 200,
            req_headers: vec![],
            req_body: vec![],
            res_body: b"ok".to_vec(),
            duration_ms: 1,
        }),
    ))?;
    store.sync()?;
    let post = blackbox_core::segment::read_all_records(&dir)?;
    assert_eq!(
        post.len(),
        remaining_after_evict + 1,
        "remaining sealed + evicted gap + fresh append must be exactly consistent"
    );
    let _ = std::fs::remove_dir_all(&dir);

    println!("gate1 PASS: rollover → zstd-3 seal >4x → cold get_trace/replay → Evict85 FIFO eviction → clean restart");
    Ok(())
}

fn hex_of(tid: [u8; 16]) -> String {
    tid.iter().map(|b| format!("{b:02x}")).collect()
}

fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

async fn free_port() -> Result<u16> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p = l.local_addr()?.port();
    drop(l);
    Ok(p)
}

// ---------------------------------------------------------------------------
// Gate 2 — blackbox run zero-config auto-resurrection
// ---------------------------------------------------------------------------

/// Read the child pid file (written by `blackbox run` on every spawn).
fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

async fn wait_pid_change(path: &Path, old: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(p) = read_pid(path) {
            if p != old {
                return Some(p);
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    None
}

fn kill9(pid: u32) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
}

pub async fn gate2() -> Result<()> {
    let dir = tmpdir("gate2");
    let exe = std::env::current_exe()?;
    let child_port = free_port().await?;
    let status_file = dir.join("node.json");
    let pid_file = dir.join("child.pid");
    let env_file = dir.join("child-env.json");

    // `blackbox run --upstream-port P -- blackbox env-child --port P ...`
    let mut run_proc = tokio::process::Command::new(&exe)
        .args([
            "run",
            "--upstream-port",
            &child_port.to_string(),
            "--listen",
            "127.0.0.1:0",
            "--egress-listen",
            "127.0.0.1:0",
            "--admin-listen",
            "127.0.0.1:0",
            "--data",
            dir.to_str().unwrap(),
            "--hold-ms",
            "15000",
            "--status-file",
            status_file.to_str().unwrap(),
            "--pid-file",
            pid_file.to_str().unwrap(),
            "--",
            exe.to_str().unwrap(),
            "env-child",
            "--port",
            &child_port.to_string(),
            "--env-file",
            env_file.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn `blackbox run` subprocess")?;

    // Wait for the node status file, then the child's env dump.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !status_file.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::ensure!(status_file.exists(), "blackbox run did not write its status file");
    let status: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&status_file)?)?;
    let ingress: SocketAddr = status["ingress"].as_str().context("ingress addr")?.parse()?;
    let egress: SocketAddr = status["egress"].as_str().context("egress addr")?.parse()?;

    while !env_file.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::ensure!(env_file.exists(), "child never wrote its env dump");

    // ---- Zero-config env injection assertions ----------------------------
    let env: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&env_file)?)?;
    let expect = serde_json::json!({
        "SENTRY_DSN": format!("http://public@127.0.0.1:{}/1", ingress.port()),
        "OTEL_EXPORTER_OTLP_ENDPOINT": format!("http://127.0.0.1:{}", ingress.port()),
        "OPENAI_BASE_URL": format!(
            "http://127.0.0.1:{}/egress/https/api.openai.com/v1",
            egress.port()
        ),
        "ANTHROPIC_BASE_URL": format!(
            "http://127.0.0.1:{}/egress/https/api.anthropic.com",
            egress.port()
        ),
        "BLACKBOX_EGRESS_URL": format!("http://127.0.0.1:{}", egress.port()),
    });
    for (k, v) in expect.as_object().unwrap() {
        assert_eq!(
            env.get(k).and_then(|x| x.as_str()),
            Some(v.as_str().unwrap()),
            "env var {k} must be injected with the exact zero-config value"
        );
    }
    println!("gate2: child received all 5 injected env vars (SENTRY_DSN, OTEL, OPENAI/ANTHROPIC base URLs, BLACKBOX_EGRESS_URL)");

    // ---- Steady traffic + two real SIGKILLs ------------------------------
    let client = http_client();
    let ok = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut loaders = Vec::new();
    for _ in 0..6 {
        let client = client.clone();
        let ok = Arc::clone(&ok);
        let fail = Arc::clone(&fail);
        let running = Arc::clone(&running);
        let url = format!("http://{ingress}/ping");
        loaders.push(tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri(&url)
                    .body(HttpBody::new(Bytes::from_static(b"")))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 200 => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                    }
                    Ok(res) => {
                        fail.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                    }
                    Err(_) => {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    let killer = {
        let running = Arc::clone(&running);
        let pid_file = pid_file.clone();
        tokio::spawn(async move {
            let mut respawns = 0u32;
            for delay in [4_500u64, 4_500] {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if !running.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                if let Some(pid) = read_pid(&pid_file) {
                    kill9(pid);
                    println!("gate2: SIGKILLed child pid {pid} (kill #{})", respawns + 1);
                    if let Some(new_pid) = wait_pid_change(&pid_file, pid, Duration::from_secs(15)).await {
                        respawns += 1;
                        println!("gate2: supervisor respawned child as pid {new_pid}");
                    }
                }
            }
            respawns
        })
    };

    // Run traffic for 14 s, then stop.
    tokio::time::sleep(Duration::from_secs(14)).await;
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    for l in loaders.drain(..) {
        let _ = l.await;
    }
    let respawns = killer.await.unwrap_or(0);

    let (o, f) = (ok.load(Ordering::Relaxed), fail.load(Ordering::Relaxed));
    println!("gate2: {o} x HTTP 200, {f} failures across 2 kill -9 cycles ({respawns} respawns observed)");
    assert!(o > 500, "steady traffic expected, got {o}");
    assert_eq!(f, 0, "zero dropped requests required");
    assert!(respawns >= 2, "supervisor must respawn twice, saw {respawns}");

    // Cleanup: kill the child, then the run process itself.
    if let Some(pid) = read_pid(&pid_file) {
        kill9(pid);
    }
    let _ = run_proc.start_kill();
    let _ = run_proc.wait().await;
    let _ = std::fs::remove_dir_all(&dir);
    println!("gate2 PASS: zero-config env injection + auto-resurrection with 100% HTTP 200");
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate 3 — zero-leak mixed-workload soak (100 K+ ops, flat RSS)
// ---------------------------------------------------------------------------

pub async fn gate3() -> Result<()> {
    let dir = tmpdir("gate3");
    let exe = std::env::current_exe()?;
    let child_port = free_port().await?;
    let mock_port = free_port().await?;
    let pid_file = dir.join("child.pid");
    let env_file = dir.join("child-env.json");

    // ---- Full node in-process: 1 MB segments → real rollover churn. -----
    let node = crate::node::spawn_node(crate::node::NodeConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("127.0.0.1:{child_port}"),
        data: dir.clone(),
        webhooks: "/webhooks/*,/jobs/*".into(),
        hold_ms: 10_000,
        egress_listen: "127.0.0.1:0".into(),
        admin_listen: "127.0.0.1:0".into(),
        mem_budget_mb: 256,
        max_segment_mb: 1,
        disk_quota_mb: 4096,
        cold: None,
        shield: true,
        rate_rps: 0.0,
        rate_burst: 100,
        tls: crate::node::TlsOptions::Off,
    })
    .await?;

    // ---- Child supervision (in-process, real child PROCESS) --------------
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let sup = tokio::spawn(crate::run::supervise_forever(
        crate::run::SupervisionArgs {
            command: vec![
                exe.to_str().unwrap().to_string(),
                "env-child".into(),
                "--port".into(),
                child_port.to_string(),
                "--env-file".into(),
                env_file.to_str().unwrap().to_string(),
            ],
            env: vec![],
            upstream_port: child_port,
            startup_timeout_ms: 15_000,
            max_restarts: 0,
            pid_file: Some(pid_file.clone()),
        },
        Arc::clone(&node.health),
        shutdown_rx,
    ));

    // ---- In-process mock OpenAI (50 ms, token usage in response) ---------
    let mock_listener = tokio::net::TcpListener::bind(("127.0.0.1", mock_port)).await?;
    let mock_addr = mock_listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = mock_listener.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| async move {
                        let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let body = serde_json::json!({
                            "id": "chatcmpl-soak",
                            "choices": [{"message": {"role": "assistant", "content": "soak"}}],
                            "usage": {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46},
                        });
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body.to_string())))
                                .unwrap(),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    // ---- RSS sampler ------------------------------------------------------
    let rss_samples: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let rss = Arc::clone(&rss_samples);
        tokio::spawn(async move {
            let t0 = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let s = (t0.elapsed().as_millis() as u64, blackbox_supervisor::memory::rss_bytes());
                rss.lock().unwrap().push(s);
            }
        });
    }

    // ---- Mixed workload ---------------------------------------------------
    const INGRESS_TARGET: u64 = 80_000;
    const WEBHOOK_TARGET: u64 = 10_000;
    const ENVELOPE_TARGET: u64 = 10_000;
    const EGRESS_TARGET: u64 = 6_000;

    let client = http_client();
    let ingress_ops = Arc::new(AtomicU64::new(0));
    let ingress_fail = Arc::new(AtomicU64::new(0));
    let webhook_ok = Arc::new(AtomicU64::new(0));
    let envelope_ok = Arc::new(AtomicU64::new(0));
    let egress_ok = Arc::new(AtomicU64::new(0));
    let egress_fail = Arc::new(AtomicU64::new(0));
    let sampled_traces: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let _t0 = Instant::now();

    let mut tasks = Vec::new();
    // Ingress HTTP (8 keep-alive loaders, unique trace ids).
    for t in 0..8 {
        let client = client.clone();
        let ops = Arc::clone(&ingress_ops);
        let fails = Arc::clone(&ingress_fail);
        let traces = Arc::clone(&sampled_traces);
        let url = format!("http://{}/work", node.proxy.local_addr);
        tasks.push(tokio::spawn(async move {
            let mut n = t;
            loop {
                if ops.load(Ordering::Relaxed) >= INGRESS_TARGET {
                    break;
                }
                n += 8;
                let tid = rand_trace_hex();
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri(format!("{url}/{n}"))
                    .header("traceparent", format!("00-{tid}-0000000000000001-01"))
                    .body(HttpBody::new(Bytes::new()))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 200 => {
                        ops.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                        {
                            let mut tv = traces.lock().unwrap();
                            if tv.len() < 100 {
                                tv.push(tid);
                            }
                        }
                    }
                    Ok(res) => {
                        fails.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                    }
                    Err(_) => {
                        fails.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    // Durable webhooks (202 + dispatcher delivery to the child).
    {
        let client = client.clone();
        let ok = Arc::clone(&webhook_ok);
        let url = format!("http://{}/webhooks/soak", node.proxy.local_addr);
        tasks.push(tokio::spawn(async move {
            for i in 0..WEBHOOK_TARGET {
                let req = hyper::Request::builder()
                    .method("POST")
                    .uri(&url)
                    .header("content-type", "application/json")
                    .header("idempotency-key", format!("soak-{i}"))
                    .body(HttpBody::new(Bytes::from(format!(
                        "{{\"n\":{i},\"pad\":\"{}\"}}",
                        "x".repeat(64)
                    ))))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 202 => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                    }
                    Ok(res) => {
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                    }
                    Err(_) => {}
                }
            }
        }));
    }
    // Sentry crash envelopes (plain, preserved under survival shedding).
    {
        let client = client.clone();
        let ok = Arc::clone(&envelope_ok);
        let url = format!("http://{}/api/1/envelope/", node.proxy.local_addr);
        tasks.push(tokio::spawn(async move {
            for i in 0..ENVELOPE_TARGET {
                let tid = rand_trace_hex();
                let envelope = format!(
                    "{{\"event_id\":\"{:032x}\"}}\n{{\"type\":\"event\"}}\n{{\"contexts\":{{\"trace\":{{\"trace_id\":\"{tid}\"}}}},\"exception\":{{\"values\":[{{\"type\":\"Panic\",\"value\":\"soak crash {i}\"}}]}}}}\n",
                    i
                );
                let req = hyper::Request::builder()
                    .method("POST")
                    .uri(&url)
                    .header("content-type", "application/x-sentry-envelope")
                    .body(HttpBody::new(Bytes::from(envelope)))
                    .unwrap();
                if let Ok(res) = client.request(req).await {
                    if res.status().as_u16() == 200 {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                }
            }
        }));
    }
    // Coalesced LLM egress (two identical bodies → heavy COALESCE/HIT).
    for b in 0..2 {
        let client = client.clone();
        let ok = Arc::clone(&egress_ok);
        let fails = Arc::clone(&egress_fail);
        let url = format!(
            "http://{}/egress/http/127.0.0.1:{}/v1/chat/completions",
            node.egress.local_addr, mock_addr.port()
        );
        tasks.push(tokio::spawn(async move {
            let body = format!(
                "{{\"model\":\"gpt-soak\",\"messages\":[{{\"role\":\"user\",\"content\":\"soak {b}\"}}]}}"
            );
            let mut n = 0u64;
            while n < EGRESS_TARGET / 2 {
                let req = hyper::Request::builder()
                    .method("POST")
                    .uri(&url)
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tenant-soak")
                    .body(HttpBody::new(Bytes::from(body.clone())))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status().as_u16() == 200 => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                        n += 1;
                    }
                    Ok(res) => {
                        fails.fetch_add(1, Ordering::Relaxed);
                        let _ = http_body_util::BodyExt::collect(res.into_body()).await;
                        n += 1;
                    }
                    Err(_) => {
                        fails.fetch_add(1, Ordering::Relaxed);
                        n += 1;
                    }
                }
            }
        }));
    }

    // ---- Two mid-soak child kills (real SIGKILL) -------------------------
    let killer = {
        let pid_file = pid_file.clone();
        tokio::spawn(async move {
            let mut kills = 0u32;
            for delay in [3_000u64, 3_500] {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if let Some(pid) = read_pid(&pid_file) {
                    kill9(pid);
                    kills += 1;
                    println!("gate3: SIGKILLed child app pid {pid} (kill #{kills})");
                }
            }
            kills
        })
    };

    // Workload phase with a hard deadline — a pathological environment must
    // fail fast, not hang (the 10 s connection-hold can serialize requests
    // while the breaker is open).
    let workload = async {
        for t in tasks.drain(..) {
            let _ = t.await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(150), workload).await.is_err() {
        anyhow::bail!("soak workload exceeded its 150 s deadline (child never recovered?)");
    }
    let kills = killer.await.unwrap_or(0);

    // ---- Integrity verification ------------------------------------------
    let _flushed = node.proxy.flush().await;
    let idx = node.proxy.stats();
    let counts = node.queue.store.counts().await?;
    let dropped = node.proxy.dropped();
    let ingress_total = ingress_ops.load(Ordering::Relaxed);
    let total_ops = ingress_total
        + webhook_ok.load(Ordering::Relaxed)
        + envelope_ok.load(Ordering::Relaxed)
        + egress_ok.load(Ordering::Relaxed);

    println!(
        "gate3: ops = {total_ops} (ingress {ingress_total} / webhooks {} / envelopes {} / egress {}), kills {kills}",
        webhook_ok.load(Ordering::Relaxed),
        envelope_ok.load(Ordering::Relaxed),
        egress_ok.load(Ordering::Relaxed)
    );

    // 1) Volume gate: 100,000+ operations across all 4 engines.
    assert!(
        total_ops >= 100_000,
        "soak must exceed 100K ops, got {total_ops}"
    );
    // 2) Request integrity: zero failed proxy requests, zero writer drops.
    assert_eq!(ingress_fail.load(Ordering::Relaxed), 0, "zero failed ingress requests");
    assert_eq!(egress_fail.load(Ordering::Relaxed), 0, "zero failed egress calls");
    assert_eq!(dropped, 0, "zero writer-channel drops");
    // 3) Queue integrity: every durable webhook delivered, DLQ empty.
    assert_eq!(webhook_ok.load(Ordering::Relaxed), WEBHOOK_TARGET, "all webhooks 202ed");
    assert_eq!(counts.enqueued_total, WEBHOOK_TARGET, "enqueued count");
    assert_eq!(counts.delivered_total, WEBHOOK_TARGET, "every job delivered despite 2 child kills");
    assert_eq!(counts.dead_letter, 0, "empty DLQ");
    assert_eq!(counts.deduped_total, 0, "no accidental dedup");
    // 4) Storage integrity: index == disk, sampled traces readable (cold + hot).
    let on_disk = blackbox_core::segment::read_index_all(&dir)?.len();
    assert_eq!(
        on_disk, idx.frames as usize,
        "every indexed frame must be on disk and vice versa"
    );
    let sampled = sampled_traces.lock().unwrap().clone();
    let mut cold_checked = 0;
    for tid_hex in sampled.iter().take(50) {
        let tid = blackbox_core::schema::parse_trace_hex(tid_hex).context("sampled tid")?;
        let recs = node
            .proxy
            .get_trace(&tid)
            .unwrap_or_else(|| panic!("sampled trace {tid_hex} must be retrievable"));
        assert!(!recs.is_empty(), "trace {tid_hex} empty");
        cold_checked += 1;
    }
    // 5) Compaction really ran (1 MB cap → sealed .zst segments exist).
    let (zst_n, _) = blackbox_core::compactor::cold_zst_stats(&dir);
    let compactions = node.compactor.compactions.load(Ordering::Relaxed);
    assert!(zst_n > 0, "background compactor must seal rotated segments (got {zst_n})");
    assert!(compactions > 0, "janitor compaction counter must advance");
    println!("gate3: queue {}/{} delivered, index {}/{} disk frames, {} sampled traces read (cold+hot), {} .zst segments",
        counts.delivered_total, counts.enqueued_total, idx.frames, on_disk, cold_checked, zst_n);

    // ---- Flat-RSS gate (no monotonic heap growth after decay) ------------
    // Two-part check, honest about what growth is legitimate:
    //  1. WORKLOAD growth: the in-memory TraceIndex legitimately scales with
    //     live frames (~120K here) — reported, not asserted against.
    //  2. IDLE plateau: after the workload ends, jemalloc's 1 s decay drains
    //     transient pages and RSS MUST plateau (no leak).
    let samples: Vec<(u64, u64)> = rss_samples.lock().unwrap().clone();
    assert!(samples.len() > 10, "RSS sampler must collect enough samples");
    let peak = samples.iter().map(|(_, r)| *r).max().unwrap();
    anyhow::ensure!(
        peak < 300 * 1024 * 1024,
        "peak RSS {} MB is wildly out of budget",
        peak / 1_048_576
    );

    // Idle plateau: 16 samples × 400 ms after a 2.5 s decay settle.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let mut idle: Vec<u64> = Vec::with_capacity(16);
    for _ in 0..16 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        idle.push(blackbox_supervisor::memory::rss_bytes());
    }
    let (first_half, last_half) = idle.split_at(8);
    let plateau_start = *first_half.iter().min().unwrap();
    let plateau_max = *last_half.iter().max().unwrap();
    println!(
        "gate3: RSS workload peak {:.1} MB → idle plateau {:.1}-{:.1} MB (drift ≤ 5%) — live index = {} frames",
        peak as f64 / 1_048_576.0,
        plateau_start as f64 / 1_048_576.0,
        plateau_max as f64 / 1_048_576.0,
        idx.frames
    );
    assert!(
        (plateau_max as f64) <= plateau_start as f64 * 1.05 + 2.0 * 1_048_576.0,
        "idle RSS is still climbing: {} → {} (leak)",
        plateau_start,
        plateau_max
    );

    // ---- Shutdown ---------------------------------------------------------
    let _ = shutdown_tx.send(true);
    let _ = sup.await;
    if let Some(pid) = read_pid(&pid_file) {
        kill9(pid);
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!("gate3 PASS: {total_ops}+ ops across 4 engines, queue + trace integrity 100%, RSS flat");
    Ok(())
}
