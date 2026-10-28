//! Phase 6 verification gates:
//!
//! - [`gate1`] — Evicted cold-tier time-travel replay: seal → sync to a
//!   local S3-compatible server → tiered Evict85 (healthy first, crash/5xx
//!   pinned) → `get_trace` + the REAL `blackbox replay` CLI fetch the
//!   evicted segment from S3 and replay with 100% accuracy.
//! - [`gate2`] — Bit-rot self-healing: flip bytes inside a sealed `.zst` →
//!   a trace request detects the corruption, pulls the clean replica from
//!   S3, atomically replaces the damaged file, and returns the valid trace.
//! - [`gate3`] — Bad-update canary auto-rollback: a tampered signature is
//!   rejected instantly; a validly-signed "broken" binary panics in the
//!   canary and is rolled back automatically while the live server keeps
//!   serving 100% of traffic.

use anyhow::{Context, Result};
use bytes::Bytes;
use crate::util::hex_of;
use http_body_util::Full;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> PathBuf {
    // Sweep leftovers from PREVIOUS gate runs (panics never clean up, and
    // packed CI runners run out of /tmp fast) except this process's own.
    let own = format!("blackbox-p6-{tag}-{}", std::process::id());
    if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("blackbox-p6-") && name != own {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let d = std::env::temp_dir().join(own);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Seeded xorshift byte flipper (deterministic corruption).
fn flip_bytes(buf: &mut [u8], flips: usize, mut state: u64) {
    for _ in 0..flips {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pos = (state as usize) % buf.len();
        buf[pos] ^= 0xFF;
    }
}

// ---------------------------------------------------------------------------
// Shared gate workload builders
// ---------------------------------------------------------------------------

use blackbox_core::schema::{EgressHttpMock, IngressHttp, RecordPayload, SentryCrash};
use blackbox_core::segment::{SegmentConfig, SegmentStore};

const SEG_CAP: u64 = 1024 * 1024; // 1 MB — fast forced rollovers

/// One sealed segment set with per-segment retention classes:
/// seg 1 contains a SentryCrash, seg 3 contains a 5xx, seg 2 a 4xx;
/// the mock-egress trace (`mock_tid`) lives in seg 0 (healthy).
fn build_segments(dir: &Path, n_segments: u32) -> Result<(u32, [u8; 16], String)> {
    let mut store = SegmentStore::open_with(dir, SegmentConfig { max_segment_bytes: SEG_CAP, ..Default::default() })?;
    let big_body = "{\"event\":\"synthetic\",\"pad\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".repeat(48);

    let mock_tid: [u8; 16] = {
        let mut t = [0xB0u8; 16];
        t[1] = 0x07;
        t
    };
    let mock_url = "http://api.blackbox.test/v1/charge";
    let mock_body = br#"{"amount":4200,"currency":"usd"}"#.to_vec();
    let mock_resp = br#"{"charge":"ch_cold_12345","status":"succeeded"}"#.to_vec();

    let mut seq: u64 = 0;
    while store.active_segment_id() < n_segments {
        let seg = store.active_segment_id();
        // The replayable egress trace lands in segment 0 (healthy tier).
        if seg == 0 && seq % 97 == 0 {
            seq += 1;
            store.append(&blackbox_core::schema::TraceRecord::new(
                mock_tid,
                seq,
                RecordPayload::EgressHttpMock(EgressHttpMock {
                    seq_no: 0,
                    request_fingerprint: blackbox_core::egress_key::fingerprint(
                        "POST", mock_url, &mock_body,
                    ),
                    method: "POST".into(),
                    request_url: mock_url.into(),
                    response_status: 200,
                    response_headers: vec![("content-type".into(), "application/json".into())],
                    response_body: mock_resp.clone(),
                    upstream_host: "api.blackbox.test".into(),
                    recorded_at_ms: blackbox_core::schema::now_ms(),
                }),
            ))?;
            continue;
        }
        let payload = if seg == 1 && seq % 200 == 1 {
            RecordPayload::SentryCrash(SentryCrash {
                project_id: "1".into(),
                event_id: format!("e{seq}"),
                envelope: b"crash-envelope".to_vec(),
            })
        } else if seg == 3 && seq % 200 == 3 {
            RecordPayload::IngressHttp(IngressHttp {
                method: "GET".into(),
                uri: "/boom".into(),
                status: 500,
                req_headers: vec![],
                req_body: vec![],
                res_body: b"boom".to_vec(),
                duration_ms: 1,
            })
        } else if seg == 2 && seq % 200 == 2 {
            RecordPayload::IngressHttp(IngressHttp {
                method: "GET".into(),
                uri: "/missing".into(),
                status: 404,
                req_headers: vec![],
                req_body: vec![],
                res_body: b"missing".to_vec(),
                duration_ms: 1,
            })
        } else {
            RecordPayload::IngressHttp(IngressHttp {
                method: "POST".into(),
                uri: "/api/events".into(),
                status: 200,
                req_headers: vec![],
                req_body: big_body.clone().into_bytes(),
                res_body: b"{\"ok\":true}".to_vec(),
                duration_ms: 2,
            })
        };
        let tid = blackbox_core::schema::new_id128().to_be_bytes();
        store.append(&blackbox_core::schema::TraceRecord::new(tid, seq, payload))?;
        seq += 1;
    }
    store.sync()?;
    let active = store.active_segment_id();
    assert!(active >= n_segments, "gate needs {n_segments} rollovers, got {active}");
    drop(store);
    Ok((active, mock_tid, mock_url.to_string()))
}

struct ColdFixture {
    cold: Arc<blackbox_cold::ColdTier>,
    state: Arc<blackbox_cold::mock::MockS3State>,
    dir: PathBuf,
}

/// Build the storage + a fresh local S3 mock + a synced cold tier.
async fn cold_fixture(tag: &str, n_segments: u32) -> Result<ColdFixture> {
    use blackbox_core::compactor::compact_all;
    let dir = tmpdir(tag);
    let (active, _, _) = build_segments(&dir, n_segments)?;
    compact_all(&dir, active, blackbox_core::compactor::DEFAULT_COMPRESS_LEVEL)?;

    let (addr, state) = blackbox_cold::mock::spawn_mock_s3(
        "127.0.0.1:0",
        &format!("blackbox-p6-{tag}"),
        "p6-access",
        "p6-secret",
    )
    .await?;
    let cfg = blackbox_cold::S3Config {
        endpoint: format!("http://{addr}"),
        bucket: format!("blackbox-p6-{tag}"),
        region: "us-east-1".into(),
        access_key: "p6-access".into(),
        secret_key: "p6-secret".into(),
        prefix: "segments/".into(),
    };
    let cold = blackbox_cold::ColdTier::open(cfg, &dir)?;
    Ok(ColdFixture { cold, state, dir })
}

// ---------------------------------------------------------------------------
// Gate 1 — evicted cold-tier time-travel replay
// ---------------------------------------------------------------------------

pub async fn gate1() -> Result<()> {
    use blackbox_core::compactor::evict_cold_tiered;

    let fx = cold_fixture("gate1", 5).await?;
    let dir = fx.dir.clone();
    let dir = &dir;
    let active = 5u32;
    let mock_tid: [u8; 16] = {
        let mut t = [0xB0u8; 16];
        t[1] = 0x07;
        t
    };
    let mock_url = "http://api.blackbox.test/v1/charge";

    // ---- Sync all 5 sealed segments to the cold tier ---------------------
    let report = fx.cold.sync_sealed(dir, active)?;
    assert_eq!(report.failures, 0, "cold sync must succeed");
    assert!(report.uploaded >= 5, "all sealed segments synced, got {:?}", report);
    let puts_after_sync = fx.state.put_count();
    assert!(puts_after_sync >= 10, "zst + idx per segment (got {puts_after_sync})");

    for id in 0..active {
        let meta = fx
            .cold
            .seg_state(id)
            .unwrap_or_else(|| panic!("segment {id} must be SyncedToCold"));
        let local = std::fs::read(blackbox_core::compactor::zst_artifact_path(dir, id))?;
        assert_eq!(meta.zst_blake3, *blake3::hash(&local).as_bytes(), "digest recorded for {id}");
    }
    // Retention classification straight out of the sidecars.
    assert_eq!(fx.cold.evict_tier(0), Some(blackbox_cold::TIER_HEALTHY));
    assert_eq!(fx.cold.evict_tier(1), Some(blackbox_cold::TIER_HAS_CRASH_OR_5XX));
    assert_eq!(fx.cold.evict_tier(2), Some(blackbox_cold::TIER_HAS_4XX));
    assert_eq!(fx.cold.evict_tier(3), Some(blackbox_cold::TIER_HAS_CRASH_OR_5XX));
    println!(
        "gate1: {} sealed segments synced to local S3 mock ({} PUTs), digests recorded, tiers classified",
        report.uploaded,
        fx.state.put_count()
    );

    // ---- Tiered Evict85: healthy first, crash/5xx pinned ------------------
    // The janitor drives evict_cold_tiered with the DiskMonitor's free
    // target (down to 80% of quota). This gate drives it directly with a
    // target equal to the two OLDEST HEALTHY segments' bytes — precise
    // enough to prove the tier order without depending on the runner's
    // absolute-FS state.
    let seg_bytes = |id: u32| -> u64 {
        let mut n = std::fs::metadata(blackbox_core::compactor::zst_artifact_path(dir, id))
            .map(|m| m.len())
            .unwrap_or(0);
        n += std::fs::metadata(blackbox_core::compactor::idx_path(dir, id))
            .map(|m| m.len())
            .unwrap_or(0);
        n
    };
    let free_target = seg_bytes(0) + seg_bytes(4);
    let tier_of = |id: u32| fx.cold.evict_tier(id);
    let (removed, freed) = evict_cold_tiered(dir, free_target, &tier_of)?;

    let seg0_gone = !blackbox_core::compactor::zst_artifact_path(dir, 0).exists();
    let seg1_pinned = blackbox_core::compactor::zst_artifact_path(dir, 1).exists();
    let seg3_pinned = blackbox_core::compactor::zst_artifact_path(dir, 3).exists();
    assert!(removed >= 1 && freed > 0, "eviction must free space");
    assert!(seg0_gone, "oldest HEALTHY segment evicted first");
    assert!(seg1_pinned, "SentryCrash segment PINNED locally");
    assert!(seg3_pinned, "5xx segment PINNED locally");
    // Cold metadata survives the local eviction (that's the whole point).
    assert!(fx.cold.seg_state(0).is_some(), "seg 0 still SyncedToCold in redb");
    println!(
        "gate1: tiered Evict85 → {removed} healthy segment(s) evicted ({freed} bytes); crash/5xx segments pinned"
    );

    // ---- Time-travel: get_trace on the EVICTED segment (library) ----------
    let gets_before = fx.state.get_count();
    let index = blackbox_ingress::index::TraceIndex::rebuild(dir)?;
    assert!(
        index.get_trace(&mock_tid).is_none(),
        "without the cold tier attached, the evicted trace is unknown after restart"
    );
    let mut index = blackbox_ingress::index::TraceIndex::rebuild(dir)?;
    index.set_cold(Arc::clone(&fx.cold));
    let records = index
        .get_trace(&mock_tid)
        .expect("cold tier must serve the evicted trace");
    assert!(!records.is_empty());
    assert!(records.iter().all(|r| r.trace_id == mock_tid));
    assert!(
        matches!(records[0].payload, RecordPayload::EgressHttpMock(ref m) if m.response_body == br#"{"charge":"ch_cold_12345","status":"succeeded"}"#.to_vec()),
        "restored egress record byte-exact"
    );
    assert!(
        fx.state.get_count() > gets_before,
        "the trace fetch must have hit S3 (GET count {} → {})",
        gets_before,
        fx.state.get_count()
    );
    assert!(
        blackbox_core::compactor::zst_artifact_path(dir, 0).exists(),
        "evicted segment re-materialized locally"
    );
    println!(
        "gate1: get_trace transparently restored segment_000000 from S3 ({} GETs) — 100% byte-accurate",
        fx.state.get_count()
    );

    // ---- The REAL CLI: blackbox replay <tid> reads through S3 -------------
    // Evict the segment AGAIN so the CLI's own cold-tier path must fetch it.
    // Drop OUR ColdTier AND the index that holds an Arc to it first: redb
    // holds an exclusive file lock per database, and the CLI subprocess
    // must be able to open cold.redb.
    std::fs::remove_file(blackbox_core::compactor::zst_artifact_path(dir, 0))?;
    let _ = std::fs::remove_file(blackbox_core::compactor::idx_path(dir, 0));
    let mock_state = Arc::clone(&fx.state);
    let total_puts = mock_state.put_count();
    let cold_endpoint = fx.cold.endpoint();
    let cold_bucket = fx.cold.bucket();
    drop(index); // releases its Arc<ColdTier> ...
    drop(fx.cold); // ... so this releases the redb file lock for the CLI
    let tid_hex = hex_of(&mock_tid);
    let egress_port = free_port().await?;
    let ingress_port = free_port().await?;
    let gets_before_cli = mock_state.get_count();
    let exe = std::env::current_exe()?;
    let mut cli = tokio::process::Command::new(&exe)
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
        .env("BLACKBOX_COLD_ENDPOINT", &cold_endpoint)
        .env("BLACKBOX_COLD_BUCKET", &cold_bucket)
        .env("BLACKBOX_COLD_ACCESS_KEY_ID", "p6-access")
        .env("BLACKBOX_COLD_SECRET_ACCESS_KEY", "p6-secret")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn blackbox replay CLI")?;
    let egress_addr: std::net::SocketAddr = format!("127.0.0.1:{egress_port}").parse()?;
    if !wait_port(egress_addr, Duration::from_secs(30)).await {
        let _ = cli.kill().await;
        let out = cli.wait_with_output().await;
        let cli_out = out
            .map(|o| {
                format!(
                    "status={:?}\nstdout:\n{}\nstderr:\n{}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_else(|e| format!("wait_with_output failed: {e}"));
        panic!("replay CLI mock interceptor must come up; CLI output:\n{cli_out}");
    }

    let mock_body = br#"{"amount":4200,"currency":"usd"}"#.to_vec();
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
    assert_eq!(status, 200, "evicted-segment mock must be served via S3 restore");
    assert!(
        String::from_utf8_lossy(&body).contains("ch_cold_12345"),
        "100% accuracy: exact recorded response, got {}",
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
    assert_eq!(status, 428, "unrecorded call stays sandbox-blocked");
    assert!(hdrs.iter().any(|(k, v)| k == "x-blackbox-replay-blocked" && v == "true"));
    cli.kill().await?;
    let _ = cli.wait().await;
    assert!(
        mock_state.get_count() > gets_before_cli,
        "the CLI fetch must have gone through the cold tier ({} → {})",
        gets_before_cli,
        mock_state.get_count()
    );

    // Cold metadata must not carry a stale .tmp artifact.
    assert!(!dir.join("segment_000000.log.zst.bbcold.tmp").exists());
    let _ = std::fs::remove_dir_all(dir);
    println!(
        "gate1 PASS: seal → S3 sync ({} PUTs) → tiered Evict85 → evicted-segment replay via S3 (200 exact + 428 guard)",
        total_puts
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate 2 — bit-rot self-healing
// ---------------------------------------------------------------------------

pub async fn gate2() -> Result<()> {
    let fx = cold_fixture("gate2", 3).await?;
    let dir = &fx.dir;
    fx.cold.sync_sealed(dir, 3)?;
    assert_eq!(fx.cold.stats().upload_failures, 0);

    // A trace that lives in segment 1.
    let (_seg, _off, victim_meta) = blackbox_core::segment::read_meta_all(dir)?
        .into_iter()
        .find(|(s, _, _)| *s == 1)
        .context("segment 1 has frames")?;

    let zst = blackbox_core::compactor::zst_artifact_path(dir, 1);
    let clean_digest = fx.cold.seg_state(1).unwrap().zst_blake3;

    // ---- Round 1: flip bytes → get_trace must self-heal ------------------
    let mut bytes = std::fs::read(&zst)?;
    flip_bytes(&mut bytes, 8, 0x5EED_0001);
    std::fs::write(&zst, &bytes)?;
    let corrupt_hash = blake3::hash(&bytes);

    let mut index = blackbox_ingress::index::TraceIndex::rebuild(dir)?;
    index.set_cold(Arc::clone(&fx.cold));
    let records = index
        .get_trace(&victim_meta.trace_id)
        .expect("self-healing get_trace must return the trace");
    assert!(!records.is_empty());
    assert!(records.iter().all(|r| r.trace_id == victim_meta.trace_id));

    let healed = std::fs::read(&zst)?;
    assert_eq!(*blake3::hash(&healed).as_bytes(), clean_digest, "file replaced by clean replica");
    assert_ne!(*blake3::hash(&healed).as_bytes(), *corrupt_hash.as_bytes());
    let st1 = fx.cold.stats();
    assert!(st1.corrupt_detected >= 1 && st1.heals >= 1, "stats {st1:?}");
    println!(
        "gate2: round 1 — 8 corrupted bytes detected, clean .zst pulled from S3 ({} GETs), atomic replace, trace served",
        fx.state.get_count()
    );

    // ---- Round 2: corrupt again → restore_trace heals again ---------------
    let mut bytes = std::fs::read(&zst)?;
    flip_bytes(&mut bytes, 5, 0x5EED_0002);
    std::fs::write(&zst, &bytes)?;
    let records = fx
        .cold
        .restore_trace(dir, &victim_meta.trace_id)?
        .expect("second heal round");
    assert!(!records.is_empty());
    let healed2 = std::fs::read(&zst)?;
    assert_eq!(*blake3::hash(&healed2).as_bytes(), clean_digest);
    assert!(fx.cold.stats().heals >= 2);

    // ---- Round 3: sidecar corruption also heals ---------------------------
    let idx = blackbox_core::compactor::idx_path(dir, 1);
    std::fs::write(&idx, b"garbage-not-an-idx")?;
    let records = fx
        .cold
        .restore_trace(dir, &victim_meta.trace_id)?
        .expect("sidecar heal round");
    assert!(!records.is_empty());
    assert!(blackbox_core::compactor::load_idx(dir, 1)?.is_some(), "sidecar restored");
    println!("gate2: rounds 2+3 — re-corruption and sidecar corruption both auto-healed");

    let _ = std::fs::remove_dir_all(dir);
    println!(
        "gate2 PASS: bit-rot detected on request → clean S3 replica → atomic overwrite → 100% valid trace (heals: {})",
        fx.cold.stats().heals
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate 3 — bad-update canary auto-rollback
// ---------------------------------------------------------------------------

pub async fn gate3() -> Result<()> {
    let dir = tmpdir("gate3");
    let data = dir.join("data");
    std::fs::create_dir_all(&data)?;

    // ---- Live node + continuous traffic ----------------------------------
    let upstream_port = free_port().await?;
    let exe = std::env::current_exe()?;
    let env_file = dir.join("env-child.json");
    let mut upstream = tokio::process::Command::new(&exe)
        .args([
            "env-child",
            "--port",
            &upstream_port.to_string(),
            "--env-file",
            env_file.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    assert!(
        wait_port(
            format!("127.0.0.1:{upstream_port}").parse()?,
            Duration::from_secs(15)
        )
        .await,
        "upstream app must come up"
    );

    let node = crate::node::spawn_node(crate::node::NodeConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("127.0.0.1:{upstream_port}"),
        data: data.clone(),
        webhooks: "/webhooks/*".into(),
        hold_ms: 1_000,
        egress_listen: "127.0.0.1:0".into(),
        admin_listen: "127.0.0.1:0".into(),
        mem_budget_mb: 128,
        max_segment_mb: 1,
        disk_quota_mb: 4096,
        cold: None,
        shield: true,
        rate_rps: 0.0,
        rate_burst: 100,
        tls: crate::node::TlsOptions::Off,
    })
    .await?;

    let failures = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let traffic = tokio::spawn({
        let failures = Arc::clone(&failures);
        let successes = Arc::clone(&successes);
        let url = format!("http://{}/ping", node.proxy.local_addr);
        let stop = Arc::clone(&stop);
        async move {
            let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .build_http();
            while !stop.load(Ordering::Relaxed) {
                match client.get(url.parse().unwrap()).await {
                    Ok(resp) if resp.status() == 200 => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
    });

    // ---- Steady-state warmup: prove the node serves BEFORE any update -----
    let warm_start = successes.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let warm_served = successes.load(Ordering::Relaxed) - warm_start;
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "warmup: the node itself must not drop anything"
    );
    assert!(warm_served >= 30, "warmup traffic must flow ({warm_served})");
    println!("gate3: warmup — {warm_served} requests served in steady state, 0 failures");

    // ---- Keys + a candidate (copy of the running binary) ------------------
    // The gate's signing key is deterministic (reruns behave identically);
    // its verifying key is passed to the updater subprocess explicitly.
    let sk = load_sk()?;
    let vk_hex = hex_of(&sk.verifying_key().to_bytes());
    let candidate = dir.join("candidate-blackbox");
    std::fs::copy(&exe, &candidate)?;
    let candidate_sig = dir.join("candidate.sig");

    // ---- 3a. TAMPERED signature → instant rejection -----------------------
    let mut sig_hex = crate::selfupdate::sign_bytes(&sk, &std::fs::read(&candidate)?);
    {
        // TAMPER: flip one hex character of the 128-hex signature.
        let mut chars: Vec<char> = sig_hex.chars().collect();
        chars[7] = if chars[7] == '0' { '1' } else { '0' };
        sig_hex = chars.into_iter().collect();
    }
    std::fs::write(&candidate_sig, sig_hex)?;
    let t0 = Instant::now();
    let out = run_updater(&exe, &candidate, &candidate_sig, &vk_hex, &data).await?;
    let tampered_ms = t0.elapsed().as_millis();
    assert!(
        !out.status.success(),
        "tampered signature must be rejected"
    );
    assert!(tampered_ms < 5_000, "rejection must be instant, took {tampered_ms}ms");
    assert!(
        out.stdout.contains("signature"),
        "rejection must name the cause: {}",
        out.stdout
    );
    assert!(!data.join("redb.bak.json").exists(), "NO snapshot on tampered rejection");
    assert!(
        !exe.parent().unwrap().join("blackbox.candidate").exists(),
        "nothing staged on tampered rejection"
    );
    let served_after_tampered = successes.load(Ordering::Relaxed);
    println!(
        "gate3: tampered signature rejected instantly ({tampered_ms}ms) — zero side effects (traffic: {served_after_tampered} served, 0 dropped)"
    );

    // ---- 3b. Validly-signed BROKEN binary → canary rollback ---------------
    let broken = dir.join("broken-candidate");
    std::fs::write(
        &broken,
        "#!/bin/sh\necho \"thread 'main' panicked at src/main.rs:1:1:\\ndeliberately broken update candidate\" >&2\nexit 101\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::write(
        &candidate_sig,
        crate::selfupdate::sign_bytes(&sk, &std::fs::read(&broken)?),
    )?;
    let exe_hash_before = sha256_of(&std::fs::read(&exe)?);
    let out = run_updater(&exe, &broken, &candidate_sig, &vk_hex, &data).await?;
    assert!(
        !out.status.success(),
        "broken candidate must fail the update: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("canary FAILED") && out.stdout.contains("rolled back"),
        "rollback must be explicit: {}",
        out.stdout
    );
    assert!(data.join("redb.bak.json").exists(), "snapshot taken before canary");
    assert!(data.join("jobs.redb.bak").exists(), "redb snapshot is real");
    {
        // The snapshot must be a VALID, openable redb file.
        let db = blackbox_core::kv::open_redb(data.join("jobs.redb.bak"))
            .context("redb.bak must open as a valid database")?;
        drop(db);
    }
    assert!(
        !exe.parent().unwrap().join("blackbox.candidate").exists(),
        "candidate removed on rollback"
    );
    assert_eq!(
        sha256_of(&std::fs::read(&exe)?),
        exe_hash_before,
        "the working binary was never replaced"
    );
    let served_after_broken = successes.load(Ordering::Relaxed);
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "no request may fail while the broken update is being canaried"
    );
    println!(
        "gate3: validly-signed broken candidate panicked in canary → auto-rollback (snapshot verified, binary untouched; traffic: {} served cumulatively, 0 dropped)",
        served_after_broken
    );

    // ---- 3c. Validly-signed GOOD candidate → promotion, zero downtime -----
    std::fs::write(
        &candidate_sig,
        crate::selfupdate::sign_bytes(&sk, &std::fs::read(&candidate)?),
    )?;
    let out = run_updater(&exe, &candidate, &candidate_sig, &vk_hex, &data).await?;
    assert!(out.status.success(), "good candidate must promote: {}", out.stdout);
    assert!(out.stdout.contains("promoted"), "{}", out.stdout);
    assert!(exe.parent().unwrap().join("blackbox.prev").exists(), "previous binary kept");
    assert!(!exe.parent().unwrap().join("blackbox.candidate").exists(), "staging cleaned");
    let served_after_good = successes.load(Ordering::Relaxed);
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "no request may fail while the healthy update is being canaried + promoted"
    );
    println!(
        "gate3: healthy candidate passed the canary → promoted on disk (traffic: {} served cumulatively, 0 dropped)",
        served_after_good
    );

    // ---- Traffic integrity across ALL THREE update scenarios --------------
    let f = failures.load(Ordering::Relaxed);
    let s = successes.load(Ordering::Relaxed);
    assert!(s > 10, "traffic must have actually flowed ({s} successes)");
    assert_eq!(f, 0, "ZERO dropped requests across the whole update cycle, got {f}");
    stop.store(true, Ordering::Relaxed);
    let _ = traffic.await;
    let _ = upstream.kill().await;

    // Cleanup the promotion artifacts (target dir hygiene).
    let _ = std::fs::remove_file(exe.parent().unwrap().join("blackbox.prev"));
    let _ = std::fs::remove_dir_all(&dir);

    println!("gate3 PASS: tampered → instant reject · broken-signed → auto-rollback · good → promote; {s} requests, {f} failures");
    Ok(())
}

fn load_sk() -> Result<ed25519_dalek::SigningKey> {
    // The gate's own signing key (generated once per run, kept in memory).
    use std::sync::OnceLock;
    static SK: OnceLock<ed25519_dalek::SigningKey> = OnceLock::new();
    Ok(SK
        .get_or_init(|| {
            // Deterministic seed so gate reruns behave identically.
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            ed25519_dalek::SigningKey::from_bytes(&seed)
        })
        .clone())
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

struct UpdaterOut {
    status: std::process::ExitStatus,
    stdout: String,
}

async fn run_updater(
    exe: &Path,
    candidate: &Path,
    sig: &Path,
    pubkey_hex: &str,
    data: &Path,
) -> Result<UpdaterOut> {
    let out = tokio::process::Command::new(exe)
        .args([
            "self-update",
            "--from",
            candidate.to_str().unwrap(),
            "--sig",
            sig.to_str().unwrap(),
            "--pubkey",
            pubkey_hex,
            "--data",
            data.to_str().unwrap(),
            "--canary-window-ms",
            "15000",
        ])
        .output()
        .await
        .context("run blackbox self-update")?;
    Ok(UpdaterOut {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr),
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn wait_port(addr: std::net::SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn free_port() -> Result<u16> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p = l.local_addr()?.port();
    drop(l);
    Ok(p)
}

/// Hand-rolled HTTP/1.1 call with an ABSOLUTE-FORM request target.
async fn forward_proxy_call(
    addr: std::net::SocketAddr,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut req = format!(
        "{method} {url} HTTP/1.1\r\nhost: {url}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
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
        .ok_or_else(|| anyhow::anyhow!("no header end"))?;
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
