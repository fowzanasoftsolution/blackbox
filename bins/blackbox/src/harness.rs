//! The Phase 1 Crash & Corruption Harness (blueprint §5 Phase 1 gate).
//!
//! Three gates, each of which must PASS for Phase 1 to ship:
//!
//! 1. `harness corrupt` — deterministic torn-write + bit-flip injection into
//!    a populated segment; recovery must always yield a byte-exact valid
//!    prefix, never panic, and be idempotent on second open.
//! 2. `harness kill9` — real `SIGKILL` mid-append via a child `blackbox
//!    write-loop` process; on reopen every recovered frame must be
//!    CRC-valid + bytecheck-valid with contiguous seq numbers, and the torn
//!    tail must be auto-truncated.
//! 3. `harness rss` — idle-resident footprint must stay under 25 MB
//!    (blueprint Phase 1 gate: `<25 MB idle RSS`).

use crate::stats::{fmt_bytes, fmt_ns};
use anyhow::{bail, Context, Result};
use blackbox_core::schema::{now_ms, new_id128, EgressHttpMock, QueueJobRecord, RecordPayload, TraceRecord};
use blackbox_core::segment::{recover_file, read_all_records, SegmentStore};
use blackbox_supervisor::disk::DiskMonitor;
use blackbox_supervisor::memory::RamMonitor;
use std::path::PathBuf;

/// Seeded xorshift64* — deterministic corruption without a rand dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1) * 0x9E3779B97F4A7C15 | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn tmpdir(tag: &str) -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("blackbox-harness-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Realistic mixed records: durable webhook jobs + egress replay mocks.
fn gen_record(seq: u64) -> TraceRecord {
    let payload = if seq % 2 == 0 {
        RecordPayload::QueueJob(QueueJobRecord {
            queue: "webhooks.stripe".into(),
            payload: format!("{{\"type\":\"invoice.paid\",\"seq\":{seq}}}").into_bytes(),
            attempt: 0,
            max_attempts: 8,
            available_at_ms: now_ms(),
        })
    } else {
        RecordPayload::EgressHttpMock(EgressHttpMock {
            seq_no: seq,
            request_fingerprint: {
                let mut fp = [0u8; 32];
                fp[..8].copy_from_slice(&seq.to_be_bytes());
                fp[8..16].copy_from_slice(&(seq.wrapping_mul(0x9E3779B97F4A7C15)).to_be_bytes());
                fp
            },
            method: "POST".into(),
            request_url: format!("https://api.stripe.com/v1/charges/{seq}"),
            response_status: 200,
            response_headers: vec![
                ("content-type".into(), "application/json".into()),
                ("x-request-id".into(), format!("req-{seq}")),
            ],
            response_body: vec![0x5Au8; 128],
            upstream_host: "api.stripe.com".into(),
            recorded_at_ms: now_ms(),
        })
    };
    TraceRecord::new(
        {
            // trace id: 16 bytes from a 128-bit id (split into two u64 halves).
            let id = new_id128();
            let mut tid = [0u8; 16];
            tid[..8].copy_from_slice(&(id as u64).to_be_bytes());
            tid[8..].copy_from_slice(&((id >> 64) as u64).to_be_bytes());
            tid
        },
        seq,
        payload,
    )
}

/// Walk frame boundaries of an intact file; returns the byte offset where
/// each frame starts plus total count.
fn walk_frames(buf: &[u8]) -> Result<Vec<u64>> {
    let mut offsets = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        offsets.push(off as u64);
        let v = blackbox_core::frame::parse_frame(buf, off)
            .map_err(|p| anyhow::anyhow!("unexpected problem at {off}: {p:?}"))?;
        off += v.total_len as usize;
    }
    Ok(offsets)
}

// ---------------------------------------------------------------------------
// Gate 1: deterministic corruption + recovery
// ---------------------------------------------------------------------------

pub fn run_corrupt(frames: u64, seed: u64, mode: &str) -> Result<()> {
    println!("═══ HARNESS corrupt: frames={frames} seed={seed} mode={mode} ═══");
    let dir = tmpdir("corrupt")?;
    let seg_path = dir.join("segment_000000.log");

    // 1. Populate — generate ONCE and reuse: gen_record is nondeterministic
    // (fresh trace ids + timestamps), so the originals must be the exact
    // objects written to disk for the byte-match check to be meaningful.
    let originals: Vec<TraceRecord> = (0..frames).map(gen_record).collect();
    let mut store = SegmentStore::open(&dir)?;
    for rec in &originals {
        store.append(rec)?;
    }
    store.sync()?;
    let full_len = store.active_len();
    drop(store);

    // 2. Corrupt.
    let mut rng = Rng::new(seed);
    let mut buf = std::fs::read(&seg_path)?;
    let boundaries = walk_frames(&buf)?;
    let mut applied = String::new();

    match mode {
        "torn" | "both" => {
            // Tear INSIDE a random frame's payload (past its 32B header).
            let f = rng.below(boundaries.len() as u64) as usize;
            let start = boundaries[f];
            let frame_total = if f + 1 < boundaries.len() {
                (boundaries[f + 1] - start) as usize
            } else {
                buf.len() - start as usize
            };
            if frame_total > blackbox_core::frame::HEADER_SIZE + 8 {
                let cut = start as usize
                    + blackbox_core::frame::HEADER_SIZE
                    + 4
                    + (rng.below((frame_total - blackbox_core::frame::HEADER_SIZE - 8) as u64)
                        as usize);
                buf.truncate(cut);
                applied.push_str(&format!("torn@{cut} "));
            } else {
                buf.truncate(start as usize + frame_total - 1);
                applied.push_str(&format!("torn@{} ", buf.len()));
            }
        }
        _ => {}
    }
    match mode {
        "flip" | "both" => {
            let byte = rng.below(buf.len() as u64) as usize;
            let bit = rng.below(8) as u8;
            buf[byte] ^= 1u8 << bit;
            applied.push_str(&format!("flip@{byte}+b{bit} "));
        }
        _ => {}
    }
    std::fs::write(&seg_path, &buf)?;

    // 3. Recover.
    let t0 = std::time::Instant::now();
    let report = recover_file(&seg_path)?;
    let recovered = SegmentStore::open(&dir)?;
    let records = read_all_records(&dir)?;
    let recovery_us = t0.elapsed().as_micros() as u64;

    // 4. Verify invariants.
    let m = records.len();
    let mut checks: Vec<(String, bool)> = Vec::new();
    checks.push((
        format!("recovery opened cleanly ({} event(s))", report.events.len()),
        true,
    ));
    checks.push((
        format!("contiguous prefix recovered: {m}/{frames} frames"),
        m <= frames as usize,
    ));
    let prefix_exact = records
        .iter()
        .zip(originals.iter())
        .all(|(got, want)| got.trace_id == want.trace_id && got.seq_no == want.seq_no && got.payload == want.payload);
    checks.push((
        "every recovered frame byte-matches its original (prefix integrity)".into(),
        prefix_exact,
    ));
    // Idempotency: second recovery must find nothing to fix.
    let report2 = recover_file(&seg_path)?;
    checks.push((
        "second recovery is a no-op (idempotent)".into(),
        report2.events.is_empty(),
    ));
    // Reopen-append continuity: store usable right after healing.
    let mut recovered = recovered;
    recovered.append(&gen_record(frames))?;
    recovered.sync()?;
    checks.push(("append works immediately after healing".into(), true));

    // Report.
    println!("  file: {} → {} bytes after heal", fmt_bytes(full_len), fmt_bytes(report.valid_len));
    println!("  corruption applied: {applied}");
    for ev in &report.events {
        println!(
            "  event: offset={} truncated={} reason={}",
            ev.offset, fmt_bytes(ev.truncated_bytes), ev.reason
        );
    }
    let mut pass = true;
    for (label, ok) in &checks {
        println!("  [{}] {label}", if *ok { "PASS" } else { "FAIL" });
        pass &= *ok;
    }
    println!("  recovery time: {} ({} frames)", fmt_ns(recovery_us * 1_000), m);
    println!("═══ HARNESS corrupt: {} ═══\n", if pass { "PASS ✓" } else { "FAIL ✗" });

    let _ = std::fs::remove_dir_all(&dir);
    if !pass {
        bail!("corruption harness failed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate 2: real SIGKILL mid-append
// ---------------------------------------------------------------------------

pub fn run_kill9(records: u64, iterations: u32, seed: u64) -> Result<()> {
    println!("═══ HARNESS kill9: records={records} iterations={iterations} seed={seed} ═══");
    let exe = std::env::current_exe().context("cannot locate current exe")?;
    let mut rng = Rng::new(seed);
    let mut all_pass = true;

    for iter in 0..iterations {
        let dir = tmpdir(&format!("kill9-{iter}"))?;
        let mut child = std::process::Command::new(&exe)
            .args([
                "write-loop",
                "--dir",
                dir.to_str().unwrap(),
                "--records",
                &records.to_string(),
                "--sync-every",
                "512",
            ])
            .stdout(std::process::Stdio::null())
            .spawn()
            .context("spawn write-loop child")?;

        let sleep_ms = 30 + rng.below(250) as u64;
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        let pid = child.id();
        // SIGKILL mid-append — the exact scenario the segment engine exists for.
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        )?;
        let _ = child.wait();

        // Reopen → automatic recovery.
        let t0 = std::time::Instant::now();
        let _store = SegmentStore::open(&dir)?;
        let records_got = read_all_records(&dir)?;
        let recovery_us = t0.elapsed().as_micros() as u64;

        // Verify: contiguous, CRC-valid, bytecheck-valid prefix.
        let contiguous = records_got
            .iter()
            .enumerate()
            .all(|(i, r)| r.seq_no == i as u64);
        let idempotent = {
            let seg = dir.join("segment_000000.log");
            if seg.exists() {
                recover_file(&seg)?.events.is_empty()
            } else {
                true
            }
        };
        let pass = contiguous && idempotent && !records_got.is_empty();
        all_pass &= pass;

        println!(
            "  it={iter:<2} killed_after={sleep_ms:<4}ms pid={pid:<7} recovered={:<6} recovery={} [{}]",
            records_got.len(),
            fmt_ns(recovery_us * 1_000),
            if pass { "PASS" } else { "FAIL" }
        );
        if !pass {
            println!("    contiguous={contiguous} idempotent={idempotent}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    println!("═══ HARNESS kill9: {} ═══\n", if all_pass { "PASS ✓" } else { "FAIL ✗" });
    if !all_pass {
        bail!("kill9 harness failed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate 3: <25 MB idle RSS
// ---------------------------------------------------------------------------

pub fn run_rss(budget_mb: u64) -> Result<()> {
    println!("═══ HARNESS rss: budget={budget_mb}MB ═══");
    let dir = tmpdir("rss")?;

    // Startup path: open store (recovery), append traffic, supervisor polls.
    let mut store = SegmentStore::open(&dir)?;
    for seq in 0..1_000u64 {
        store.append(&gen_record(seq))?;
    }
    store.sync()?;

    let ram = RamMonitor::new(512 * 1024 * 1024).poll();
    let disk = DiskMonitor::new(dir.clone(), 4 * 1024 * 1024 * 1024)
        .poll()
        .map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "  supervisor ram: used={} level={:?} (jemalloc={:?})",
        fmt_bytes(ram.used_bytes),
        ram.level,
        ram.jemalloc_bytes.map(fmt_bytes)
    );
    println!(
        "  supervisor disk: used={} quota_ratio={:.3} level={:?}",
        fmt_bytes(disk.used_bytes),
        disk.quota_ratio,
        disk.level
    );

    // Idle settle.
    drop(store);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let rss = blackbox_supervisor::memory::rss_bytes();
    let budget = budget_mb * 1024 * 1024;
    let pass = rss > 0 && rss < budget;
    println!(
        "  idle RSS: {} / budget {} [{}]",
        fmt_bytes(rss),
        fmt_bytes(budget),
        if pass { "PASS" } else { "FAIL" }
    );
    println!("═══ HARNESS rss: {} ═══\n", if pass { "PASS ✓" } else { "FAIL ✗" });

    let _ = std::fs::remove_dir_all(&dir);
    if !pass {
        bail!("rss gate failed: {} >= {}", rss, budget);
    }
    Ok(())
}
