//! Phase 6 — Ed25519-verified canary self-update (blueprint §4.5).
//!
//! ```text
//! blackbox keygen --out-dir keys/
//! blackbox sign-update --key keys/blackbox_ed25519.key --input new-binary --out sig.hex
//! blackbox self-update --from new-binary --sig sig.hex [--pubkey hex] [--data dir]
//! ```
//!
//! Update pipeline (each step aborts before the next on failure):
//!
//! 1. **Verify** — Ed25519 (ed25519-dalek) over SHA-256(candidate bytes).
//!    A tampered signature is rejected INSTANTLY: nothing is written, no
//!    snapshot taken, no process spawned.
//! 2. **Snapshot** — every `*.redb` in the data dir is copied to `<f>.bak`
//!    plus a `redb.bak.json` manifest (atomic-ish: copy + fsync; redb's own
//!    crash-safe format makes any torn copy recoverable on open).
//! 3. **Stage** — the candidate is written NEXT TO the running binary as
//!    `blackbox.candidate` (fsync + chmod 755).
//! 4. **Canary** — the candidate is spawned with `--self-test --canary-port
//!    N --data <scratch>` on an ISOLATED scratch data dir, so a broken
//!    candidate can never touch production state. Success = /healthz 200
//!    (or clean exit 0) inside the canary window; failure = panic, non-zero
//!    exit, or hang.
//! 5. **Promote / Roll back** — on success the old binary is renamed to
//!    `blackbox.prev` and the candidate takes its place (the running server
//!    keeps serving from its inode — zero dropped traffic; restart
//!    activates). On failure the candidate is deleted and the snapshot is
//!    kept; the live server was NEVER touched.
//!
//! The public key comes from (in order): `--pubkey <hex>`, the
//! `BLACKBOX_UPDATE_PUBKEY` env var, or `<data>/update.pub`. Production
//! builds should bake the release key into the binary.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Canary health-probe window (ms) before a hung candidate is killed.
pub const DEFAULT_CANARY_WINDOW_MS: u64 = 10_000;

// ---------------------------------------------------------------------------
// Keys & signatures
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair (seed from the OS CSPRNG via /dev/urandom —
/// this crate targets Linux only, like the rest of Blackbox).
pub fn generate_keypair() -> Result<(SigningKey, VerifyingKey)> {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut seed)
        })
        .context("read /dev/urandom")?;
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    Ok((sk, vk))
}

/// `blackbox keygen --out-dir <dir>`: writes `blackbox_ed25519.key` (hex
/// seed — keep OFF the box) + `blackbox_ed25519.pub` (hex verifying key).
pub fn keygen(out_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let (sk, vk) = generate_keypair()?;
    let sk_path = out_dir.join("blackbox_ed25519.key");
    let vk_path = out_dir.join("blackbox_ed25519.pub");
    std::fs::write(&sk_path, crate::phase6::hex_of(&sk.to_bytes()))?;
    std::fs::write(&vk_path, crate::phase6::hex_of(&vk.to_bytes()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600));
    }
    println!("keypair written:");
    println!("  private (KEEP OFF THE BOX): {}", sk_path.display());
    println!("  public  (verify key):       {}", vk_path.display());
    Ok(vk_path)
}

/// Load a hex Ed25519 seed from `--key <hex | @file>`.
pub fn load_signing_key(spec: &str) -> Result<SigningKey> {
    let hex = if let Some(path) = spec.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("read key file {path}"))?
    } else {
        spec.to_string()
    };
    let bytes = crate::phase6::hex_bytes(hex.trim())
        .ok_or_else(|| anyhow!("key must be 64 hex chars (ed25519 seed)"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("ed25519 seed must be exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Resolve the verifying key: `--pubkey <hex>` > `BLACKBOX_UPDATE_PUBKEY`
/// env > `<data>/update.pub` file.
pub fn resolve_verifying_key(explicit: Option<&str>, data_dir: &Path) -> Result<VerifyingKey> {
    let hex_opt = explicit
        .map(|s| s.to_string())
        .or_else(|| std::env::var("BLACKBOX_UPDATE_PUBKEY").ok())
        .or_else(|| {
            let p = data_dir.join("update.pub");
            std::fs::read_to_string(&p).ok().map(|s| (p, s)).map(|(_, s)| s)
        });
    let Some(hex) = hex_opt else {
        bail!(
            "no update public key configured — pass --pubkey <hex>, set \
             BLACKBOX_UPDATE_PUBKEY, or write <data>/update.pub"
        );
    };
    let bytes = crate::phase6::hex_bytes(hex.trim())
        .ok_or_else(|| anyhow!("public key must be 64 hex chars"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("ed25519 verifying key must be exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).context("invalid ed25519 verifying key")
}

/// Sign SHA-256(candidate) with the signing key → 128-hex signature.
pub fn sign_bytes(sk: &SigningKey, candidate: &[u8]) -> String {
    let digest = Sha256::digest(candidate);
    crate::phase6::hex_of(&sk.sign(&digest).to_bytes())
}

/// Verify the signature over SHA-256(candidate). Returns the verifying key
/// match as `Result` — an `Err` here is the instant-rejection path.
pub fn verify_signature(vk: &VerifyingKey, candidate: &[u8], sig_hex: &str) -> Result<()> {
    let bytes = crate::phase6::hex_bytes(sig_hex.trim())
        .ok_or_else(|| anyhow!("signature must be 128 hex chars"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("ed25519 signature must be exactly 64 bytes"))?;
    let sig = Signature::from_bytes(&arr);
    let digest = Sha256::digest(candidate);
    vk.verify(&digest, &sig)
        .map_err(|e| anyhow!("signature verification FAILED: {e}"))
}

// ---------------------------------------------------------------------------
// Candidate loading
// ---------------------------------------------------------------------------

/// Read candidate bytes from a local path or an http:// URL.
pub async fn load_candidate(from: &str) -> Result<Vec<u8>> {
    if let Some(url) = from.strip_prefix("http://") {
        let uri: hyper::Uri = format!("http://{url}")
            .parse()
            .context("parse http URL")?;
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.set_nodelay(true);
        let client: hyper_util::client::legacy::Client<
            _,
            http_body_util::Full<bytes::Bytes>,
        > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
        let resp = client
            .get(uri)
            .await
            .context("fetch candidate over http")?;
        if !resp.status().is_success() {
            bail!("candidate fetch returned HTTP {}", resp.status());
        }
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .context("read candidate body")?
            .to_bytes()
            .to_vec();
        Ok(bytes)
    } else {
        std::fs::read(from).with_context(|| format!("read candidate {}", from))
    }
}

// ---------------------------------------------------------------------------
// redb snapshot
// ---------------------------------------------------------------------------

/// Copy every `*.redb` in the data dir to `<name>.bak` + write a
/// `redb.bak.json` manifest. Returns (files, bytes).
pub fn snapshot_redb(data_dir: &Path) -> Result<(usize, u64)> {
    let mut files = Vec::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(data_dir).context("read data dir")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if name.ends_with(".redb") && !name.ends_with(".bak") {
            let src = entry.path();
            let dst = src.with_extension("redb.bak");
            let bytes = std::fs::read(&src).with_context(|| format!("read {}", src.display()))?;
            write_durable(&dst, &bytes, 0o644)?;
            total += bytes.len() as u64;
            files.push(serde_json::json!({
                "source": name,
                "snapshot": dst.file_name().map(|s| s.to_string_lossy()).unwrap_or_default(),
                "bytes": bytes.len(),
            }));
        }
    }
    let manifest = serde_json::json!({
        "taken_at_ms": blackbox_core::schema::now_ms(),
        "files": files,
        "total_bytes": total,
    });
    write_durable(
        &data_dir.join("redb.bak.json"),
        manifest.to_string().as_bytes(),
        0o644,
    )?;
    Ok((files.len(), total))
}

/// Restore the `*.redb.bak` snapshots over their live files (offline op —
/// run BEFORE starting the node; refused while files are locked).
pub fn restore_redb_snapshot(data_dir: &Path) -> Result<usize> {
    let mut n = 0usize;
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if let Some(base) = name.strip_suffix(".redb.bak").map(|b| b.to_string()) {
            let src = data_dir.join(&name);
            let dst = data_dir.join(format!("{base}.redb"));
            std::fs::copy(&src, &dst).with_context(|| format!("restore {}", dst.display()))?;
            n += 1;
            println!("restored {} from {}", dst.display(), src.display());
        }
    }
    Ok(n)
}

fn write_durable(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.sync_data()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canary
// ---------------------------------------------------------------------------

/// Outcome of one canary probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryVerdict {
    Healthy,
    Failed { reason: CanaryFailure },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // SpawnFailed documents the spawn-error case for callers
pub enum CanaryFailure {
    NonZeroExit(i32),
    ExitedNoStatus,
    WindowExceeded,
    SpawnFailed,
}

/// Spawn `candidate --self-test --canary-port <port> --data <scratch>` and
/// judge it: /healthz 200 or exit 0 within `window` = Healthy; panic /
/// non-zero exit / hang = Failed. The scratch dir is created and REMOVED by
/// the caller afterwards.
pub async fn run_canary(
    candidate: &Path,
    canary_port: u16,
    scratch: &Path,
    window: Duration,
) -> Result<CanaryVerdict> {
    use tokio::process::Command;
    let mut child = Command::new(candidate)
        .arg("self-test")
        .arg("--canary-port")
        .arg(canary_port.to_string())
        .arg("--data")
        .arg(scratch)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            tracing::warn!(error = %e, "canary spawn failed");
            e
        })
        .context("spawn canary candidate")?;

    let deadline = Instant::now() + window;
    let probe_addr = format!("127.0.0.1:{canary_port}");
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_millis(250)));
    let client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);

    loop {
        // Did it die?
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(CanaryVerdict::Healthy)
                } else {
                    Ok(CanaryVerdict::Failed {
                        reason: status
                            .code()
                            .map(|c| CanaryFailure::NonZeroExit(c))
                            .unwrap_or(CanaryFailure::ExitedNoStatus),
                    })
                };
            }
            Ok(None) => {}
            Err(e) => return Err(e.into()),
        }

        // Health probe (port bound + /healthz 200).
        let url = hyper::Uri::try_from(format!("http://{probe_addr}/healthz")).unwrap();
        if let Ok(resp) = client.get(url.clone()).await {
            if resp.status() == hyper::StatusCode::OK {
                // Candidate proved itself; stop it (its job is done).
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Ok(CanaryVerdict::Healthy);
            }
        }

        if Instant::now() >= deadline {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Ok(CanaryVerdict::Failed {
                reason: CanaryFailure::WindowExceeded,
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// The orchestrator
// ---------------------------------------------------------------------------

/// Full report of a self-update run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Signature rejected — NOTHING was mutated (no snapshot, no stage).
    RejectedSignature(String),
    /// Canary failed — candidate removed, snapshot retained, server untouched.
    RolledBack { reason: String },
    /// Canary passed — candidate promoted on disk (restart to activate).
    Promoted { prev_binary: PathBuf },
}

/// Run the whole pipeline. `explicit_pubkey` overrides env/file lookup.
pub async fn run_self_update(
    from: &str,
    sig_path: &Path,
    explicit_pubkey: Option<&str>,
    data_dir: &Path,
    canary_window_ms: u64,
) -> Result<UpdateOutcome> {
    let t0 = Instant::now();

    // ---- 1. Verify (instant rejection — no side effects). ----------------
    let candidate = load_candidate(from).await?;
    let vk = resolve_verifying_key(explicit_pubkey, data_dir)?;
    let sig = std::fs::read_to_string(sig_path)
        .with_context(|| format!("read signature {}", sig_path.display()))?;
    if let Err(e) = verify_signature(&vk, &candidate, &sig) {
        return Ok(UpdateOutcome::RejectedSignature(e.to_string()));
    }
    println!(
        "self-update: signature verified ({} bytes candidate, {} µs)",
        candidate.len(),
        t0.elapsed().as_micros()
    );

    // ---- 2. Snapshot redb. ------------------------------------------------
    let (n_files, n_bytes) = snapshot_redb(data_dir)?;
    println!(
        "self-update: redb snapshot taken ({} file(s), {} bytes) → *.redb.bak + redb.bak.json",
        n_files, n_bytes
    );

    // ---- 3. Stage candidate next to the running binary. -------------------
    let exe = std::env::current_exe().context("locate current binary")?;
    let exe_dir = exe.parent().ok_or_else(|| anyhow!("exe has no parent"))?;
    let staged = exe_dir.join("blackbox.candidate");
    write_durable(&staged, &candidate, 0o755).context("stage candidate")?;

    // ---- 4. Canary on an ISOLATED scratch data dir. -----------------------
    let scratch = std::env::temp_dir().join(format!(
        "blackbox-canary-{}-{}",
        std::process::id(),
        blackbox_core::schema::now_ms()
    ));
    std::fs::create_dir_all(&scratch)?;
    let canary_port = free_port().await?;
    let verdict = run_canary(
        &staged,
        canary_port,
        &scratch,
        Duration::from_millis(canary_window_ms),
    )
    .await;
    let _ = std::fs::remove_dir_all(&scratch);

    match verdict.context("canary execution")? {
        CanaryVerdict::Healthy => {
            // ---- 5a. Promote: old binary → blackbox.prev, staged → exe. ---
            let prev = exe_dir.join("blackbox.prev");
            let _ = std::fs::remove_file(&prev);
            std::fs::rename(&exe, &prev).context("rename current binary to blackbox.prev")?;
            std::fs::rename(&staged, &exe).context("promote candidate")?;
            println!(
                "self-update: canary PASSED — candidate promoted (previous binary kept as {}); \
                 the running server keeps serving its current image, restart to activate",
                prev.display()
            );
            Ok(UpdateOutcome::Promoted { prev_binary: prev })
        }
        CanaryVerdict::Failed { reason } => {
            // ---- 5b. Roll back: delete the candidate, keep the snapshot. --
            let _ = std::fs::remove_file(&staged);
            let why = match reason {
                CanaryFailure::NonZeroExit(c) => format!("candidate exited non-zero ({c})"),
                CanaryFailure::ExitedNoStatus => "candidate was killed by a signal".into(),
                CanaryFailure::WindowExceeded => "candidate failed the canary health window".into(),
                CanaryFailure::SpawnFailed => "candidate could not be spawned".into(),
            };
            tracing::warn!(reason = %why, "SELF-UPDATE ROLLBACK");
            println!(
                "self-update: canary FAILED ({why}) — rolled back automatically: \
                 candidate removed, redb snapshot retained, previous binary still serving"
            );
            Ok(UpdateOutcome::RolledBack { reason: why })
        }
    }
}

pub async fn free_port() -> Result<u16> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let p = l.local_addr()?.port();
    drop(l);
    Ok(p)
}

// ---------------------------------------------------------------------------
// `blackbox --self-test` — the canary payload
// ---------------------------------------------------------------------------

/// Minimal boot: SegmentStore + redb JobStore on a SCRATCH dir + a /healthz
/// listener. Serves until killed (the orchestrator probes then stops it).
pub async fn self_test(canary_port: u16, data: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&data)?;
    let mut store = blackbox_core::segment::SegmentStore::open(&data)?;
    store
        .append(&blackbox_core::schema::TraceRecord::new(
            [7u8; 16],
            0,
            blackbox_core::schema::RecordPayload::TelemetryLog(blackbox_core::schema::TelemetryLog {
                level: 3,
                service: "blackbox-self-test".into(),
                message: "canary boot".into(),
                attributes: vec![],
            }),
        ))
        .context("self-test segment append")?;
    store.sync()?;
    drop(store);

    let (_handle, _stats, _join) =
        blackbox_queue::spawn_job_store(&data.join("jobs.redb"), blackbox_queue::JobStoreConfig::default())
            .await
            .context("self-test redb JobStore")?;

    let addr: std::net::SocketAddr = ([127, 0, 0, 1], canary_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("SELF-TEST OK: engines booted, health on http://{addr}/healthz");
    println!("self-test: canary serving /healthz on {addr}");

    // Health = a real redb roundtrip: if the queue actor's writer loop is
    // wedged, /healthz answers 503 and the orchestrator rolls back.
    let counts_store = _handle;
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let _ = tcp.set_nodelay(true);
        let counts_store = counts_store.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let counts_store = counts_store.clone();
                async move {
                    let _ = http_body_util::BodyExt::collect(req.into_body()).await;
                    // Health reflects real engine state: redb actor roundtrip.
                    let healthy = counts_store.counts().await.is_ok();
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(if healthy { 200 } else { 503 })
                            .header("content-type", "text/plain")
                            .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                b"blackbox self-test ok\n",
                            )))
                            .expect("healthz builds"),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                .await;
        });
    }
}
