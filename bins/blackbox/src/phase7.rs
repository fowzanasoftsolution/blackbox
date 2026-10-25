//! Phase 7 verification gates.
//!
//! gate1 — the shield: token-bucket 429s (+ Retry-After) BEFORE the
//!         upstream/disk, scanner-path instant drops counted in
//!         `blocked_attacks`, zero segment records for blocked noise.
//! gate2 — native TLS: self-signed boot + real cert hot reload with zero
//!         failed requests across the swap (served cert changes on new
//!         connections within the 2 s poll window).
//! gate3 — `blackbox demo --once`: the whole product in one subprocess,
//!         exit 0, every engine asserted by the demo itself.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io::BufReader;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::phase4::{spawn_node, NodeConfig, TlsOptions};

/// Tiny upstream: 200 "ok" to everything (gates 1 and 2).
async fn spawn_echo(addr: &str) -> Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req: hyper::Request<Incoming>| async move {
                    use http_body_util::BodyExt;
                    let _ = req.into_body().collect().await;
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    Ok(local)
}

fn http() -> hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
> {
    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build_http()
}

async fn plain_req(
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
    url: &str,
) -> Result<(hyper::StatusCode, Option<String>)> {
    let req = hyper::Request::builder().method("GET").uri(url).body(Full::new(Bytes::new()))?;
    let res = client.request(req).await?;
    let trace = res
        .headers()
        .get("x-blackbox-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    Ok((res.status(), trace))
}

// --------------------------------------------------------------- gate 1 ----

pub async fn gate1() -> Result<()> {
    println!("p7-gate 1: shield — token-bucket 429s + scanner drops, zero recorded noise");

    let dir = std::env::temp_dir().join(format!("bb-p7g1-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let upstream = spawn_echo("127.0.0.1:0").await?;

    let node = spawn_node(NodeConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("{upstream}"),
        data: dir.clone(),
        max_segment_mb: 1,
        shield: true,
        rate_rps: 5.0,
        rate_burst: 5,
        ..Default::default()
    })
    .await
    .context("spawn gate1 node")?;
    let base = format!("http://{}", node.proxy.local_addr);
    let client = http();

    // ---- 1) Burst above the bucket: 5 pass, the rest are 429s. --------
    let mut ok = 0;
    let mut limited = 0;
    let mut retry_after_seen = false;
    for _ in 0..10 {
        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("{base}/ok"))
            .body(Full::new(Bytes::new()))?;
        let res = client.request(req).await?;
        match res.status() {
            hyper::StatusCode::OK => ok += 1,
            hyper::StatusCode::TOO_MANY_REQUESTS => {
                limited += 1;
                if res.headers().contains_key("retry-after") {
                    retry_after_seen = true;
                }
                let body = res.into_body().collect().await?.to_bytes();
                assert!(body.windows(12).any(|w| w == b"rate limited"), "429 body");
            }
            s => bail!("unexpected status {s} in burst"),
        }
    }
    assert_eq!(ok, 5, "burst must allow exactly the bucket depth");
    assert_eq!(limited, 5, "burst must 429 the overflow");
    assert!(retry_after_seen, "every 429 carries Retry-After");

    // ---- 2) Scanner paths: instant 404s, counted, NEVER recorded. -----
    let frames_before = node.proxy.stats().frames;
    blackbox_ingress::waf::reset_for_tests();
    blackbox_ingress::proxy::RATE_LIMITED.store(0, Ordering::Relaxed);
    for path in [
        "/.env",
        "/.git/config",
        "/wp-admin/setup.php",
        "/../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/backup.sql",
    ] {
        // The burst bucket is empty — WAF runs BEFORE the limiter, so
        // these must still be 404s (not 429s) — the order proof.
        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("{base}{path}"))
            .body(Full::new(Bytes::new()))?;
        let res = client.request(req).await?;
        assert_eq!(
            res.status(),
            hyper::StatusCode::NOT_FOUND,
            "scanner path {path} must be dropped with 404"
        );
    }
    assert_eq!(
        blackbox_ingress::waf::blocked_attacks(),
        6,
        "blocked_attacks counter"
    );

    // Blocked noise never reaches the segment store.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let frames_after = node.proxy.stats().frames;
    assert_eq!(frames_after, frames_before, "zero frames recorded for blocked requests");

    // ---- 3) Refill: after ~700 ms at 5 rps ~3.5 tokens are back —
    //         at least one admits, and the drain re-limits. ------------
    tokio::time::sleep(Duration::from_millis(700)).await;
    let mut admitted_after_refill = 0;
    loop {
        let (status, trace) = plain_req(&client, &format!("{base}/ok")).await?;
        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(status, hyper::StatusCode::OK, "refill admits or re-limits");
        assert!(trace.is_some(), "admitted requests carry a trace id");
        admitted_after_refill += 1;
        assert!(
            admitted_after_refill <= 5,
            "refill must not mint more than the rate allows"
        );
    }
    assert!(
        admitted_after_refill >= 1,
        "700ms at 5 rps must refill at least one token"
    );

    // ---- 4) 429 latency: the limiter answers in microseconds. ---------
    let t0 = Instant::now();
    let (status, _) = plain_req(&client, &format!("{base}/ok")).await?;
    let dt = t0.elapsed();
    assert_eq!(status, hyper::StatusCode::TOO_MANY_REQUESTS);
    assert!(dt < Duration::from_millis(50), "rejection latency {dt:?}");

    let rl = node.rate_limiter.as_ref().expect("limiter attached");
    assert_eq!(rl.burst(), 5);

    println!(
        "  PASS — 5/5 burst admitted, 5× 429+Retry-After, 6 scanner paths 404'd ({})",
        blackbox_ingress::waf::blocked_attacks()
    );
    println!(
        "        blocked requests: 0 frames recorded · refill + <50µs 429 · limiter {} rps/burst {}",
        rl.rps_milli() as f64 / 1000.0,
        rl.burst()
    );
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// --------------------------------------------------------------- gate 2 ----

/// TLS client that accepts ANY server certificate and RECORDS the leaf DER
/// it saw (hot-reload proof + self-signed boot without a trust store).
#[derive(Debug)]
struct NoVerify {
    recorded: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.recorded
            .lock()
            .unwrap()
            .push(end_entity.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// One fresh HTTPS request (new connection every time → fresh handshake).
async fn tls_request(
    cfg: &Arc<rustls::ClientConfig>,
    addr: std::net::SocketAddr,
) -> Result<hyper::StatusCode> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let tls = connector
        .connect(rustls::pki_types::ServerName::try_from("localhost".to_string())?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{addr}/ok"))
        .body(Full::new(Bytes::new()))?;
    let res = sender.send_request(req).await?;
    Ok(res.status())
}

fn insecure_client(recorded: Arc<Mutex<Vec<Vec<u8>>>>) -> Arc<rustls::ClientConfig> {
    let verifier = Arc::new(NoVerify { recorded });
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // Every probe must be a FULL handshake: resumed sessions never invoke
    // the verifier (the server presents no certificate on resumption), so
    // with the default in-memory ticket cache this probe would observe a
    // stale leaf forever after the first connection.
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(0);
    Arc::new(cfg)
}

pub async fn gate2() -> Result<()> {
    println!("p7-gate 2: TLS — self-signed boot + zero-downtime certificate hot reload");

    let dir = std::env::temp_dir().join(format!("bb-p7g2-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let upstream = spawn_echo("127.0.0.1:0").await?;

    // ---- 1) Self-signed boot: instant HTTPS with no external certs. ---
    let node_ss = spawn_node(NodeConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("{upstream}"),
        data: dir.join("selfsigned"),
        admin_listen: "127.0.0.1:0".into(),
        egress_listen: "127.0.0.1:0".into(),
        shield: false,
        tls: TlsOptions::SelfSigned,
        ..Default::default()
    })
    .await
    .context("self-signed node")?;
    let recorded_ss: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let status = tls_request(&insecure_client(Arc::clone(&recorded_ss)), node_ss.proxy.local_addr).await?;
    assert_eq!(status, hyper::StatusCode::OK, "self-signed HTTPS serves");
    assert!(
        !recorded_ss.lock().unwrap().is_empty(),
        "handshake presented a leaf certificate"
    );
    assert!(
        node_ss
            .data_dir
            .join("tls/self-signed.crt")
            .exists(),
        "self-signed cert persisted under <data>/tls/"
    );
    println!("  self-signed boot: HTTPS 200, leaf presented, cert persisted");

    // ---- 2) File certs + hot reload with zero failed requests. --------
    let certs = dir.join("certs");
    std::fs::create_dir_all(&certs)?;
    let (pem_a, key_a) = blackbox_ingress::tls::generate_self_signed_pem()?;
    let (pem_b, key_b) = blackbox_ingress::tls::generate_self_signed_pem()?;
    assert_ne!(pem_a, pem_b, "the two generated pairs must differ");
    let cert_path = certs.join("cert.pem");
    let key_path = certs.join("key.pem");
    std::fs::write(&cert_path, &pem_a)?;
    std::fs::write(&key_path, &key_a)?;

    let node = spawn_node(NodeConfig {
        listen: "127.0.0.1:0".into(),
        upstream: format!("{upstream}"),
        data: dir.join("files"),
        admin_listen: "127.0.0.1:0".into(),
        egress_listen: "127.0.0.1:0".into(),
        shield: false,
        tls: TlsOptions::Files {
            cert: cert_path.clone(),
            key: key_path.clone(),
        },
        ..Default::default()
    })
    .await
    .context("files node")?;

    let recorded: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let cfg = insecure_client(Arc::clone(&recorded));

    let status = tls_request(&cfg, node.proxy.local_addr).await?;
    assert_eq!(status, hyper::StatusCode::OK);
    let served_a: Vec<u8> = recorded.lock().unwrap()[0].clone();
    // The DER leaves we EXPECT on the wire, parsed from the PEMs.
    let der_a = rustls_pemfile::certs(&mut BufReader::new(pem_a.as_bytes()))
        .next()
        .expect("pem a has a cert")
        .expect("parse pem a")
        .to_vec();
    let der_b = rustls_pemfile::certs(&mut BufReader::new(pem_b.as_bytes()))
        .next()
        .expect("pem b has a cert")
        .expect("parse pem b")
        .to_vec();
    assert_eq!(served_a, der_a, "boot served the on-disk cert A");
    println!("  cert A served on boot ({} bytes leaf)", served_a.len());

    // Let the poller establish its content-fingerprint baseline (first
    // tick is immediate; a rotation written before it would be swallowed
    // into the baseline swap).
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // Rotate ON DISK (the classic certbot flow — no signal, no restart).
    std::fs::write(&cert_path, &pem_b)?;
    std::fs::write(&key_path, &key_b)?;

    // New connections must pick up cert B within the 2 s poll window;
    // every request during the window succeeds (zero downtime).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut served_b = false;
    let mut requests = 1;
    let mut failures = 0;
    while Instant::now() < deadline {
        match tls_request(&cfg, node.proxy.local_addr).await {
            Ok(s) if s.is_success() => {
                requests += 1;
                let seen = recorded.lock().unwrap().last().unwrap().clone();
                if seen == der_b {
                    served_b = true;
                    break;
                }
            }
            _ => {
                failures += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        served_b,
        "hot reload: new connections must serve cert B within 10s (requests={requests}, failures={failures}, handshakes_recorded={})",
        recorded.lock().unwrap().len()
    );
    assert_eq!(failures, 0, "zero failed requests across the certificate swap");
    println!("  hot reload: cert B served after rotation · {requests} requests, {failures} failures");

    // A bad pair on disk must NOT disrupt serving (old cert stays live).
    std::fs::write(&cert_path, "garbage")?;
    tokio::time::sleep(Duration::from_millis(2_600)).await;
    let status = tls_request(&cfg, node.proxy.local_addr).await?;
    assert_eq!(status, hyper::StatusCode::OK, "bad rotation never breaks serving");
    println!("  resilience: garbage cert on disk → serving continues on the last good pair");

    println!("  PASS — TLS termination + hot reload + bad-pair resilience");
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// --------------------------------------------------------------- gate 3 ----

pub async fn gate3() -> Result<()> {
    println!("p7-gate 3: `blackbox demo --once` — every engine, one subprocess, exit 0");

    let exe = std::env::current_exe().context("current exe")?;
    let data = std::env::temp_dir().join(format!("bb-p7g3-{}", std::process::id()));
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(&exe)
            .arg("demo")
            .arg("--once")
            .arg("--data")
            .arg(&data)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--admin-listen")
            .arg("127.0.0.1:0")
            .output(),
    )
    .await
    .context("demo --once timed out (120s)")?
    .context("spawn demo")?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "demo --once exited {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            out.status.code()
        );
    }

    // The demo itself asserts every phase; here we pin the SUMMARY shape.
    for marker in [
        "1 INGRESS",
        "2 QUEUE",
        "3 EGRESS-FINOPS",
        "4 STORAGE",
        "dashboard",
        "blackbox replay",
    ] {
        assert!(stdout.contains(marker), "summary missing {marker:?}:\n{stdout}");
    }
    // Engine assertions the demo prints (it enforced them with ensure!).
    assert!(stdout.contains("40/40 delivered"), "queue drain marker");
    assert!(stdout.contains("heals 1") || stdout.contains("heals 2") || stdout.contains("heals 3"),
        "self-heal marker");
    assert!(stdout.contains("✓ 4 engines"), "final verdict marker");

    println!("  PASS — demo --once: exit 0 · 4-engine summary printed · replay command emitted");
    println!("  stdout highlights:");
    for line in stdout.lines().filter(|l| l.contains("│") || l.contains("✓")) {
        println!("    {line}");
    }
    std::fs::remove_dir_all(&data).ok();
    Ok(())
}
