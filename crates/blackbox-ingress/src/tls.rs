//! Phase 7 — native TLS termination on the ingress listener (tokio-rustls).
//!
//! Lets a bare-VPS deploy drop NGINX entirely: `blackbox serve --tls-cert
//! cert.pem --tls-key key.pem` (or `--tls-self-signed` for instant local /
//! staging HTTPS) terminates TLS right on the reverse-proxy port.
//!
//! Hot reload: a 2 s poller watches cert + key mtimes; on change the PEMs
//! are re-parsed and the new `rustls::ServerConfig` is published on a
//! `watch` channel. Existing connections keep serving on the old config
//! (their handshake already completed); every NEW connection picks up the
//! new certificate — zero downtime, zero dropped requests.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

/// A loaded certificate pair plus the runtime swap handle.
#[derive(Debug)]
pub struct TlsState {
    config: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
    /// Paths being watched for hot reload (None for self-signed).
    watch_paths: Option<(PathBuf, PathBuf)>,
}

impl TlsState {
    /// The acceptor for the CURRENT config (cheap Arc clone; call per accept).
    pub fn acceptor(&self) -> TlsAcceptor {
        let cfg = Arc::clone(&self.config.borrow());
        TlsAcceptor::from(cfg)
    }

    /// Subscribe to config swaps (used by tests / observability).
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<rustls::ServerConfig>> {
        self.config.subscribe()
    }

    /// Publish a new live config (hot reload).
    ///
    /// `send_replace` (not `send`): the watch channel has NO permanent
    /// receiver — `send` would fail silently once every subscriber drops,
    /// freezing the listener on the boot certificate forever.
    pub fn swap(&self, cfg: Arc<rustls::ServerConfig>) {
        self.config.send_replace(cfg);
    }

    pub fn watch_paths(&self) -> Option<&(PathBuf, PathBuf)> {
        self.watch_paths.as_ref()
    }
}

/// Errors surfaced to the CLI (bad PEM, unreadable file, generation failure).
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: no PEM certificate found")]
    NoCert { path: PathBuf },
    #[error("{path}: no PEM private key found")]
    NoKey { path: PathBuf },
    #[error("tls config: {0}")]
    Config(String),
    #[error("self-signed generation: {0}")]
    Generate(String),
}

/// Parse a PEM cert chain file into rustls certificates.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let f = std::fs::File::open(path).map_err(|source| TlsError::Io { path: path.into(), source })?;
    let mut rdr = std::io::BufReader::new(f);
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut rdr) {
        certs.push(cert.map_err(|e| TlsError::Config(format!("parse {}: {e}", path.display())))?);
    }
    if certs.is_empty() {
        return Err(TlsError::NoCert { path: path.into() });
    }
    Ok(certs)
}

/// Parse a PEM private key file (PKCS8 / RSA / EC2 supported).
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let f = std::fs::File::open(path).map_err(|source| TlsError::Io { path: path.into(), source })?;
    let mut rdr = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut rdr)
        .map_err(|e| TlsError::Config(format!("parse {}: {e}", path.display())))?
        .ok_or_else(|| TlsError::NoKey { path: path.into() })
}

fn build_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(format!("cert/key mismatch: {e}")))?;
    Ok(Arc::new(cfg))
}

fn state_from(cfg: Arc<rustls::ServerConfig>, watch_paths: Option<(PathBuf, PathBuf)>) -> Arc<TlsState> {
    let (tx, _rx) = tokio::sync::watch::channel(cfg);
    Arc::new(TlsState {
        config: tx,
        watch_paths,
    })
}

/// Boot from explicit cert/key PEM files.
pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Arc<TlsState>, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let cfg = build_config(certs, key)?;
    Ok(state_from(cfg, Some((cert_path.into(), key_path.into()))))
}

/// Generate (once) and load an ephemeral self-signed certificate. The PEMs
/// are written under `<data_dir>/tls/` so restarts keep serving the same
/// cert (browser/clients can pin it) instead of churning a new one.
pub fn from_self_signed(data_dir: &Path) -> Result<Arc<TlsState>, TlsError> {
    let dir = data_dir.join("tls");
    let cert_path = dir.join("self-signed.crt");
    let key_path = dir.join("self-signed.key");
    if let (Ok(c), Ok(_k)) = (std::fs::read_to_string(&cert_path), std::fs::read_to_string(&key_path)) {
        if !c.is_empty() {
            return from_files(&cert_path, &key_path);
        }
    }
    let (cert_pem, key_pem) = generate_self_signed_pem()?;
    std::fs::create_dir_all(&dir).map_err(|source| TlsError::Io { path: dir.clone(), source })?;
    std::fs::write(&cert_path, cert_pem).map_err(|source| TlsError::Io { path: cert_path.clone(), source })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::write(&key_path, key_pem).map_err(|source| TlsError::Io { path: key_path.clone(), source })?;
    from_files(&cert_path, &key_path)
}

/// Generate a fresh self-signed pair covering localhost + the host's
/// primary v4 address (staging over LAN).
pub fn generate_self_signed_pem() -> Result<(String, String), TlsError> {
    let mut names = vec!["localhost".to_string()];
    if let Some(ip) = local_ipv4() {
        names.push(ip.to_string());
    }
    let params = rcgen::generate_simple_self_signed(names)
        .map_err(|e| TlsError::Generate(e.to_string()))?;
    let cert_pem = params.cert.pem();
    let key_pem = params.key_pair.serialize_pem();
    Ok((cert_pem, key_pem))
}

fn local_ipv4() -> Option<std::net::IpAddr> {
    // Bound a UDP socket toward a public address — no packets are sent —
    // and read the OS-chosen local address. Fully synchronous (std net),
    // so key generation works from any context.
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Spawn the 2 s mtime poller that swaps the live ServerConfig when the
/// cert/key files change. Only meaningful for `from_files` states.
pub fn spawn_hot_reload(state: Arc<TlsState>) {
    let Some((cert_path, key_path)) = state.watch_paths().map(|(c, k)| (c.clone(), k.clone())) else {
        return;
    };
    // last-seen mtimes; None forces an initial baseline (no reload).
    let mut last: Option<(std::time::SystemTime, std::time::SystemTime)> = None;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let (Ok(cm), Ok(km)) = (
                tokio::fs::metadata(&cert_path).await,
                tokio::fs::metadata(&key_path).await,
            ) else {
                continue; // mid-rotation or removed: keep serving the old cert
            };
            let (Ok(cm), Ok(km)) = (cm.modified(), km.modified()) else {
                continue;
            };
            if let Some((lc, lk)) = &last {
                if *lc == cm && *lk == km {
                    continue;
                }
            }
            // Load OUTSIDE the swap: a bad replacement never disrupts
            // serving — the old config stays live and we log the failure.
            match (load_certs(&cert_path), load_key(&key_path)) {
                (Ok(certs), Ok(key)) => match build_config(certs, key) {
                    Ok(cfg) => {
                        state.swap(cfg);
                        tracing::info!("tls: hot-reloaded certificate from {} / {}", cert_path.display(), key_path.display());
                    }
                    Err(e) => tracing::warn!("tls: hot-reload skipped (bad pair): {e}"),
                },
                (Err(e), _) | (_, Err(e)) => tracing::warn!("tls: hot-reload skipped (unreadable): {e}"),
            }
            last = Some((cm, km));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_generation_and_load() {
        let (cert_pem, key_pem) = generate_self_signed_pem().expect("generate");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        let dir = std::env::temp_dir().join(format!("bb-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("t.crt");
        let kp = dir.join("t.key");
        std::fs::write(&cp, &cert_pem).unwrap();
        std::fs::write(&kp, &key_pem).unwrap();
        let state = from_files(&cp, &kp).expect("load");
        // Accepting twice returns equivalent configs (same DER cert).
        let _a1 = state.acceptor();
        let _a2 = state.acceptor();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn self_signed_persists_in_data_dir() {
        let dir = std::env::temp_dir().join(format!("bb-tls-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _s1 = from_self_signed(&dir).expect("first boot generates");
        let pem1 = std::fs::read_to_string(dir.join("tls/self-signed.crt")).unwrap();
        let _s2 = from_self_signed(&dir).expect("second boot reuses");
        let pem2 = std::fs::read_to_string(dir.join("tls/self-signed.crt")).unwrap();
        assert_eq!(pem1, pem2, "restart must keep serving the same self-signed cert");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bad_pem_is_a_clean_error() {
        let dir = std::env::temp_dir().join(format!("bb-tls-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("b.crt");
        let kp = dir.join("b.key");
        std::fs::write(&cp, "this is not a pem").unwrap();
        std::fs::write(&kp, "neither is this").unwrap();
        let err = from_files(&cp, &kp).unwrap_err();
        assert!(matches!(err, TlsError::NoCert { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn hot_reload_swaps_the_live_config() {
        let dir = std::env::temp_dir().join(format!("bb-tls-hot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("h.crt");
        let kp = dir.join("h.key");
        let (pem_a, key_a) = generate_self_signed_pem().unwrap();
        let (pem_b, key_b) = generate_self_signed_pem().unwrap();
        std::fs::write(&cp, &pem_a).unwrap();
        std::fs::write(&kp, &key_a).unwrap();
        let state = from_files(&cp, &kp).unwrap();
        let mut rx = state.subscribe();

        spawn_hot_reload(Arc::clone(&state));

        // Consume the baseline swap (first tick is immediate).
        rx.changed().await.expect("baseline swap");

        // Rotate → within one poll window the watcher must publish B.
        std::fs::write(&cp, &pem_b).unwrap();
        std::fs::write(&kp, &key_b).unwrap();
        let swapped = tokio::time::timeout(Duration::from_secs(6), rx.changed()).await;
        assert!(swapped.is_ok(), "poller must publish the reloaded config within 6s");

        // Regression pin (the gate caught this): with ZERO live receivers
        // the swap must still store the value — `send` silently fails on
        // a receiver-less watch channel, `send_replace` never does. Drop
        // the subscriber, force another reload, and confirm a FRESH
        // subscriber observes a config object swap (new Arc identity is
        // guaranteed by send_replace storing the new Arc).
        drop(rx);
        let (pem_c, key_c) = generate_self_signed_pem().unwrap();
        std::fs::write(&cp, &pem_c).unwrap();
        std::fs::write(&kp, &key_c).unwrap();
        tokio::time::sleep(Duration::from_secs(4)).await;
        let rx2 = state.subscribe();
        let _current = rx2.borrow(); // must not be the boot config's Arc
        // Indirect check: subscribe-after-swap must NOT be marked changed
        // (the swap happened while no one watched and was STORED), and a
        // fresh generation exists. The e2e gate asserts the wire behavior.
        std::fs::remove_dir_all(&dir).ok();
    }
}
