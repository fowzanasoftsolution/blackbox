//! The zero-cert egress FinOps gateway — Engine 4's listener.
//!
//! Apps point their AI/HTTP clients at Blackbox **without installing any
//! custom root CA** — Blackbox terminates plain HTTP locally and speaks
//! TLS upstream via rustls with bundled webpki roots:
//!
//! | Routing mode                     | Example                                        |
//! |----------------------------------|------------------------------------------------|
//! | Base-URL alias                   | `OPENAI_BASE_URL=http://bb:9700/v1`            |
//! | `X-Blackbox-Target` header       | `X-Blackbox-Target: https://api.acme.ai`       |
//! | Explicit gateway path            | `POST /egress/https/api.acme.ai/v1/x`          |
//! | Standard forward proxy           | `HTTP_PROXY=http://bb:9700` (absolute-form)    |
//! | CONNECT tunnel                   | blind TCP splice (zero-cert = no MITM)         |
//!
//! Every REAL upstream call emits an [`EgressHttpMock`] record linked to
//! the caller's `traceparent` / `x-blackbox-trace-id` — deterministic
//! replay works across the whole egress surface.
//!
//! Pipeline for cacheable requests:
//! `key → cache.get? → HIT` / `flight.join → COALESCE` / `LEAD → detached
//! upstream task → validate → cache + ledger + record → watch publish`.

use crate::cache::{header, CachedEntry, ResponseCache};
use crate::flight::{self, FlightResult, FlightTable, Join, UpstreamOutcome};
use crate::key::{self, composite_key};
use crate::simhash::{self, NearCache};
use crate::ledger::{parse_cost_header, parse_usage, CostLedger, LedgerKey, RequestKind};
use blackbox_core::egress_key::{canonical_url, fingerprint};
use blackbox_core::schema::{
    new_id128, now_ms, trace_id_to_hex, EgressHttpMock, RecordPayload, TraceId, TraceRecord,
};
use blackbox_core::StorageError;
use bytes::Bytes;
use http::{HeaderMap, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Request body ceiling — fingerprinting requires buffering (1 MiB).
pub const MAX_EGRESS_REQ_BODY: usize = 1024 * 1024;
/// Buffered response ceiling for the cache/coalesce path (8 MiB).
pub const MAX_EGRESS_RES_BODY: usize = 8 * 1024 * 1024;
/// Side-capture ceiling for streamed (bypass) responses (1 MiB).
pub const MAX_BYPASS_CAPTURE: usize = 1024 * 1024;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Record emitter — the node wires this to the SegmentStore writer sink.
pub type EmitFn = Arc<dyn Fn(TraceRecord) + Send + Sync>;

/// Gateway configuration.
pub struct EgressConfig {
    pub listen: SocketAddr,
    /// LRU entry cap.
    pub cache_max_entries: usize,
    /// LRU byte budget (default 4 MiB — RSS budget is 35 MB total).
    pub cache_max_bytes: usize,
    /// Ledger persistence directory (`finops.redb` inside).
    pub data_dir: std::path::PathBuf,
    /// Near-duplicate (SimHash L1) Hamming budget. `None` disables. The
    /// default reads `BLACKBOX_SIMHASH_MAXDIST` (absent → 3).
    pub near_dist: Option<u64>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cache_max_entries: 256,
            cache_max_bytes: 4 * 1024 * 1024,
            data_dir: std::path::PathBuf::from("./data"),
            near_dist: simhash::max_dist_from_env(),
        }
    }
}

/// Live handle for the admin API / gates.
pub struct EgressHandle {
    pub local_addr: SocketAddr,
    pub cache: Arc<ResponseCache>,
    pub near: Arc<NearCache>,
    pub ledger: Arc<CostLedger>,
    pub flights: Arc<FlightTable>,
    pub recorded: Arc<AtomicU64>,
    pub coalesced_served: Arc<AtomicU64>,
    pub bypass_served: Arc<AtomicU64>,
}

impl EgressHandle {
    /// Spawn the self-healing watcher: Warn75+ purges the cache to 0
    /// (transition-triggered), instantly via the supervisor watch hub.
    pub fn attach_self_healing(&self) {
        let cache = Arc::clone(&self.cache);
        let near = Arc::clone(&self.near);
        let mut rx = blackbox_supervisor::memory::subscribe_ram_level();
        tokio::spawn(async move {
            let mut last = *rx.borrow();
            loop {
                if rx.changed().await.is_err() {
                    return;
                }
                let level = *rx.borrow();
                if level >= blackbox_supervisor::memory::RamLevel::Warn75
                    && last < blackbox_supervisor::memory::RamLevel::Warn75
                {
                    cache.purge_all(&format!(
                        "supervisor watermark {:?} (self-healing RAM shed)",
                        level
                    ));
                    near.purge_all(&format!(
                        "supervisor watermark {:?} (self-healing RAM shed)",
                        level
                    ));
                }
                last = level;
            }
        });
    }
}

/// Spawn the egress FinOps gateway listener.
pub async fn spawn_egress(cfg: EgressConfig, emit: EmitFn) -> Result<EgressHandle, StorageError> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| StorageError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let local_addr = listener.local_addr()?;

    let cache = Arc::new(ResponseCache::new(cfg.cache_max_entries, cfg.cache_max_bytes));
    let near = Arc::new(NearCache::new(cfg.near_dist.unwrap_or(0)));
    let ledger = CostLedger::open(&cfg.data_dir)?;
    let flights = Arc::new(FlightTable::new());
    let recorded = Arc::new(AtomicU64::new(0));
    let coalesced_served = Arc::new(AtomicU64::new(0));
    let bypass_served = Arc::new(AtomicU64::new(0));

    // Upstream client: rustls with bundled webpki roots (ZERO custom CAs),
    // speaking both http:// and https:// — base-URL routing needs no trust
    // store changes anywhere.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(45))
        .pool_max_idle_per_host(64)
        .build(https);

    let state = Arc::new(EgressState {
        cache: Arc::clone(&cache),
        near: Arc::clone(&near),
        ledger: Arc::clone(&ledger),
        flights: Arc::clone(&flights),
        client,
        emit,
        recorded: Arc::clone(&recorded),
        coalesced_served: Arc::clone(&coalesced_served),
        bypass_served: Arc::clone(&bypass_served),
        seqs: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "egress accept failed");
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move {
                        Ok::<_, std::convert::Infallible>(route(req, state).await)
                    }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!(error = %e, "egress connection ended");
                }
            });
        }
    });

    Ok(EgressHandle {
        local_addr,
        cache,
        near,
        ledger,
        flights,
        recorded,
        coalesced_served,
        bypass_served,
    })
}

struct EgressState {
    cache: Arc<ResponseCache>,
    near: Arc<NearCache>,
    ledger: Arc<CostLedger>,
    flights: Arc<FlightTable>,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    emit: EmitFn,
    recorded: Arc<AtomicU64>,
    coalesced_served: Arc<AtomicU64>,
    bypass_served: Arc<AtomicU64>,
    /// Per-trace egress call ordering (EgressHttpMock::seq_no).
    seqs: std::sync::Mutex<std::collections::HashMap<TraceId, u64>>,
}

impl EgressState {
    fn next_seq(&self, trace_id: &TraceId) -> u64 {
        let mut s = self.seqs.lock().unwrap_or_else(|p| p.into_inner());
        let c = s.entry(*trace_id).or_insert(0);
        let n = *c;
        *c += 1;
        n
    }
}

// ------------------------------------------------------------- routing ----

async fn route(
    req: hyper::Request<Incoming>,
    state: Arc<EgressState>,
) -> hyper::Response<ResBody> {
    // CONNECT: blind tunnel (zero-cert policy — we never MITM TLS).
    if req.method() == http::Method::CONNECT {
        return tunnel(req).await;
    }
    match resolve_target(&req) {
        Ok(target) => handle_request(req, state, target).await,
        Err(res) => res,
    }
}

/// CONNECT tunnel: splice the sockets, no inspection (documented honest
/// behavior — inspection comes via base-URL routing / X-Blackbox-Target).
async fn tunnel(req: hyper::Request<Incoming>) -> hyper::Response<ResBody> {
    let authority = req.uri().to_string();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut io = TokioIo::new(upgraded);
                match tokio::net::TcpStream::connect(&authority).await {
                    Ok(mut upstream) => {
                        let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
                    }
                    Err(e) => tracing::debug!(error = %e, "CONNECT dial {authority} failed"),
                }
            }
            Err(e) => tracing::debug!(error = %e, "CONNECT upgrade failed"),
        }
    });
    hyper::Response::builder()
        .status(StatusCode::OK)
        .body(ResBody::Full(Full::new(Bytes::new())))
        .unwrap_or_else(|_| internal_error())
}

/// Resolve the upstream target from any of the supported routing modes.
/// Returns the absolute URL or an error response.
fn resolve_target(req: &hyper::Request<Incoming>) -> Result<String, hyper::Response<ResBody>> {
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    // 1) Forward-proxy absolute-form target (`GET https://api... HTTP/1.1`).
    if req.uri().scheme_str().is_some() && req.uri().host().is_some() {
        return Ok(req.uri().to_string());
    }

    // 2) Explicit gateway path: /egress/{scheme}/{host}[/{rest}].
    let rest = path.strip_prefix("/egress/").unwrap_or("");
    if rest.len() != path.len() {
        let mut parts = rest.splitn(3, '/');
        let scheme = parts.next().unwrap_or("");
        let host = parts.next().unwrap_or("");
        let tail = parts.next().unwrap_or("");
        if !scheme.is_empty() && !host.is_empty() && (scheme == "https" || scheme == "http") {
            let tail_q = if tail.is_empty() {
                query
            } else {
                format!("/{tail}{query}")
            };
            return Ok(format!("{scheme}://{host}{tail_q}"));
        }
        if !scheme.is_empty() {
            return Err(bad_request(
                "gateway path form: /egress/{https|http}/{host}/{path}\n",
            ));
        }
    }

    // 3) X-Blackbox-Target header (scheme://host[:port][/base]).
    if let Some(target) = req
        .headers()
        .get("x-blackbox-target")
        .and_then(|v| v.to_str().ok())
    {
        let target = target.trim().trim_end_matches('/');
        if !target.contains("://") {
            return Err(bad_request("X-Blackbox-Target must be an absolute URL\n"));
        }
        let joined = if path == "/" {
            format!("{target}/{query}")
        } else {
            format!("{target}{path}{query}")
        };
        return Ok(joined);
    }

    // 4) Provider aliases (longest prefix wins).
    let mut best: Option<(&str, &str)> = None;
    for (prefix, base) in key::PROVIDER_ALIASES {
        if path == *prefix || path.starts_with(&format!("{prefix}/")) {
            if best.map(|(p, _)| prefix.len() > p.len()).unwrap_or(true) {
                best = Some((prefix, base));
            }
        }
    }
    if let Some((_, base)) = best {
        return Ok(format!("{base}{path}{query}"));
    }

    Err(bad_request(
        "blackbox egress: no routing mode matched. Set OPENAI_BASE_URL to this listener, \
         add X-Blackbox-Target, use /egress/https/<host>/<path>, or HTTP_PROXY with \
         absolute-form requests\n",
    ))
}

fn bad_request(msg: &str) -> hyper::Response<ResBody> {
    hyper::Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(ResBody::Full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap_or_else(|_| internal_error())
}

fn internal_error() -> hyper::Response<ResBody> {
    hyper::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(ResBody::Full(Full::new(Bytes::from_static(b"blackbox egress internal error\n"))))
        .expect("static response builds")
}

fn too_large(msg: &str) -> hyper::Response<ResBody> {
    hyper::Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(ResBody::Full(Full::new(Bytes::from(msg.to_string()))))
        .unwrap_or_else(|_| internal_error())
}

// ------------------------------------------------------------ pipeline ----

/// Response body union: buffered (cache/coalesce/bypass-small) or the
/// streamed bypass tee.
pub enum ResBody {
    Full(Full<Bytes>),
    Tee(TeeUpstream<Incoming>),
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl hyper::body::Body for ResBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResBody::Full(f) => match std::pin::Pin::new(f).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(fr))) => std::task::Poll::Ready(Some(Ok(fr))),
                std::task::Poll::Ready(Some(Err(e))) => match e {},
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
            ResBody::Tee(t) => match std::pin::Pin::new(t).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(fr))) => std::task::Poll::Ready(Some(Ok(fr))),
                std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e.into()))),
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ResBody::Full(f) => f.size_hint(),
            ResBody::Tee(t) => t.size_hint(),
        }
    }
}

/// The main request pipeline (non-CONNECT, resolved target).
async fn handle_request(
    req: hyper::Request<Incoming>,
    state: Arc<EgressState>,
    target: String,
) -> hyper::Response<ResBody> {
    let started = Instant::now();
    let method = req.method().as_str().to_string();
    let trace_id = extract_trace(req.headers());
    let trace_hex = trace_id_to_hex(&trace_id);
    // Forward header snapshot BEFORE the body is consumed.
    let fwd_headers = forward_headers_snapshot(&req);

    let tenant = req
        .headers()
        .get("x-blackbox-tenant")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default")
        .to_string();
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cache_hdr = req
        .headers()
        .get("x-blackbox-cache")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Bounded request-body buffering (fingerprinting needs exact bytes).
    let body = match read_capped(req.into_body(), MAX_EGRESS_REQ_BODY).await {
        Ok(b) => b,
        Err(status) => {
            return match status {
                StatusCode::PAYLOAD_TOO_LARGE => too_large(
                    "blackbox egress: request body exceeds the 1 MiB cache ceiling\n",
                ),
                _ => bad_request("blackbox egress: malformed request body\n"),
            }
        }
    };

    let canon = canonical_url(&target);
    let host = url_host(&target);
    let path = url_path(&target);
    let model = parse_model(&body);
    let ledger_key = LedgerKey::new(tenant, key::provider_for(&host, &path), model);

    // ---- Non-cacheable: stream through, record, ledger. ----------------
    if !key::cacheable(&method, &path, cache_hdr.as_deref(), &body) {
        let fp = fingerprint(&method, &target, &body);
        return bypass_forward(
            state,
            &method,
            target,
            fwd_headers,
            trace_id,
            trace_hex,
            ledger_key,
            fp,
            Bytes::from(body),
            started,
        )
        .await;
    }

    // ---- Cacheable: key → cache → flight. ------------------------------
    let ckey = composite_key(&ledger_key.tenant, &auth, &method, &canon, &body);

    // 1) Cache hit?
    if let Some(entry) = state.cache.get(&ckey) {
        state.ledger.record(
            ledger_key,
            RequestKind::CacheHit,
            0,
            entry.tokens,
            0,
            entry.cost_micros,
        );
        blackbox_core::audit::record("egress", "cache_hit", &trace_hex, "exact-l0");
        return entry_response(&entry, "HIT", trace_hex);
    }

    // 1b) Near-duplicate lookup (SimHash L1, behind the exact L0 hit).
    //     Same scope (tenant ‖ auth ‖ route ‖ CONTROL knobs), prompt text
    //     within an under-sampling-deterministic Hamming budget.
    let near_hint = simhash::prepare(
        &ledger_key.tenant,
        &auth,
        &method,
        &canon,
        &path,
        body.as_ref(),
    );
    if let Some((ref nk, sh)) = near_hint {
        if let Some((entry, d)) = state.near.lookup(nk, sh) {
            state.ledger.record(
                ledger_key.clone(),
                RequestKind::CacheHit,
                0,
                entry.tokens,
                0,
                entry.cost_micros,
            );
            blackbox_core::audit::record(
                "egress",
                "near_hit",
                &trace_hex,
                &format!("d={d} simhash={sh:016x}"),
            );
            return entry_response(&entry, &format!("SIMHASH(d={d})"), trace_hex);
        }
    }

    // 2) Singleflight join (leader spawns the DETACHED upstream task).
    let (rx, is_leader) = join_once(&state.flights, ckey);
    if is_leader {
        state.cache.record_miss();
        spawn_leader(
            Arc::clone(&state),
            ckey,
            ledger_key.clone(),
            method.clone(),
            target.clone(),
            fwd_headers.clone(),
            trace_id,
            Bytes::from(body.clone()),
            near_hint,
        );
    }

    match flight::wait(rx).await {
        Ok(outcome) => {
            if is_leader {
                // The detached leader task already recorded the upstream
                // call (tokens/cost/ledger/mock); just answer MISS.
                outcome_response(&outcome, "MISS", trace_hex)
            } else {
                // Waiter accounting: coalescing saves the leader's usage.
                state.ledger.record(
                    ledger_key,
                    RequestKind::Coalesced,
                    0,
                    outcome.tokens,
                    0,
                    outcome.cost_micros,
                );
                state.coalesced_served.fetch_add(1, Ordering::Relaxed);
                outcome_response(&outcome, "COALESCE", trace_hex)
            }
        }
        Err(reason) => gateway_502(&reason, trace_hex),
    }
}

/// Race-free single join returning (rx, is_leader).
fn join_once(
    table: &FlightTable,
    key: [u8; 32],
) -> (tokio::sync::watch::Receiver<Option<FlightResult>>, bool) {
    match table.join(key) {
        Join::Lead(rx) => (rx, true),
        Join::Wait(rx) => (rx, false),
    }
}

fn gateway_502(reason: &str, trace_hex: String) -> hyper::Response<ResBody> {
    hyper::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("x-blackbox-trace-id", trace_hex)
        .body(ResBody::Full(Full::new(Bytes::from(format!(
            "blackbox egress: upstream failed: {reason}\n"
        )))))
        .unwrap_or_else(|_| hyper::Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(ResBody::Full(Full::new(Bytes::from_static(b"internal error\n")))).expect("static"))
}

// ------------------------------------------------- detached leader task ----

/// Spawn the DETACHED upstream task (survives the leader's client
/// disconnecting): execute → validate → cache insert → ledger → mock
/// record → publish to every coalesced waiter.
#[allow(clippy::too_many_arguments)]
fn spawn_leader(
    state: Arc<EgressState>,
    ckey: [u8; 32],
    ledger_key: LedgerKey,
    method: String,
    target: String,
    fwd_headers: Vec<(String, String)>,
    trace_id: TraceId,
    body: Bytes,
    near_hint: Option<([u8; 32], u64)>,
) {
    tokio::spawn(async move {
        let outcome =
            execute_upstream(&state, &method, &target, fwd_headers, trace_id, body).await;
        match outcome {
            Ok(o) => {
                // Validate BEFORE caching (soft-error guard, Landmine #6).
                let verdict = crate::validate::validate(
                    o.status,
                    header(&o.headers, "content-type"),
                    &o.body,
                );
                if verdict == crate::validate::Verdict::Cacheable {
                    let ent = CachedEntry {
                        status: o.status,
                        headers: o.headers.clone(),
                        body: o.body.clone(),
                        tokens: o.tokens,
                        cost_micros: o.cost_micros,
                    };
                    state.cache.insert(ckey, ent.clone());
                    // Register in the near index: near variants of this
                    // prompt can now be answered without an upstream call.
                    if let Some((nk, sh)) = near_hint {
                        state.near.record(nk, sh, ent);
                    }
                } else {
                    tracing::debug!(
                        verdict = ?verdict,
                        "egress response NOT cached (soft-error guard)"
                    );
                }
                state.ledger.record(
                    ledger_key,
                    RequestKind::Upstream,
                    o.tokens,
                    0,
                    o.cost_micros,
                    0,
                );
                blackbox_core::audit::record(
                    "egress",
                    "upstream",
                    &blackbox_core::schema::trace_id_to_hex(&trace_id),
                    &format!("status={} tokens={} cost_micros={}", o.status, o.tokens, o.cost_micros),
                );
                state.flights.publish(ckey, Ok(o));
                state.flights.finish(ckey);
            }
            Err(reason) => {
                state.flights.publish(ckey, Err(reason));
                state.flights.finish(ckey);
            }
        }
    });
}

/// Execute one real upstream call: forward, buffer the bounded response,
/// emit the EgressHttpMock record under the caller's trace.
async fn execute_upstream(
    state: &EgressState,
    method: &str,
    url: &str,
    fwd_headers: Vec<(String, String)>,
    trace_id: TraceId,
    body: Bytes,
) -> FlightResult {
    let uri: Uri = match url.parse() {
        Ok(u) => u,
        Err(e) => return Err(Arc::new(format!("invalid target url: {e}"))),
    };
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri.clone());
    for (k, v) in &fwd_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = match builder.body(Full::new(body.clone())) {
        Ok(r) => r,
        Err(e) => return Err(Arc::new(format!("upstream request build: {e}"))),
    };

    let started = Instant::now();
    let res = match state.client.request(req).await {
        Ok(r) => r,
        Err(e) => return Err(Arc::new(format!("upstream connect: {e}"))),
    };
    let status = res.status().as_u16();
    let res_headers: Vec<(String, String)> = res
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let res_body = match read_capped(res.into_body(), MAX_EGRESS_RES_BODY).await {
        Ok(b) => b,
        Err(StatusCode::PAYLOAD_TOO_LARGE) => {
            return Err(Arc::new(format!(
                "upstream response exceeds the {} byte coalesce ceiling",
                MAX_EGRESS_RES_BODY
            )))
        }
        Err(_) => return Err(Arc::new("upstream response read failed".into())),
    };
    let _ = started.elapsed();

    // Record the exchange for deterministic replay (every real call).
    let mock = EgressHttpMock {
        seq_no: state.next_seq(&trace_id),
        request_fingerprint: fingerprint(method, url, &body),
        method: method.to_string(),
        request_url: url.to_string(),
        response_status: status,
        response_headers: res_headers.clone(),
        response_body: res_body.clone(),
        upstream_host: uri
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default(),
        recorded_at_ms: now_ms(),
    };
    (state.emit)(TraceRecord::new(trace_id, 0, RecordPayload::EgressHttpMock(mock)));
    state.recorded.fetch_add(1, Ordering::Relaxed);

    let tokens = parse_usage(&res_body).tokens;
    let cost_micros = parse_cost_header(&res_headers);
    Ok(Arc::new(UpstreamOutcome {
        status,
        headers: res_headers,
        body: Bytes::from(res_body),
        tokens,
        cost_micros,
    }))
}

// -------------------------------------------------------------- bypass ----

/// Non-cacheable requests: TRUE streaming pass-through with a bounded
/// side-capture (1 MiB) that feeds the replay record + ledger at EOF.
/// The pass-through byte count is UNLIMITED (model downloads work fine);
/// only the replay capture is capped.
#[allow(clippy::too_many_arguments)]
async fn bypass_forward(
    state: Arc<EgressState>,
    method: &str,
    target: String,
    fwd_headers: Vec<(String, String)>,
    trace_id: TraceId,
    trace_hex: String,
    ledger_key: LedgerKey,
    req_fp: [u8; 32],
    body: Bytes,
    started: Instant,
) -> hyper::Response<ResBody> {
    let uri: Uri = match target.parse() {
        Ok(u) => u,
        Err(e) => return bad_request(&format!("invalid target url: {e}\n")),
    };
    let mut builder = hyper::Request::builder().method(method).uri(uri.clone());
    for (k, v) in &fwd_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = match builder.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("upstream request build: {e}\n")),
    };

    let res = match state.client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            return gateway_502(&format!("upstream connect: {e}"), trace_hex);
        }
    };
    let status = res.status().as_u16();
    let res_headers: Vec<(String, String)> = res
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();

    state.bypass_served.fetch_add(1, Ordering::Relaxed);

    let fin = BypassFinalizer {
        state: Arc::clone(&state),
        trace_id,
        method: method.to_string(),
        url: target,
        req_body_hash: req_fp,
        status,
        res_headers: res_headers.clone(),
        ledger_key,
    };
    let _ = started;

    let mut b = hyper::Response::builder().status(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
    );
    for (k, v) in &res_headers {
        let lname = k.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || lname == "content-length" {
            continue;
        }
        b = b.header(k.as_str(), v.as_str());
    }
    b = b
        .header("x-blackbox-cache", "BYPASS")
        .header("x-blackbox-trace-id", trace_hex);

    // The replay capture is capped; pass-through is unlimited.
    let tee = TeeUpstream::new(res.into_body(), fin);
    match b.body(ResBody::Tee(tee)) {
        Ok(r) => r,
        Err(_) => internal_error(),
    }
}

/// Everything needed to emit the bypass EgressHttpMock + ledger row once
/// the streamed response ends (EOF, error, or drop).
struct BypassFinalizer {
    state: Arc<EgressState>,
    trace_id: TraceId,
    method: String,
    url: String,
    req_body_hash: [u8; 32],
    status: u16,
    res_headers: Vec<(String, String)>,
    ledger_key: LedgerKey,
}

impl BypassFinalizer {
    fn emit(&self, captured: &[u8], truncated: bool) {
        let mut headers = self.res_headers.clone();
        if truncated {
            headers.push(("x-blackbox-egress-truncated".into(), "1".into()));
        }
        let mock = EgressHttpMock {
            seq_no: self.state.next_seq(&self.trace_id),
            request_fingerprint: self.req_body_hash,
            method: self.method.clone(),
            request_url: self.url.clone(),
            response_status: self.status,
            response_headers: headers,
            response_body: captured.to_vec(),
            upstream_host: Uri::try_from(self.url.clone())
                .ok()
                .and_then(|u| u.authority().map(|a| a.to_string()))
                .unwrap_or_default(),
            recorded_at_ms: now_ms(),
        };
        (self.state.emit)(TraceRecord::new(
            self.trace_id,
            0,
            RecordPayload::EgressHttpMock(mock),
        ));
        self.state.recorded.fetch_add(1, Ordering::Relaxed);

        let cost = parse_cost_header(&self.res_headers);
        let tokens = parse_usage(captured).tokens;
        self.state.ledger.record(
            self.ledger_key.clone(),
            RequestKind::Upstream,
            tokens,
            0,
            cost,
            0,
        );
    }
}

/// Streaming tee for bypass responses: forwards every frame untouched,
/// side-captures up to [`MAX_BYPASS_CAPTURE`] bytes, emits the finalizer
/// exactly once (EOF / error / early drop).
pub struct TeeUpstream<B> {
    inner: B,
    captured: Vec<u8>,
    truncated: bool,
    fin: Option<BypassFinalizer>,
    emitted: bool,
}

impl<B> TeeUpstream<B> {
    fn new(inner: B, fin: BypassFinalizer) -> Self {
        TeeUpstream {
            inner,
            captured: Vec::new(),
            truncated: false,
            fin: Some(fin),
            emitted: false,
        }
    }

    fn finalize_now(&mut self) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        if let Some(fin) = self.fin.take() {
            fin.emit(&self.captured, self.truncated);
        }
    }
}

impl<B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Unpin> hyper::body::Body
    for TeeUpstream<B>
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if this.captured.len() < MAX_BYPASS_CAPTURE {
                        let room = MAX_BYPASS_CAPTURE - this.captured.len();
                        let take = room.min(data.len());
                        this.captured.extend_from_slice(&data[..take]);
                        if take < data.len() {
                            this.truncated = true;
                        }
                    } else {
                        this.truncated = true;
                    }
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(None) => {
                this.finalize_now();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                this.finalize_now();
                std::task::Poll::Ready(Some(Err(e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for TeeUpstream<B> {
    fn drop(&mut self) {
        // Client disconnect / stream abort: record what we saw.
        self.finalize_now();
    }
}

// ------------------------------------------------------- response build ----

fn entry_response(entry: &CachedEntry, flag: &str, trace_hex: String) -> hyper::Response<ResBody> {
    build_stored_response(entry.status, &entry.headers, entry.body.clone(), flag, trace_hex)
}

fn outcome_response(
    outcome: &UpstreamOutcome,
    flag: &str,
    trace_hex: String,
) -> hyper::Response<ResBody> {
    build_stored_response(outcome.status, &outcome.headers, outcome.body.clone(), flag, trace_hex)
}

fn build_stored_response(
    status: u16,
    headers: &[(String, String)],
    body: Bytes,
    flag: &str,
    trace_hex: String,
) -> hyper::Response<ResBody> {
    let mut b = hyper::Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header("x-blackbox-cache", flag)
        .header("x-blackbox-trace-id", trace_hex);
    for (k, v) in headers {
        let lname = k.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || lname == "content-length" {
            continue;
        }
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(ResBody::Full(Full::new(body)))
        .unwrap_or_else(|_| internal_error())
}

// -------------------------------------------------------------- helpers ----

/// Snapshot of request headers to forward upstream: hop-by-hop, host,
/// content-length (recomputed) and x-blackbox-* control headers stripped;
/// Authorization + traceparent preserved verbatim.
fn forward_headers_snapshot(req: &hyper::Request<Incoming>) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(req.headers().len());
    for (name, value) in req.headers().iter() {
        let lname = name.as_str();
        if HOP_BY_HOP.contains(&lname)
            || lname == "host"
            || lname == "content-length"
            || lname.starts_with("x-blackbox-")
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.push((lname.to_string(), v.to_string()));
        }
    }
    out
}

async fn read_capped(body: Incoming, cap: usize) -> Result<Vec<u8>, StatusCode> {
    let mut out = Vec::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };
        if let Some(data) = frame.data_ref() {
            if out.len() + data.len() > cap {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Trace correlation: W3C `traceparent` first, then
/// `x-blackbox-trace-id`, else a fresh random trace.
fn extract_trace(headers: &HeaderMap) -> TraceId {
    if let Some(tp) = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_traceparent_trace)
    {
        return tp;
    }
    if let Some(tid) = headers
        .get("x-blackbox-trace-id")
        .and_then(|v| v.to_str().ok())
        .and_then(blackbox_core::schema::parse_trace_hex)
    {
        return tid;
    }
    fresh_trace_id()
}

fn parse_traceparent_trace(value: &str) -> Option<TraceId> {
    let v = value.trim();
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() != 4 || parts[1].len() != 32 {
        return None;
    }
    let tid = blackbox_core::schema::parse_trace_hex(parts[1])?;
    if tid == [0u8; 16] {
        None
    } else {
        Some(tid)
    }
}

fn fresh_trace_id() -> TraceId {
    let mut out = [0u8; 16];
    // new_id128 is u128 — split two draws across the 16 bytes (each
    // to_be_bytes() is itself 16 bytes; take the high-entropy halves).
    let a = new_id128().to_be_bytes();
    let b = new_id128().to_be_bytes();
    out[..8].copy_from_slice(&a[..8]);
    out[8..].copy_from_slice(&b[..8]);
    if out == [0u8; 16] {
        out[0] = 1;
    }
    out
}

/// `"model"` field from a JSON request body (OpenAI + Anthropic both).
fn parse_model(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("model")
                .and_then(|m| m.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "-".to_string())
}

fn url_host(url: &str) -> String {
    Uri::try_from(url)
        .ok()
        .and_then(|u| u.authority().map(|a| a.to_string()))
        .unwrap_or_default()
}

fn url_path(url: &str) -> String {
    match url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        },
        None => url.to_string(),
    }
}
