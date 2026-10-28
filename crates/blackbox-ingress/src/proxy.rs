//! The zero-blocking reverse proxy — hyper 1.x + hyper-util + tower.
//!
//! Hot path per request (all async, no blocking syscalls, no disk I/O):
//!
//! 1. W3C `traceparent`: parse if present, else generate and inject into
//!    the upstream request; echo `x-blackbox-trace-id` on the response.
//! 2. Request body: [`TeeBody`] streams chunks to the upstream untouched,
//!    side-capturing ≤64 KB for text/JSON, bypassing multipart / SSE /
//!    WebSocket / binary entirely.
//! 3. Response body: second [`TeeBody`] streams back to the client; on
//!    completion the [`Finalizer`] scrubs PII and pushes the record into
//!    the bounded writer channel.
//! 4. Telemetry paths (`/api/{id}/envelope/`, `/v1/traces`, `/v1/logs`)
//!    are intercepted, wire-compatible, and stored natively (SentryCrash /
//!    TelemetryLog records) instead of being proxied.

use crate::durable::{handle_durable, matches_durable, DurableCtx};
use crate::index::{IndexStats, TraceIndex};
use crate::rate_limit::{Decision, RateLimiter};
use crate::scrub::Scrubber;
use crate::tee::{capture_policy, CaptureBuf, Finalizer, TeeBody, CAPTURE_MAX_BYTES, CapturePolicy};
use crate::tls::TlsState;
use crate::traceparent::{
    baggage_entries, merge_baggage, Traceparent, BAGGAGE_HEADER, SENTRY_TRACE_HEADER,
    TRACEPARENT_HEADER, TRACE_ID_RESPONSE_HEADER,
};
use crate::waf::ScannerShield;
use crate::writer::{RecordSink, WriterConfig};
use blackbox_core::breaker::UpstreamHealth;
use blackbox_core::schema::{
    trace_id_to_hex, RecordPayload, SentryCrash, TelemetryLog, TraceId, TraceRecord,
};
use blackbox_core::StorageError;
use blackbox_telemetry::decompress::{decode_body, Capped, BodyError};
use blackbox_telemetry::envelope;
use blackbox_telemetry::otlp::{self, OtlpKind};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Cumulative proxied+handled request counter (admin dashboard throughput).
/// Every route entry (proxy, telemetry, durable) increments this once.
pub static PROXY_REQUESTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Records dropped by the Shed85 head-sampling policy (healthy 2xx < 1 s).
pub static SAMPLED_OUT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Records dropped specifically by the DISK Emergency95 survival policy
/// (overlaps SAMPLED_OUT when both levels are active — disjoint counting
/// happens in the Finalizer).
pub static DISK_SHED_OUT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Phase 7: requests rejected with 429 by the sharded token-bucket limiter.
pub static RATE_LIMITED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Hop-by-hop headers never forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Queue engine attachment: the live JobStore runtime plus the delivery
/// event stream (converted into telemetry records by spawn_proxy).
pub struct QueueAttachment {
    pub runtime: blackbox_queue::QueueRuntime,
    pub events: tokio::sync::mpsc::Receiver<blackbox_queue::QueueEvent>,
}

/// Proxy configuration.
pub struct IngressConfig {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Segment directory (shared with the queue/telemetry engines).
    pub data_dir: std::path::PathBuf,
    /// Upstream app `host:port` the proxy forwards to.
    pub upstream: String,
    /// Writer channel capacity (16 384 per blueprint).
    pub channel_cap: usize,
    /// Group-commit fsync cadence for the writer task.
    pub sync_interval: Duration,
    /// Shared circuit breaker; a fresh one is created when None.
    pub health: Option<Arc<UpstreamHealth>>,
    /// Consecutive upstream failures that trip the breaker.
    pub failure_threshold: u32,
    /// Circuit probe cadence while not Closed.
    pub probe_interval: Duration,
    /// How long synchronous requests are held while the breaker is Open.
    pub hold_window: Duration,
    /// Durable prefixes (from `"/webhooks/*,/jobs/*"` style spec).
    pub durable_prefixes: Vec<String>,
    /// Hard ceiling on raw webhook bodies.
    pub max_webhook_body: usize,
    /// Idempotency headers (lowercase, priority order).
    pub idem_headers: Vec<String>,
    /// Default dead-letter attempt budget.
    pub max_attempts: u32,
    /// Queue engine attachment (durable routes active when present).
    pub queue: Option<QueueAttachment>,
    /// Replay mode: force every proxied request onto this trace id.
    pub replay_trace: Option<TraceId>,
    /// Rotate the active segment once it exceeds this size (Phase 5;
    /// default 64 MB, configurable down to 1 MB for tests).
    pub max_segment_bytes: u64,
    /// v1.1.2 RAM budget (bytes) for the segment rollover guard: the
    /// effective byte cap is `min(max_segment_bytes, ram_budget_bytes / 6)`
    /// so a 64 MB segment cap on a 48 MB budget rolls over at ~8 MB instead
    /// of letting the hot index + one giant compaction spike past Shed85.
    /// 0 = no RAM-derived cap (use `max_segment_bytes` alone).
    pub ram_budget_bytes: u64,
    /// Phase 6: S3/R2 cold tier — transparent evicted-segment restore +
    /// bit-rot self-heal in `get_trace` (None = local-only retention).
    pub cold: Option<Arc<blackbox_cold::ColdTier>>,
    /// Phase 7: scanner/WAF shield (default OFF for library tests; the
    /// CLI turns it ON unless `--no-shield`).
    pub shield: ScannerShield,
    /// Phase 7: sharded token-bucket rate limiter (None = unlimited).
    pub rate_limit: Option<Arc<RateLimiter>>,
    /// Phase 7: native TLS termination (None = plain HTTP listener).
    pub tls: Option<Arc<TlsState>>,
}

impl Default for IngressConfig {
    fn default() -> Self {
        IngressConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: std::path::PathBuf::from("./data"),
            upstream: "127.0.0.1:9000".into(),
            channel_cap: crate::writer::DEFAULT_CHANNEL_CAP,
            sync_interval: crate::writer::DEFAULT_SYNC_INTERVAL,
            health: None,
            failure_threshold: 3,
            probe_interval: Duration::from_millis(50),
            hold_window: Duration::from_millis(3_000),
            durable_prefixes: vec!["/webhooks/".into(), "/jobs/".into()],
            max_webhook_body: 1024 * 1024,
            idem_headers: crate::durable::DEFAULT_IDEM_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_attempts: 10,
            queue: None,
            replay_trace: None,
            max_segment_bytes: blackbox_core::segment::DEFAULT_MAX_SEGMENT_BYTES,
            ram_budget_bytes: 48 * 1024 * 1024,
            cold: None,
            shield: ScannerShield::disabled(),
            rate_limit: None,
            tls: None,
        }
    }
}

/// Unified response body: teed upstream stream or a synthetic full body.
pub enum ProxyBody {
    Tee(TeeBody<Incoming>),
    Full(Full<Bytes>),
}

impl hyper::body::Body for ProxyBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ProxyBody::Tee(t) => match std::pin::Pin::new(t).poll_frame(cx) {
                std::task::Poll::Ready(Some(Err(e))) => {
                    std::task::Poll::Ready(Some(Err(e.into())))
                }
                std::task::Poll::Ready(Some(Ok(f))) => std::task::Poll::Ready(Some(Ok(f))),
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
            ProxyBody::Full(f) => match std::pin::Pin::new(f).poll_frame(cx) {
                std::task::Poll::Ready(Some(Err(e))) => match e {},
                std::task::Poll::Ready(Some(Ok(f))) => std::task::Poll::Ready(Some(Ok(f))),
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ProxyBody::Tee(t) => t.size_hint(),
            ProxyBody::Full(f) => f.size_hint(),
        }
    }
}

/// Shared per-proxy state handed to every connection task.
pub(crate) struct ProxyCtx {
    pub(crate) sink: RecordSink,
    pub(crate) scrubber: Arc<Scrubber>,
    upstream_authority: Arc<str>,
    client: Client<HttpConnector, ProxyBody>,
    pub(crate) health: Arc<UpstreamHealth>,
    hold_window: Duration,
    durable: Option<Arc<DurableCtx>>,
    replay_trace: Option<TraceId>,
    /// Phase 7: request guard (scanner shield + optional rate limiter).
    pub(crate) shield: ScannerShield,
    pub(crate) rate_limiter: Option<Arc<RateLimiter>>,
}

/// Handle for tests / the CLI: query the live index and writer state.
#[derive(Clone)]
pub struct ProxyHandle {
    pub local_addr: SocketAddr,
    pub sink: RecordSink,
    pub index: Arc<RwLock<TraceIndex>>,
    /// Active-segment watch (Phase 5 compactor/janitor subscription).
    pub active_segments: tokio::sync::watch::Receiver<u32>,
    /// v1.1.2 graceful stop: flipped to `true` to stop accepting and to make
    /// every connection finish its in-flight request before closing.
    shutdown: tokio::sync::watch::Sender<bool>,
    /// v1.1.2: accepted-but-not-yet-finished connections (bounded wait).
    connections: Arc<std::sync::atomic::AtomicUsize>,
}

impl ProxyHandle {
    pub fn get_trace(&self, trace_id: &TraceId) -> Option<Vec<TraceRecord>> {
        self.index.read().unwrap().get_trace(trace_id)
    }

    pub fn stats(&self) -> IndexStats {
        self.index.read().unwrap().stats()
    }

    /// Cumulative handled-request count since process start.
    pub fn total_requests(&self) -> u64 {
        PROXY_REQUESTS.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records dropped by Shed85 head-based sampling.
    pub fn sampled_out(&self) -> u64 {
        SAMPLED_OUT.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records dropped by the disk Emergency95 survival policy.
    pub fn disk_shed_out(&self) -> u64 {
        DISK_SHED_OUT.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Currently active segment id (watch value).
    pub fn active_segment_id(&self) -> u32 {
        *self.active_segments.borrow()
    }

    /// Poll until the trace has at least `expect` records (or timeout).
    pub async fn wait_trace(
        &self,
        trace_id: &TraceId,
        expect: usize,
        timeout: Duration,
    ) -> Vec<TraceRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(recs) = self.get_trace(trace_id) {
                if recs.len() >= expect {
                    return recs;
                }
            }
            if Instant::now() >= deadline {
                return self.get_trace(trace_id).unwrap_or_default();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub async fn flush(&self) -> u64 {
        self.sink.flush().await
    }

    /// v1.1.2 graceful stop: stop accepting new connections, wait (bounded)
    /// for in-flight connections to finish — their response finalizers push
    /// the LAST telemetry record, so returning a 200 without this wait could
    /// lose an ACKNOWLEDGED record on shutdown — then drain + fsync the
    /// writer. Returns the flushed record count.
    pub async fn shutdown(&self) -> u64 {
        let _ = self.shutdown.send(true);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.connections.load(std::sync::atomic::Ordering::Acquire) > 0
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.flush().await
    }

    pub fn dropped(&self) -> u64 {
        self.sink.dropped()
    }
}

/// Bind, recover, rebuild the index and start serving. Returns immediately.
pub async fn spawn_proxy(cfg: IngressConfig) -> Result<ProxyHandle, StorageError> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| StorageError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
    let local_addr = listener.local_addr()?;

    let (sink, index, active_segments, _writer) = spawn_writer_task(&cfg);
    // Phase 6: hand the cold tier to the index (evicted-segment restore +
    // bit-rot self-heal in get_trace).
    if let Some(cold) = &cfg.cold {
        index.write().expect("index lock").set_cold(Arc::clone(cold));
    }

    // Circuit breaker: shared or fresh, plus its 50 ms probe task.
    let health = match cfg.health.clone() {
        Some(h) => h,
        None => UpstreamHealth::new(cfg.failure_threshold),
    };
    health.spawn_prober(&cfg.upstream, cfg.probe_interval);

    // Durable routes + queue-event → telemetry conversion.
    let durable: Option<Arc<DurableCtx>> = cfg.queue.map(|att| {
        let d = Arc::new(DurableCtx {
            prefixes: cfg.durable_prefixes.clone(),
            store: att.runtime.store.clone(),
            max_body: cfg.max_webhook_body,
            idem_headers: cfg.idem_headers.clone(),
            max_attempts: cfg.max_attempts,
        });
        // Convert dispatcher events into TelemetryLog records on the
        // recorded trace (scrub-free: events carry metadata only).
        let sink = sink.clone();
        let mut events = att.events;
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                let (level, msg, attrs) = match ev.kind {
                    blackbox_queue::QueueEventKind::Delivered { attempt, status } => (
                        3u8,
                        "queue job delivered".to_string(),
                        vec![
                            ("blackbox.component".into(), "queue".into()),
                            ("job_id".into(), ev.job_id.to_string()),
                            ("queue".into(), ev.queue.clone()),
                            ("attempt".into(), attempt.to_string()),
                            ("status".into(), status.to_string()),
                        ],
                    ),
                    blackbox_queue::QueueEventKind::Rescheduled { attempt, status, delay_ms, error } => (
                        4u8,
                        "queue job failed; retry scheduled".to_string(),
                        vec![
                            ("blackbox.component".into(), "queue".into()),
                            ("job_id".into(), ev.job_id.to_string()),
                            ("queue".into(), ev.queue.clone()),
                            ("attempt".into(), attempt.to_string()),
                            ("status".into(), status.to_string()),
                            ("delay_ms".into(), delay_ms.to_string()),
                            ("error".into(), error),
                        ],
                    ),
                    blackbox_queue::QueueEventKind::DeadLettered { attempt, status, error } => (
                        5u8,
                        "queue job dead-lettered".to_string(),
                        vec![
                            ("blackbox.component".into(), "queue".into()),
                            ("job_id".into(), ev.job_id.to_string()),
                            ("queue".into(), ev.queue.clone()),
                            ("attempt".into(), attempt.to_string()),
                            ("status".into(), status.to_string()),
                            ("error".into(), error),
                        ],
                    ),
                };
                let rec = TraceRecord::new(
                    ev.trace_id,
                    sink.next_seq(),
                    RecordPayload::TelemetryLog(TelemetryLog {
                        level,
                        service: "blackbox-queue".into(),
                        message: msg,
                        attributes: attrs,
                    }),
                );
                sink.try_send(rec);
            }
        });
        d
    });

    let upstream: Arc<str> = cfg.upstream.as_str().into();

    // Upstream client: pooled keep-alive connections, TCP_NODELAY on every
    // socket (both directions — the listener side sets it per-accept).
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(60)));
    connector.set_connect_timeout(Some(Duration::from_secs(3)));
    let client: Client<HttpConnector, ProxyBody> = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(256)
        .build(connector);

    let ctx = Arc::new(ProxyCtx {
        sink: sink.clone(),
        scrubber: Arc::new(Scrubber::new()),
        upstream_authority: upstream,
        client,
        hold_window: cfg.hold_window,
        durable,
        replay_trace: cfg.replay_trace,
        health,
        shield: cfg.shield,
        rate_limiter: cfg.rate_limit.clone(),
    });

    let ctx_for_loop = ctx.clone();
    let tls_for_loop = cfg.tls.clone();
    // v1.1.2 graceful stop plumbing: the accept loop stops accepting when
    // `shutdown` flips, each connection task runs under hyper's
    // `with_graceful_shutdown` (finishes its in-flight request, then closes
    // instead of waiting for the client to drop a keep-alive), and the
    // `connections` counter lets `ProxyHandle::shutdown` bound its wait.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tokio::spawn({
        let connections = Arc::clone(&connections);
        async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            let (tcp, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                },
                // Shutdown requested: stop accepting NEW connections.
                _ = shutdown_rx.changed() => break,
            };
            // Zero-blocking hot path: TCP_NODELAY on the accepted socket.
            let _ = tcp.set_nodelay(true);
            let ctx = ctx_for_loop.clone();
            let tls = tls_for_loop.clone();
            let conn_shutdown = shutdown_rx.clone();
            connections.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let connections = Arc::clone(&connections);
            tokio::spawn(async move {
                // Phase 7: native TLS termination when configured — the
                // handshake runs on this task, the hot path stays identical
                // below it (plain vs TLS is just which IO feeds hyper).
                let io: ProxyIo = match &tls {
                    Some(t) => {
                        let acceptor = t.acceptor();
                        match acceptor.accept(tcp).await {
                            Ok(s) => ProxyIo::Tls(s),
                            Err(e) => {
                                tracing::debug!(error = %e, "tls handshake failed");
                                connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                                return;
                            }
                        }
                    }
                    None => ProxyIo::Plain(tcp),
                };
                // tower service bridged into hyper's Service trait. The
                // peer address rides in the request extensions for the
                // Phase 7 guard (rate-limit key when no forwarded header).
                let tower_svc = tower::service_fn(move |mut req: hyper::Request<Incoming>| {
                    req.extensions_mut().insert(peer);
                    let ctx = ctx.clone();
                    async move { Ok::<_, std::convert::Infallible>(route(req, ctx).await) }
                });
                let svc = hyper_util::service::TowerToHyperService::new(tower_svc);
                // v1.1.2 graceful stop (hyper 1.x pattern): poll the
                // connection until either it finishes or the shutdown signal
                // flips; on shutdown, stop reading NEW requests on this
                // keep-alive connection but keep polling so the in-flight
                // request completes — its response Finalizer must still push
                // the acknowledged record before the writer drains.
                let mut conn_shutdown = conn_shutdown;
                let mut conn = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(io), svc)
                    .with_upgrades();
                let result = tokio::select! {
                    res = &mut conn => res,
                    _ = conn_shutdown.changed() => {
                        // `UpgradeableConnection: Unpin`, so Pin::new is sound.
                        std::pin::Pin::new(&mut conn).graceful_shutdown();
                        (&mut conn).await
                    }
                };
                if let Err(e) = result {
                    tracing::debug!(error = %e, "connection ended");
                }
                connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            });
        }
        }
    });

    Ok(ProxyHandle {
        local_addr,
        sink,
        index,
        active_segments,
        shutdown: shutdown_tx,
        connections,
    })
}

/// Listener IO after optional TLS termination (both legs are Unpin, the
/// impls are pure delegation).
enum ProxyIo {
    Plain(tokio::net::TcpStream),
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl tokio::io::AsyncRead for ProxyIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyIo::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ProxyIo::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ProxyIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ProxyIo::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ProxyIo::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyIo::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ProxyIo::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ProxyIo::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ProxyIo::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn spawn_writer_task(cfg: &IngressConfig) -> (RecordSink, Arc<RwLock<TraceIndex>>, tokio::sync::watch::Receiver<u32>, tokio::task::JoinHandle<u64>) {
    let wcfg = WriterConfig {
        data_dir: cfg.data_dir.clone(),
        channel_cap: cfg.channel_cap,
        sync_interval: cfg.sync_interval,
        max_segment_bytes: cfg.max_segment_bytes,
        ram_budget_bytes: cfg.ram_budget_bytes,
    };
    let (sink, index, join, active) = crate::writer::spawn_writer_full(wcfg);
    (sink, index, active, join)
}

// ------------------------------------------------------------- routing ----

async fn route(req: hyper::Request<Incoming>, ctx: Arc<ProxyCtx>) -> hyper::Response<ProxyBody> {
    PROXY_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = req.uri().path().to_string();

    // --- Phase 7: scanner/WAF shield — instant drop, zero side effects.
    //     Runs before the rate limiter so probe noise never burns token
    //     budget, and before every route so attack traffic never reaches
    //     the upstream app, the queue actor or the segment store.
    if ctx.shield.check(&path).is_some() {
        return full_response(
            http::StatusCode::from_u16(crate::waf::SHIELD_STATUS)
                .unwrap_or(http::StatusCode::NOT_FOUND),
            vec![],
            Bytes::from_static(crate::waf::SHIELD_BODY.as_bytes()),
        );
    }

    // --- Phase 7: sharded lock-free token bucket. Rejects BEFORE the
    //     upstream or disk sees the request; 429 + Retry-After.
    if let Some(rl) = &ctx.rate_limiter {
        let key = guard_key(&req);
        if let Decision::Limited { retry_after_ms } = rl.check(&key) {
            RATE_LIMITED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return full_response(
                http::StatusCode::TOO_MANY_REQUESTS,
                vec![
                    ("retry-after", retry_after_ms.div_ceil(1000).to_string()),
                    (
                        "x-blackbox-retry-after-ms",
                        retry_after_ms.to_string(),
                    ),
                ],
                Bytes::from_static(b"rate limited by blackbox shield\n"),
            );
        }
    }

    let segments: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    // Sentry wire-compatible: /api/{project_id}/envelope/ (trailing slash optional).
    if segments.len() == 3 && segments[0] == "api" && segments[2] == "envelope" {
        return handle_envelope(req, ctx, segments[1].to_string()).await;
    }
    // OTLP wire-compatible: /v1/traces and /v1/logs.
    if path == "/v1/traces" {
        return handle_otlp(req, ctx, OtlpKind::Traces).await;
    }
    if path == "/v1/logs" {
        return handle_otlp(req, ctx, OtlpKind::Logs).await;
    }
    // Durable webhook routes: raw-byte-preserving 202 ingestion.
    if let Some(durable) = &ctx.durable {
        if matches_durable(&durable.prefixes, &path) {
            return handle_durable(req, &ctx, durable).await;
        }
    }
    handle_proxy(req, ctx).await
}

/// 500 for impossible-to-reach build failures (always a bug, never a client).
fn internal_error() -> hyper::Response<ProxyBody> {
    full_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        vec![],
        Bytes::from_static(b"blackbox internal error\n"),
    )
}

fn full_response(status: StatusCode, headers: Vec<(&str, String)>, body: Bytes) -> hyper::Response<ProxyBody> {
    let mut b = hyper::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(ProxyBody::Full(Full::new(body)))
        .expect("static response builds")
}

// -------------------------------------------------------------- proxy ----

/// Breaker bookkeeping for an upstream HTTP answer: 502/503/504 from the
/// app (or from us) count as failures, everything else as success.
fn note_upstream_status(health: &Arc<UpstreamHealth>, status: StatusCode) {
    if matches!(status, StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT) {
        health.record_failure();
    } else {
        health.record_success();
    }
}

/// Honest 502 after the hold window expired (or a non-retryable failure):
/// emits the record with what the client actually got.
#[allow(clippy::too_many_arguments)]
fn upstream_unavailable(
    ctx: Arc<ProxyCtx>,
    trace_id: TraceId,
    method: String,
    uri: String,
    req_headers: Vec<(String, String)>,
    req_capture: Arc<std::sync::Mutex<CaptureBuf>>,
    req_content_type: Option<String>,
    started: Instant,
) -> hyper::Response<ProxyBody> {
    let fin = Finalizer {
        sink: ctx.sink.clone(),
        scrubber: ctx.scrubber.clone(),
        trace_id,
        method,
        uri,
        req_headers,
        req_capture,
        req_content_type,
        res_status: 502,
        res_headers: vec![],
        started,
    };
    fin.emit(CaptureBuf::new(CAPTURE_MAX_BYTES));
    full_response(
        StatusCode::BAD_GATEWAY,
        vec![(
            TRACE_ID_RESPONSE_HEADER,
            trace_id_to_hex(&trace_id),
        )],
        Bytes::from_static(b"upstream unavailable\n"),
    )
}

async fn handle_proxy(req: hyper::Request<Incoming>, ctx: Arc<ProxyCtx>) -> hyper::Response<ProxyBody> {
    let started = Instant::now();
    let (mut head, body) = req.into_parts();
    let method: String = head.method.to_string();
    let uri_str = head
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // --- 1) W3C traceparent: parse or generate, inject upstream. ---
    // Replay mode forces the replay trace id (deterministic time travel).
    let (tp, injected) = match ctx.replay_trace {
        Some(tid) => (
            Traceparent {
                version: *b"00",
                trace_id: tid,
                parent_span_id: {
                    let mut s = [0u8; 8];
                    fastrand::fill(&mut s);
                    if s == [0u8; 8] {
                        s[0] = 1;
                    }
                    s
                },
                flags: *b"01",
            },
            true,
        ),
        None => match head
            .headers
            .get(TRACEPARENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(Traceparent::parse)
        {
            Some(tp) => (tp, false),
            None => (Traceparent::generate(), true),
        },
    };
    let trace_hex = trace_id_to_hex(&tp.trace_id);
    let trace_id: TraceId = tp.trace_id;

    // --- 2) Upgrade detection (WebSocket etc.). ---
    let is_upgrade = head
        .headers
        .get(http::header::UPGRADE)
        .is_some();
    let server_upgrade = if is_upgrade {
        head.extensions.remove::<hyper::upgrade::OnUpgrade>()
    } else {
        None
    };

    // Request content-type + capture policy; shared capture buffer.
    let req_ct = head
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let req_policy = capture_policy(req_ct.as_deref(), is_upgrade);
    let req_capture = Arc::new(std::sync::Mutex::new(CaptureBuf::new(CAPTURE_MAX_BYTES)));
    let tee_req_body = TeeBody::request(body, req_policy, req_capture.clone());

    // --- 3) Build the upstream request. ---
    let upstream_uri = match build_upstream_uri(&head.uri, &ctx.upstream_authority) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "upstream uri build failed");
            return internal_error();
        }
    };
    let mut upstream_req = match hyper::Request::builder()
        .method(head.method.clone())
        .uri(upstream_uri.clone())
        .body(tee_req_body)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "upstream request build failed");
            return internal_error();
        }
    };

    copy_forward_headers(&mut head.headers, upstream_req.headers_mut(), is_upgrade);
    if injected {
        match HeaderValue::from_str(&tp.to_header_value()) {
            Ok(hv) => {
                upstream_req.headers_mut().insert(TRACEPARENT_HEADER, hv);
            }
            Err(e) => {
                tracing::error!(error = %e, "traceparent value build failed");
                return internal_error();
            }
        }
    }
    // Real-SDK correlation: sentry-sdk continues traces ONLY from the
    // `sentry-trace` header (it ignores W3C traceparent), so also inject
    // the same trace id in Sentry's wire format. Without this a REAL SDK
    // attached to the injected SENTRY_DSN starts a random trace and its
    // crash envelope no longer lands next to the request that caused it.
    // Never overrides a caller-supplied sentry-trace.
    // `sentry_trace_upstream` records what actually rides upstream — ours
    // when injected, the caller's own on passthrough — so the baggage
    // entries below can never contradict it.
    let sentry_trace_upstream: Option<String> =
        match upstream_req.headers().get(SENTRY_TRACE_HEADER) {
            Some(v) => v.to_str().ok().map(String::from),
            None => {
                let st = tp.to_sentry_trace();
                match HeaderValue::from_str(&st) {
                    Ok(hv) => {
                        upstream_req.headers_mut().insert(SENTRY_TRACE_HEADER, hv);
                        Some(st)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "sentry-trace value build failed");
                        return internal_error();
                    }
                }
            }
        };
    // Real-SDK parity (baggage): @sentry/node v8+ joins and propagates
    // traces through the W3C `baggage` header (its dynamic-sampling
    // context), and sentry-sdk (Python) carries the same `sentry-*`
    // entries. Inject ours so the EXACT trace id rides the shared W3C bus
    // too: absent → inject, present without `sentry-trace_id` → append
    // (caller entries survive), key already present → untouched. The id
    // comes from the upstream sentry-trace (32-hex guard skips malformed
    // caller values) so the two headers always agree.
    let baggage_tid = sentry_trace_upstream
        .as_deref()
        .and_then(|st| st.split('-').next())
        .filter(|t| t.len() == 32);
    if let Some(tid_hex) = baggage_tid {
        let action = match upstream_req.headers().get(BAGGAGE_HEADER) {
            None => Some(baggage_entries(tid_hex)),
            Some(v) => v
                .to_str()
                .ok()
                .and_then(|s| merge_baggage(Some(s), tid_hex)),
        };
        if let Some(bv) = action {
            match HeaderValue::from_str(&bv) {
                Ok(hv) => {
                    upstream_req.headers_mut().insert(BAGGAGE_HEADER, hv);
                }
                Err(e) => {
                    tracing::error!(error = %e, "baggage value build failed");
                    return internal_error();
                }
            }
        }
    }
    // Header snapshot for the record (as sent upstream).
    let req_headers_snapshot: Vec<(String, String)> = upstream_req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    // Clones for the connect-failure retry path (see below).
    let retry_method = head.method.clone();
    let retry_uri = upstream_uri.clone();
    let retry_headers = upstream_req.headers().clone();
    let is_idempotent = matches!(head.method, http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE | http::Method::PUT | http::Method::DELETE);
    let expected_body_len = head
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let is_chunked = head
        .headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    // --- 4) Circuit-breaker hold, then send upstream. ---
    //
    // While the breaker is Open (upstream restarting), requests park on the
    // health watch channel for up to `hold_window` and are released the
    // moment the probe confirms recovery — invisible app restarts.
    let hold_deadline = Instant::now() + ctx.hold_window;
    if !ctx.health.wait_available(hold_deadline).await {
        tracing::debug!("hold window expired; upstream still unreachable");
        return upstream_unavailable(
            ctx,
            trace_id,
            method,
            uri_str,
            req_headers_snapshot,
            req_capture,
            req_ct,
            started,
        );
    }

    let upstream_req = upstream_req.map(ProxyBody::Tee);
    let upstream_res = match ctx.client.request(upstream_req).await {
        Ok(res) => {
            note_upstream_status(&ctx.health, res.status());
            res
        }
        Err(e) => {
            // Transport-level failure (refused dial or reset on a pooled
            // connection) — the upstream is unreachable right now. Trip the
            // breaker IMMEDIATELY (blueprint: "connection refused → Open")
            // so the retry below waits for recovery instead of hammering a
            // dead port.
            let connect_phase = e.is_connect();
            ctx.health.record_connect_failure();
            tracing::debug!(error = %e, connect_phase, "upstream request failed");

            // Retry policy: idempotent methods are safe to retry on ANY
            // transport error (reset or refused — the definition of
            // idempotent). Non-idempotent methods retry only on
            // connect-phase errors when the tee captured the COMPLETE body
            // (the app never saw the connection). Otherwise: honest 502.
            let capture_complete = req_policy == CapturePolicy::Capture && {
                let guard = match req_capture.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                !guard.truncated
                    && match expected_body_len {
                        Some(n) => guard.data.len() == n,
                        None => !is_chunked && guard.data.is_empty(),
                    }
            };
            let retryable = is_idempotent || (connect_phase && capture_complete);
            if !retryable || !ctx.health.wait_available(hold_deadline).await {
                return upstream_unavailable(
                    ctx,
                    trace_id,
                    method,
                    uri_str,
                    req_headers_snapshot,
                    req_capture,
                    req_ct,
                    started,
                );
            }

            // Hold released — rebuild and retry ONCE with the exact bytes.
            let body_bytes = match req_capture.lock() {
                Ok(g) => Bytes::from(g.data.clone()),
                Err(p) => Bytes::from(p.into_inner().data.clone()),
            };
            let mut retry_req = match hyper::Request::builder()
                .method(retry_method.clone())
                .uri(retry_uri.clone())
                .body(Full::new(body_bytes))
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "retry request build failed");
                    return upstream_unavailable(
                        ctx,
                        trace_id,
                        method,
                        uri_str,
                        req_headers_snapshot,
                        req_capture,
                        req_ct,
                        started,
                    );
                }
            };
            *retry_req.headers_mut() = retry_headers.clone();
            match ctx.client.request(retry_req.map(ProxyBody::Full)).await {
                Ok(res) => {
                    note_upstream_status(&ctx.health, res.status());
                    res
                }
                Err(_) => {
                    return upstream_unavailable(
                        ctx,
                        trace_id,
                        method,
                        uri_str,
                        req_headers_snapshot,
                        req_capture,
                        req_ct,
                        started,
                    );
                }
            }
        }
    };

    // --- 5) 101 Switching Protocols: bidirectional tunnel passthrough. ---
    if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        return upgrade_passthrough(
            ctx,
            upstream_res,
            trace_id,
            method,
            uri_str,
            req_headers_snapshot,
            req_capture,
            server_upgrade,
            started,
        );
    }

    let (res_head, res_body) = upstream_res.into_parts();
    let res_ct = res_head
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let res_policy = capture_policy(res_ct.as_deref(), false);

    // --- 6) Response back with tee capture + finalizer. ---
    let fin = Finalizer {
        sink: ctx.sink.clone(),
        scrubber: ctx.scrubber.clone(),
        trace_id,
        method,
        uri: uri_str,
        req_headers: req_headers_snapshot,
        req_capture,
        req_content_type: req_ct,
        res_status: res_head.status.as_u16(),
        res_headers: res_head
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
            .collect(),
        started,
    };

    let mut out = hyper::Response::builder().status(res_head.status);
    for (k, v) in res_head.headers.iter() {
        if is_hop_by_hop(k) {
            continue;
        }
        out = out.header(k, v);
    }
    out = out.header(TRACE_ID_RESPONSE_HEADER, trace_hex);
    let body = ProxyBody::Tee(TeeBody::response(res_body, res_policy, fin));
    match out.body(body) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "response build failed");
            internal_error()
        }
    }
}

/// 101 passthrough: splice the client and upstream upgraded streams with
/// `copy_bidirectional`; emit a metadata-only record immediately (bodies of
/// a tunnel are never captured).
#[allow(clippy::too_many_arguments)]
fn upgrade_passthrough(
    ctx: Arc<ProxyCtx>,
    mut upstream_res: hyper::Response<Incoming>,
    trace_id: TraceId,
    method: String,
    uri: String,
    req_headers: Vec<(String, String)>,
    req_capture: Arc<std::sync::Mutex<CaptureBuf>>,
    server_upgrade: Option<hyper::upgrade::OnUpgrade>,
    started: Instant,
) -> hyper::Response<ProxyBody> {
    // Metadata-only record (blueprint: WebSocket upgrades bypass capture).
    let mut rec_headers = req_headers;
    ctx.scrubber.scrub_headers(&mut rec_headers);
    let payload = blackbox_core::schema::IngressHttp {
        method,
        uri,
        status: 101,
        req_headers: rec_headers,
        req_body: Vec::new(),
        res_body: Vec::new(),
        duration_ms: started.elapsed().as_millis() as u64,
    };
    let _ = req_capture; // shared buffer stays empty for tunnels
    let rec = TraceRecord::new(trace_id, ctx.sink.next_seq(), RecordPayload::IngressHttp(payload));
    ctx.sink.try_send(rec);

    // Build the 101 response for the downstream client, re-arming the
    // server-side upgrade with a CLONE of the OnUpgrade (the clone shares
    // the upgrade channel; the original is awaited by the tunnel task).
    let mut out = hyper::Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in upstream_res.headers().iter() {
        if matches!(k.as_str(), "content-length" | "transfer-encoding") {
            continue;
        }
        out = out.header(k, v);
    }
    out = out.header(TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(&trace_id));
    let mut resp = out
        .body(ProxyBody::Full(Full::new(Bytes::new())))
        .expect("101 response builds");
    if let Some(up) = &server_upgrade {
        resp.extensions_mut().insert(up.clone());
    }

    // Tunnel: client stream ↔ upstream stream, bidirectional copy.
    tokio::spawn(async move {
        let res = async {
            let client_up = hyper::upgrade::on(&mut upstream_res).await?;
            let server_up = server_upgrade
                .ok_or_else(|| BoxError::from("no server upgrade available"))?
                .await?;
            Ok::<(hyper::upgrade::Upgraded, hyper::upgrade::Upgraded), BoxError>(
                (client_up, server_up),
            )
        }
        .await;
        match res {
            Ok((mut cu, mut su)) => {
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(&mut cu),
                    &mut TokioIo::new(&mut su),
                )
                .await;
            }
            Err(e) => tracing::debug!(error = %e, "upgrade tunnel failed"),
        }
    });

    resp
}

/// Origin-form URI → upstream absolute URI.
fn build_upstream_uri(orig: &Uri, upstream: &str) -> Result<Uri, BoxError> {
    // Accept BOTH bare `host:port` and full URLs (`http://host:port/base`,
    // the form `blackbox replay`'s own help + admin replay_command print).
    // A URL is split into authority + optional base path; the base path is
    // prepended to every forwarded request.
    let (authority, base_path) = match upstream.split_once("://") {
        Some((_scheme, rest)) => match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].trim_end_matches('/').to_string()),
            None => (rest.to_string(), String::new()),
        },
        None => (upstream.to_string(), String::new()),
    };
    if authority.is_empty() || authority.contains('/') {
        return Err(BoxError::from(format!(
            "upstream uri: invalid upstream `{upstream}` (need host:port or a URL)"
        )));
    }
    let pq = orig
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Uri::builder()
        .scheme("http")
        .authority(authority.as_str())
        .path_and_query(if base_path.is_empty() {
            pq
        } else {
            format!("{base_path}{pq}")
        })
        .build()
        .map_err(|e| BoxError::from(format!("upstream uri: {e}")))
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// Phase 7: client identity for the rate limiter. API key first (fair
/// multi-tenant limits behind shared NAT), then the leftmost
/// `X-Forwarded-For` hop (the original client as seen by the edge), then
/// the socket peer address.
fn guard_key(req: &hyper::Request<Incoming>) -> Vec<u8> {
    if let Some(k) = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
    {
        let mut out = Vec::with_capacity(k.len() + 4);
        out.extend_from_slice(b"key:");
        out.extend_from_slice(k.as_bytes());
        return out;
    }
    if let Some(fwd) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(hop) = fwd.split(',').next() {
            let hop = hop.trim();
            if !hop.is_empty() {
                let mut out = Vec::with_capacity(hop.len() + 3);
                out.extend_from_slice(b"ip:");
                out.extend_from_slice(hop.as_bytes());
                return out;
            }
        }
    }
    if let Some(peer) = req.extensions().get::<SocketAddr>() {
        return format!("ip:{}", peer.ip()).into_bytes();
    }
    b"ip:unknown".to_vec()
}

/// Forward request headers, dropping hop-by-hop + framing headers hyper
/// re-derives (host, content-length). Upgrade requests keep their
/// `connection`/`upgrade` headers so the upstream sees the upgrade.
fn copy_forward_headers(src: &mut HeaderMap, dst: &mut HeaderMap, is_upgrade: bool) {
    for (name, value) in src.drain() {
        let Some(name) = name else { continue };
        let lname = name.as_str();
        if lname == "content-length" || lname == "host" {
            continue; // hyper recomputes both
        }
        if is_hop_by_hop(&name) && !(is_upgrade && (lname == "connection" || lname == "upgrade")) {
            continue;
        }
        dst.insert(name, value);
    }
}

// ---------------------------------------------------------- telemetry ----

/// Read an `Incoming` body into a [`Capped`] buffer (streaming, early-abort
/// past the compressed ceiling).
async fn read_capped(body: Incoming) -> Result<Capped, BodyError> {
    let mut capped = Capped::default();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| BodyError::Malformed(format!("body read: {e}")))?;
        if let Some(data) = frame.data_ref() {
            capped.push(data)?;
        }
    }
    Ok(capped)
}

fn body_error_response(e: &BodyError, trace_id: &TraceId) -> hyper::Response<ProxyBody> {
    let status = match e {
        BodyError::TooLarge | BodyError::TooLargeRaw => StatusCode::PAYLOAD_TOO_LARGE,
        BodyError::UnsupportedEncoding(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        BodyError::Malformed(_) => StatusCode::BAD_REQUEST,
    };
    full_response(
        status,
        vec![(TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(trace_id))],
        Bytes::from(format!("{e}\n")),
    )
}

/// Sentry wire-compatible ingestion: `POST /api/{project_id}/envelope/`.
///
/// - `Content-Encoding: gzip|zstd` decoded under the 2 MiB decompression
///   ceiling (413 past it — the anti-zip-bomb guard).
/// - The envelope is stored verbatim as a `SentryCrash` record linked to
///   the trace id from the envelope header, the event payload, the request
///   `traceparent`, or a freshly generated id (in that priority order).
async fn handle_envelope(
    req: hyper::Request<Incoming>,
    ctx: Arc<ProxyCtx>,
    project_id: String,
) -> hyper::Response<ProxyBody> {
    // Optional request-level trace id (fallback if the envelope has none).
    let req_trace = req
        .headers()
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(Traceparent::parse)
        .map(|tp| tp.trace_id);

    let encoding = req
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // 1) Read (capped) → 2) decode (capped) → 3) parse.
    let decoded = match read_capped(req.into_body()).await {
        Ok(c) if c.is_empty() => {
            let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
            return body_error_response(&BodyError::Malformed("empty envelope".into()), &tid);
        }
        Ok(c) => match decode_body(&encoding, &c.buf) {
            Ok(d) => d,
            Err(e) => {
                let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
                return body_error_response(&e, &tid);
            }
        },
        Err(e) => {
            let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
            return body_error_response(&e, &tid);
        }
    };

    let parsed = match envelope::parse(&decoded) {
        Ok(p) => p,
        Err(e) => {
            let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
            return full_response(
                StatusCode::BAD_REQUEST,
                vec![(TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(&tid))],
                Bytes::from(format!("invalid envelope: {e}\n")),
            );
        }
    };

    let trace_id = parsed
        .trace_id
        .or(req_trace)
        .unwrap_or_else(|| Traceparent::generate().trace_id);

    // Store verbatim, linked to the trace.
    let record = TraceRecord::new(
        trace_id,
        ctx.sink.next_seq(),
        RecordPayload::SentryCrash(SentryCrash {
            project_id,
            event_id: parsed.event_id.clone(),
            envelope: decoded,
        }),
    );
    ctx.sink.try_send(record);

    // Sentry-compatible ack.
    full_response(
        StatusCode::OK,
        vec![
            ("content-type", "application/json".into()),
            (TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(&trace_id)),
        ],
        Bytes::from(format!("{{\"id\":\"{}\"}}", parsed.event_id)),
    )
}

/// OTLP wire-compatible ingestion: `POST /v1/traces` + `POST /v1/logs`.
/// Each span/log record becomes a `TelemetryLog` record linked by trace_id.
async fn handle_otlp(
    req: hyper::Request<Incoming>,
    ctx: Arc<ProxyCtx>,
    kind: OtlpKind,
) -> hyper::Response<ProxyBody> {
    let req_trace = req
        .headers()
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(Traceparent::parse)
        .map(|tp| tp.trace_id);
    let encoding = req
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let decoded = match read_capped(req.into_body()).await {
        Ok(c) => match decode_body(&encoding, &c.buf) {
            Ok(d) => d,
            Err(e) => {
                let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
                return body_error_response(&e, &tid);
            }
        },
        Err(e) => {
            let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
            return body_error_response(&e, &tid);
        }
    };

    let records = match otlp::decode(kind, &content_type, &decoded) {
        Ok(r) => r,
        Err(e) => {
            let tid = req_trace.unwrap_or_else(|| Traceparent::generate().trace_id);
            return full_response(
                StatusCode::BAD_REQUEST,
                vec![(TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(&tid))],
                Bytes::from(format!("invalid OTLP payload: {e}\n")),
            );
        }
    };

    let mut primary: Option<TraceId> = None;
    for r in records {
        let trace_id = r.trace_id.or(req_trace).unwrap_or_else(|| Traceparent::generate().trace_id);
        primary.get_or_insert(trace_id);
        let record = TraceRecord::new(
            trace_id,
            ctx.sink.next_seq(),
            RecordPayload::TelemetryLog(TelemetryLog {
                level: r.level,
                service: r.service,
                message: r.message,
                attributes: r.attributes,
            }),
        );
        ctx.sink.try_send(record);
    }

    let echo = primary.unwrap_or_else(|| Traceparent::generate().trace_id);
    full_response(
        StatusCode::OK,
        vec![
            ("content-type", "application/json".into()),
            (TRACE_ID_RESPONSE_HEADER, trace_id_to_hex(&echo)),
        ],
        Bytes::from_static(b"{\"partialSuccess\":{}}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &'static str) -> Uri {
        Uri::from_static(s)
    }

    /// Regression (real-sdk matrix): `blackbox replay --target <URL>` —
    /// the URL form its own help text and the admin `replay_command` print —
    /// must not produce `http://http://…` ("invalid uri character").
    #[test]
    fn upstream_uri_accepts_bare_and_url_forms() {
        // Bare host:port (classic form).
        assert_eq!(
            build_upstream_uri(&uri("/llm?x=1"), "127.0.0.1:3000").unwrap().to_string(),
            "http://127.0.0.1:3000/llm?x=1"
        );
        // Full URL, no path (the replay CLI's documented form).
        assert_eq!(
            build_upstream_uri(&uri("/llm"), "http://127.0.0.1:18081").unwrap().to_string(),
            "http://127.0.0.1:18081/llm"
        );
        // Full URL with a base path — every request is prefixed.
        assert_eq!(
            build_upstream_uri(&uri("/llm?a=1"), "http://127.0.0.1:80/api").unwrap().to_string(),
            "http://127.0.0.1:80/api/llm?a=1"
        );
        assert_eq!(
            build_upstream_uri(&uri("/"), "https://app.internal/svc/").unwrap().to_string(),
            "http://app.internal/svc/"
        );
        // Garbage must fail cleanly, not build a nonsense URI.
        assert!(build_upstream_uri(&uri("/x"), "http://").is_err());
    }
}
