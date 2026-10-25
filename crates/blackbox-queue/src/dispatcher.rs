//! Webhook dispatcher — lease-claiming delivery loop with adaptive
//! backpressure and circuit-breaker integration.
//!
//! ```text
//!  every tick:
//!    if breaker Open ────────────► skip (dispatch paused, jobs wait on disk)
//!    due = store.due_jobs(now, free_permits)
//!    for job in due:               claim(job, lease_until)     (atomic, redb)
//!      └─ delivery task: POST {upstream}{url_path}
//!           raw headers + RAW body (HMAC-safe, never scrubbed)
//!           2xx ────────► store.succeed(id)        → row deleted
//!           429/5xx/conn ► store.fail(id, attempt+1, now+jitter(base·2^n, max))
//!                          breaker.record_failure()
//!           other 4xx ──► store.fail(id, dead=true) → DeadLetter (payload kept)
//!  reaper task: store.reap_expired(now) on a timer + once at startup
//!               (InFlight jobs from a kill -9 crash recover to Pending)
//! ```
//!
//! Delivery events are published on an `mpsc::Sender<QueueEvent>` so the
//! assembly layer (which owns the PII scrubber and the SegmentStore sink)
//! can convert them into telemetry records without creating a dependency
//! cycle between blackbox-queue and blackbox-ingress.

use crate::model::{BackoffConfig, DeliveryVerdict, DurableJob, JobId};
use blackbox_core::breaker::{state_name, UpstreamHealth};
use blackbox_core::schema::{now_ms, trace_id_to_hex, TraceId};
use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use http_body_util::Full;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

/// Hop-by-hop + framing headers never re-sent at delivery time (hyper
/// re-derives host/content-length; connection framing belongs to the hop).
const STRIP_ON_DELIVERY: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Delivery state machine tuning.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Upstream app authority (`host:port`) deliveries are sent to.
    pub upstream: String,
    /// Max concurrent in-flight deliveries.
    pub concurrency: usize,
    /// Poll cadence for due jobs.
    pub tick: Duration,
    /// Dispatch lease window (reaper recovers past it on crash).
    pub lease_duration: Duration,
    /// Delivery HTTP timeout.
    pub delivery_timeout: Duration,
    pub backoff: BackoffConfig,
    /// Dead-letter after this many failed attempts (jobs may override).
    pub default_max_attempts: u32,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        DispatcherConfig {
            upstream: "127.0.0.1:9000".into(),
            concurrency: 64,
            tick: Duration::from_millis(25),
            lease_duration: Duration::from_secs(30),
            delivery_timeout: Duration::from_secs(10),
            backoff: BackoffConfig::default(),
            default_max_attempts: 10,
        }
    }
}

/// Delivery lifecycle event (consumed by the assembly for telemetry).
#[derive(Debug, Clone)]
pub struct QueueEvent {
    pub job_id: JobId,
    pub trace_id: TraceId,
    pub queue: String,
    pub kind: QueueEventKind,
}

#[derive(Debug, Clone)]
pub enum QueueEventKind {
    Delivered { attempt: u32, status: u16 },
    Rescheduled { attempt: u32, status: u16, delay_ms: u64, error: String },
    DeadLettered { attempt: u32, status: u16, error: String },
}

/// Runtime handle for the queue engine.
pub struct QueueRuntime {
    pub store: crate::store::JobStoreHandle,
    pub cfg: DispatcherConfig,
}

/// Spawn the dispatcher + reaper. `events` receives delivery transitions
/// (may be dropped by the caller to skip telemetry).
pub async fn spawn_queue_runtime(
    db_path: &std::path::Path,
    store_cfg: crate::store::JobStoreConfig,
    cfg: DispatcherConfig,
    health: Arc<UpstreamHealth>,
    events: Option<mpsc::Sender<QueueEvent>>,
) -> Result<QueueRuntime, blackbox_core::StorageError> {
        let (store, _stats, _join) = crate::store::spawn_job_store(db_path, store_cfg).await?;

        // Startup reaper pass: InFlight jobs from a kill -9 crash go back to
        // Pending BEFORE the first dispatch tick.
        let reaped = store.reap_expired(now_ms()).await.unwrap_or(0);
        if reaped > 0 {
            tracing::info!("queue startup: recovered {reaped} InFlight job(s) to Pending");
        }

        // Delivery client: pooled keep-alive connections, NODELAY.
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_keepalive(Some(Duration::from_secs(60)));
        connector.set_connect_timeout(Some(Duration::from_secs(3)));
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new())
                .pool_idle_timeout(Duration::from_secs(60))
                .pool_max_idle_per_host(128)
                .build(connector);

        let permits = Arc::new(Semaphore::new(cfg.concurrency));
        let store_for_loop = store.clone();
        let health_for_loop = Arc::clone(&health);
        let cfg_for_loop = cfg.clone();

        tokio::spawn(async move {
            dispatch_loop(
                store_for_loop,
                health_for_loop,
                client,
                permits,
                cfg_for_loop,
                events,
            )
            .await;
        });

        tokio::spawn(reaper_loop(store.clone(), Duration::from_secs(2)));

    Ok(QueueRuntime { store, cfg })
}

async fn reaper_loop(store: crate::store::JobStoreHandle, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await; // immediate first tick — skip (startup pass already ran)
    loop {
        tick.tick().await;
        match store.reap_expired(now_ms()).await {
            Ok(0) => {}
            Ok(n) => tracing::info!("lease reaper: recovered {n} expired InFlight job(s)"),
            Err(e) => tracing::error!(error = %e, "lease reaper failed"),
        }
    }
}

async fn dispatch_loop(
    store: crate::store::JobStoreHandle,
    health: Arc<UpstreamHealth>,
    client: Client<HttpConnector, Full<Bytes>>,
    permits: Arc<Semaphore>,
    cfg: DispatcherConfig,
    events: Option<mpsc::Sender<QueueEvent>>,
) {
    loop {
        // Circuit breaker pause: while Open, NOTHING is dispatched — jobs
        // accumulate durably in redb until the probe confirms recovery.
        if health.state() == blackbox_core::breaker::STATE_OPEN {
            tokio::time::sleep(cfg.tick).await;
            continue;
        }

        // Atomically claim a whole wave of due jobs (one write op), sized
        // to the free delivery permits.
        let free = permits.available_permits().max(1);
        let lease_until = now_ms() + cfg.lease_duration.as_millis() as u64;
        let wave = match store.claim_batch(free, lease_until).await {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "claim_batch failed");
                tokio::time::sleep(cfg.tick).await;
                continue;
            }
        };
        if wave.is_empty() {
            tokio::time::sleep(cfg.tick).await;
            continue;
        }

        for job in wave {
            // Wait for a permit (bounded concurrency; don't stampede upstream).
            let Ok(permit) = permits.clone().acquire_owned().await else { return };
            let store = store.clone();
            let health = Arc::clone(&health);
            let client = client.clone();
            let cfg = cfg.clone();
            let events = events.clone();
            tokio::spawn(async move {
                let _permit = permit;
                deliver_job(store, health, client, cfg, events, job).await;
            });
        }
    }
}

async fn deliver_job(
    store: crate::store::JobStoreHandle,
    health: Arc<UpstreamHealth>,
    client: Client<HttpConnector, Full<Bytes>>,
    cfg: DispatcherConfig,
    events: Option<mpsc::Sender<QueueEvent>>,
    job: DurableJob,
) {
    // The job arrives atomically claimed (Pending -> InFlight under lease)
    // by the dispatcher's claim_batch wave.
    let started = Instant::now();
    let (status, error) = send_delivery(&client, &cfg, &job).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let verdict = match status {
        Some(s) => DeliveryVerdict::from_status(s),
        None => DeliveryVerdict::Retryable, // connect/timeout/error
    };

    match verdict {
        DeliveryVerdict::Success => {
            let s = status.unwrap_or(200);
            health.record_success();
            let _ = store.succeed(job.job_id).await;
            tracing::debug!(job = job.job_id, status = s, "delivered in {elapsed_ms}ms");
            blackbox_core::audit::record(
                "queue",
                "deliver",
                &blackbox_core::schema::trace_id_to_hex(&job.trace_id),
                &format!("queue={} status={} attempt={}", job.queue, s, job.attempt + 1),
            );
            emit_event(events, &job, QueueEventKind::Delivered { attempt: job.attempt + 1, status: s }).await;
        }
        DeliveryVerdict::Retryable => {
            if status.is_none() {
                health.record_connect_failure(); // refused/reset/timeout
            } else {
                health.record_failure(); // 429/5xx HTTP answer
            }
            let attempt = job.attempt + 1;
            let dead = attempt >= job.max_attempts;
            let delay_ms = if dead { 0 } else { cfg.backoff.delay_ms(attempt - 1) };
            let available = now_ms() + delay_ms;
            let err = error.unwrap_or_else(|| {
                format!("upstream status {}", status.unwrap_or(0))
            });
            let _ = store
                .fail(job.job_id, attempt, available, dead, status.unwrap_or(0), err.clone())
                .await;
            if dead {
                tracing::warn!(job = job.job_id, attempts = attempt, "dead-lettered: {err}");
                blackbox_core::audit::record(
                    "queue",
                    "dead_letter",
                    &blackbox_core::schema::trace_id_to_hex(&job.trace_id),
                    &format!("queue={} status={} error={err}", job.queue, status.unwrap_or(0)),
                );
                emit_event(events, &job, QueueEventKind::DeadLettered { attempt, status: status.unwrap_or(0), error: err }).await;
            } else {
                tracing::debug!(job = job.job_id, attempt, delay_ms, "retry scheduled: {err}");
                emit_event(events, &job, QueueEventKind::Rescheduled { attempt, status: status.unwrap_or(0), delay_ms, error: err }).await;
            }
        }
        DeliveryVerdict::Permanent => {
            let s = status.unwrap_or(0);
            // A 4xx answer means the app IS alive (it responded) — not a
            // breaker failure.
            health.record_success();
            let err = error.unwrap_or_else(|| format!("upstream status {s}"));
            let attempt = job.attempt + 1;
            let _ = store
                .fail(job.job_id, attempt, now_ms(), true, s, err.clone())
                .await;
            tracing::warn!(job = job.job_id, status = s, "permanent rejection, dead-lettered");
            emit_event(events, &job, QueueEventKind::DeadLettered { attempt, status: s, error: err }).await;
        }
    }
}

/// Send one delivery attempt with the RAW stored bytes. Returns
/// `(Some(status), None)` on an HTTP answer or `(None, Some(err))` on a
/// connect/timeout error.
async fn send_delivery(
    client: &Client<HttpConnector, Full<Bytes>>,
    cfg: &DispatcherConfig,
    job: &DurableJob,
) -> (Option<u16>, Option<String>) {
    let uri = match http::Uri::builder()
        .scheme("http")
        .authority(cfg.upstream.as_str())
        .path_and_query(if job.url_path.is_empty() { "/" } else { job.url_path.as_str() })
        .build()
    {
        Ok(u) => u,
        Err(e) => return (None, Some(format!("delivery uri build: {e}"))),
    };

    let mut builder = hyper::Request::builder().method(job.method.as_str()).uri(uri);
    for (k, v) in &job.headers {
        let name = match HeaderName::from_bytes(k.as_bytes()) {
            Ok(n) => n,
            Err(_) => continue, // unparseable header: skip, never fail delivery
        };
        if STRIP_ON_DELIVERY.contains(&name.as_str()) {
            continue;
        }
        if let Ok(val) = HeaderValue::from_bytes(v.as_bytes()) {
            builder = builder.header(name, val);
        }
    }
    // Correlation headers: the delivery lands in the ORIGINAL trace.
    if job.trace_id != [0u8; 16] {
        let span = {
            let mut s = [0u8; 8];
            fastrand::fill(&mut s);
            s
        };
        let tp = format!("00-{}-{}-01", trace_id_to_hex(&job.trace_id), hex8(&span));
        if let Ok(v) = HeaderValue::from_str(&tp) {
            builder = builder.header("traceparent", v);
        }
        if let Ok(v) = HeaderValue::from_str(&trace_id_to_hex(&job.trace_id)) {
            builder = builder.header("x-blackbox-trace-id", v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(&job.attempt.to_string()) {
        builder = builder.header("x-blackbox-attempt", v);
    }
    if let Ok(v) = HeaderValue::from_str(&job.job_id.to_string()) {
        builder = builder.header("x-blackbox-job-id", v);
    }

    let req = match builder.body(Full::new(Bytes::from(job.body.clone()))) {
        Ok(r) => r,
        Err(e) => return (None, Some(format!("delivery request build: {e}"))),
    };

    match tokio::time::timeout(cfg.delivery_timeout, client.request(req)).await {
        Ok(Ok(res)) => (Some(res.status().as_u16()), None),
        Ok(Err(e)) => {
            // Drain body errors from pooled connections count as failures too.
            (None, Some(format!("delivery: {e}")))
        }
        Err(_) => (None, Some("delivery timed out".into())),
    }
}

async fn emit_event(
    events: Option<mpsc::Sender<QueueEvent>>,
    job: &DurableJob,
    kind: QueueEventKind,
) {
    if let Some(tx) = events {
        let ev = QueueEvent {
            job_id: job.job_id,
            trace_id: job.trace_id,
            queue: job.queue.clone(),
            kind,
        };
        if tx.send(ev).await.is_err() {
            tracing::debug!("queue event channel closed; event dropped");
        }
    }
}

fn hex8(id: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for b in id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

/// Snapshot of dispatcher-visible health for the admin surface.
pub fn breaker_summary(health: &UpstreamHealth) -> String {
    format!(
        "{} (failures={}, open_for_ms={}, transitions={})",
        state_name(health.state()),
        health.failures(),
        health.open_for_ms(),
        health.transitions()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn breaker_summary_formats() {
        let h = UpstreamHealth::new(2);
        assert!(breaker_summary(&h).contains("closed"));
        h.record_failure();
        h.record_failure();
        assert!(breaker_summary(&h).contains("open"));
    }
}
