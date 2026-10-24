//! Streaming tee body — the zero-blocking capture primitive.
//!
//! [`TeeBody`] wraps a `hyper::body::Incoming` and forwards every frame to
//! the consumer **as it arrives** (zero buffering delay: the poll passes the
//! original `Bytes` through untouched). Independently, it side-copies at
//! most [`CAPTURE_MAX_BYTES`] into a capture buffer — and only when the
//! payload class allows it:
//!
//! | Content-Type                                | Capture               |
//! |---------------------------------------------|-----------------------|
//! | `text/*` (except `text/event-stream`)       | ≤ 64 KB               |
//! | `application/json`, `*+json`                | ≤ 64 KB               |
//! | `multipart/*`, `text/event-stream`          | bypass (headers only) |
//! | WebSocket upgrade, anything else            | bypass                |
//!
//! When the response body finishes (or errors, or is dropped), the captured
//! bytes flow into the [`Finalizer`], which builds the `IngressHttp`
//! `TraceRecord` — PII-scrubbed — and hands it to the bounded writer
//! channel. Disk I/O never touches the proxy hot path.

use crate::scrub::Scrubber;
use crate::writer::RecordSink;
use blackbox_core::schema::{IngressHttp, RecordPayload, TraceId, TraceRecord};
use bytes::Bytes;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Instant;

/// Per-direction capture ceiling (blueprint §3 Engine 1: 64 KB side-copy).
pub const CAPTURE_MAX_BYTES: usize = 64 * 1024;

/// Whether (and how much of) a body stream is side-copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePolicy {
    /// Side-copy up to 64 KB, then set the truncated flag.
    Capture,
    /// Record metadata/headers only (multipart, SSE, WebSocket, binary).
    Bypass,
}

/// Decide the capture policy from a Content-Type + upgrade state.
pub fn capture_policy(content_type: Option<&str>, is_upgrade: bool) -> CapturePolicy {
    if is_upgrade {
        return CapturePolicy::Bypass;
    }
    let Some(ct) = content_type else {
        return CapturePolicy::Bypass;
    };
    let ct = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.is_empty() {
        return CapturePolicy::Bypass;
    }
    if ct.starts_with("multipart/") || ct == "text/event-stream" {
        return CapturePolicy::Bypass;
    }
    if ct.starts_with("text/") || ct == "application/json" || ct.ends_with("+json") {
        return CapturePolicy::Capture;
    }
    CapturePolicy::Bypass
}

/// Bounded capture buffer: keeps the FIRST 64 KB, marks the rest truncated.
#[derive(Debug, Default)]
pub struct CaptureBuf {
    pub data: Vec<u8>,
    pub truncated: bool,
    cap: usize,
}

impl CaptureBuf {
    pub fn new(cap: usize) -> Self {
        // 1 KB eager: most API responses fit; the Vec grows on demand up to
        // `cap`. At 30 K req/s × 2 buffers this cuts allocation churn ~8×.
        CaptureBuf {
            data: Vec::with_capacity(1024),
            truncated: false,
            cap,
        }
    }

    #[inline]
    pub fn extend(&mut self, chunk: &[u8]) {
        if self.truncated || chunk.is_empty() {
            return;
        }
        let room = self.cap.saturating_sub(self.data.len());
        if room == 0 {
            self.truncated = true;
            return;
        }
        let n = chunk.len().min(room);
        self.data.extend_from_slice(&chunk[..n]);
        if n < chunk.len() {
            self.truncated = true;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Where a tee body writes its side-copy.
enum CaptureSink {
    /// Request side — the record finalizer reads this buffer when the
    /// response completes.
    Shared(Arc<Mutex<CaptureBuf>>),
    /// Response side — owned by the tee, moved into the finalizer.
    Owned(CaptureBuf),
}

impl CaptureSink {
    #[inline]
    fn extend(&mut self, chunk: &[u8]) {
        match self {
            CaptureSink::Shared(m) => {
                if let Ok(mut g) = m.lock() {
                    g.extend(chunk);
                }
            }
            CaptureSink::Owned(b) => b.extend(chunk),
        }
    }

    fn take_owned(&mut self) -> CaptureBuf {
        match self {
            CaptureSink::Owned(_) => match std::mem::replace(
                self,
                CaptureSink::Owned(CaptureBuf::new(CAPTURE_MAX_BYTES)),
            ) {
                CaptureSink::Owned(b) => b,
                _ => unreachable!(),
            },
            CaptureSink::Shared(_) => CaptureBuf::new(CAPTURE_MAX_BYTES),
        }
    }
}

/// Everything needed to emit the completed `IngressHttp` record once the
/// response body is done.
pub struct Finalizer {
    pub sink: RecordSink,
    pub scrubber: Arc<Scrubber>,
    pub trace_id: TraceId,
    pub method: String,
    pub uri: String,
    /// Request headers as sent upstream (pre-scrub snapshot).
    pub req_headers: Vec<(String, String)>,
    /// Request body capture shared with the request-side [`TeeBody`].
    pub req_capture: Arc<Mutex<CaptureBuf>>,
    pub req_content_type: Option<String>,
    pub res_status: u16,
    /// Response headers (pre-scrub snapshot).
    pub res_headers: Vec<(String, String)>,
    pub started: Instant,
}

impl Finalizer {
    /// Emit the record. Consumes the finalizer; runs entirely off the disk
    /// path (a `try_send` into the bounded channel).
    ///
    /// Phase 4 self-healing: when the supervisor's RAM level is `Shed85+`,
    /// head-based adaptive sampling keeps 100 % of errors (any non-2xx) and
    /// slow traces (≥ 1 s) but only ~1 % of healthy, fast 2xx responses —
    /// the single biggest lever for shedding telemetry write volume under
    /// memory pressure without losing a single failure signal.
    ///
    /// Phase 5 survival mode: the DISK `Emergency95` watermark sheds the
    /// same healthy-fast-2xx class while PRESERVING 100 % of SentryCrash,
    /// 4xx/5xx, and redb queue jobs (the durable queue never touches this
    /// path — redb writes are not segment telemetry).
    pub fn emit(self, res_body: CaptureBuf) {
        let Self {
            sink,
            scrubber,
            trace_id,
            method,
            uri,
            mut req_headers,
            req_capture,
            req_content_type: _ignored,
            res_status,
            mut res_headers,
            started,
        } = self;

        let duration_ms = started.elapsed().as_millis() as u64;

        // --- Shed85 (RAM) / Emergency95 (disk) head-based sampling --------
        let ram_shed = blackbox_supervisor::memory::current_ram_level()
            >= blackbox_supervisor::memory::RamLevel::Shed85;
        let disk_shed = blackbox_supervisor::disk::current_disk_level()
            >= blackbox_supervisor::disk::DiskLevel::Emergency95;
        if (ram_shed || disk_shed) && is_healthy(&res_status, duration_ms) {
            // 1 % keep-rate for healthy fast responses (~1 in 100).
            if fastrand::u64(..100) != 0 {
                if disk_shed && !ram_shed {
                    crate::proxy::DISK_SHED_OUT
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                crate::proxy::SAMPLED_OUT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }

        // 1) Header scrubbing (both directions).
        scrubber.scrub_headers(&mut req_headers);
        scrubber.scrub_headers(&mut res_headers);

        // 2) Request body: take the shared capture and scrub if JSON-ish.
        let mut req_body = match req_capture.lock() {
            Ok(mut guard) => std::mem::take(&mut guard.data),
            Err(_) => Vec::new(),
        };
        scrub_body(&scrubber, &mut req_body);

        // 3) Response body already captured (response CT gated capture).
        let mut res_body = res_body;
        scrub_body(&scrubber, &mut res_body.data);

        let payload = IngressHttp {
            method,
            uri,
            status: res_status,
            req_headers,
            req_body,
            res_body: res_body.data,
            duration_ms,
        };
        let record = TraceRecord::new(trace_id, sink.next_seq(), RecordPayload::IngressHttp(payload));
        sink.try_send(record);
    }
}

/// A "healthy" trace under the Shed85 sampling policy: 2xx status AND
/// finished in under a second. Everything else (errors, slow requests) is
/// always recorded at 100 %.
#[inline]
fn is_healthy(status: &u16, duration_ms: u64) -> bool {
    (200..300).contains(status) && duration_ms < 1_000
}

/// Scrub a captured body when it looks like JSON (content-type gate happens
/// at capture time; here we double-check the bytes themselves).
fn scrub_body(scrubber: &Scrubber, body: &mut Vec<u8>) {
    if body.is_empty() {
        return;
    }
    let first = body.iter().find(|&&b| !b.is_ascii_whitespace());
    if matches!(first, Some(b'{') | Some(b'[')) {
        scrubber.scrub_json(body);
    }
}

/// Streaming tee wrapper around `hyper::body::Incoming` (or any Body).
pub struct TeeBody<B> {
    inner: B,
    policy: CapturePolicy,
    sink: CaptureSink,
    fin: Option<Finalizer>,
    done: bool,
}

impl<B> TeeBody<B> {
    /// Request-side tee: capture feeds the shared buffer; nothing is
    /// finalized here (the response finalizer owns the record).
    pub fn request(inner: B, policy: CapturePolicy, shared: Arc<Mutex<CaptureBuf>>) -> Self {
        TeeBody {
            inner,
            policy,
            sink: CaptureSink::Shared(shared),
            fin: None,
            done: false,
        }
    }

    /// Response-side tee: on completion, `fin.emit(buf)` fires.
    pub fn response(inner: B, policy: CapturePolicy, fin: Finalizer) -> Self {
        TeeBody {
            inner,
            policy,
            sink: CaptureSink::Owned(CaptureBuf::new(CAPTURE_MAX_BYTES)),
            fin: Some(fin),
            done: false,
        }
    }
}

impl<B> TeeBody<B> {
    /// Emit the record (response side) if not already done. No bounds on B:
    /// the Drop impl and poll both call this.
    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        if let Some(fin) = self.fin.take() {
            let buf = self.sink.take_owned();
            fin.emit(buf);
        }
    }
}

impl<B> TeeBody<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, B::Error>>> {
        match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            Some(Ok(frame)) => {
                if self.policy == CapturePolicy::Capture {
                    if let Some(data) = frame.data_ref() {
                        self.sink.extend(data.as_ref());
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => {
                self.finish(); // record what we captured even on stream error
                Poll::Ready(Some(Err(e)))
            }
            None => {
                self.finish();
                Poll::Ready(None)
            }
        }
    }
}

impl<B> hyper::body::Body for TeeBody<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut().poll_inner(cx)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for TeeBody<B> {
    fn drop(&mut self) {
        // Bodies dropped before completion (client aborts, connection
        // teardown) still emit their record with whatever was captured.
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::Scrubber;
    use crate::writer::{RecordSink, WriterConfig};
    use http_body_util::{BodyExt, Full};

    fn policy(ct: &str) -> CapturePolicy {
        capture_policy(Some(ct), false)
    }

    #[test]
    fn capture_policy_matrix() {
        assert_eq!(policy("application/json"), CapturePolicy::Capture);
        assert_eq!(policy("application/json; charset=utf-8"), CapturePolicy::Capture);
        assert_eq!(policy("text/plain"), CapturePolicy::Capture);
        assert_eq!(policy("application/vnd.api+json"), CapturePolicy::Capture);
        assert_eq!(policy("multipart/form-data; boundary=x"), CapturePolicy::Bypass);
        assert_eq!(policy("text/event-stream"), CapturePolicy::Bypass);
        assert_eq!(policy("application/octet-stream"), CapturePolicy::Bypass);
        assert_eq!(policy("image/png"), CapturePolicy::Bypass);
        assert_eq!(capture_policy(Some("application/json"), true), CapturePolicy::Bypass);
        assert_eq!(capture_policy(None, false), CapturePolicy::Bypass);
    }

    #[test]
    fn capture_buf_caps_at_limit() {
        let mut b = CaptureBuf::new(1000);
        b.extend(&vec![b'a'; 600]);
        b.extend(&vec![b'b'; 600]);
        assert_eq!(b.data.len(), 1000);
        assert!(b.truncated);
    }

    #[tokio::test]
    async fn tee_streams_every_byte_and_finalizes_once() {
        // Response side: a full body streams through; finalizer emits 1 record.
        let cfg = WriterConfig {
            data_dir: std::env::temp_dir().join(format!("blackbox-tee-{}", std::process::id())),
            ..WriterConfig::default()
        };
        let _ = std::fs::remove_dir_all(&cfg.data_dir);
        let (sink, index, writer) = crate::writer::spawn_writer(cfg);

        let fin = Finalizer {
            sink: sink.clone(),
            scrubber: Arc::new(Scrubber::new()),
            trace_id: [9u8; 16],
            method: "GET".into(),
            uri: "/tee".into(),
            req_headers: vec![("authorization".into(), "Bearer x".into())],
            req_capture: Arc::new(Mutex::new(CaptureBuf::new(CAPTURE_MAX_BYTES))),
            req_content_type: None,
            res_status: 200,
            res_headers: vec![("content-type".into(), "text/plain".into())],
            started: Instant::now(),
        };

        let full = Full::new(Bytes::from(vec![0x41u8; 200_000])); // 200 KB text
        let tee = TeeBody::response(full, CapturePolicy::Capture, fin);

        // Stream through and count bytes.
        let mut total = 0usize;
        let mut body = std::pin::pin!(tee);
        while let Some(frame) = BodyExt::frame(&mut body).await.transpose().unwrap() {
            if let Ok(d) = frame.into_data() {
                total += d.len();
            }
        }
        assert_eq!(total, 200_000, "every byte must stream through");

        // The finalizer already fired on body completion.
        sink.flush().await;
        let tid = [9u8; 16];
        let recs = index.read().unwrap().get_trace(&tid).unwrap_or_default();
        assert_eq!(recs.len(), 1, "exactly one record finalized");
        if let blackbox_core::schema::RecordPayload::IngressHttp(h) = &recs[0].payload {
            assert_eq!(h.status, 200);
            assert_eq!(h.res_body.len(), crate::tee::CAPTURE_MAX_BYTES, "capped at 64 KB");
            assert_eq!(
                h.req_headers[0].1,
                "[REDACTED]",
                "authorization header must be scrubbed"
            );
        } else {
            panic!("expected IngressHttp payload");
        }
        drop(writer);
        drop(sink);
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!(
            "blackbox-tee-{}",
            std::process::id()
        )));
    }
}
