//! # blackbox-ingress — Engine 1: Ingress Shield & Flight Recorder (Phase 2)
//!
//! A <1 ms-overhead reverse proxy that records everything, blocks nothing:
//!
//! - [`proxy`] — the hyper 1.x / hyper-util / tower reverse proxy: W3C
//!   `traceparent` injection, streaming tee capture, wire-compatible Sentry
//!   (`/api/{project}/envelope/`) + OTLP (`/v1/traces`, `/v1/logs`)
//!   interception, WebSocket tunnel passthrough. TCP_NODELAY + connection
//!   pooling on both legs; the hot path never touches disk.
//! - [`tee`] — the zero-buffering capture primitive (`TeeBody`): chunks pass
//!   through untouched while the first 64 KB of text/JSON are side-copied;
//!   multipart / SSE / WebSocket / binary bypass capture entirely.
//! - [`scrub`] — aho-corasick PII scrubber applied before framing
//!   (sensitive headers + JSON key values).
//! - [`writer`] — bounded channel (16 384) into a dedicated segment-writer
//!   task with 5 ms group-commit fsyncs; the proxy is never blocked on disk.
//! - [`index`] — in-memory trace index: `trace_id → (segment_id, offset)`
//!   exact map, roaring bitmaps for status classes and `has_sentry_crash`,
//!   bloom fast-negative path; rebuilt from the startup recovery scan.
//! - [`durable`] — Phase 3 durable webhook ingestion: raw-byte-preserving
//!   202 path (HMAC-safe), idempotency dedup, scrubbed telemetry copy.
//! - [`rate_limit`] — Phase 7 sharded lock-free token-bucket rate limiter
//!   (429 + Retry-After before the upstream or disk is touched).
//! - [`waf`] — Phase 7 scanner/WAF shield: instant drop of /.env, /.git,
//!   wp-admin, path traversal, … (counted, never recorded).
//! - [`tls`] — Phase 7 native TLS termination (tokio-rustls) with zero-
//!   downtime certificate hot reload.
//! - [`traceparent`] — W3C Trace Context parsing/generation.
//! - [`verify`] — Phase 2 gate harness: end-to-end causal-link test, stream
//!   & bomb-safety test, and the 2-vCPU throughput/latency benchmark.
//! - [`verify3`] — Phase 3 gate harness: zero-lost-webhooks chaos test,
//!   invisible-restart connection hold, deterministic replay sandbox.

pub mod durable;
pub mod index;
pub mod proxy;
pub mod rate_limit;
pub mod scrub;
pub mod tee;
pub mod tls;
pub mod traceparent;
pub mod verify;
pub mod verify3;
pub mod waf;
pub mod writer;

/// Crate identity tag.
pub const ENGINE: &str = "ingress-shield";
