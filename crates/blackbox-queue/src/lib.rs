//! # blackbox-queue — Engine 2: Durable Webhooks & Workflow Dispatch
//!
//! The at-least-once delivery backbone for `/webhooks/*` and `/jobs/*`
//! routes, built on the Phase 1 group-commit storage core:
//!
//! - [`model`] — the [`model::DurableJob`] lease-based state machine
//!   (`Pending → InFlight{lease} → Delivered | DeadLetter`) and full-jitter
//!   exponential backoff. Raw request bytes are preserved EXACTLY (HMAC
//!   safety); the PII scrubber only ever sees the telemetry copy.
//! - [`store`] — single-writer group-commit actor over redb: one ACID
//!   fsync per batch, atomic idempotency dedup (`bq_idem`), due/lease/dlq
//!   secondary indexes maintained in the same transaction as the job row.
//! - [`dispatcher`] — lease-claiming delivery loop: 2xx → Delivered,
//!   429/5xx/connect-refused → backoff+jitter reschedule, other 4xx →
//!   DeadLetter (payload retained for 1-click retry). Dispatch pauses while
//!   the shared [`blackbox_core::breaker::UpstreamHealth`] circuit is Open;
//!   a lease reaper recovers InFlight jobs after a kill -9 crash.
//! - [`replay`] — deterministic time-travel replay: exact
//!   `(method, url, body-hash)` matching with sequence-ordered fallback and
//!   a strict `428` sandbox guard against unrecorded outgoing calls.
//! - [`interceptor`] — the egress forward-proxy listener that records
//!   outgoing calls in production (`HTTP_PROXY` interception) and serves
//!   recorded responses during replay.
//! - [`admin`] — offline `blackbox queue status | retry-dlq` redb access.

pub mod admin;
pub mod dispatcher;
pub mod interceptor;
pub mod model;
pub mod replay;
pub mod store;

pub use dispatcher::{spawn_queue_runtime, DispatcherConfig, QueueEvent, QueueEventKind, QueueRuntime};
pub use model::{BackoffConfig, DeliveryVerdict, DurableJob, JobId, JobState};
pub use replay::ReplayEngine;
pub use store::{spawn_job_store, EnqueueOutcome, JobCounts, JobStoreConfig, JobStoreHandle};

/// Crate identity tag.
pub const ENGINE: &str = "durable-queue";
