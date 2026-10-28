//! # blackbox-core — the shared storage core (Phase 1)
//!
//! Three load-bearing components, per the Project Blackbox blueprint §2/§3:
//!
//! 1. [`schema`] — rkyv 0.8 unified trace schema. One `TraceRecord` envelope with a
//!    `RecordPayload` enum covering all four engines, including the Phase 3
//!    deterministic-replay fields (`RecordPayload::EgressHttpMock`).
//! 2. [`frame`] — self-describing 32-byte-aligned frame codec with CRC32C payload +
//!    header checksums. Frames are padded to 16-byte boundaries so every serialized
//!    payload on disk sits at a 16-byte-aligned offset for zero-copy `rkyv::access`.
//! 3. [`segment`] — append-only segment engine: `pwrite`-style appends (never `mmap`
//!    on active buffers), torn-write auto-truncation recovery, 64 MB rotation,
//!    zstd cold-seal.
//! 4. [`queue_actor`] — single-writer group-commit actor over `redb`: bounded mpsc,
//!    5 ms / 1 000-op ACID batch commits, 250 ms reader timeout.

pub mod audit;
pub mod breaker;
pub mod compactor;
pub mod egress_key;
pub mod error;
pub mod frame;
pub mod kv;
pub mod queue_actor;
pub mod schema;
pub mod segment;

pub use error::StorageError;
