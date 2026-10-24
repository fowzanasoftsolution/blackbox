//! # blackbox-cold — the Phase 6 S3/R2 cold tier (zero-bloat)
//!
//! Completes the Blueprint §4 Self-Healing Matrix:
//!
//! 1. [`sigv4`] — hand-rolled AWS Signature V4 signer on the existing
//!    `sha2` + `hmac` stack. No `aws-sdk-s3` (binary stays flat); pinned to
//!    the AWS documentation's worked example by a unit test.
//! 2. [`client`] — minimal S3-compatible client (PUT / GET / HEAD /
//!    ListObjectsV2, path-style) speaking to AWS S3, Cloudflare R2, MinIO
//!    and any SigV4-conformant store — including our local [`mock`].
//! 3. [`tier`] — the [`tier::ColdTier`]: seal→S3 sync with BLAKE3 digests
//!    in redb (`state = SyncedToCold`), transparent restore of evicted
//!    segments, bit-rot self-heal (verify → re-fetch → atomic replace),
//!    and the crash-pinned eviction tiers consumed by
//!    `blackbox_core::compactor::evict_cold_tiered`.
//!
//! ## Configuration (all via environment)
//!
//! | Variable                        | Meaning                          | Default     |
//! |---------------------------------|----------------------------------|-------------|
//! | `BLACKBOX_COLD_ENDPOINT`        | `http(s)://host[:port]`          | — (required)|
//! | `BLACKBOX_COLD_BUCKET`          | bucket name                      | — (required)|
//! | `BLACKBOX_COLD_ACCESS_KEY_ID`   | access key                       | — (required)|
//! | `BLACKBOX_COLD_SECRET_ACCESS_KEY`| secret key                      | — (required)|
//! | `BLACKBOX_COLD_REGION`          | SigV4 region                     | `us-east-1` |
//! | `BLACKBOX_COLD_PREFIX`          | object key prefix                | `segments/` |
//!
//! When the variables are unset the cold tier is simply not constructed and
//! the node behaves exactly as v1.1 (local-only retention).

pub mod client;
pub mod hex;
pub mod mock;
pub mod sigv4;
pub mod tier;

pub use client::{ColdError, S3Client, S3Config};
pub use tier::{ColdTier, SegmentSyncMeta, SyncReport, TIER_HAS_4XX, TIER_HAS_CRASH_OR_5XX, TIER_HEALTHY};
