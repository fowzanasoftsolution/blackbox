//! # blackbox-egress — Engine 4: Egress FinOps & Smart API/LLM Proxy
//!
//! The outbound half of the omni-sidecar: apps point `OPENAI_BASE_URL` /
//! `ANTHROPIC_BASE_URL` / `HTTP_PROXY` at this listener and get, with ZERO
//! custom root CA certificates (plain-HTTP termination locally, rustls +
//! bundled webpki roots upstream):
//!
//! - [`gateway`] — the zero-cert listener: base-URL gateway routing
//!   (`/egress/https/<host>/<path>`, `X-Blackbox-Target`, provider aliases),
//!   standard forward proxying (absolute-form), blind CONNECT tunnels, and
//!   full plaintext inspection for every routed call.
//! - [`flight`] — detached singleflight coalescing: one upstream call per
//!   identical request burst, published over a `tokio::sync::watch` so the
//!   leader's caller may disconnect freely.
//! - [`cache`] — tenant-scoped byte-budgeted LRU response cache.
//! - [`key`] — composite `BLAKE3(tenant ‖ blake3(auth) ‖ method ‖ url ‖ body)`
//!   keys + the cacheability policy (GET/HEAD + deterministic AI POSTs,
//!   `stream: true` excluded).
//! - [`validate`] — the soft-error schema guard: HTTP 200 + `{"error": ...}`
//!   is NEVER cached (no cache poisoning from provider rate-limit bodies).
//! - [`ledger`] — real-time FinOps cost & token ledger (in-memory + redb).
//! - [`gates_phase4`] — Phase 4 gate harness: singleflight coalescing, cache
//!   poisoning guard, RAM shedding, the SimHash near-cache gate (v1.1) and
//!   the tamper-evident audit-chain gate.
//! - Supervisor self-healing: 75 % RAM watermark purges the cache to 0
//!   bytes via the watch hub; 85 % enables head-based ingress sampling.
//!
//! Every real upstream call emits an `EgressHttpMock` record linked to the
//! caller's W3C `traceparent`, so Phase 3 deterministic replay covers the
//! whole egress surface.

pub mod cache;
pub mod flight;
pub mod gates_phase4;
pub mod gateway;
pub mod key;
pub mod ledger;
pub mod simhash;
pub mod validate;

pub use cache::{CachedEntry, ResponseCache};
pub use flight::{FlightTable, UpstreamOutcome};
pub use gateway::{
    spawn_egress, EgressConfig, EgressHandle, EmitFn, ResBody, MAX_BYPASS_CAPTURE,
    MAX_EGRESS_REQ_BODY, MAX_EGRESS_RES_BODY,
};
pub use gates_phase4::{gate1, gate2, gate3};
pub use ledger::{CostLedger, LedgerEntry, LedgerKey, RequestKind, Usage};

/// Crate identity tag.
pub const ENGINE: &str = "egress-finops";
