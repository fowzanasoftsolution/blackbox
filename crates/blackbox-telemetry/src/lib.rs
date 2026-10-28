//! # blackbox-telemetry — Engine 3: Wire-Compatible Flight Recorder (Phase 2)
//!
//! Parsing layer for the wire-compatible telemetry ingestion endpoints the
//! ingress proxy routes to:
//!
//! - [`decompress`] — gzip/zstd body decoding under a strict 2 MiB
//!   decompressed ceiling (anti-zip-bomb guard → HTTP 413).
//! - [`envelope`] — Sentry `POST /api/{project_id}/envelope/` envelope
//!   parsing: `event_id` + trace id from the envelope header
//!   `trace.trace_id` or the event payload `contexts.trace.trace_id`.
//! - [`otlp`] — OTLP/HTTP `POST /v1/traces` and `/v1/logs` (JSON **and**
//!   protobuf encodings) decoded into [`otlp::OtlpRecord`]s correlated by
//!   `trace_id`.
//! - [`pb`] — the dependency-free protobuf wire-format walker the OTLP
//!   protobuf path is built on.
//!
//! The ingress proxy (`blackbox-ingress`) owns the HTTP surface, PII
//! scrubbing, segment writing and the bloom+sidecar trace index; this crate
//! is deliberately pure parsing so it is trivially testable against real
//! SDK payloads.

pub mod decompress;
pub mod envelope;
pub mod otlp;
pub mod pb;

/// Crate identity tag used by diagnostics.
pub const ENGINE: &str = "flight-recorder";

#[cfg(test)]
mod tests {
    #[test]
    fn engine_tag() {
        assert_eq!(super::ENGINE, "flight-recorder");
    }
}
