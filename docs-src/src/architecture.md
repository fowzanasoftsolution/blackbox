# Architecture

One Cargo workspace, eight crates, one binary — every crate owns one engine and
every feature ships with a verification gate in the same file family
(`gates_phase<n>`), so "does it hold up" is a compile-time question, not a
sprint-planning one.

| Crate | Engine |
|---|---|
| `crates/blackbox` | the CLI: node assembly (`node`), command plumbing (`ops`, `run`, `selfupdate`), dashboard, demo, benchmarks, and the phase-gate harnesses |
| `crates/blackbox-core` | storage engine: frames, schema, segment store, compactor, breaker, queue actor, the audit chain |
| `crates/blackbox-ingress` | reverse proxy, tee capture, scrubber, WAF, rate limiter, TLS, trace index |
| `crates/blackbox-queue` | durable jobs: leases, dispatcher, reaper, idempotency sweep |
| `crates/blackbox-telemetry` | Sentry envelope + OTLP ingestion/wire formats |
| `crates/blackbox-egress` | gateway, singleflight, response cache, FinOps ledger, SimHash near-cache |
| `crates/blackbox-cold` | hand-rolled SigV4, S3/R2 tier policy, mock bucket |
| `crates/blackbox-supervisor` | RAM/disk watermark monitors, process supervision |

## Lifecycle of one request

```
your app ──► BLACKBOX ingress ──► WAF/L7 scanner shield ──► rate limiter
                │                                            │
                ▼                                            ▼
        scrubber (PII redact)                    202/durable enqueue (or
                │                                passthrough + tee recording)
                ▼
        segment writer (CRC32C frames, fsync'd)
                │          rollover guard caps the hot segment
                ▼
        background compactor ──► sealed .zst + .idx/.sidx sidecars
                │                    (streamed frame-by-frame, bounded RAM)
                └──► cold tier (S3/R2 double-write, digest verified)
```

## The watermark operating system

The supervisor watches RAM and disk and reacts at defined points:

| Watermark | RAM reaction | Disk reaction |
|---|---|---|
| `Normal` | — | — |
| `Warn75` | log + trace | — |
| `Compress75` | — | compress sealed segments |
| `Shed85` | head-sample *healthy* 2xx telemetry (errors/slow traces stay at 100%) | FIFO-evict oldest cold `.zst` (crash + 5xx segments stay pinned) |
| `Backpressure95` | informational tier | survival shed: queue jobs + crash evidence survive at 100% |

Shed is *deliberate* and *derived from real evidence*: the 6-hour soak that
root-caused the shed design (`bb-soak-6h`) is pinned by the in-repo memory gate
(`soak_memory_bound`) that fails CI if the whole stack crosses the 43 MiB
soak gate.

## Self-healing storage

A CRC or decompress failure on read is bit-rot: the segment is restored
transparently from the digest-verified cold-tier replica and the damaged file
is replaced atomically. Sealed-segment semantics are strict: a RAW segment may
carry a torn tail (a `kill -9` mid-append is legitimate) but an unreadable
frame inside a completed, fsync'd sealed `.zst` surfaces as
`StorageError::Corrupt` so the heal path engages instead of silently skipping.

## The audit chain

A hash-linked, tamper-evident chain over the record stream with printable
anchors (`blackbox audit current-anchor`). Its documented boundary: an
unanchored truncation that removes history below every exported checkpoint is
reported honestly as a shorter, clean chain inside the truncated prefix — export
and pin anchors when truncation detection matters.
