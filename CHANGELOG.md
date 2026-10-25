# Changelog

All notable changes to Project Blackbox are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org).

## [Unreleased]

### Changed
- Professionalized the repository layout: uniform `crates/*` workspace with
  a single binary crate; verification harnesses standardized as
  `gates_phase<n>.rs` per crate (product-phase naming is intentional and kept
  where it *is* the product concept); functional plumbing renamed by role
  (`node`, `ops`, `janitor`, `util`). No gate names, CLI verbs or wire
  contracts changed — 21/21 gates and all 201 tests unchanged.
- Added production documentation: this changelog, `SECURITY.md` and
  `CONTRIBUTING.md`; README restructured with badges, table of contents and
  an install section.

## [1.1.0] — 2026-10-25

The Pro-differentiator release, built to the product blueprint §6 spec:
pure Rust, zero ML models, zero new dependencies.

### Added
- **SimHash near-duplicate prompt cache** (L1 behind the exact-match L0):
  normalize → word 3-shingles → FNV-1a → 64-bit Charikar SimHash; near
  variants (key-order shuffle, case/whitespace/punctuation drift, drifted
  ids) are served byte-identically with the `x-blackbox-cache:
  SIMHASH(d=0..3)` flag and one upstream call per prompt family. Tenant-
  scoped BLAKE3 keys; deterministic-only (temperature/top_p/n frozen);
  `/v1/embeddings` + `/v1/moderations` excluded; the 75 % RAM watermark
  purges it. Gate 4: **1 upstream call for a 1,001-request variant storm**;
  `prepare()` pipeline **3.4 µs/prompt** (budget < 5 µs).
- **Tamper-evident audit chain**: SHA-256 hash-chained JSONL in
  `<data>/audit.log`, fsynced checkpoints every 1,024 records, interior
  edits/insertions/deletions break the chain at their line, exported file-tail
  anchors make history truncation detectable on re-import. New CLI:
  `blackbox audit verify|current-anchor`. Auditing on by default
  (`BLACKBOX_AUDIT=0` escapes).

## [1.0.3] — 2026-10-25

### Added
- `blackbox startup-sim` — a standalone SaaS launch-day simulation example
  plus a clean-room `CASE_STUDY`.

### Fixed
- Concurrent `blackbox replay` against a *live* node: redb-lock detection
  auto-clones the data dir into a scratch copy (hardlinked cold artifacts,
  real copies of the mutable set) — the live node is never touched; forced
  via `--data-copy`.
- TLS hot reload on container filesystems: change detection now hashes PEM
  content instead of trusting mtime.
- Race-free WAF attack-counter tests under parallel `cargo test`.

## [1.0.2]

### Fixed
- Release pipeline re-runs are idempotent: an existing release for a tag is
  replaced (release object + assets) instead of failing, so adding the
  signing key after an unsigned first run only needs a re-run.

## [1.0.1]

### Added
- `W3C baggage` header parity for `@sentry/node` v8+: `sentry-trace_id`,
  `sentry-public_key` and `sentry-sample_rate` are injected/appended upstream
  (caller entries preserved, key never duplicated), so real SDKs propagate
  the exact trace id across async boundaries — pinned as regression tests.
- Appended `@sentry/node continueTrace` parity check to the SDK matrix job.

### Fixed
- Demo determinism fix (stable headless scenario output).

## [1.0.0] — 2026-10-25

First production release: the four-engine omni-sidecar for a single $5 VPS
(2 cores / 4 GB), one <16 MB static binary, zero code changes required from
the wrapped application.

### Added
- **Engine 1 — Ingress shield & flight recorder**: <1 ms reverse proxy with
  W3C `traceparent` injection, streaming tee capture (first 64 KB of
  text/JSON), wire-compatible Sentry `/api/{project}/envelope/` + OTLP
  `/v1/traces|/v1/logs` interception, aho-corasick PII scrubbing on the
  telemetry copy. Measured 31,029 req/s, p99 added latency 166 µs.
- **Engine 2 — Durable webhook queue**: 202-on-write ingestion into redb,
  lease-based delivery (`Pending → InFlight → Delivered | DeadLetter`) with
  full-jitter backoff, an upstream circuit breaker, 24 h idempotency dedup,
  byte-exact HMAC preservation, and deterministic time-travel replay
  (`blackbox replay`) with a 428-blocked sandbox for unrecorded calls.
- **Engine 3 — Egress FinOps proxy**: detached singleflight coalescing,
  byte-budgeted tenant-scoped LRU cache, BLAKE3 composite keys, soft-error
  cache-poisoning guard, per-(tenant, provider, model) cost ledger with
  token accounting.
- **Engine 4 — Storage lifecycle & self-healing**: append-only segments with
  CRC32C frames, zstd-3 compaction (measured 194× ratio), `.idx` sidecars,
  disk ring quota (compress 75 % / FIFO-evict 85 % with crash pinning /
  survival shed 95 %), hand-rolled SigV4 sync to any S3-compatible bucket,
  and digest-verified bit-rot self-healing.
- **Supervisor**: RAM/disk watermark hubs, auto-resurrection with circuit
  breaker and connection hold (`blackbox run` wraps any app with five
  injected env vars; measured 351,888 requests, 0 failures across two
  `kill -9` cycles).
- **Launch polish (Phase 7)**: lock-free sharded token-bucket rate limiter
  (429 + Retry-After < 50 µs), scanner shield (404, zero recorded frames),
  native TLS termination with zero-downtime hot reload, the admin dashboard,
  `blackbox demo` (headless `--once` acceptance gate) and a production README.
- **Canonical update path (Phase 6)**: Ed25519-verified `blackbox self-update`
  with redb snapshot + isolated canary boot + automatic rollback; production
  release verifying key baked into the binary.
- **Tooling**: GitHub Actions CI (release-mode workspace tests, the demo
  gate, and a real-SDK compatibility matrix against official `sentry-sdk`
  and `openai` Python clients on a real FastAPI app — including brotli
  envelopes), a signed GitHub Release pipeline with a one-line install
  script, `blackbox keygen|sign-update` provisioning, and the
  `scripts/sdk_matrix/` live wire-contract suite.

### Fixed
- Release signing: `sign-update` uses `--input`; release notes read the
  verifying key from the packaged `.pub` file.

[Unreleased]: https://github.com/Nsiowj1/blackbox/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Nsiowj1/blackbox/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/Nsiowj1/blackbox/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Nsiowj1/blackbox/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Nsiowj1/blackbox/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Nsiowj1/blackbox/commits/v1.0.0
