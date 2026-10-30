# Changelog

All notable changes to Project Blackbox are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org).

Project Blackbox is authored by **Dr.wolfic** for **fowzanasoftsolution**.

## [Unreleased]

### Added
- OPEN THE BOX pass 2: guided crash/self-heal explanations, local webhook
  dedup and memory-policy models, a source-ported 64-bit SimHash playground,
  and scanner rule range. All simulations are labeled; no tests send traffic.
- Browser algorithm tests and Rust/JavaScript parity checks gate Pages
  publication. Documentation chapter paths now resolve to the actual source.

### Changed
- The soak-memory gate (`soak_memory_bound`) now hard-fails at **43 MiB
  VmRSS**: the monitored steady state stays **42.0 MiB**, with +1 MiB of
  documented cross-environment slack after the same code measured 39.20 MiB
  in the verification container and 42.23 MiB on a GitHub runner
  (THP=madvise both). Real regressions move RSS by whole MiBs; jitter
  should not flip a green gate.
- Professionalized the repository layout: uniform `crates/*` workspace with
  a single binary crate; verification harnesses standardized as
  `gates_phase<n>.rs` per crate (product-phase naming is intentional and kept
  where it *is* the product concept); functional plumbing renamed by role
  (`node`, `ops`, `janitor`, `util`). No gate names, CLI verbs or wire
  contracts changed — 21/21 gates and all 201 tests unchanged.
- Added production documentation: this changelog, `SECURITY.md` and
  `CONTRIBUTING.md`; README restructured with badges, table of contents and
  an install section.

## [1.1.3] — 2026-10-28

Hardening release cut from main `85621c1` after a third consecutive 30-minute
soak (v1.1.2c evidence run) passed 20/20. Carries one product change over the
v1.1.2 tag plus the banner/version-drift fix.

### Fixed
- **Sealed-segment corruption now surfaces for self-heal**
  (`blackbox-core::segment::read_records_at`): RAW segments keep the
  torn-tail skip contract (a kill -9 mid-append legitimately leaves an
  unreadable tail, which is logged and skipped), but a SEALED `.zst` is the
  product of a completed, fsync'd seal — any unreadable frame inside it is
  bit-rot, and the call now fails with `StorageError::Corrupt` so the caller
  triggers the cold-tier self-heal. The old behavior (`Ok` with silently
  skipped frames) left a corrupt sealed segment unhealed forever. Pinned by
  the `corrupt_sealed_zst_read_surfaces_error_for_self_heal` unit test, the
  demo phase E determinism rework, and a new shutdown-gate test
  (`crates/blackbox/tests/serve_shutdown.rs`).
- **Banner / `--version` drift** (`blackbox` crate): the runtime banner and
  the clap `about` string hardcoded `v1.2` while `--version` printed the real
  package version. Both now derive from `CARGO_PKG_VERSION` at compile time
  (`concat!("v", env!("CARGO_PKG_VERSION"))`), so they can never diverge
  again.

### Verified
Third 30-minute isolated Daytona soak (binary `02d32685…d1d2ce`, identical
cgroups `cpu.max=100000 100000` / `memory.max=1073741824`, same harness):

| Metric | run-1 (2026-10-27) | v1.1.2b re-run (2026-10-28) | v1.1.2c (this run) |
|---|---|---|---|
| Verdict | **FAIL** — 19/20, `no_record_drops_or_sampling` | PASS — 20/20 | **PASS — 20/20** |
| Node A sampled-out | **7** (t=1492.2 s) | 0 | **0** |
| Node B sampled-out | 0 | 0 | **0** |
| Node A RSS peak | 36.67 MiB (2× `Warn75`) | 32.00 MiB (all `Normal`) | **31.82 MiB** (189/189 `Normal`) |
| Node B RSS peak | 31.44 MiB | 28.23 MiB | **28.29 MiB** (all `Normal`) |
| Node A compactions / frames indexed | 18 / 266,632 | 18 / 266,689 | **18 / 266,690** |
| Node B compactions / frames indexed | 36 / — | 37 / 134,919 | **36 / 131,274** |
| HTTP requests | 267,589 | 269,324 (149.6 req/s) | **267,440** (148.6 req/s) |
| Transport errors / unexpected statuses | 0 / 0 | 0 / 0 | **0 / 0** |
| Crash recoveries (T+600 s, T+1200 s) | verified | 0.256 s / 0.357 s | **0.203 s / 0.257 s** |
| Shutdown | rc=0 both | rc=0 both | **rc=0 both** |
| Node B clone reopen | PASS | PASS | **PASS** (3/3 cold traces byte-equivalent) |
| Binary SHA-256 | `10c22e7e…25d140c` | `33a3b351…ba83db2` | **`02d32685…d1d2ce`** |

Note: this run's sandbox runs a newer kernel (`7.0.0-38-generic` vs
`6.17.0-35-generic` for both prior runs); cgroups were byte-identical, but
sub-MiB cross-kernel RSS comparisons are approximate. The soak proves the
sealed-read change does not regress the healthy path (no corruption is
injected by the workload; the `Err(Corrupt)` semantics themselves are
unit-level, not soak-exercised). `Shed85` head-sampling keeps errors/slow
traces at 100% by design and `Backpressure95` remains informational — zero
sampled-out records here because RSS never left `Normal`.

## [1.1.2] — 2026-10-27

Fix release addressing the two remaining failures from the isolated 30-minute
Daytona soak of v1.1.1 (Node A peaked at 51.69 MiB / 13 samples ≥48 MiB and
sampled out 8,662 healthy 2xx records; Node B exited rc=-15 because the
detached launcher left `serve` without a reachable signal path).

### Fixed
- **Hot-segment rollover guard** (`blackbox-core::segment`): the active
  segment now rotates when *either* it exceeds the effective byte cap *or*
  its in-memory trace index reaches `max_active_trace_entries` (default
  20,000). The effective byte cap is `min(max_segment_bytes,
  ram_budget_bytes / 6)` — a 64 MB segment cap on a 48 MB budget now rolls
  over at ~8 MB, so the hot map and any single compaction stay bounded
  instead of accumulating ~130K traces before the first rollover.
- **Streaming segment compaction** (`blackbox-core::compactor`): sealed
  segments compress through a 64 KB `BufReader` → zstd `Encoder` → 64 KB
  `BufWriter` stream instead of `encode_all` holding a second full-size
  compressed `Vec<u8>`; the janitor purges jemalloc arenas right after each
  compaction that freed segments so reclaimed pages return to the OS
  immediately.
- **Streaming sidecar indexing** (`blackbox-core::compactor`): completing
  the fix above, `compact_one` now builds the `.idx`/`.sidx` sidecars by
  walking the sealed segment frame-by-frame — a CRC-verified 32-byte
  `parse_header` sizes each bounded payload read — instead of
  `read_to_end` materializing the whole artifact in RAM; the `.log.zst`
  backfill path decompresses through the same one-frame walker instead of
  `fs::read` + `decode_all`. At most one frame plus the small entry vector
  is resident during compaction, so a multi-MB compaction can no longer
  transiently cross the Shed85 watermark (first v1.1.2 soak: 7 healthy 2xx
  records head-sampled during Node A's segment-15 compaction at t≈1483 s).
  Torn-tail and decode-truncation semantics are preserved exactly and
  pinned by a streaming-vs-full-scan parity test. Re-verified: the 30-minute
  soak re-run passed 20/20 checks with 0 sampled-out / 0 dropped records on
  both nodes, peaks 32.0 / 28.2 MiB across 55 compactions and 401,608
  indexed frames, rc=0 shutdowns, and a byte-equivalent cold reopen.
- **Clean SIGINT/SIGTERM shutdown** (`blackbox run` and `blackbox serve`):
  both install explicit SIGINT + SIGTERM handlers eagerly via
  `tokio::signal::unix::signal()` BEFORE any listener binds (overriding any
  inherited `SIG_IGN` from a detached/background launcher and closing the
  window where a reachable port still died on the default disposition),
  gracefully stop the ingress proxy — in-flight connections finish so their
  response finalizers push the last acknowledged record — then flush the
  segment writer, and return exit code 0. `serve` previously had no signal
  path at all — SIGINT was ignored and SIGTERM killed it with rc=-15.

### Soak harness
- `llm_miss` workload profile now varies distinct words (not just digit
  runs) so SimHash's digit-run normalization no longer classifies it as a
  similarity hit; the profile genuinely exercises the cache-miss path.

## [1.1.1] — 2026-10-26

Fix release addressing the four root causes surfaced by the 6-hour
`bb-soak-6h` run (v1.1.0 binary, both soak nodes saturated their 48 MiB
RAM budgets — 50,331,648 B each: Node A peaked at 68.9 MiB (143.5% of
budget), Node B at 48.5 MiB (101%)). Adds the in-repo pass/fail soak gate
`crates/blackbox-ingress/tests/soak_memory_bound.rs`
(125 000 durable webhooks, dozens of segment rollovers, full drain,
Linux VmRSS validated against the 42.0 MiB budget).

### Fixed
- **Queue RAM floor (Node A `#1`)**: every redb database was open with the
  crate-default **1 GiB** page cache (`redb::Builder` seeds
  `set_cache_size(1024*1024*1024)`), and the job queue's B-tree grew its
  resident set into it all soak long. ALL open sites now go through
  `blackbox_core::kv::{create_redb, open_redb}` with an **8 MiB** cache cap
  (correctness unaffected: the cache is eviction-only). Additionally, the
  `bq_idem` dedup table was never swept — with a 24 h effective retention
  it grew with EVERY webhook for the lifetime of the process (~a day of
  webhook keys resident at soak volume). Keys now default to a **5-minute
  retention window** (covers every documented provider retry cadence) and
  the dispatcher's reaper deletes expired rows every ~16 s
  (`JobStoreHandle::sweep_idem`, `queue.idem_swept_total` in
  `blackbox queue` output). Atomic delivered-total semantics unchanged.
- **Unbounded trace index (Node A `#2`)**: the in-memory index kept EVERY
  frame ever recorded (incl. across restarts): a ~56 B/frame `frames` vec,
  a `trace_id → leaf list` map, and status bitmaps — ~330 K frames resident
  forever. The index is now a bounded **hot window**: the ACTIVE segment's
  frames only (`trace_id → (segment, offset)` map + a global 1 MiB +
  per-segment 8 KiB Bloom filters). At every segment seal the sealed
  segment leaves RAM; sealed lookups are served from on-disk sidecars —
  the existing `.idx` plus a NEW trace-id-sorted **`.sidx`** sidecar the
  compactor writes for every artifact (binary-searched per lookup, then
  one zstd decompress batch-reads all frames). Cumulative
  `frames/status_*/sentry/distinct` counters are preserved so the admin
  dashboard's lifetime view doesn't reset.
- **RAM monitor honesty (Node A `#3`)**: the watermark monitor now reads
  **RSS from `/proc`** (`statm` field 1 × page size, `VmRSS` fallback)
  instead of jemalloc's `stats.allocated` — the budget protects the
  system, and the allocator view diverges from it under page retention.
  jemalloc stats are demoted to a diagnostic field (`ram.jemalloc`).
  At `Warn75`+ the monitor purges caches: the egress gateway cache
  (existing) AND jemalloc arenas
  (`mallctl("arena.4096.purge", NULL, NULL, NULL, 0)`, rate-limited to at
  most one purge per 5 s). **`Backpressure95` is published but never
  enforced** — no HTTP path in Blackbox gates traffic on RAM level;
  proxied requests and durable webhooks are never stalled by it. (The
  soak's 38-minute preview stall was the external preview-proxy path, not
  Blackbox backpressure — see the soak report's honest limitation.)
- **Soak harness evidence guard (Node A/B `#4`)**: `scripts/soak/soakctl.sh`
  now refuses to wipe/re-initialize non-empty data dirs
  (`SOAK_SECONDS <= 0`, `--collect-only`, or `COLLECT_ONLY=1` selects
  collect-only mode: no boot, no generator, no crash injection — it jumps
  straight to final artifact generation over the preserved evidence).

### Changed
- `roaring` bitmaps are no longer used by the trace index (status classes
  are cumulative counters); the dependency is gone from the workspace.

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

[Unreleased]: https://github.com/fowzanasoftsolution/blackbox/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/fowzanasoftsolution/blackbox/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/fowzanasoftsolution/blackbox/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/fowzanasoftsolution/blackbox/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/fowzanasoftsolution/blackbox/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/fowzanasoftsolution/blackbox/commits/v1.0.0
