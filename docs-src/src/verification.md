# Verification

Every claim on this site is backed by an in-repo gate that runs in release mode
in CI, plus three 30-minute isolated soaks on real harnesses. Nothing is
asserted; everything is replayable.

## The gate matrix

Run any gate directly on a release binary (`blackbox p1-gate <n>` …
`blackbox p7-gate <n>`), or via `cargo test --workspace --release`
(217 tests as of v1.1.3).

| Phase | Gate | Proves |
|---|---|---|
| 1 | corrupt / kill9 / rss | torn-write + bit-flip recovery, real SIGKILL mid-append, idle RSS < 25 MB |
| 2 | causal link, stream+bomb, throughput | 3-record causal chain w/ PII redaction, 50 MB safe streaming, ≥ 8 K req/s |
| 3 | zero-lost webhooks, invisible restart, replay | 5,000/5,000 delivered, connection hold across app restart, deterministic replay |
| 4 | singleflight, poison guard, RAM shed, SimHash near-cache, audit chain | one upstream call per burst, no cache poisoning, watermarked shedding, 1,001-variant storm, tamper detection |
| 5 | rollover, resurrection, soak | zstd rollover + cold replay, auto-resurrection, 100 K-op flat-RSS soak |
| 6 | cold tier, bit-rot heal, canary update | S3 sync + tiered eviction, transparent healing, signed canary with rollback |
| 7 | shield, TLS, demo | rate limit + scanner drop metrics, hot-reloaded TLS, `demo --once` exit 0 |

The soak-memory gate deserves a note: `soak_memory_bound` boots the real stack
(ingress + redb JobStore actor + dispatcher + segment writer + compactor),
pushes 125,000 durable webhooks, drains completely and asserts the whole
process stayed under the 43 MiB soak gate (42.0 MiB monitored steady state
+ 1 MiB cross-environment slack; 39.20 MiB container, 42.23 MiB runner). It is
sensitive to transparent
huge pages: runner images ship THP=`always`, which inflates VmRSS on jemalloc,
so CI normalizes to THP=`madvise` first (see `.github/workflows/ci.yml`).

## Three 30-minute soaks

Identical cgroups and harness throughout (1 CPU / 1 GiB). The third run's
sandbox ran a newer kernel, so sub-MiB cross-kernel RSS comparisons are
approximate — disclosed rather than hidden.

| Metric | run-1 (2026-10-27) | re-run (2026-10-28) | v1.1.2c (2026-10-28) |
|---|---|---|---|
| Verdict | **FAIL** — 19/20, sampled-out | PASS — 20/20 | **PASS — 20/20** |
| Node A / B sampled-out | **7 / 0** | 0 / 0 | **0 / 0** |
| RSS peak A / B | 36.67 / 31.44 MiB | 32.00 / 28.23 MiB | **31.82 / 28.29 MiB** (189/189 `Normal`) |
| Compactions / frames indexed | 18 / 266,632 | 18–37 / 401,608 | **52 / ~398 K** |
| HTTP requests | 267,589 | 269,324 | **267,440** (148.6 req/s) |
| Transport errors | 0 | 0 | **0** |
| Crash recoveries | verified | 0.256 / 0.357 s | **0.203 / 0.257 s** |
| Cold reopen | PASS | PASS | **3/3 byte-equivalent** |

`0 sampled-out` here is *because RSS never left* `Normal` — the design intent is
that when a node IS squeezed, healthy telemetry sheds first and
errors/crashes/queue jobs survive at 100%. The gate harnesses pin exactly that
behavior; the soak proves it does not fire on healthy workloads.

The comparison charts are regenerated deterministically from raw evidence by
`scripts/soak/soak-graphs.py RUN1_RAW RUN2_RAW` (pure stdlib; the dated
evidence directories live outside the repo, hashed in the provenance table).
