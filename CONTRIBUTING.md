# Contributing to Blackbox

Thanks for looking at the code. This document covers how the repo is laid
out, how to build and verify, what the verification gates are, and the
commit conventions — so a change that passes here passes CI.

## Repository layout

A Cargo workspace, eight crates, one binary:

```
crates/
  blackbox               the CLI: node assembly, ops, run wrapper,
                         self-update, dashboard, demo, benchmarks
  blackbox-core          frames, schema, segment store, compactor,
                         breaker, queue actor, audit chain
  blackbox-ingress       proxy, tee, scrubber, WAF, rate limit, TLS, index
  blackbox-queue         durable jobs: leases, dispatcher, reaper
  blackbox-telemetry     Sentry envelope + OTLP wire formats
  blackbox-egress        gateway, singleflight, cache, ledger, simhash
  blackbox-cold          hand-rolled SigV4, tier policy, mock bucket
  blackbox-supervisor    RAM/disk watermark monitors, supervision
```

### Naming convention

- Verification harnesses are always `gates_phase<n>.rs` (or
  `tests/phase<n>_gates.rs`) — the phase number is part of the product
  (the blueprint's Phase 1..7 spec), so it is the *one* historical number
  that stays.
- Everything else is named by what it does: `node`, `ops`, `janitor`,
  `util`, … — not by when it was written.

## Building and testing

Requirements: Linux (or a Linux container), Rust stable, `libzstd-dev`.

```bash
cargo build --workspace --release
cargo test  --workspace --release    # 217 tests
./target/release/blackbox demo --once   # 4-engine smoke gate, exit 0 expected
```

Note: development happened in a disposable Linux container (`bb-build`,
workspace mounted at `/ws/blackbox`) because the Windows-native toolchain
cannot build this stack end-to-end. If you develop on a non-Linux host, the
container sync protocol that CI-equivalently verifies everything:

```bash
# 1. pack the repo (host side; target/ and .git stay local)
tar --exclude=./target --exclude=./.git -czf /tmp/bb.tgz .

# 2. refresh the container tree
docker cp /tmp/bb.tgz bb-build:/tmp/bb.tgz
docker exec bb-build bash -c 'cd /ws && rm -rf blackbox/crates && tar -C blackbox -xzf /tmp/bb.tgz'

# 3. build + full battery (use bash -c, not a login shell)
docker exec bb-build bash -c 'cd /ws/blackbox && cargo build --workspace --release 2>&1 | tail -3'
docker exec bb-build bash -c 'cd /ws/blackbox && cargo test  --workspace --release 2>&1 | grep -E "test result" | sort | uniq -c'

# 4. the release gate
docker exec bb-build bash -c 'cd /ws/blackbox && ./target/release/blackbox demo --once'
```

CI runs the same steps (`cargo build/test --workspace --release`,
`blackbox demo --once`, and the real-SDK matrix). Any failure blocks merge.

## The verification gates

Every feature ships with a gate: a self-contained harness that proves the
feature works under load, crash and tampering. Run any gate directly on a
release binary (`blackbox p1-gate <n>` … `p7-gate <n>`), or via the test
harnesses integrated in `cargo test`.

| Phase | Gate | Proves |
|---|---|---|
| 1 | corrupt / kill9 / rss | torn-write + bit-flip recovery, real SIGKILL mid-append, idle RSS < 25 MB |
| 2 | causal link, stream+bomb, throughput | 3-record causal chain w/ PII redaction, 50 MB safe streaming, ≥ 8 K req/s |
| 3 | zero-lost webhooks, invisible restart, replay | 5,000/5,000 delivered, connection hold across app restart, deterministic replay |
| 4 | singleflight, poison guard, RAM shed, SimHash near-cache, audit chain | one upstream call per burst, no cache poisoning, watermarked shedding, 1,001-variant storm, tamper detection |
| 5 | rollover, resurrection, soak | zstd rollover + cold replay, auto-resurrection, 100 K-op flat-RSS soak |
| 6 | cold tier, bit-rot heal, canary update | S3 sync + tiered eviction, transparent healing, signed canary with rollback |
| 7 | shield, TLS, demo | rate limit + scanner drop metrics, hot-reloaded TLS, `demo --once` exit 0 |

The full matrix with measured numbers is in the
[README](README.md#verification).

When you add or change an engine: extend the phase's gate file rather than
inventing a new folder of ad-hoc tests, keep the existing fixture contracts
(the gate JSON fixtures are byte-sensitive — see comments in
`gates_phase4.rs`), and make sure the suite count stays green.

## Commit conventions

Subjects follow `area: summary` in the imperative, e.g.:

```
simhash: near-duplicate prompt cache + tamper-evident audit chain (v1.1.0)
replay: concurrent live-server replay via redb-lock detection + --data-copy scratch clone
fix(release): sign-update uses --input (not --in)
```

- One logical change per commit; the prefix names the area (`waf:`,
  `tls:`, `ci:`, `release:`, `sdk:` are established prefixes).
- Version bumps happen at tag time (tags trigger the release pipeline) —
  do not ship version strings inside unrelated commits.
- Tags `v*` are annotated and are the only release trigger.

## House rules

- **No secrets in the repo, ever.** No tokens, key files or private seeds in
  source, fixtures or git history. The compiled-in release *verifying* key
  (public half, by design) is the only baked-in key material.
- Destructive or unreachable test code (`#[allow(dead_code)]` on shipped
  paths) is rejected; if a module exists it should compile in the default
  build with zero warnings.
- Keep the dependency tree lean; the binary budget is
  < 21 MB (currently 17.1 MB).
- Rebranding-in-files (editor config, IDE cruft) should not appear in diffs.

## Reporting security issues

Do **not** open public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md) for private disclosure.
