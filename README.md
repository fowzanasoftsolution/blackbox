<div align="center">

[![CI](https://github.com/Nsiowj1/blackbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Nsiowj1/blackbox/actions/workflows/ci.yml)
[![Release](https://github.com/Nsiowj1/blackbox/actions/workflows/release.yml/badge.svg)](https://github.com/Nsiowj1/blackbox/actions/workflows/release.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![30-min soak](https://img.shields.io/badge/30--min%20soak-20%2F20%20PASS-brightgreen.svg)](#verification-all-measured-on-a-2-vcpu-shared-runner)

</div>

# Project Blackbox — the Rust Omni-Sidecar

**One ~17 MB static binary that replaces four layers of infrastructure** — Sentry,
Temporal+Redis, NGINX and your egress cache — by living inside your app's process
space on a $5 VPS (2 cores / 4 GB) and recording *everything* with zero code
changes.

```
                        ┌──────────────────────────────────────────────────────────┐
 your users ──HTTPS──►  │  BLACKBOX  (one static binary, 48 MB RAM budget)         │
                        │                                                          │
                        │  1 INGRESS      TLS termination · rate limit · WAF shield │
                        │                 reverse proxy · flight recorder          │
                        │  2 QUEUE        durable webhooks · leases · DLQ · replay  │
                        │  3 EGRESS       LLM coalescing · cache · cost ledger      │
                        │  4 STORAGE      segments → zstd → S3/R2 · self-healing    │
                        │                                                          │
                        │  supervisor: RAM/disk watermarks · auto-resurrection      │
                        └───────────────┬──────────────────────────┬───────────────┘
                                        │                          │
                                 your app (any language)      S3 / R2 cold tier
```

**v1.1.3 status - all seven phases complete + the Pro differentiators.** 217
workspace tests green in release, **21/21 verification gates passing**, binary
**17.18 MB**, and a **30-minute isolated soak at 20/20** (three runs; latest
on main `85621c1`): both nodes peaked at **31.8 / 28.3 MiB** (48 MB budget,
189/189 samples `Normal`), **0 records sampled out** across 54 compactions /
**397,964 streamed-indexed frames**, both crash recoveries verified, both
nodes shut down rc=0, and the cold-data reopen byte-equivalent. v1.1.2
hardened the RAM story end to end: the rollover guard bounds the hot segment
and map, and compaction + sidecar indexing stream frame-by-frame instead of
materializing artifacts. v1.1.3 adds sealed-read corruption surfacing for the
cold-tier self-heal and pins the startup banner to `CARGO_PKG_VERSION` so it
can no longer drift from `blackbox --version`. v1.1 ships the two
Pro differentiators as pure Rust: a SimHash near-duplicate prompt cache and a
tamper-evident audit chain.

## Contents

- [Install](#install)
- [Experience everything in 60 seconds](#experience-everything-in-60-seconds)
- [Deploy to a bare VPS](#deploy-to-a-bare-vps)
- [The four engines](#the-four-engines)
- [The Pro differentiators (v1.1)](#the-pro-differentiators-v11)
- [Admin dashboard](#admin-dashboard)
- [CLI reference](#cli-reference)
- [Environment](#environment)
- [Storage watermarks & data layout](#storage-watermarks--data-layout)
- [Cold tier setup (S3 / R2 / MinIO)](#cold-tier-setup-s3--r2--minio)
- [Self-update (air-gap friendly)](#self-update-air-gap-friendly)
- [SDK compatibility matrix](#sdk-compatibility-matrix)
- [Deployment snippets](#deployment-snippets)
- [Verification](#verification-all-measured-on-a-2-vcpu-shared-runner)
- [Repository layout](#repository-layout)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Install

**One line (Linux x86_64 / aarch64)** — downloads the latest signed GitHub
release, verifies the SHA-256 checksum, installs to `/usr/local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/Nsiowj1/blackbox/main/scripts/install.sh | sh
```

**From source** — Rust stable, no C toolchain needed:

```bash
git clone https://github.com/Nsiowj1/blackbox && cd blackbox
cargo build --release --workspace
sudo cp target/release/blackbox /usr/local/bin/   # or ~/.local/bin
```

**Docker** (static binary, no runtime deps) — see
[Deployment snippets](#deployment-snippets).

Verify the installation: `blackbox demo --once` runs the full four-engine
smoke test headlessly and must exit 0.

## Experience everything in 60 seconds

```bash
blackbox demo
```

That single command boots a **self-contained topology** — an embedded shop app,
an LLM provider, a mock S3 bucket — and drives ~5 seconds of scripted traffic
through all four engines, then leaves the live dashboard running:

```
  A normal traffic … ok
  A2 bulk uploads (segment rollovers) … ok
  B coalesced LLM calls … ok (1 upstream calls · 3818 saved tokens)
  C webhook burst … ok (40/40 delivered · 0 lost)
  D checkout bug → Sentry crash … ok (trace f15b… · IngressHttp 500 + SentryCrash)
  E bit-rot self-heal … ok (corrupt .zst → digest-verified cold restore)

  ┌──────────────────────── 4 ENGINES ────────────────────────┐
  │ 1 INGRESS        requests 112 · indexed 194 · traces 112  │
  │ 2 QUEUE          webhooks 40/40 delivered · DLQ 0         │
  │ 3 EGRESS-FINOPS  LLM calls 24 → 1 upstream · 95.8% saved  │
  │ 4 STORAGE        uploads 2 · bit-rot heals 1              │
  └───────────────────────────────────────────────────────────┘

  dashboard: http://127.0.0.1:9690
  replay:    blackbox replay f15b… --target … --data …
```

`--once` runs the same scenario head-less and exits 0 — it is the Phase 7
acceptance gate and doubles as a smoke test for any deployment.

## Deploy to a bare VPS

### The zero-config path: `blackbox run`

Wrap ANY app — no code, no config file. Blackbox boots every engine, spawns
your app with five injected env vars, and supervises it forever:

```bash
blackbox run --upstream-port 3000 -- ./my-app
```

Your app now runs with:

```text
SENTRY_DSN                  = http://public@127.0.0.1:<ingress>/1     # crashes, wire-compatible
OTEL_EXPORTER_OTLP_ENDPOINT = http://127.0.0.1:<ingress>              # traces + logs
OPENAI_BASE_URL             = http://127.0.0.1:<egress>/egress/https/api.openai.com/v1
ANTHROPIC_BASE_URL          = http://127.0.0.1:<egress>/egress/https/api.anthropic.com
BLACKBOX_EGRESS_URL         = http://127.0.0.1:<egress>
```

Crash or hang → the circuit breaker trips instantly, in-flight requests are
**held** (not 502'd), the app respawns with full-jitter exponential backoff,
and held requests release the moment the port accepts again. Measured: two
`kill -9` cycles mid-traffic with **351,888 requests and 0 failures**.

### The front-door path: `blackbox serve`

Already running your app behind a process manager? Point Blackbox at it:

```bash
blackbox serve --upstream 127.0.0.1:3000 --listen 0.0.0.0:8080
```

### Native TLS — drop NGINX

```bash
# real certs (e.g. certbot / acme.sh output) — reloaded live, zero downtime:
blackbox serve --upstream 127.0.0.1:3000 \
  --tls-cert /etc/letsencrypt/live/app/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/app/privkey.pem

# instant HTTPS for staging / local (persisted under <data>/tls/):
blackbox serve --upstream 127.0.0.1:3000 --tls-self-signed
```

Certificate files are polled every 2 s; a rotation swaps the live
`rustls::ServerConfig` atomically — new connections get the new cert, existing
connections ride through, and a **corrupt half-written pair on disk never
disrupts serving** (the last good pair stays live).

### Rate limiting + scanner shield (on by default)

```bash
blackbox serve --upstream 127.0.0.1:3000 --rps 50 --burst 100   # 0 = unlimited
```

* **Token bucket, lock-free and sharded** — 64 shards × 256 slots of single
  `AtomicU64` buckets, CAS-only check, no mutex on the hot path. Keyed by
  `x-api-key` → `x-forwarded-for` → socket peer. Overflow answers
  **429 + Retry-After** in **<50 µs**, *before* your app or the disk sees the
  request.
* **Scanner shield** — `/.env`, `/.git/*`, `wp-admin`, `phpmyadmin`, path
  traversal (`../`, percent-encoded variants), backup suffixes and friends are
  dropped with a bare **404** before the limiter, the proxy, or the segment
  store ever see them. Every drop increments `guard.blocked_attacks` on the
  admin API; blocked noise is **never recorded** into the trace index.
  Disable with `--no-shield`.

## The four engines

### 1 · Ingress shield & flight recorder

A <1 ms-overhead reverse proxy that records everything and blocks nothing:
W3C `traceparent` injection, streaming tee capture (first 64 KB of text/JSON,
multipart/SSE/WebSocket bypass), wire-compatible **Sentry
`/api/{project}/envelope/`** and **OTLP `/v1/traces` + `/v1/logs`** ingestion,
PII scrubbing (aho-corasick) applied only to the telemetry copy — the raw
bytes in redb are never scrubbed. Measured 31,029 req/s proxied with **p99
added latency 166 µs**.

### 2 · Durable webhook queue (zero Redis)

`/webhooks/*` and `/jobs/*` get a **202 in <1 ms** after one group-commit to
redb, then delivery with lease semantics (`Pending → InFlight →
Delivered | DeadLetter`), full-jitter backoff, an upstream circuit breaker,
and 24 h idempotency dedup (Stripe/GitHub signature headers). HMAC signatures
survive byte-exactly. Deterministic **time-travel replay**:
`blackbox replay <trace_id> --target http://staging` re-runs a recorded
request against any environment — unrecorded upstream calls are **428-blocked**
in the replay sandbox.

### 3 · Egress FinOps proxy

Point `OPENAI_BASE_URL` (or `HTTP_PROXY`, or the `X-Blackbox-Target` header)
at the egress listener and every identical concurrent LLM call **coalesces
into one upstream request** — detached singleflight, byte-budgeted LRU cache,
BLAKE3 composite keys with zero cross-tenant leakage, soft-error guard (a 200
with `"error"` in the JSON is never cached), and a per-`(
tenant, provider, model )` **cost ledger** with token accounting. Measured:
24 identical calls → **1 upstream call, 95.8 % saved**.

### 4 · Storage lifecycle & self-healing

Append-only segments (32 B frames + CRC32C, 16 B alignment) rotate at the
size cap, compact to **zstd-3 (measured 194× ratio)** with `.idx` sidecars
(restarts rebuild the index with zero decompression), and sync to any
S3-compatible bucket via a **hand-rolled SigV4 client** (no aws-sdk). The
disk ring quota compresses at 75 %, FIFO-evicts cold segments at 85 % (crash
and 5xx segments stay **pinned** locally), and sheds healthy telemetry at 95 %
while crashes/queue jobs survive at 100 %. Bit-rot is **self-healing**: a
CRC/decompress failure on read transparently pulls the digest-verified
replica from the cold tier and atomically replaces the damaged file. v1.1.3
completes the trigger: a RAW segment keeps its torn-tail skip contract
(kill -9 mid-append is legitimate), but an unreadable frame inside a SEALED
`.zst` — the product of a completed, fsync'd seal — surfaces as
`StorageError::Corrupt`, so the heal actually fires instead of silently
skipping the segment forever.

## The Pro differentiators (v1.1)

Built to the product blueprint §6 spec — pure Rust, **zero ML models, zero
new dependencies**:

### SimHash near-duplicate prompt cache (L1 behind the exact match)

`OPENAI_BASE_URL` traffic pays upstream **once per prompt family**: byte-equal
calls hit the L0 exact cache, and a near variant — JSON key-order shuffle,
punctuation, case, whitespace, or a drifted order-id inside the prompt — is
then served **byte-identically** from the near cache, flagged
`x-blackbox-cache: SIMHASH(d=0..3)`:

* normalize (lowercase, punctuation → space, whitespace collapse, digit runs
  → `#`) → word 3-shingles → FNV-1a → 64-bit Charikar SimHash; a hit is a
  Hamming distance ≤ 3 (`BLACKBOX_SIMHASH_MAXDIST=0` disables the near cache),
* the near key is `BLAKE3(tenant ‖ auth ‖ method ‖ URL ‖ CONTROL)` where
  CONTROL freezes model, sampling knobs (temperature/top_p/n — deterministic
  prompts only), tools, roles and message shapes: only prompt *text* drifts,
* `/v1/embeddings` and `/v1/moderations` are excluded; the 75 % RAM watermark
  purges the near cache together with L0 (self-healing).

Measured: **1 upstream call answered a 1,001-request variant storm**
(all ≤ d=3, byte-identical), escape classes — a genuinely different prompt,
`temperature 0.7`, a different tenant — all paid upstream, and the whole
`prepare()` pipeline runs at **3.4 µs/prompt** (budget < 5 µs).

### Tamper-evident audit chain

Every queue, egress, replay and cold-tier state touch is appended to
`<data>/audit.log` as a SHA-256 hash-chained JSONL record — interior edits,
insertions and deletions all break the chain at their line. Every 1,024
records a checkpoint line commits the running anchor and fsyncs; export the
anchor externally (`blackbox audit current-anchor` → a KMS/cosign note) and
any **history truncation** becomes detectable on re-import. Verify any time:

```bash
blackbox audit verify --data ./data            # full recompute; exit 2 on tamper
blackbox audit verify --data ./data --anchor 5:8e9fd718…   # pinned history
blackbox audit current-anchor --data ./data    # print seq:hash for external anchoring
```

Zero signing keys needed — the chain is self-verifying locally and
enterprises pin their own anchor. Auditing is **on by default**
(`BLACKBOX_AUDIT=0` escapes).

## Admin dashboard

```
http://<host>:9690/          live dashboard (no JS framework, one embedded HTML file)
GET /api/stats               ingress/queue/egress/storage/guard/cold/breaker JSON
GET /api/finops              per-tenant cost ledger rows + savings %
GET /api/queue               pending / in-flight / DLQ counts
GET /api/trace/<32hex>       flight-recorder view of one trace (+ 1-click replay cmd)
POST /api/egress/purge       drop the entire FinOps cache
```

Lock it down with `BLACKBOX_ADMIN_TOKEN` (sent as `x-admin-token`).

## CLI reference

```
blackbox run          wrap + supervise any app (injects the 5 env vars)
blackbox serve        full node against an already-running upstream
blackbox demo         self-contained 4-engine demo (--once for CI)
blackbox replay <tid>  deterministic time-travel replay against --target.
                       Safe against a LIVE node: the dir is auto-cloned into
                       a scratch copy when `serve`/`run` holds the redb
                       locks (or pass --data-copy to force it) — recorded
                       mocks replay verbatim, unrecorded egress is 428-blocked,
                       the live node is never touched
blackbox queue status|retry-dlq      offline queue administration
blackbox audit verify|current-anchor offline audit-chain verification
                                     (--data, optional --anchor seq:hash;
                                     verify exits 2 on any tamper)
blackbox self-update  Ed25519-verified canary update (auto-rollback)
blackbox keygen | sign-update        update signing tooling
blackbox harness | bench | p2..p7-gate   verification harnesses
```

Serve/run flags that matter: `--listen` `--upstream` `--data` `--webhooks
"/webhooks/*"` `--egress-listen` `--admin-listen` `--mem-budget-mb`
`--max-segment-mb` `--disk-quota-mb` `--rps` `--burst` `--shield/--no-shield`
`--tls-cert` `--tls-key` `--tls-self-signed`.

## Environment

| Variable | Effect |
|---|---|
| `BLACKBOX_ADMIN_TOKEN` | require `x-admin-token` on the admin API |
| `BLACKBOX_COLD_ENDPOINT` / `_BUCKET` / `_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | attach the S3/R2 cold tier (path-style; R2/MinIO compatible) |
| `BLACKBOX_COLD_REGION` (default `us-east-1`) | SigV4 region |
| `BLACKBOX_SIMHASH_MAXDIST` | near-duplicate cache Hamming budget (default `3`; `0` disables the L1 near cache) |
| `BLACKBOX_AUDIT` | set `0` to disable the tamper-evident audit chain (on by default) |
| `BLACKBOX_VERIFY_PUBKEY` | override the Ed25519 verifying key for `self-update` (enterprise keys; `BLACKBOX_UPDATE_PUBKEY` still honored as the legacy name) |
| `NO_COLOR` | plain demo/summary output |

## Storage watermarks & data layout

`<data>/` holds `segment_NNNNNN.log[.zst]` (+ `.idx`), `jobs.redb` (queue),
`finops.redb` (ledger), `cold.redb` (tier index), `audit.log` (hash-chained
JSONL) and `tls/` (generated certs). RAM watermarks on the 48 MB budget:
75 % → purge egress + near caches · 85 % → head-
sample healthy 2xx telemetry · 95 % → backpressure. Disk watermarks on the
4 GB quota: 75 % → aggressive compaction · 85 % → FIFO evict cold segments ·
95 % → survival shedding (crashes + queue jobs always survive).

## Cold tier setup (S3 / R2 / MinIO)

```bash
export BLACKBOX_COLD_ENDPOINT=https://<acct>.r2.cloudflarestorage.com
export BLACKBOX_COLD_BUCKET=blackbox-cold
export BLACKBOX_COLD_ACCESS_KEY_ID=...
export BLACKBOX_COLD_SECRET_ACCESS_KEY=...
blackbox serve --upstream 127.0.0.1:3000
```

Sealed `.zst` + `.idx` pairs upload asynchronously (BLAKE3 + SHA-256 digests
recorded in `cold.redb`); evicted segments are restored transparently on
first touch; corrupt local replicas are healed from the bucket automatically.

## Self-update (air-gap friendly)

```bash
blackbox keygen --out-dir ./keys
blackbox sign-update --key ./keys/blackbox_ed25519.key --input ./blackbox.new --out update.sig
# on the server (official releases verify against the compiled-in key — zero config):
blackbox self-update --from ./blackbox.new --sig update.sig
```

Signature verify → redb snapshot → **isolated canary boot** (scratch data
dir, real `/healthz` + redb roundtrip) → promote/rollback. A tampered or
broken candidate can never touch the running binary; exit codes: `2` rejected
signature, `3` rolled back.

**Release key chain** — the verifying key resolves as: `--pubkey` >
`BLACKBOX_VERIFY_PUBKEY` > legacy `BLACKBOX_UPDATE_PUBKEY` >
`<data>/update.pub` > the **compiled-in official release key**
(`77b44dc4dd7f50fef3dc959963050fb490e78a15a438aed18418ce2109a1f153`).
Enterprise forks bake their own key at build time via
`BLACKBOX_RELEASE_PUBKEY=<64 hex>`.

## SDK compatibility matrix

`scripts/sdk_matrix/` proves the wire contracts against the **official**
`sentry-sdk` and `openai` Python clients on a real FastAPI app launched
with `blackbox run` (no code changes, injected env only):

```bash
python3 scripts/sdk_matrix/run_matrix.py   # 13+ legs: sentry crash capture
                                           # + brotli envelopes, openai
                                           # cache-HIT + dedup, replay,
                                           # baggage parity
```

Behaviors pinned by live SDK runs and frozen as Rust regression tests
(`verify_sdk`): `sentry-trace` injection so real SDK crash envelopes land
on the proxy trace, brotli (`Content-Encoding: br`) envelope decoding,
`blackbox replay --target <URL>` form, and W3C `baggage` injection —
`sentry-trace_id=<32-hex>,sentry-sampled=true` is injected/appended
upstream (caller entries preserved, the key never duplicated) so
@sentry/node v8+ and sentry-sdk propagate the exact same trace id across
async boundaries. CI runs the whole matrix on every push/PR (`sdk-compat`
job) plus an @sentry/node `continueTrace` parity check.

## Deployment snippets

**systemd** (`/etc/systemd/system/blackbox.service`):

```ini
[Unit]
After=network-online.target
[Service]
ExecStart=/usr/local/bin/blackbox run --listen 0.0.0.0:8080 \
  --tls-cert /etc/ssl/app/fullchain.pem --tls-key /etc/ssl/app/privkey.pem \
  --rps 100 --burst 200 --data /var/lib/blackbox -- ./my-app
Restart=always
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```

**Docker** (static binary, no runtime deps):

```dockerfile
FROM debian:bookworm-slim
COPY blackbox /usr/local/bin/blackbox
COPY my-app /srv/app
EXPOSE 8080 9690
CMD ["blackbox", "run", "--listen", "0.0.0.0:8080", "--data", "/data", "--", "/srv/app"]
```

## Verification (all measured on a 2-vCPU shared runner)

Gate sources live in `crates/*/src/gates_phase<n>.rs` and
`crates/*/tests/phase<n>_gates.rs` — every gate is also a CI test. Run any
gate directly: `blackbox p1..p7-gate <n>`, or the whole battery:
`cargo test --workspace --release` (217 tests) + `blackbox demo --once`.

| Phase | Gate | Measured result |
|---|---|---|
| 1 | torn write / bit-flip / kill -9 recovery | deterministic harness: **PASS** (crash-pinned fsync discipline) |
| 2 | causal link · stream safety · throughput | 3-record causal chain + PII redaction · 50 MB intact, bombs 413 · **31,029 req/s, p99 Δ166 µs, RSS 33.1 MB** |
| 3 | zero-lost webhooks · invisible restart · replay | **5000/5000** HMAC-intact, 0 dupes · **43,973 req, 0 failures** across a real app kill · replay 200-exact + 428 sandbox |
| 4 | singleflight · soft-error guard · RAM shed · SimHash near-cache · audit chain | 50 req/2 tenants → 2 upstream, 96 % saved · poisoned response never cached · Warn75 purge → 0 · **1 upstream call for 1,001 near variants** (all ≤ SIMHASH(d=3), byte-identical), 3 escape classes pay upstream, prepare() **3.4 µs/prompt** (< 5 µs) · 5-record chain verifies; edit → **hash break @line 2**, deletion → **seq break @line 4**, truncation vs exported anchor faults pre-pass, unanchored prefix verifies clean |
| 5 | rollover · auto-resurrection · 100K soak | **194× zstd**, cold replay via real CLI · **351,888 req, 0 failures** over 2 kill -9 · **106,007 ops**, 120 rotations, index == disk |
| 6 | cold tier · bit-rot heal · canary update | 10 PUTs + tiered eviction with crash pinning + byte-exact S3 restore · 3 heal rounds, digest-verified · tamper 30 ms reject, broken candidate auto-rollback |
| 7 | shield · TLS · demo | **5/5 burst + 5× 429 + Retry-After**, 6 scanner paths 404'd, **0 frames recorded** for attacks, <50 µs rejections · self-signed boot + **hot reload, 12 req 0 failures** + garbage-cert resilience · `demo --once` exit 0, **4 engines in 3.1 s** |

**Budgets:** binary **17.18 MB** (red line < 21 MB, final audit < 35 MB) ·
idle RSS ≈ 18 MB · load RSS 33.1 MB (< 35 MB) · 217 workspace tests green in
release.

**30-minute isolated soaks (Daytona sandbox, 1 CPU / 1 GiB cgroup):** the
latest run (v1.1.2c — main `85621c1`, binary `02d32685…d1d2ce`) posted
267,440 requests @ 148.6 req/s over the full 1800 s window with **0 transport
errors / 0 unexpected HTTP statuses**; **98,444/98,444 logical webhooks
delivered** with byte-identical bodies and all 4,926 deliberate duplicate
submissions deduped; **0 records sampled out, 0 dropped** on both nodes
(`Shed85` never fired — errors/slow traces stay at 100 % by design); RAM
peaks **31.82 MiB (Node A) / 28.29 MiB (Node B)** against the 48 MB budget,
**189/189 samples `Normal`** on both nodes; **54 compactions indexing
397,964 frames** through the streaming sidecar indexer with `.idx`/`.sidx`
present for every sealed segment; both injected app crashes recovered
health-verified (0.203 s / 0.257 s); the post-drain queue fully drained and
both nodes exited **rc=0**; the cold clone reopen produced byte-equivalent
records. Check-level verdict **20/20 PASS**; full raw evidence, manifests
and hashes live in the dated soak report directory outside this repository.

**Three-run comparison** (identical cgroups and harness throughout; the
third run's sandbox has a newer kernel — `7.0.0-38-generic` vs
`6.17.0-35-generic` — so sub-MiB cross-run RSS comparisons are approximate):

| Metric | run-1 (2026-10-27) | re-run (2026-10-28) | v1.1.2c (main `85621c1`) |
|---|---|---|---|
| Verdict | **FAIL** — 19/20, `no_record_drops_or_sampling` | PASS — 20/20 | **PASS — 20/20** |
| Node A sampled-out | **7** (t=1492.2 s) | 0 | **0** |
| Node B sampled-out | 0 | 0 | **0** |
| Node A RSS peak | 36.67 MiB (2× `Warn75`) | 32.00 MiB (all `Normal`) | **31.82 MiB** (189/189 `Normal`) |
| Node B RSS peak | 31.44 MiB | 28.23 MiB | **28.29 MiB** (all `Normal`) |
| Compactions / frames indexed (A · B) | 18/266,632 · 36/— | 18/266,689 · 37/134,919 | **18/266,690 · 36/131,274** |
| HTTP requests | 267,589 | 269,324 (149.6 req/s) | **267,440** (148.6 req/s) |
| Transport errors / unexpected statuses | 0 / 0 | 0 / 0 | **0 / 0** |
| Crash recoveries (T+600 s, T+1200 s) | verified | 0.256 s / 0.357 s | **0.203 s / 0.257 s** |
| Shutdown | rc=0 both | rc=0 both | **rc=0 both** |
| Node B clone reopen | PASS | PASS | **PASS** (3/3 cold traces byte-equivalent) |
| Binary SHA-256 | `10c22e7e…25d140c` | `33a3b351…ba83db2` | **`02d32685…d1d2ce`** |

**Post-release hardening on main (`85621c1`, shipped in v1.1.3):** sealed-
segment reads now **surface corruption** — a RAW segment keeps the torn-tail
skip contract (kill -9 mid-append legitimately leaves an unreadable tail),
but any unreadable frame inside a completed, fsync'd SEALED `.zst` is bit-rot
and fails with `StorageError::Corrupt`, so the caller triggers the cold-tier
self-heal instead of silently skipping the segment forever.

![Node RSS timeline — run-1 vs re-verification run](docs/soak/rss-timeline.svg)

![Run-1 vs re-verification comparison](docs/soak/soak-comparison.svg)

The charts are regenerated deterministically from the raw evidence by
`scripts/soak/soak-graphs.py` (pure stdlib, no chart dependencies); the full
comparison narrative lives in
[`docs/soak/V1.1.2-COMPARISON.md`](docs/soak/V1.1.2-COMPARISON.md).

## Repository layout

A Cargo workspace of eight crates (uniform `crates/*`, one binary crate):

| Crate | Contents |
|---|---|
| `crates/blackbox` | the CLI binary: node assembly (`node`), command plumbing (`ops`, `run`, `selfupdate`), dashboard, demo, benchmarks, and every verification gate |
| `crates/blackbox-core` | storage engine: frames, schema, segment store, compactor, breaker, queue actor, the audit chain |
| `crates/blackbox-ingress` | reverse proxy, tee capture, scrubber, WAF, rate limiter, TLS, trace index, gate harnesses |
| `crates/blackbox-queue` | durable jobs: leases, dispatcher, reaper, interceptor |
| `crates/blackbox-telemetry` | Sentry envelope + OTLP ingestion/wire formats |
| `crates/blackbox-egress` | gateway, singleflight, cache, finops ledger, SimHash near cache, gate harnesses |
| `crates/blackbox-cold` | hand-rolled SigV4, S3/R2 tier policy, mock bucket |
| `crates/blackbox-supervisor` | RAM/disk watermark monitors, process supervision |

Naming convention: `gates_phase<n>` modules hold the verification harnesses
for product phase *n*; everything else is named by role (`node`, `ops`,
`janitor`, `util`) — no historical sprint names survive.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — build protocol, gate inventory and
the commit convention. PRs that regress any gate fail CI by construction.

## Security

See [SECURITY.md](SECURITY.md) — how to report vulnerabilities (GitHub
private vulnerability reporting), supported versions, and the release-signing
discipline. Do not open public issues for security reports.

## License

Apache-2.0 — see [LICENSE](LICENSE).
