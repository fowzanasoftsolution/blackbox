# Project Blackbox — the Rust Omni-Sidecar

**One <16 MB static binary that replaces four layers of infrastructure** — Sentry,
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

**v1.2 status — all seven phases complete.** 165 workspace tests green in
release, **19/19 verification gates passing**, binary **15.9 MB**, load RSS
**33 MB** (48 MB budget). Phase 7 adds the launch polish: a lock-free request
shield, native TLS with zero-downtime cert reload, and a one-command demo.

---

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
replica from the cold tier and atomically replaces the damaged file.

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
blackbox replay <tid> deterministic time-travel replay against --target
blackbox queue status|retry-dlq      offline queue administration
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
| `BLACKBOX_VERIFY_PUBKEY` | override the Ed25519 verifying key for `self-update` (enterprise keys; `BLACKBOX_UPDATE_PUBKEY` still honored as the legacy name) |
| `NO_COLOR` | plain demo/summary output |

## Storage watermarks & data layout

`<data>/` holds `segment_NNNNNN.log[.zst]` (+ `.idx`), `jobs.redb` (queue),
`finops.redb` (ledger), `cold.redb` (tier index) and `tls/` (generated certs).
RAM watermarks on the 48 MB budget: 75 % → purge egress cache · 85 % → head-
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
python3 scripts/sdk_matrix/run_matrix.py   # 13 legs: sentry crash capture
                                           # + brotli envelopes, openai
                                           # cache-HIT + dedup, replay
```

Behaviors pinned by live SDK runs and frozen as Rust regression tests
(`verify_sdk`): `sentry-trace` injection so real SDK crash envelopes land
on the proxy trace, brotli (`Content-Encoding: br`) envelope decoding, and
`blackbox replay --target <URL>` form.

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

| Phase | Gate | Measured result |
|---|---|---|
| 1 | torn write / bit-flip / kill -9 recovery | deterministic harness: **PASS** (crash-pinned fsync discipline) |
| 2 | causal link · stream safety · throughput | 3-record causal chain + PII redaction · 50 MB intact, bombs 413 · **31,029 req/s, p99 Δ166 µs, RSS 33.1 MB** |
| 3 | zero-lost webhooks · invisible restart · replay | **5000/5000** HMAC-intact, 0 dupes · **43,973 req, 0 failures** across a real app kill · replay 200-exact + 428 sandbox |
| 4 | singleflight · soft-error guard · RAM shed | 50 req/2 tenants → 2 upstream, 96 % saved · poisoned response never cached · Warn75 purge → 0 |
| 5 | rollover · auto-resurrection · 100K soak | **194× zstd**, cold replay via real CLI · **351,888 req, 0 failures** over 2 kill -9 · **106,007 ops**, 120 rotations, index == disk |
| 6 | cold tier · bit-rot heal · canary update | 10 PUTs + tiered eviction with crash pinning + byte-exact S3 restore · 3 heal rounds, digest-verified · tamper 30 ms reject, broken candidate auto-rollback |
| 7 | shield · TLS · demo | **5/5 burst + 5× 429 + Retry-After**, 6 scanner paths 404'd, **0 frames recorded** for attacks, <50 µs rejections · self-signed boot + **hot reload, 12 req 0 failures** + garbage-cert resilience · `demo --once` exit 0, **4 engines in 3.1 s** |

**Budgets:** binary **15.9 MB** (red line < 21 MB, final audit < 35 MB) ·
idle RSS ≈ 18 MB · load RSS 33.1 MB (< 35 MB) · 165 workspace tests green in
release.

## Building from source

```bash
cargo build --release --bin blackbox     # Rust stable, no C toolchain needed
ls -la target/release/blackbox
cargo test --release --workspace         # 165 tests
./target/release/blackbox demo --once    # 19-gate smoke in one command
```

The workspace is eight crates: `blackbox-core` (frames/schema/compactor/
breaker), `blackbox-ingress` (proxy/tee/scrub/guard/tls/index), `blackbox-
queue` (leases/dispatch/replay), `blackbox-telemetry` (Sentry/OTLP), `black
box-egress` (gateway/singleflight/cache/ledger), `blackbox-cold`
(SigV4/tier/mock), `blackbox-supervisor` (RAM/disk monitors) and the `black
box` CLI.

## License

Apache-2.0 — see [LICENSE](LICENSE).
