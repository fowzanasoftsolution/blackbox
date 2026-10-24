# Project Blackbox — Rust "Omni-Sidecar" (v1.2: Phase 6 S3/R2 Cold Tier + Bit-Rot Self-Heal + Canary Self-Update)

One static Rust binary that sits alongside your app server and consolidates five
infrastructure layers: ingress shield, wire-compatible telemetry (Sentry/OTLP),
zero-Redis durable queue, egress FinOps/AI caching, and a storage lifecycle
(rotation → zstd compaction → ring-quota eviction). See the blueprint for the
full fact-checked architecture.

**Status: v1.2 — ALL SIX PHASES COMPLETE (Blueprint §4 Self-Healing Matrix: 100 %).**
150 workspace tests green in release; binary **19.9 MB** (Phase 6 budget < 20 MB,
final audit target < 35 MB); load RSS **29.8 MB** (target < 35 MB). All
Phase 1–5 gates still pass.

## Phase 6 verification gates (v1.2)

| Gate | Result |
|---|---|
| 1 — Evicted cold-tier time-travel replay | 5 sealed segments → **hand-rolled SigV4** client syncs all 5 `.zst` + `.idx` pairs to a local S3-compatible server (**10 PUTs**, BLAKE3 digests + `state = SyncedToCold` recorded in redb, per-trace cold index persisted); tiered `Evict85` evicts the **oldest HEALTHY segments first** while the **SentryCrash and 5xx segments stay PINNED** locally; after a restart with the segment gone, `get_trace` transparently re-fetches from S3 (**2 GETs**, digest-verified, atomically re-materialized) and serves the trace **byte-exact**; then the REAL `blackbox replay <tid>` CLI re-fetches the evicted segment from S3 itself and replays it — **200 with the exact recorded body**, unrecorded call **428-blocked** |
| 2 — Bit-rot self-healing | 8 seeded bytes flipped inside a live `segment_000001.log.zst` → a trace request detects the corruption (zstd/frame CRC verification), logs a **self-healing event**, pulls the clean replica from S3, verifies its BLAKE3 digest, **atomically replaces the damaged file**, and returns the **100 % valid trace**; re-corruption and sidecar corruption both auto-heal on request (**3 heals total, zero errors surfaced to the caller**); a tampered S3 replica is rejected by digest mismatch and never served |
| 3 — Bad-update canary auto-rollback | **tampered signature → rejected in ~30 ms with ZERO side effects** (no snapshot, no staging, no process spawned); a **validly-signed "broken" binary** (panics, exit 101) is caught by the isolated canary (`--self-test` on a scratch data dir) → **automatic rollback**: candidate deleted, `redb.bak` snapshot taken + verified as an openable redb file, working binary untouched (hash-identical); a **validly-signed healthy candidate** passes the canary and is **promoted on disk** (`blackbox.prev` kept, restart to activate) — all while the live server kept serving: **warmup 93 + update-cycle requests, 0 failures end-to-end** |

## Phase 5 verification gates (v1.1)

| Gate | Result |
|---|---|
| 1 — Hot-to-cold `.zst` rollover & cold replay | 1 647 records across **5 rollovers at the 1 MB cap**; every sealed segment compressed with **zstd-3 → 194× ratio** (spec ≥ 4×); each `.log.zst` ships a `BBIDX01` **`.idx` sidecar** (46 B/frame: trace_id, offset, len, seq, ts, class, kind) so restarts rebuild the index **without decompressing anything**; `blackbox replay <trace_id>` (the real CLI) reads the recorded charge **straight out of a compressed cold segment** — 200 with the exact recorded body, unrecorded call **428-blocked**; an `Evict85` reading **evicts the oldest `.zst` FIFO** (sidecar goes with it, active raw untouched); restart after full compaction opens a **fresh active segment at max_id + 1** and never resurrects a compacted id |
| 2 — `blackbox run` zero-config auto-resurrection | `blackbox run --upstream-port P -- blackbox env-child …` injects **all 5 env vars exactly** (`SENTRY_DSN=http://public@127.0.0.1:<ingress>/1`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OPENAI_BASE_URL=/egress/https/api.openai.com/v1`, `ANTHROPIC_BASE_URL`, `BLACKBOX_EGRESS_URL`); two real **`kill -9`** cycles mid-traffic → breaker trips instantly, requests are HELD, child respawned with full-jitter exponential backoff (100 ms → 5 s cap, 30 s stability reset), port-accept releases the hold → **351 888 requests, 0 failures** |
| 3 — Zero-leak 100K-op soak | mixed workload: **106 007 ops** (80 K ingress w/ unique trace ids + 10 K durable webhooks + 10 K Sentry crash envelopes + 6 K coalesced LLM egress) with **2 mid-soak child SIGKILLs** and **1 MB segment churn (~120 rotations)** → every webhook delivered (**10 000/10 000, DLQ empty, 0 dedup collisions**), index == disk (**120 074/120 074 frames**), 50 sampled traces readable across cold `.zst` + hot segments, **35 `.zst` segments sealed live by the background compactor**, zero writer drops, RSS **workload peak 105 MB → idle plateau 72–77 MB (drift ≤ 5 %, decaying)** — no monotonic growth after jemalloc decay |

## Phase 5 architecture additions

- **`blackbox-core::compactor`** — the storage lifecycle engine:
  - **Rotation** is size-cap driven (`SegmentConfig.max_segment_bytes`, CLI
    `--max-segment-mb`, default 64 MB, configurable down to 1 MB); rotation
    never stalls writers (the old segment is fsynced, the new one created,
    both under the writer task's single thread).
  - **Background compactor**: wakes on every rotation (watch channel) + a
    2 s tick and compresses sealed `.log` → `.log.zst` (zstd-3) with the
    crash-safe order `.idx` → `.zst.tmp`+rename → raw removal. Readers
    always prefer a raw `.log` over a `.zst` sibling, so a crash at any
    step leaves a state every reader already understands.
  - **`.idx` sidecar (BBIDX01)**: fixed 46-byte/frame entries carrying the
    full metadata the in-memory index needs — restarts rebuild via
    `read_meta_all` with **zero decompression** (sidecar-less segments fall
    back to decompress-on-demand; cold point-reads decompress the whole
    segment on first touch).
  - **Disk Ring Quota** (`DiskMonitor`, CLI `--disk-quota-mb`, default 4 GB):
    **75 %** → aggressive full compaction pass; **85 %** → FIFO eviction of
    the oldest cold `.zst` segments (down to 80 % of quota; raws are never
    deleted); **95 % (Emergency95)** → survival mode: the ingress Finalizer
    sheds healthy fast 2xx telemetry while **SentryCrash, 4xx/5xx and redb
    queue jobs are preserved at 100 %** (the durable queue never touches the
    segment path).
  - **Restart-after-compaction**: the active segment is always the highest
    `.log`; when the highest artifact is a `.zst` the store opens a fresh
    active at `max_id + 1` — sealed ids are never resurrected (with a raw+
    `.zst` crash window, the raw wins and the compactor re-seals).
- **`blackbox run` zero-config child supervisor** — `blackbox run
  --upstream-port 3000 -- python3 app.py` boots the full node and spawns the
  wrapped app with `SENTRY_DSN` / `OTEL_EXPORTER_OTLP_ENDPOINT` /
  `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `BLACKBOX_EGRESS_URL` injected
  (no code, no config files). The child is supervised: **crash** (exit ≠ 0 /
  SIGSEGV / SIGABRT) or **startup timeout** or **hang** (port stops accepting,
  4 consecutive probes) → `UpstreamHealth.record_connect_failure()` trips the
  breaker instantly (in-flight requests HOLD, no 502s) → respawn with
  full-jitter exponential backoff (100 ms base ×2ⁿ, 5 s cap, 30 s stability
  reset) → `record_success()` on first port-accept releases held traffic.
  `--pid-file` (rewritten every spawn) + `--status-file` (node addresses
  JSON) make it orchestrator-friendly; SIGINT/SIGTERM tear down the child.
- **Admin API additions**: `/api/stats` now reports `disk` (level / used /
  quota / pct) and `storage` (active segment, sealed raw vs cold `.zst`
  counts + bytes, compactions, evictions, bytes saved, frames indexed,
  `sampled_out` vs `disk_shed_out`).

## Phase 6 architecture additions

- **`blackbox-cold` (new crate, zero-bloat)** — the S3/R2 cold tier:
  - **Hand-rolled AWS Signature V4** (`sigv4.rs`) on the existing
    `sha2` + `hmac` stack — **no `aws-sdk-s3`** (the binary stays flat at
    19.9 MB). Canonical request construction is pinned to the AWS
    documentation's worked example by a unit test, so canonicalization
    drift breaks CI, not a customer's MinIO. Compatible with AWS S3,
    Cloudflare R2 (path-style, `region = "auto"`), MinIO and any
    SigV4-conformant store.
  - **Minimal client** (`client.rs`): PUT / GET / HEAD / ListObjectsV2
    (continuation-token aware, dependency-free XML) over the same
    hyper + rustls stack the egress proxy already links. What you sign is
    what you send: the canonical query string is shared between the
    signature and the request URI byte-for-byte.
  - **Local S3-compatible mock** (`mock.rs`) for gates/dev: verifies the
    `x-amz-content-sha256` payload hash against the body (real integrity)
    and rejects unsigned requests with 403; exposes put/get/list counters
    so the gates PROVE which requests hit the cold tier.
- **Seal → S3 sync** (`tier.rs`): the storage janitor uploads every sealed
  `.zst` + `.idx` pair (BLAKE3 digests + lengths + retention flags stored
  in the redb `seg_meta` table, `state = SyncedToCold`) and persists a
  **per-trace cold index** (`trace_id → segment`) that survives both
  evictions and restarts. Metadata is committed ONLY after both objects
  uploaded — an interrupted pass simply retries on the next wake.
- **Crash-pinned tiered retention**: `evict_cold_tiered` orders eviction
  candidates healthy-2xx-only first → 4xx → **crash/5xx pinned longest**;
  **unsynced segments are never evicted** (the tier classifier returns
  `None` until a verified replica exists). Without a cold tier the Phase 5
  FIFO behavior is preserved.
- **Transparent self-healing reads**: `TraceIndex::get_trace` (and the
  `blackbox replay` CLI) restore an evicted segment from S3 on demand and
  **bit-rot heal** a corrupt local `.zst` (zstd/frame verification →
  clean replica → BLAKE3 verify → atomic tmp+rename replace) — the caller
  never sees an error. redb slices are decoded through an `AlignedVec`
  copy (the Phase 1/4 alignment landmine, honored).
- **Ed25519 canary self-update** (`blackbox self-update`, §4.5):
  1. **Verify** — `ed25519-dalek` over SHA-256(candidate); a tampered
     signature is rejected INSTANTLY with zero side effects. Keys:
     `blackbox keygen` + `blackbox sign-update`; the verifying key comes
     from `--pubkey` / `BLACKBOX_UPDATE_PUBKEY` / `<data>/update.pub`.
  2. **Snapshot** — every `*.redb` is copied to `*.redb.bak` with a
     `redb.bak.json` manifest (`blackbox restore-snapshot` restores
     offline before the next start).
  3. **Canary** — the staged candidate is spawned as
     `blackbox self-test` on an ISOLATED scratch data dir (a broken
     candidate can never touch production state); success = a `/healthz`
     200 backed by a real redb roundtrip within the canary window
     (default 10 s), failure = panic / non-zero exit / hang.
  4. **Promote or roll back** — success renames the old binary to
     `blackbox.prev` and the candidate into place (the running server
     keeps serving its own inode — zero dropped traffic; restart
     activates); failure deletes the candidate and keeps the snapshot.
  The whole pipeline is rollback-safe by construction: every mutating
  step happens only after every preceding check passed.

## Phase 4 verification gates (v1.0)

| Gate | Result |
|---|---|
| 1 — Singleflight coalescing & FinOps savings | 50 concurrent identical LLM POSTs across 2 tenants @ 50 ms mock OpenAI → **exactly 2 upstream calls** (1/tenant, zero cross-tenant leakage — every body carries its own tenant marker), **48× `COALESCE`/`HIT`**, ledger reports **96.0 % cost & token savings** (48×750 µ$ saved / 50×750 baseline) |
| 2 — Cache poisoning & soft-error guard | upstream answers `200 OK` + `{"error":{"message":"rate_limit_exceeded"}}` on call #1 → **NOT cached** (MISS); call #2 reaches upstream again and succeeds (MISS, cached); call #3 is a **HIT** with the exact healthy body — upstream hit count stays at 2 |
| 3 — Self-healing RAM shed & audit | 75 % RAM watermark → **cache purged to 0 entries instantly** (watch-hub wake, transition-triggered); 85 % arms head-based sampling (100 % errors/slow, ~1 % healthy 2xx); 1 200-request load → full-system RSS **21–22 MB**; stripped release binary **16.2 MB** |

## Phase 4 architecture additions

- **`blackbox-egress` (Engine 4)** — the zero-cert FinOps proxy:
  - **Routing**: `OPENAI_BASE_URL=http://blackbox:9700` (provider aliases
    `/v1/chat/completions` → `api.openai.com`, `/v1/messages` →
    `api.anthropic.com`), `X-Blackbox-Target: https://…`, explicit
    `/egress/{https|http}/{host}/{path}`, standard absolute-form
    `HTTP_PROXY`, and blind `CONNECT` tunnels — **zero custom root CAs**;
    upstream TLS via rustls with bundled webpki roots, full plaintext
    inspection on every routed call.
  - **Detached singleflight**: one upstream call per identical burst; the
    leader runs in an independent `tokio::spawn` publishing to a
    `tokio::sync::watch`, so a disconnected first caller never cancels the
    coalesced waiters.
  - **Tenant-scoped cache**: `BLAKE3(tenant ‖ blake3(auth) ‖ method ‖
    canonical_url ‖ body)` keys (auth hashed before composition); GET/HEAD +
    deterministic AI POSTs only, `stream: true` excluded; byte-budgeted LRU
    (256 entries / 4 MiB); `x-blackbox-cache: HIT|MISS|COALESCE|BYPASS` on
    every response.
  - **Soft-error guard (Landmine #6)**: only `200` + complete JSON without a
    top-level `error` key / `"status":"failed"` is cached.
  - **FinOps ledger**: parses OpenAI `usage.prompt_tokens/completion_tokens`,
    Anthropic `usage.input_tokens/output_tokens`, and `x-api-cost-micros`;
    in-memory + redb-persisted rows per `(tenant, provider, model)` with
    tokens/cost spent vs saved and a live savings %.
  - **Replay integration**: every real upstream call emits an `EgressHttpMock`
    under the caller's `traceparent` / `x-blackbox-trace-id`.
- **Self-healing wiring**: the supervisor publishes RAM levels to a process-wide
  watch hub; Warn75 purges the egress cache to 0 bytes instantly, Shed85
  enables head-based ingress sampling (100 % errors/slow ≥ 1 s, ~1 % healthy
  fast 2xx), Backpressure95 is armed for telemetry 429s.
- **Embedded Admin (port 9690)**: single-page dashboard (include_str!, no
  assets) with live ingress req/s, trace inspector + 1-click replay command,
  queue/DLQ status, breaker + RAM watermarks + disk, egress cache stats and
  FinOps $ saved; JSON API under `/api/stats|finops|queue|trace/{id}` +
  `POST /api/egress/purge`; optional `BLACKBOX_ADMIN_TOKEN`.

## Phase 3 verification gates

| Gate | Result |
|---|---|
| 1 — Zero-Lost-Webhooks chaos | 5 000 signed webhooks burst; upstream killed (connection refused) for 1.5 s halfway through delivery → 100 % `202` (p50 ≈ 0.8–0.9 ms, p99 ≈ 1.8–4 ms on a shared 2-core runner), **5 000/5 000 delivered, every HMAC-SHA256 verified intact (raw bytes preserved), zero duplicates, idempotency dedup proven** |
| 2 — Invisible app restart | upstream killed for 400 ms under steady sync traffic → circuit breaker trips, requests are HELD and released on recovery → **36 967 requests, 0 failures, zero 502s** |
| 3 — Deterministic replay sandbox | record: checkout → egress Stripe call → Sentry crash → 500; replay: mock Stripe SHUT DOWN, fixed app re-executes → gets the EXACT recorded charge id, live API untouched, unrecorded egress **428-blocked** (`x-blackbox-replay-blocked: true`) |

## Phase 3 architecture additions

- **`blackbox-queue` (Engine 2)** — lease-based durable delivery:
  - `store`: single-writer group-commit actor over redb with FIVE tables
    (`bq_jobs`/`bq_due`/`bq_lease`/`bq_dlq`/`bq_idem`) updated atomically per
    transaction; rkyv pre-encoding on the caller side; atomic idempotency dedup
    (24 h retention) in the same commit as the insert; drain-first batching
    (no artificial fsync window on the 202 path); replies fanned out
    post-commit from inside the commit closure.
  - `dispatcher`: atomic `claim_batch` waves (Pending → InFlight under a
    30 s lease), raw-byte delivery (headers + body EXACTLY as received —
    HMAC-safe), 2xx → Delivered, 429/5xx/connect → full-jitter exponential
    backoff (`min(base·2^n, max)`), other 4xx → DeadLetter (full payload
    retained), lease reaper recovers InFlight jobs after kill -9.
  - `replay` + `interceptor`: forward-proxy egress listener that records
    `EgressHttpMock` frames in production (HTTP_PROXY interception) and serves
    them verbatim during `blackbox replay <trace_id> --target <url>` — exact
    `(method, canonical_url, SHA256(body))` matching with sequence-ordered
    fallback for nonce-bearing bodies, and a strict 428 sandbox guard against
    unrecorded outgoing calls.
- **Shared circuit breaker (`blackbox-core::breaker`)** — one atomic
  `UpstreamHealth` across ingress + queue: connect-refused trips immediately,
  consecutive 502/503/504 trip at threshold, a 50 ms TCP-connect prober flips
  Open → HalfOpen → Closed, and synchronous ingress requests are HELD on a
  watch channel for up to 3 s (connection hold) so brief app restarts are
  invisible. Idempotent-method requests additionally retry once after
  recovery using the tee's exact-byte capture.
- **Durable ingest route (blackbox-ingress::durable)** — `/webhooks/*`,
  `/jobs/*` (configurable): raw body + headers persisted unmodified into redb,
  `202 Accepted` + `x-blackbox-trace-id` + `x-blackbox-job-id` after one
  group-commit; duplicate `Idempotency-Key`/`X-GitHub-Delivery`/
  `Stripe-Signature` retries deduplicated; ONLY the telemetry copy is
  PII-scrubbed.

## Phase 2 verification gates (still passing)

| Gate | Result |
|---|---|
| 1 — End-to-end causal link | `IngressHttp + TelemetryLog + SentryCrash` correlated under one injected W3C trace id, causal order, PII redacted |
| 2 — Stream & bomb safety | 50 MB streamed intact @ ~440 MB/s, exactly 64 KB recorded, RSS 21 MB; gzip bomb (10 MB) + raw oversize → 413 |
| 3 — 2-vCPU overhead | ~35 800–38 000 req/s proxied (target 8 K), added latency p99 Δ ≈ 0.15 ms (target < 1.0 ms), RSS 30.9 MB (< 35 MB) |

## Workspace layout

```
blackbox/
├── crates/blackbox-core          # storage core (see below)
├── crates/blackbox-supervisor    # watchdog (unix-socket heartbeat, backoff restarts),
│                                 # jemalloc RAM watermarks (75/85/95 %), statvfs disk quota
├── crates/blackbox-ingress       # Engine 1 (Phase 2): reverse proxy, tee capture, PII scrub,
│                                 # W3C traceparent, roaring/bloom trace index, writer task
├── crates/blackbox-queue         # Engine 2 (Phase 3): lease-based durable queue, idempotency
│                                 # dedup, backoff+jitter dispatcher, deterministic replay +
│                                 # egress record/mock interceptor, offline queue admin
├── crates/blackbox-telemetry     # Engine 3 (Phase 2): Sentry envelope + OTLP (JSON+proto) parsing,
│                                 # gzip/zstd decode with 2 MiB anti-bomb cap, protobuf walker
├── crates/blackbox-egress        # Phase 4 stub: singleflight cache + cost ledger
└── bins/blackbox                 # CLI: run | harness | bench | serve | gate | p3-gate |
                                  #   replay <trace_id> --target <url> | queue status|retry-dlq
```

## blackbox-core components

| Module | What it guarantees |
|---|---|
| `schema` | rkyv **0.8** unified `TraceRecord` + `RecordPayload` enum (`IngressHttp`, `EgressHttpMock` with `seq_no`/`request_fingerprint`/response — the Phase 3 replay fields are baked into the disk format NOW), `TelemetryLog`, `SentryCrash`, `QueueJob`. Strict `rkyv::to_bytes::<rancor::Error>` / `rkyv::access::<Archived, rancor::Error>` idioms, bytecheck validation always on. |
| `frame` | 32-byte frame header (`magic 2B \| ver+flags 2B \| len 4B \| payload_crc32c 4B \| trace_id 16B \| header_crc32c 4B`), CRC32C over payload **and** header, zero padding to a 16-byte boundary so every payload on disk is 16-byte-aligned for zero-copy `rkyv::access`. |
| `segment` | Append-only engine: positioned `pwrite` appends (never `mmap` on active buffers — CMU landmine #1), 64 MB rotation, zstd-9 cold sealing, and **torn-write auto-truncation**: first invalid frame on open ⇒ `set_len` back to the last valid boundary, index rebuilt, WARN logged, idempotent. |
| `queue_actor` | Single-writer **Group-Commit Actor** over `redb`: bounded mpsc, ≤1 000 ops per ACID transaction or a 5 ms window, `Durability::Immediate`, replies strictly post-commit, 250 ms reader timeout, restart-durable. |

## Phase 1 verification (all passing)

```bash
cargo test --workspace --release     # 28/28

# Gate 1 — deterministic corruption (torn writes + bit flips):
blackbox harness corrupt --frames 2000 --seed 42 --mode both
#   → recovers byte-exact valid prefix, auto-truncates, idempotent

# Gate 2 — real SIGKILL mid-append:
blackbox harness kill9 --records 200000 --iterations 5
#   → kill -9 at 60–270 ms; 100 % of complete frames recovered, tail healed

# Gate 3 — idle RSS budget:
blackbox harness rss
#   → 14.6 MB idle RSS vs 25 MB budget (jemalloc background threads)

# Benchmarks:
blackbox bench segment --frames 50000
#   append: ~740 K ops/s (~820 MB/s, p50 655 ns, p99 4 µs)
#   recovery scan: 2.2 M frames/s (CRC) / 1.2 M frames/s (full rkyv+bytecheck decode)
blackbox bench queue --ops 50000 --concurrency 64
#   steady: 10 K durable enqueues/s (RTT p50 ≈ 6.4 ms = 5 ms group window)
#   burst: 2 000 concurrent → 225 K ops/s, batches saturate at the 1 000-op cap
#   restart durability: all rows intact
```

## Design decisions locked for this workspace

1. **hyper 1.x + hyper-util + tower + rustls** (Phase 2) — no pingora; one
   unified tokio runtime, zero C/OpenSSL friction beyond jemalloc/zstd.
2. **rkyv pinned to 0.8** (rancor error handling, `access`/`to_bytes` high API).
   Never mix 0.7 syntax.
3. **Replay schema baked in Phase 1** — `RecordPayload::EgressHttpMock`
   (seq_no, request_fingerprint, response_status/headers/body) is part of the
   on-disk format from day one; Phase 3 replay needs no disk migration.
4. **Apache-2.0** (full text in `LICENSE`).
5. **32-byte frame header + 16-byte padding** — enforced by construction and by
   unit tests (`payload_offset_alignment_across_many_frames`).

## Phase 2 — blackbox-ingress architecture

```
conn ──▶ TcpListener (TCP_NODELAY per accept)
          └─ hyper 1.x http1 conn (with_upgrades) + tower⇄hyper bridge
               ├─ /api/{id}/envelope/   Sentry wire-compatible → SentryCrash record
               ├─ /v1/traces,/v1/logs   OTLP JSON + protobuf   → TelemetryLog records
               └─ everything else → reverse proxy:
                    traceparent parse-or-generate + inject upstream
                    TeeBody<Incoming>  (request)  ── stream through, ≤64 KB side-copy
                    hyper-util pooled client (keep-alive, NODELAY) ⇒ upstream
                    TeeBody<Incoming>  (response) ── stream back, ≤64 KB side-copy
                    101 Switching Protocols → copy_bidirectional tunnel
                    Finalizer: scrub PII (aho-corasick) → TraceRecord ──try_send──┐
                                                                                  ▼
              bounded channel (16 384) ──▶ writer task: SegmentStore append,
              5 ms group-commit fsync, TraceIndex update (roaring bitmaps +
              bloom fast-negative + trace_id→(segment,offset) exact map)
```

Capture policy (per direction, from Content-Type): `text/*` (except
`text/event-stream`) and `application/json` / `*+json` are side-copied up to
64 KB; `multipart/*`, SSE, WebSocket upgrades and everything binary are
metadata-only. Bodies are never buffered end-to-end — chunks pass through
untouched.

PII scrubbing runs before framing: sensitive headers (`authorization`,
`cookie`, `set-cookie`, `x-api-key`, hyphen/underscore-bounded variants) get
`[REDACTED]`; JSON values under `password`, `secret`, `token`, `credit_card`,
`cvv` (case-insensitive, `access_token`-style prefixes/suffixes included)
are redacted in place — strings to `"[REDACTED]"`, numbers to `0`,
booleans/null to `null`, whole objects/arrays to `"[REDACTED]"`.

Telemetry ingestion is wire-compatible: Sentry envelopes are stored verbatim
(`event_id` + trace id from header `trace.trace_id` or event
`contexts.trace.trace_id`), gzip/zstd `Content-Encoding` decoded under a
strict 2 MiB output ceiling (413 past it), and OTLP spans/logs (JSON and
protobuf) are decoded into `TelemetryLog` records linked by `trace_id`.

## Phase 2 verification (all passing)

```bash
cargo test --workspace --release     # 82/82 (incl. the 3 gates as tests)

blackbox gate 1    # causal link: checkout → OTLP log + gzipped Sentry crash,
                   # all 3 records under one trace id in causal order, PII redacted
blackbox gate 2    # 50 MB stream intact @ ~440 MB/s, 64 KB recorded, RSS 21 MB;
                   # gzip bomb (~10 MB decompressed) and raw oversize → 413
blackbox gate 3    # keep-alive bench: ~38 K req/s proxied, p99 Δ ≈ 0.13 ms,
                   # RSS 29.5 MB under load

blackbox serve --listen 127.0.0.1:8080 --upstream 127.0.0.1:9000 --data ./data
```

## Notes for Phase 2

- Recovery policy on the ACTIVE segment is truncate-at-first-corruption;
  sealed/cold segments later get S3/R2 replica restore (blueprint §4.1).
- `SegmentStore::open` reuse path never truncates recovered data
  (`SegmentWriter::open_existing`), only brand-new segments are created fresh.
- Queue RTT is bounded below by the 5 ms group-commit window by design;
  burst workloads amortize fsyncs at up to 1 000 ops per commit.

## Phase 3 usage

```bash
# Co-located node: ingress shield + durable queue + egress recorder
blackbox serve --listen 127.0.0.1:8080 --upstream 127.0.0.1:9000 \
  --webhooks '/webhooks/*,/jobs/*' --hold-ms 3000 --data ./data
#   → POST /webhooks/stripe returns 202 + x-blackbox-job-id in ~1 ms
#   → set HTTP_PROXY=http://127.0.0.1:<egress-port> on your app to RECORD outgoing calls

# Deterministic time-travel replay of a recorded trace:
blackbox replay <trace_id> --target http://127.0.0.1:9000 --data ./data
#   → sandbox interceptor serves the recorded responses (428-blocks unrecorded calls)

# Offline queue administration (stop `serve` first — redb writer lock):
blackbox queue status --data ./data
blackbox queue retry-dlq --data ./data

# Phase 3 gates:
blackbox p3-gate 1   # zero-lost-webhooks chaos (kill upstream mid-burst)
blackbox p3-gate 2   # invisible app restart (circuit breaker hold)
blackbox p3-gate 3   # deterministic replay sandbox
```

## Phase 4 usage

```bash
# v1.0 full node: ingress shield + durable queue + egress FinOps proxy +
# supervisor self-healing + embedded admin dashboard
blackbox serve --listen 127.0.0.1:8080 --upstream 127.0.0.1:9000 \
  --egress-listen 127.0.0.1:9700 --admin-listen 127.0.0.1:9690 \
  --mem-budget-mb 48 --data ./data
#   → admin dashboard:      http://127.0.0.1:9690  (live req/s, FinOps $ saved,
#                            trace inspector with 1-click replay, watermarks)
#   → LLM/AI base-URL mode: OPENAI_BASE_URL=http://127.0.0.1:9700/v1
#                           ANTHROPIC_BASE_URL=http://127.0.0.1:9700/v1
#   → per-request override: X-Blackbox-Target: https://api.acme.ai
#   → explicit gateway:     POST /egress/https/api.acme.ai/v1/thing
#   → forward proxy:        HTTP_PROXY=http://127.0.0.1:9700 (CONNECT = blind splice)
#   → cache control:        x-blackbox-cache: enable|disable, x-blackbox-tenant: <id>
#   → optional API lock:    BLACKBOX_ADMIN_TOKEN=<secret> + x-admin-token header

# Phase 4 gates:
blackbox p4-gate 1   # singleflight coalescing + 96% FinOps savings (2 tenants)
blackbox p4-gate 2   # cache poisoning / soft-error guard
blackbox p4-gate 3   # 75% watermark cache purge + 85% sampling + RSS/binary audit
```

### Response header contract (egress)

| Header | Meaning |
|---|---|
| `x-blackbox-cache: HIT` | served from the tenant-scoped LRU (no upstream call) |
| `x-blackbox-cache: COALESCE` | served by singleflight (shared leader call, no extra upstream hit) |
| `x-blackbox-cache: MISS` | cacheable request that went upstream (leader) |
| `x-blackbox-cache: BYPASS` | non-cacheable request, streamed through (still recorded for replay) |
| `x-blackbox-trace-id` | 32-hex trace id (from your `traceparent` or freshly minted) |

### Self-healing watermarks

| Level | Trigger (of `--mem-budget-mb`) | Action |
|---|---|---|
| `Warn75` | ≥ 75 % | egress LRU purged to 0 bytes (instant, watch-hub) |
| `Shed85` | ≥ 85 % | + head-based ingress sampling: 100 % errors / slow (≥ 1 s), ~1 % healthy fast 2xx |
| `Backpressure95` | ≥ 95 % | + telemetry 429 backpressure (armed) |

## Phase 5 usage

```bash
# Zero-config wrapper — THE one-liner for any existing app. Boots the full
# node, injects the 5 observability/FinOps env vars, supervises the child:
blackbox run --upstream-port 3000 -- python3 app.py
#   → users hit the ingress (default 127.0.0.1:8080), the app is auto-healed:
#     crash / hang → breaker hold → respawn with backoff → release on recovery
#   orchestrator hooks: --pid-file ./app.pid --status-file ./node.json

# Storage lifecycle knobs on `serve` (also accepted by `run`'s node):
blackbox serve --listen 127.0.0.1:8080 --upstream 127.0.0.1:3000 \
  --max-segment-mb 64 --disk-quota-mb 4096 --data ./data
#   → rotation at 64 MB, zstd-3 sealing + .idx sidecars, ring quota:
#     75% → aggressive compaction · 85% → FIFO evict oldest .zst
#     95% → survival shedding (healthy 2xx only; crashes/5xx/queue 100%)

# Phase 6 gates:
blackbox p6-gate 1   # evicted cold-tier time-travel replay
blackbox p6-gate 2   # bit-rot self-healing
blackbox p6-gate 3   # bad-update canary rollback

# Phase 5 gates:
blackbox p5-gate 1   # 5×1 MB rollover → zstd-3 seal (>4x) → cold .zst replay → 85% eviction
blackbox p5-gate 2   # kill -9 the child twice mid-traffic → 100% HTTP 200 (env injection verified)
blackbox p5-gate 3   # 106K-op mixed soak: 2 child kills, 1 MB churn, flat idle RSS, 100% integrity
```

### Storage watermarks (disk)

| Level | Trigger (of `--disk-quota-mb`) | Action |
|---|---|---|
| `Compress75` | ≥ 75 % | aggressive full compaction pass (zstd-3 + `.idx`) |
| `Evict85` | ≥ 85 % | tiered eviction (Phase 6): healthy 2xx-only segments first (once synced to S3/R2), crash/5xx segments pinned; unsynced segments never evicted. Without a cold tier: FIFO as in Phase 5 |
| `Emergency95` | ≥ 95 % | survival: shed healthy fast 2xx telemetry; SentryCrash / 4xx / 5xx / queue jobs preserved 100 % |

## Phase 6 usage

```bash
# Cold tier: point the node at any S3/R2/MinIO endpoint (env-driven).
export BLACKBOX_COLD_ENDPOINT="https://<accountid>.r2.cloudflarestorage.com"  # or http://minio:9000
export BLACKBOX_COLD_BUCKET="blackbox-traces"
export BLACKBOX_COLD_REGION="auto"                 # us-east-1 for AWS
export BLACKBOX_COLD_ACCESS_KEY_ID="..."
export BLACKBOX_COLD_SECRET_ACCESS_KEY="..."
export BLACKBOX_COLD_PREFIX="segments/"            # default
blackbox serve --data ./data                       # seal → sync → tiered eviction → self-heal
blackbox replay <trace_id> --target http://app:3000 --data ./data   # reads through S3

# Self-update (Blueprint §4.5):
blackbox keygen --out-dir ./keys                   # once, OFF the box (keep the .key secret)
blackbox sign-update --key @./keys/blackbox_ed25519.key --in ./blackbox-new --out ./blackbox-new.sig
blackbox self-update --from ./blackbox-new --sig ./blackbox-new.sig \
    --pubkey $(cat ./data/update.pub) --data ./data
#   tampered sig  → exit 2, rejected instantly, nothing mutated
#   broken binary → exit 3, canary caught it, automatic rollback (redb.bak kept)
#   healthy       → exit 0, promoted (blackbox.prev kept; restart to activate)
blackbox restore-snapshot --data ./data            # offline, before the next start
```

Admin API additions (`GET /api/stats` → `cold`): `uploads`,
`upload_failures`, `bytes_uploaded`, `restores`, `heals`,
`corrupt_detected`, `traces_indexed`, `synced_segments`.

**Cold-tier environment variables**: `BLACKBOX_COLD_ENDPOINT`,
`BLACKBOX_COLD_BUCKET`, `BLACKBOX_COLD_ACCESS_KEY_ID`,
`BLACKBOX_COLD_SECRET_ACCESS_KEY` (all required to enable),
`BLACKBOX_COLD_REGION` (default `us-east-1`), `BLACKBOX_COLD_PREFIX`
(default `segments/`). Unset = v1.1 local-only behavior.
