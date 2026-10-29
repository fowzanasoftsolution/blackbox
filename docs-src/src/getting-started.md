# Getting started

Blackbox is a single static Rust binary that sits beside your app and does four
jobs at once: durable webhook/webjob queueing, telemetry capture (Sentry/OTLP
wire-compatible), an egress FinOps proxy (singleflight + caching + budget
ledger), and self-healing storage with a tamper-evident audit chain. Zero code
changes: you point your app's existing environment variables at the sidecar.

## Install

One line on any Linux box (x86_64 or aarch64):

```sh
curl -fsSL https://raw.githubusercontent.com/fowzanasoftsolution/blackbox/main/scripts/install.sh | sh
```

The installer did four things: fetched the release tarball for your
architecture, placed `blackbox` on your `PATH`, printed the SHA-256 of both the
archive and the unpacked binary, and dropped the release verifying key on disk
for `blackbox self-update` to pin.

## 60-second smoke

```sh
blackbox demo --once
```

Boots the real 4-engine node (ingress shield + TLS, durable queue, storage
writer + background compaction, egress FinOps proxy), fires a scripted burst
through the whole stack, prints per-engine evidence — `exit 0` expected. This
exact gate also runs in CI on every push.

## Wrap your app

`blackbox run` is the zero-config supervisor: it wraps any app in its own
process space, captures everything, watches RAM/disk watermarks and
auto-resurrects after a crash.

```sh
blackbox run --exec "node server.js" --env-file .env
```

The sidecar mounts itself in front of the app by injecting `OPENAI_BASE_URL`,
`SENTRY_DSN`-style env (or `HTTP_PROXY`) — your app just talks to the
endpoints it already knows.

## Serve a full node yourself

`blackbox serve` is the manual equivalent — the flag surface maps the exposed
surface one-to-one: listeners (`--listen`, `--egress-listen`, `--admin-listen`),
durable route spec (`/webhooks/*,/jobs/*` by default), budgets
(`--mem-budget-mb`, `--disk-quota-mb`, `--max-segment-mb`) and the shield
(`--shield`, `--rps`, `--burst`).

```sh
blackbox serve --upstream 127.0.0.1:3000 --admin-listen 127.0.0.1:9690
```

Open `http://127.0.0.1:9690/` for the admin console: RAM and disk watermarks,
the guard counters (WAF deflections, rate limits), the storage lifecycle, the
cold-tier self-heal story, the queue engine, trace inspection with
1-click replay, and the FinOps ledger per tenant/provider/model.

## Where things live

| Path | What it is |
|---|---|
| `<data>/` | hot segments (`.log`), sealed `.zst` segments, sidecar indexes, the redb KV store |
| `blackbox audit current-anchor` | printable checkpoint that pins your audit chain length |
| admin API | `GET /api/stats`, `GET /api/finops`, `GET /api/queue`, `GET /api/trace/{32-hex}`, `POST /api/egress/purge` |

Everything data-local stays local until you explicitly attach an S3/R2 cold
tier (`BLACKBOX_COLD_*` env) — the sidecar then double-writes completed
segments off-box for disaster resilience and bit-rot healing.
