# startup-sim — "Startup-in-a-Box": a launch day, simulated for real

A self-contained reference deployment that proves what Blackbox does for a
normal early-stage SaaS on a $5 VPS — using a REAL app (FastAPI + SQLite +
official sentry-sdk + official openai client), REAL failure modes, and REAL
numbers read off Blackbox's own admin API.

## The app: Buggy-Sheep Inc.

A tiny hand-craft storefront with the endpoints a real shop actually has:

| Endpoint | What it does |
|---|---|
| `GET /api/products` | catalog from SQLite |
| `POST /api/ai-summary` | official openai SDK -> egress FinOps proxy (cacheable AI route) |
| `POST /api/checkout` | charges an **external payment API first**, then applies the coupon — v0.9 ships BUG-1042: `coupon == "NULL_PTR"` dereferences a `None` product (real uncaught exception, real sentry-sdk envelope) |
| `POST /webhooks/stripe` | Stripe-HMAC-verified webhook consumer (Blackbox's durable queue delivers here) |

The app has **zero Blackbox code** — it only consumes the five environment
variables `blackbox run` injects (`SENTRY_DSN`, `OPENAI_BASE_URL`,
`ANTHROPIC_BASE_URL`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `BLACKBOX_EGRESS_URL`).

Checkout idempotency: order ids are derived from the request bytes
(`ord_ + sha256(body)[:16]`), the way idempotent payment APIs work — so
replaying the exact crashed request re-uses the same order id, and the
payment provider returns the original charge instead of double-charging.

## The simulation (sim/generate.py)

| Persona | Script | What it proves |
|---|---|---|
| **A — Normal Shoppers & AI Burst** | 20 concurrent users, 60 s | egress cache singleflight collapses identical SDK calls; FinOps $ read off `/api/finops` (`cost_micros_saved`, priced via `x-api-cost-micros`) |
| **B — Stripe Webhook Storm + Chaos** | 1,000 DISTINCT signed webhooks at 20/s; `kill -9` the FastAPI child 3x mid-stream | durable ingestion (202 during the dead windows), supervisor resurrection, 1000/1000 delivered, zero dead letters |
| **C — Edge Bug + Live Fix + Replay** | `coupon="NULL_PTR"` -> 500 -> hot-patch `app/shop.py` -> supervisor respawn -> `blackbox replay <trace_id>` | the full forensic chain (ingress 500 + payment egress + SentryCrash on ONE trace) and **exactly one customer charge** |
| **D — Attacker Bot** | rate-limit flood + `/.env`-style scanner paths | per-key guard buckets isolate the attacker; WAF 404s never touch the trace index |

## Run it

```sh
pip install fastapi uvicorn sentry-sdk openai httpx
sh sim/run_sim.sh /path/to/blackbox      # default: blackbox on $PATH
```

Exit 0 = every assertion green. The run leaves `CASE_STUDY.md` next to this
README with the numbers from YOUR machine (the committed CASE_STUDY.md was
generated inside an ephemeral Daytona clean-room sandbox: pristine Debian,
no warm caches).

## Files

```
startup-sim/
├── README.md            this file
├── CASE_STUDY.md        the generated real-run benchmark (committed)
├── app/
│   ├── shop.py          the SaaS app (buggy v0.9 line included, hot-fixed by the sim)
│   └── payment_mock.py  the external payment provider (idempotent by order id)
└── sim/
    ├── generate.py      the 60-second 4-persona traffic & chaos driver
    ├── mock_openai.py   hermetic OpenAI-shaped upstream (usage + x-api-cost-micros)
    └── run_sim.sh       one-shot orchestrator
```
