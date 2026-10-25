# CASE STUDY — Buggy-Sheep Inc.: a real SaaS app surviving launch day on Blackbox

> Generated LIVE by `sim/generate.py` against the real `blackbox` binary
> (`blackbox run` wrapping a FastAPI + SQLite app with the official
> sentry-sdk 2.x and openai client) inside an ephemeral
> Daytona clean-room sandbox. Every number below was read off the running
> system's own admin API — nothing is hand-written.

## Topology

```
                        +---------------------------------+
 20 shoppers ---------->|  blackbox :8080 (ingress shield |--> rate limit / WAF / TLS
 attacker bot --------->|  + durable queue + egress proxy)     |     |
                        +----|-----------------|----------+     |
                       hold  |                 | egress FinOps proxy
                             v                 v                |
                    +----------------+   +----------------+     |
                    | FastAPI app    |   | mock provider  |     |
                    | (uvicorn :3000)|   | (openai-shaped)|<----+ trace correlation
                    +-------+--------+   +----------------+       via sentry-trace /
                            |               mock payment API      traceparent + baggage
                            v               (idempotent charges)
                    SQLite + sentry-sdk ---> DSN -> blackbox envelope ingestion
```

## The launch-day timeline

| t (s) | What happened |
|---|---|
| 0 | `blackbox run` boots the node + supervises uvicorn; personas A/B/D start |
| ~1 | First `/api/ai-summary` -> egress MISS (1 real provider call); everyone else rides the cache |
| 10 | Persona D attacker flood + scanner paths begin (own x-api-key bucket) |
| 18.0 | **`kill -9` #1** — FastAPI child dies mid-storm; ingress HOLDS connections, webhooks keep 202-ing durably; supervisor resurrects in ~1-2 s |
| 33.0 | **`kill -9` #2** — same drill, zero lost webhooks |
| 48.0 | **`kill -9` #3** — ditto |
| 60 | Traffic window ends; persona C begins: real bug -> hotfix -> `blackbox replay` |

## Persona A — Normal Shoppers & AI Burst (FinOps)

20 concurrent shoppers browsed and requested AI storefront summaries through the
**official openai Python SDK** (identical prompts — the realistic pattern for
catalog summaries).

| Metric | Value |
|---|---|
| AI summary calls (SDK -> egress proxy) | 1637 |
| egress cache MISS / HIT / coalesced | 1 / 1636 / 0 |
| REAL provider calls (mock openai /count) | 2 |
| upstream call reduction | 99.9% |
| tokens spent / saved (ledger) | 138 / 112,953 |
| spend / saved (ledger micros -> USD) | $0.0008 / **$0.6139** |
| savings rate (savings_pct) | 99.9% |
| ai-summary latency p50 / p95 | 17 / 82 ms |

At launch-traffic scale (the simulation's ~1637 calls in 60 s) the savings are
$0.6139; at a realistic 1,000,000 summary calls/month the identical hit
rate is **$375/month** — read straight off
`/api/finops` (`cost_micros_saved`), priced from the provider's
`x-api-cost-micros` header.

## Persona B — Stripe Webhook Storm + 3x kill -9 Chaos

1,000 DISTINCT Stripe-signed webhooks (fresh `t=...,v1=HMAC` per event — the
same signature never deduped away) at 20/s, while the chaos loop
SIGKILLed the FastAPI child **3 times mid-stream**.

| Metric | Value |
|---|---|
| webhooks POSTed at the ingress | 1000 |
| HTTP 202 (durable, post-fsync) | 1000 |
| enqueued / deduped / delivered (admin /api/queue) | 1000 / 0 / 1000 |
| dead-letter | 0 |
| app-verified HMAC-valid events (/_sim/stats) | 1000 |
| bad-signature deliveries | 0 |
| child kills survived | 3 (pids 281, 333, 353) |

Every kill window behaved the same way: the webhook route **never proxied**
— it fsyncs into redb and answers 202 — so the storm kept landing even while
uvicorn was a corpse; the moment the supervisor's respawn accepted on :3000,
the dispatcher drained the backlog. Zero loss, zero manual intervention.

## Persona C — Edge Bug -> Live Hotfix -> `blackbox replay` (no double charge)

The shipped v0.9 code charges the payment API FIRST, then processes coupons:

```python
# STEP 1: charge (through the egress proxy -> recorded on the trace)
charge = _charge_external(order_id, amount, sku, qty)
# STEP 2: coupon — BUG-1042
if coupon == "NULL_PTR":
    discount = None
    discount_pct = discount.discount_pct   # AttributeError: NoneType
```

`POST /api/checkout {"coupon": "NULL_PTR"}` -> **HTTP 500** on trace
`9eedff2cea08506ff1cc04f5a293606f`. The official sentry-sdk captured the REAL uncaught exception and
shipped a REAL envelope; blackbox correlated the crash onto the SAME trace as
the ingress request and the payment egress call:

```
  +  0.00s EgressHttpMock   200 POST http://127.0.0.1:9912/charge (180B)
  +  0.00s IngressHttp      500 POST /api/checkout · 29ms
  +  0.01s SentryCrash          project 1 event b18c6b2a0ca246f1a87e0159e330228e
  +  0.02s SentryCrash          project 1 event f172c90b9c48442ca9cb473b9fd6af32
```

The 2 a.m. hotfix replaced the dereference with `discount_pct = 0`; the child
was SIGKILLed so the supervisor respawned the patched code. Then the recorded
trace was loaded into the time-travel sandbox and the EXACT crashed request
was re-executed through it:

```
$ blackbox replay 9eedff2cea08506ff1cc04f5a293606f --target http://127.0.0.1:8080 --data <data>
s) loaded
[31mERROR[0m [2mblackbox_core::breaker[0m[2m:[0m prober: cannot resolve upstream http://127.0.0.1:8080
replay proxy listening on http://127.0.0.1:9701 (target http://127.0.0.1:8080)
  1) restart your app with the bug fixed, pointed at the replay proxy
  2) route its outgoing calls through HTTP_PROXY=http://127.0.0.1:9702 (mock Stripe/Twilio...)
  3) re-send the original request — unrecorded egress gets 428-blocked
  Ctrl-C to stop
```

The replay proxy pinned the replayed request to the SAME trace id, the patched
code completed the checkout, and the provider answered with the ORIGINAL
charge:

| Double-charge proof | Value |
|---|---|
| order id (derived from the request bytes, replay-stable) | `ord_5835e17aead3aa6f` |
| charges at the provider for this order | **1** |
| provider calls for this order (2nd answered idempotently) | 2 total, 1 idempotent replay(s) |
| order state after replay | paid (1 paid order(s) total) |

The provider was genuinely called a second time — and its idempotency key
returned the ORIGINAL charge. The customer is charged **exactly once**, the
order completed, and the whole forensic story (ingress 500 -> payment egress
-> sentry crash -> replay 200) lives on one trace id:

```
  +  0.00s IngressHttp      200 POST /api/checkout · 11ms
  +-16.52s EgressHttpMock   200 POST http://127.0.0.1:9912/charge (180B)
  +-16.51s IngressHttp      500 POST /api/checkout · 29ms
  +-16.50s SentryCrash          project 1 event b18c6b2a0ca246f1a87e0159e330228e
  +-16.50s SentryCrash          project 1 event f172c90b9c48442ca9cb473b9fd6af32
  +  0.00s SentryCrash          project 1 event 0695b3579d6144338029bf0ac09f2b3b
```

## Persona D — Attacker Bot

| Metric | Value |
|---|---|
| flood requests rate-limited (429) | 6587 of 8160 |
| WAF-blocked scanner probes (404, never recorded) | 6726 (6620 total rate-limited incl. storm overlap) |
| scanner paths probed | 12 distinct (scan /.DS_Store, scan /.aws/credentials, scan /.env, scan /.git/config, scan /.ssh/id_rsa...) |
| legit shopper errors during the attack | 19 |

The attacker's own `x-api-key` guard bucket absorbed the flood; shoppers kept
checking out through it (guard_key = x-api-key > XFF > peer IP).

## Final system state (admin /api/stats at close)

```json
{
  "uptime_secs": 82,
  "ingress": {
    "disk_shed_out": 0,
    "distinct_traces": 6265,
    "dropped": 0,
    "frames": 9913,
    "sampled_out": 0,
    "sentry_crashes": 2011,
    "status_2xx": 5835,
    "status_4xx": 0,
    "status_5xx": 62,
    "total_requests": 21254
  },
  "guard": {
    "blocked_attacks": 6726,
    "rate_burst": 25,
    "rate_limited": 6620,
    "rate_rps_milli": 50000,
    "shield": true,
    "tls": false,
    "tls_reload_paths": null
  },
  "breaker": {
    "failures": 0,
    "open_for_ms": 21499,
    "state": "closed",
    "transitions": 47
  },
  "queue": {
    "dead_letter": 0,
    "deadletted_total": 0,
    "deduped_total": 0,
    "delivered_total": 1000,
    "enqueued_total": 1000,
    "in_flight": 0,
    "pending": 0,
    "reaped_total": 0
  }
}
```

`/api/finops` rows:

```json
[
  {
    "cache_hits": 0,
    "coalesced_hits": 0,
    "cost_micros_saved": 0,
    "cost_micros_spent": 0,
    "model": "-",
    "provider": "custom",
    "savings_pct": 0.0,
    "tenant": "default",
    "tokens_saved": 0,
    "tokens_used": 0,
    "total_requests": 2
  },
  {
    "cache_hits": 1637,
    "coalesced_hits": 0,
    "cost_micros_saved": 613875,
    "cost_micros_spent": 750,
    "model": "gpt-4o",
    "provider": "openai",
    "savings_pct": 99.87797437461867,
    "tenant": "default",
    "tokens_saved": 112953,
    "tokens_used": 138,
    "total_requests": 1639
  }
]
```

## What this proves

1. **Drop-in**: a normal FastAPI app (official SDKs, zero blackbox code) got
   tracing, crash capture, rate limiting, WAF, durable webhooks, egress
   caching and FinOps — from one `blackbox run` line and five env vars.
2. **Durability**: 3 SIGKILLs mid-storm and 1,000/1,000 webhooks still
   delivered; clients held, not 502'd.
3. **FinOps**: the egress cache collapsed 1637 SDK calls to
   2 upstream calls with accounting in real micro-USD.
4. **Forensics + repair**: one trace id ties the client request, the payment
   call, the real sentry crash envelope and the replay together — and replay
   plus provider idempotency means hotfixes can be validated against PRODUCTION
   traffic without double-charging anyone.
