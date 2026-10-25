"""Buggy-Sheep Inc. — a tiny but REAL FastAPI + SQLite SaaS shop.

This is the reference app for the "startup-in-a-box" simulation. It is a
normal application: the official sentry-sdk for observability, the official
openai client for AI summaries, SQLite for state, an external payment API
for charges, and Stripe-signed webhooks as the ingestion path. It has never
heard of blackbox — it only consumes the five environment variables that
`blackbox run` injects:

  SENTRY_DSN              -> official sentry-sdk init()
  OPENAI_BASE_URL         -> official openai client base_url (egress FinOps proxy)
  BLACKBOX_EGRESS_URL     -> used for the X-Blackbox-Target routing mode

Endpoints:
  GET  /api/products      catalog (SQLite)
  POST /api/ai-summary    official openai SDK -> egress proxy (cacheable AI route)
  POST /api/checkout      charges the payment API FIRST, then processes the
                          coupon — the shipped v0.9 build dereferences a None
                          product when coupon == "NULL_PTR" (real uncaught
                          exception -> real sentry-sdk envelope)
  POST /webhooks/stripe   stripe-signature HMAC-verified webhook consumer
                          (blackbox's durable queue delivers here)
  GET  /healthz           liveness
  GET  /_sim/stats        internal counters for the simulation assertions

Checkout idempotency: order ids are DERIVED from the request body hash
("ord_" + sha256(body)[:16]) the way idempotent payment APIs work, so a
time-travel `blackbox replay` of the exact crashed request re-uses the SAME
order id — and the payment provider (mock) returns the original charge
instead of double-charging.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid

import httpx
import sentry_sdk
from fastapi import FastAPI, Request, Response
from openai import OpenAI

SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
if SENTRY_DSN:
    # The official SDK, zero config beyond the injected DSN. FastAPI/Starlette
    # integration is auto-enabled in sentry-sdk 2.x; uncaught exceptions ship
    # as real wire envelopes to the injected DSN (blackbox's ingress).
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        traces_sample_rate=1.0,
        environment="startup-sim",
        release="buggy-sheep@0.9.0",
    )

MOCK_OPENAI_URL = os.environ.get("MOCK_OPENAI_URL", "")   # hermetic mode
EGRESS_URL = os.environ.get("BLACKBOX_EGRESS_URL", "")
INJECTED_OPENAI_BASE = os.environ.get("OPENAI_BASE_URL", "")
PAYMENT_API_URL = os.environ.get("PAYMENT_API_URL", "")   # external provider
STRIPE_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_startup_sim")
SHOP_DB = os.environ.get("SHOP_DB", "/tmp/shop.db")

CATALOG = [
    ("sku-wool-01", "Hand-knitted wool scarf", 4900, 120),
    ("sku-wool-02", "Merino beanie", 2900, 200),
    ("sku-cer-01",  "Stoneware mug", 1800, 340),
    ("sku-cer-02",  "Ceramic pour-over set", 6400, 75),
    ("sku-lea-01",  "Vegetable-tanned belt", 5200, 90),
]

_lock = threading.Lock()
db = sqlite3.connect(SHOP_DB, check_same_thread=False)
db.execute("PRAGMA journal_mode=WAL")
db.execute(
    "CREATE TABLE IF NOT EXISTS products ("
    " sku TEXT PRIMARY KEY, name TEXT, price_cents INTEGER, stock INTEGER)"
)
db.execute(
    "CREATE TABLE IF NOT EXISTS orders ("
    " order_id TEXT PRIMARY KEY, sku TEXT, qty INTEGER, coupon TEXT,"
    " amount_cents INTEGER, status TEXT, charge_id TEXT, created REAL)"
)
db.execute(
    "CREATE TABLE IF NOT EXISTS stripe_events ("
    " event_id TEXT PRIMARY KEY, received REAL, payload TEXT)"
)
for sku, name, price, stock in CATALOG:
    db.execute("INSERT OR IGNORE INTO products VALUES (?,?,?,?)", (sku, name, price, stock))
db.commit()

app = FastAPI()
SIM = {
    "ai_summary_calls": 0,
    "checkouts_paid": 0,
    "checkouts_failed": 0,
    "webhook_events": 0,
    "webhook_bad_sigs": 0,
}


def _make_openai_client() -> OpenAI:
    if MOCK_OPENAI_URL and EGRESS_URL:
        # Hermetic mode: the SAME egress gateway path (cache/ledger/coalescing),
        # but the target is the local mock via X-Blackbox-Target routing.
        return OpenAI(
            base_url=f"{EGRESS_URL}/v1",
            api_key="sk-shop-placeholder",
            default_headers={"X-Blackbox-Target": MOCK_OPENAI_URL},
        )
    # Zero-config production mode: injected base URL verbatim.
    return OpenAI(base_url=INJECTED_OPENAI_BASE, api_key="sk-shop-placeholder")


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": time.time()}


@app.get("/api/products")
def products():
    rows = db.execute("SELECT sku, name, price_cents, stock FROM products").fetchall()
    return {"products": [
        {"sku": r[0], "name": r[1], "price_cents": r[2], "stock": r[3]} for r in rows
    ]}


@app.post("/api/ai-summary")
async def ai_summary(req: Request):
    """Official openai client through the egress FinOps proxy. The prompt is a
    pure function of the catalog, so identical shop state -> identical request
    body -> egress cache singleflight + HIT (that is the FinOps story)."""
    body = await req.json()
    sku = body.get("sku", "sku-wool-01")
    row = db.execute(
        "SELECT sku, name, price_cents, stock FROM products WHERE sku=?", (sku,)
    ).fetchone()
    prompt = (
        f"Write a 2-sentence storefront summary for: {row[1]} "
        f"(${row[2] / 100:.2f}, {row[3]} in stock). Mention the craft."
    )
    SIM["ai_summary_calls"] += 1
    client = _make_openai_client()
    tid = _current_trace_id()
    raw = client.chat.completions.with_raw_response.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=64,
        temperature=0,
        extra_headers={"x-blackbox-trace-id": tid} if tid else None,
    )
    cache_flag = raw.headers.get("x-blackbox-cache", "?")
    completion = raw.parse()
    return {
        "summary": completion.choices[0].message.content,
        "model": completion.model,
        "cache": cache_flag,
        "usage": {
            "prompt_tokens": completion.usage.prompt_tokens,
            "completion_tokens": completion.usage.completion_tokens,
        },
    }


def _current_trace_id():
    """The active sentry trace id — the SDK continued it from the proxy's
    sentry-trace/baggage headers, so this is the CLIENT'S trace id. Outgoing
    provider calls carry it as x-blackbox-trace-id (the egress gateway's
    documented correlation header) so the whole causal chain lands on ONE
    trace: ingress request -> payment egress -> crash envelope."""
    try:
        span = sentry_sdk.get_current_span()
        if span is not None:
            return span.trace_id
    except Exception:
        pass
    return None


def _charge_external(order_id: str, amount_cents: int, sku: str, qty: int) -> dict:
    """Charge the EXTERNAL payment API (through the egress proxy so the call
    is recorded on the trace). Payment POSTs are non-AI routes -> the egress
    gateway never caches them (BYPASS) — every attempt is a real upstream
    call, and the provider-side idempotency (order_id) is what makes retries
    and replays safe."""
    r = httpx.post(
        f"{EGRESS_URL}/charge",
        json={"order_id": order_id, "amount_cents": amount_cents, "sku": sku, "qty": qty},
        headers={
            "X-Blackbox-Target": PAYMENT_API_URL,
            "Idempotency-Key": order_id,
            "x-blackbox-trace-id": _current_trace_id() or "",
        },
        timeout=10.0,
    )
    r.raise_for_status()
    return r.json()


@app.post("/api/checkout")
async def checkout(req: Request):
    raw = await req.body()
    body = json.loads(raw)
    sku = body.get("sku", "sku-wool-01")
    qty = int(body.get("qty", 1))
    coupon = body.get("coupon", "")

    row = db.execute(
        "SELECT price_cents, stock FROM products WHERE sku=?", (sku,)
    ).fetchone()
    if row is None:
        return Response(json.dumps({"error": "unknown sku"}), status_code=404,
                        media_type="application/json")

    # Order id derived from the request bytes — idempotent across retries AND
    # across `blackbox replay` of the exact same request.
    order_id = "ord_" + hashlib.sha256(raw).hexdigest()[:16]
    with _lock:
        seen = db.execute("SELECT status FROM orders WHERE order_id=?", (order_id,)).fetchone()
    if seen and seen[0] == "paid":
        return {"order_id": order_id, "status": "paid", "idempotent": True}

    amount = row[0] * qty

    # ---- STEP 1: charge the external payment API FIRST -------------------
    charge = _charge_external(order_id, amount, sku, qty)

    # ---- STEP 2: apply the coupon (where v0.9 shipped the bug) -----------
    if coupon == "NULL_PTR":
        # FIX BUG-1042 (hotfix v0.9.1): the "NULL_PTR" sentinel is a debug
        # artifact from the payments team — treat it as an unknown coupon.
        # The STEP 1 charge stands; the order completes normally.
        discount_pct = 0
    else:
        discount_pct = 10 if coupon == "LAUNCH10" else 0

    total = amount - amount * discount_pct // 100
    with _lock:
        db.execute(
            "INSERT OR REPLACE INTO orders VALUES (?,?,?,?,?,?,?,?)",
            (order_id, sku, qty, coupon, total, "paid", charge["charge_id"], time.time()),
        )
        db.execute("UPDATE products SET stock = stock - ? WHERE sku=?", (qty, sku))
        db.commit()
    SIM["checkouts_paid"] += 1
    return {
        "order_id": order_id,
        "status": "paid",
        "amount_cents": total,
        "charge_id": charge["charge_id"],
    }


@app.post("/webhooks/stripe")
async def stripe_webhook(req: Request):
    """Webhook consumer — blackbox's durable queue delivers the raw bytes here
    (direct to the upstream, bypassing the ingress shield). Verify the
    Stripe HMAC exactly like production: stripe-signature: t=<ts>,v1=<hex>."""
    raw = await req.body()
    sig = req.headers.get("stripe-signature", "")
    parts = dict(p.split("=", 1) for p in sig.split(",") if "=" in p)
    ts, v1 = parts.get("t", ""), parts.get("v1", "")
    if not ts or not v1:
        SIM["webhook_bad_sigs"] += 1
        return Response("missing signature\n", status_code=400)
    expected = hmac.new(
        STRIPE_SECRET.encode(), f"{ts}.".encode() + raw, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, v1):
        SIM["webhook_bad_sigs"] += 1
        return Response("bad signature\n", status_code=400)
    event = json.loads(raw)
    with _lock:
        db.execute(
            "INSERT OR IGNORE INTO stripe_events VALUES (?,?,?)",
            (event.get("id", str(uuid.uuid4())), time.time(), raw.decode("utf-8", "replace")),
        )
        db.commit()
    SIM["webhook_events"] += 1
    return {"received": True}


@app.post("/api/flush")
def flush():
    # Determinism helper for simulations: force the SDK to ship pending
    # envelopes NOW instead of waiting for the background flush interval.
    if SENTRY_DSN:
        sentry_sdk.flush(timeout=15)
    return {"flushed": True}


@app.get("/_sim/stats")
def sim_stats():
    paid = db.execute("SELECT COUNT(*) FROM orders WHERE status='paid'").fetchone()[0]
    events = db.execute("SELECT COUNT(*) FROM stripe_events").fetchone()[0]
    return {
        "counters": dict(SIM),
        "orders_paid": paid,
        "stripe_events": events,
    }
