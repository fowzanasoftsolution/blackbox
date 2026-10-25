"""Hermetic external payment provider (the "internet" of the simulation).

Real-world shape: POST /charge with an Idempotency-Key (order id). The
provider persists charges keyed by that idempotency key — retrying or
replaying the same checkout returns the ORIGINAL charge ("idempotent_replay":
true) instead of creating a second one. This is what makes the Persona C
proof meaningful: the replay DID call the provider again, and the provider
answered with the original charge — exactly one customer charge.

Endpoints:
  POST /charge    -> charge (idempotent by order_id)
  GET  /charges   -> full charge ledger (assertions + case study)
  GET  /count     -> {upstream_calls, charges, idempotent_replays}
"""

import time
import uuid

from fastapi import FastAPI, Request

app = FastAPI()
STATE = {"upstream_calls": 0, "charges": 0, "idempotent_replays": 0}
LEDGER = {}  # order_id -> charge dict


@app.get("/count")
def count():
    return STATE


@app.get("/charges")
def charges():
    return {"charges": list(LEDGER.values())}


@app.post("/charge")
async def charge(req: Request):
    STATE["upstream_calls"] += 1
    body = await req.json()
    order_id = body.get("order_id", "")
    if not order_id:
        return {"error": "order_id required"}, 400
    if order_id in LEDGER:
        STATE["idempotent_replays"] += 1
        out = dict(LEDGER[order_id])
        out["idempotent_replay"] = True
        return out
    time.sleep(0.02)  # provider-shaped latency
    rec = {
        "charge_id": "ch_" + uuid.uuid4().hex[:24],
        "order_id": order_id,
        "amount_cents": body.get("amount_cents", 0),
        "sku": body.get("sku", ""),
        "qty": body.get("qty", 1),
        "created": time.time(),
        "idempotent_replay": False,
    }
    LEDGER[order_id] = rec
    STATE["charges"] += 1
    return rec
