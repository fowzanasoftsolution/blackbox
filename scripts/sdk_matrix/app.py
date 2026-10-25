"""Real-World SDK matrix app — the OFFICIAL sentry-sdk + OFFICIAL openai
Python SDK, wired exactly the way `blackbox run` injects a normal app:

  SENTRY_DSN        http://public@127.0.0.1:<ingress>/1   (injected)
  OPENAI_BASE_URL   http://127.0.0.1:<egress>/egress/https/api.openai.com/v1
  BLACKBOX_EGRESS_URL http://127.0.0.1:<egress>

Two modes:
  * zero-config production mode — the openai client uses the injected
    OPENAI_BASE_URL verbatim (traffic flows to the real provider);
  * matrix mode (MOCK_OPENAI_URL set) — identical singleflight/cache/ledger
    gateway, hermetic upstream reached via the documented
    `X-Blackbox-Target` routing mode, so the matrix never spends real tokens.

The crash endpoint raises an UNCAUGHT exception; the official SDK's ASGI
integration captures it and ships a REAL wire envelope to the injected DSN.
The /llm endpoint goes through the official openai client with
`with_raw_response` so the matrix can read blackbox's `x-blackbox-cache`
response header straight from the SDK's response object.
"""

import os

import sentry_sdk
from fastapi import FastAPI, Request
from openai import OpenAI

SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        traces_sample_rate=1.0,
        environment="sdk-matrix",
        release="blackbox-sdk-matrix@1.0.0",
        debug=os.environ.get("SENTRY_DEBUG", "") not in ("", "0"),
    )

MOCK_OPENAI_URL = os.environ.get("MOCK_OPENAI_URL", "")
EGRESS_URL = os.environ.get("BLACKBOX_EGRESS_URL", "")
INJECTED_OPENAI_BASE = os.environ.get("OPENAI_BASE_URL", "")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-matrix-placeholder")

app = FastAPI()


def _trace_id_from_traceparent(tp):
    """Extract the 32-hex trace id from a W3C traceparent header."""
    if not tp:
        return None
    parts = tp.split("-")
    if len(parts) >= 2 and len(parts[1]) == 32:
        return parts[1]
    return None


def _make_client(incoming):
    if MOCK_OPENAI_URL and EGRESS_URL:
        # Matrix mode: hermetic upstream via X-Blackbox-Target (the egress
        # gateway's explicit routing mode) — same dedup/cache/ledger path.
        return OpenAI(
            base_url=f"{EGRESS_URL}/v1",
            api_key=API_KEY,
            default_headers={"X-Blackbox-Target": MOCK_OPENAI_URL},
        )
    # Zero-config production mode: the injected base URL verbatim.
    return OpenAI(base_url=INJECTED_OPENAI_BASE, api_key=API_KEY)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/echo")
def echo(incoming: Request):
    """Header echo — exactly what the proxy injected upstream. These are the
    bytes the official sentry-sdk ASGI middleware (and @sentry/node v8+ on a
    Node app) parse to continue a trace: sentry-trace + baggage must carry
    the SAME 32-hex trace id as x-blackbox-trace-id."""
    pick = ("baggage", "sentry-trace", "traceparent", "x-blackbox-trace-id")
    return {k: incoming.headers.get(k) for k in pick if incoming.headers.get(k) is not None}


@app.post("/crash")
def crash():
    # Uncaught on purpose — the official sentry-sdk ships the REAL envelope.
    raise RuntimeError("checkout crashed (real sdk matrix)")


@app.post("/flush")
def flush():
    sentry_sdk.flush(timeout=15)
    return {"flushed": True}


@app.post("/llm")
def llm(incoming: Request):
    trace_id = _trace_id_from_traceparent(incoming.headers.get("traceparent"))
    client = _make_client(incoming)

    extra_headers = {}
    if trace_id:
        # Correlate the provider call onto the caller's trace (the egress
        # gateway honors x-blackbox-trace-id / traceparent).
        extra_headers["x-blackbox-trace-id"] = trace_id

    raw = client.chat.completions.with_raw_response.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Say 'matrix ok' and nothing else."}],
        max_tokens=16,
        temperature=0,
        extra_headers=extra_headers or None,
    )
    headers = {k.lower(): v for k, v in raw.headers.items()}
    completion = raw.parse()  # official SDK model parsing (pydantic validation)

    return {
        "cache": headers.get("x-blackbox-cache"),
        "content": completion.choices[0].message.content,
        "model": completion.model,
        "usage_present": completion.usage is not None,
        "usage_total_tokens": completion.usage.total_tokens if completion.usage else None,
    }
