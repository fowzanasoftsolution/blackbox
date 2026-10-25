"""Hermetic OpenAI-compatible upstream for the startup simulation — wire-shaped
exactly like chat completions so the OFFICIAL openai SDK must parse it
(id / object / created / model / choices / usage). Counts real upstream hits
so the case study can prove deduplication (N SDK calls -> 1 upstream call)
and price the savings from the returned usage.
"""

import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
STATE = {"upstream_calls": 0}

# gpt-4o pricing: $2.50/1M input + $10.00/1M output tokens.
# 42 input + 27 output tokens = 42*2.5 + 27*10 = 375 micro-USD per call.
COST_MICROS = 375


@app.get("/count")
def count():
    return STATE


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    STATE["upstream_calls"] += 1
    body = await req.json()
    time.sleep(0.12)  # provider-shaped latency (gives singleflight a window)
    return JSONResponse(
        {
            "id": "chatcmpl-startupsim000000000000000000000",
            "object": "chat.completion",
            "created": 1761345600,
            "model": body.get("model", "gpt-4o-mini"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hand-finished in small batches, this piece pairs everyday durability with a maker's touch.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 42, "completion_tokens": 27, "total_tokens": 69},
        },
        headers={"x-api-cost-micros": str(COST_MICROS)},
    )
