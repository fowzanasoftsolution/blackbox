"""Hermetic OpenAI-compatible upstream for the SDK matrix — wire-shaped
exactly like chat completions so the OFFICIAL openai SDK must parse it
(id / object / created / model / choices / usage). Counts real upstream
hits so the matrix can prove deduplication (2 SDK calls -> 1 upstream).
"""

import time

from fastapi import FastAPI, Request

app = FastAPI()
STATE = {"upstream_calls": 0}


@app.get("/count")
def count():
    return STATE


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    STATE["upstream_calls"] += 1
    body = await req.json()
    time.sleep(0.12)  # provider-shaped latency (gives singleflight a window)
    return {
        "id": "chatcmpl-matrix0000000000000000000000000",
        "object": "chat.completion",
        "created": 1761345600,
        "model": body.get("model", "gpt-4o-mini"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "matrix ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12},
    }
