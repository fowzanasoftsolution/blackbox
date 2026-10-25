#!/usr/bin/env python3
"""SDK Compatibility Matrix driver — proves Blackbox against the OFFICIAL
sentry-sdk and openai-python SDKs on a real app launched via `blackbox run`.

Legs:
  1. SENTRY   — real uncaught exception → official SDK ships a real wire
                envelope to the injected SENTRY_DSN → admin /api/trace shows
                IngressHttp(500) + SentryCrash on ONE trace.
  2. FINOPS   — two identical calls through the official openai client →
                second response carries `x-blackbox-cache: HIT`, both parse
                in the SDK, exactly ONE real upstream call.
  3. REPLAY   — `blackbox replay <trace_id>` against the real app: the
                replay proxy re-executes the recorded request pinned to the
                same trace id.

Usage: python3 run_matrix.py   (env: BLACKBOX_BIN, MATRIX_PY, MATRIX_WORK)

Exit code 0 = every leg green. Designed for CI and for the ephemeral
Daytona clean-room run.
"""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BLACKBOX = os.environ.get("BLACKBOX_BIN", os.path.join(HERE, "..", "..", "target", "release", "blackbox"))
BLACKBOX = os.path.abspath(BLACKBOX)
MATRIX_PY = os.environ.get("MATRIX_PY", sys.executable)  # python with fastapi/uvicorn/sentry-sdk/openai
WORK = os.environ.get("MATRIX_WORK", "/tmp/bb-sdk-matrix")

PORT_APP = int(os.environ.get("MATRIX_PORT_APP", "18080"))
PORT_INGRESS = int(os.environ.get("MATRIX_PORT_INGRESS", "18081"))
PORT_MOCK = int(os.environ.get("MATRIX_PORT_MOCK", "18082"))
PORT_ADMIN = int(os.environ.get("MATRIX_PORT_ADMIN", "19690"))
PORT_REPLAY = int(os.environ.get("MATRIX_PORT_REPLAY", "18083"))
PORT_REPLAY_EG = int(os.environ.get("MATRIX_PORT_REPLAY_EG", "18084"))

INGRESS = f"http://127.0.0.1:{PORT_INGRESS}"
ADMIN = f"http://127.0.0.1:{PORT_ADMIN}"
RESULTS = []
PROCS = []


def sh_env():
    env = dict(os.environ)
    env["MOCK_OPENAI_URL"] = f"http://127.0.0.1:{PORT_MOCK}"
    env.setdefault("OPENAI_API_KEY", "sk-matrix-placeholder")
    return env


def http(method, url, body=None, timeout=15, headers=None):
    data = body if body is not None else (b"{}" if method == "POST" else None)
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            try:
                return r.status, hdrs, json.loads(raw)
            except Exception:
                return r.status, hdrs, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            return e.code, hdrs, json.loads(raw)
        except Exception:
            return e.code, hdrs, raw


def spawn(cmd, **kw):
    tag = os.path.basename(cmd[0]) + "-" + str(len(PROCS))
    errf = open(os.path.join(WORK, f"{tag}.stderr.log"), "ab")
    outf = open(os.path.join(WORK, f"{tag}.stdout.log"), "ab")
    p = subprocess.Popen(cmd, env=sh_env(), stdout=outf, stderr=errf, **kw)
    PROCS.append(p)
    return p


def wait_http(url, want=200, deadline_s=40, what=""):
    t0 = time.time()
    last = None
    while time.time() - t0 < deadline_s:
        try:
            status, _, _ = http("GET", url, timeout=5)
            last = status
            if status == want:
                return True
        except Exception as e:
            last = repr(e)
        time.sleep(0.4)
    print(f"  !! timed out waiting for {what or url} (last={last})")
    return False


def leg(name, ok, detail):
    RESULTS.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'} — {name}: {detail}")


def cleanup(*_):
    for p in PROCS:
        try:
            p.terminate()
        except Exception:
            pass
    for p in PROCS:
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def main():
    os.makedirs(WORK, exist_ok=True)
    data_dir = os.path.join(WORK, "data")
    import shutil

    shutil.rmtree(data_dir, ignore_errors=True)

    print("=== SDK Compatibility Matrix ===")
    print(f"  blackbox : {BLACKBOX}")
    print(f"  matrix py: {MATRIX_PY}")
    print(f"  work dir : {WORK}")

    # ---- topology: mock upstream + blackbox run -- <real app> -------------
    spawn([MATRIX_PY, "-m", "uvicorn", "mock_openai:app", "--host", "127.0.0.1",
           "--port", str(PORT_MOCK), "--app-dir", HERE, "--log-level", "warning"])
    spawn([BLACKBOX, "run", "--upstream-port", str(PORT_APP),
           "--listen", f"127.0.0.1:{PORT_INGRESS}",
           "--egress-listen", "127.0.0.1:0",
           "--admin-listen", f"127.0.0.1:{PORT_ADMIN}",
           "--data", data_dir,
           "--", MATRIX_PY, "-m", "uvicorn", "app:app", "--host", "127.0.0.1",
           "--port", str(PORT_APP), "--app-dir", HERE, "--log-level", "warning"])

    if not wait_http(f"{INGRESS}/healthz", what="blackbox ingress -> app"):
        leg("boot", False, "the wrapped app never became reachable through the proxy")
        return 1
    leg("boot", True, f"`blackbox run` wrapped uvicorn; ingress {INGRESS} -> app :{PORT_APP}")

    try:
        # ---------------- leg 1: REAL sentry-sdk crash ---------------------
        print("[1] sentry-sdk: real uncaught exception through the official SDK")
        status, hdrs, _ = http("POST", f"{INGRESS}/crash")
        trace_hdr = hdrs.get("x-blackbox-trace-id", "")
        leg("sentry/500", status == 500, f"POST /crash -> {status}, trace {trace_hdr[:16]}…")
        leg("sentry/trace-header", len(trace_hdr) == 32, "x-blackbox-trace-id is 32-hex")

        http("POST", f"{INGRESS}/flush")  # force the SDK transport to ship

        crash_rec = None
        trace_json = {}
        deadline = time.time() + 20
        while time.time() < deadline:
            _, _, trace_json = http("GET", f"{ADMIN}/api/trace/{trace_hdr}")
            records = trace_json.get("records", trace_json.get("items", []))
            crash_rec = next((r for r in records if r.get("kind") == "SentryCrash"), None)
            if crash_rec:
                break
            time.sleep(0.5)
        leg("sentry/envelope-captured", crash_rec is not None,
            "official SDK envelope ingested (SentryCrash record)" if crash_rec
            else f"no SentryCrash on the trace: {json.dumps(trace_json)[:300]}")
        if crash_rec:
            kinds = sorted({r["kind"] for r in trace_json["records"]})
            leg("sentry/one-trace", "IngressHttp" in kinds,
                f"correlated records on trace {trace_hdr[:16]}…: {kinds}")

        # ---------------- leg 2: REAL openai SDK + cache -------------------
        print("[2] openai-python: two identical calls through the official client")
        s1, h1, r1 = http("POST", f"{INGRESS}/llm")
        s2, _, r2 = http("POST", f"{INGRESS}/llm")
        t_llm = h1.get("x-blackbox-trace-id", "")
        leg("openai/sdk-parse", s1 == 200 and s2 == 200 and r1.get("content") == "matrix ok"
            and r2.get("content") == "matrix ok",
            f"official SDK parsed both responses (content={r1.get('content')!r} / {r2.get('content')!r})")
        leg("openai/usage-model", r1.get("usage_present") and r2.get("usage_present"),
            f"usage parsed by the SDK ({r1.get('usage_total_tokens')} tokens)")
        leg("openai/second-call-HIT", r2.get("cache") == "HIT",
            f"x-blackbox-cache: call1={r1.get('cache')} call2={r2.get('cache')}")
        _, _, cnt = http("GET", f"http://127.0.0.1:{PORT_MOCK}/count")
        leg("openai/dedup", cnt.get("upstream_calls") == 1,
            f"real upstream calls for 2 SDK calls: {cnt.get('upstream_calls')}")

        # the first (MISS) call is the one whose egress exchange was recorded
        leg("openai/correlated", len(t_llm) == 32,
            f"llm call #1 on trace {t_llm[:16] if t_llm else '—'}… (cache={r1.get('cache')})")
        _, _, tj2 = http("GET", f"{ADMIN}/api/trace/{t_llm}")
        kinds2 = sorted({r["kind"] for r in tj2.get("records", [])})
        leg("openai/egress-recorded", "EgressHttpMock" in kinds2,
            f"records on the llm trace: {kinds2}")

        # ---------------- leg 3: blackbox replay against the real app ------
        print("[3] blackbox replay <trace_id> against the real app")
        replay = spawn([BLACKBOX, "replay", t_llm, "--target", INGRESS,
                        "--data", data_dir,
                        "--listen", f"127.0.0.1:{PORT_REPLAY}",
                        "--egress", f"127.0.0.1:{PORT_REPLAY_EG}"],
                       start_new_session=True)
        time.sleep(1.5)
        if replay.poll() is not None:
            leg("replay/started", False, "replay process exited early (no recorded mocks?)")
        else:
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{PORT_REPLAY}/llm", data=b"{}", method="POST")
                with urllib.request.urlopen(req, timeout=20) as resp:
                    rr = json.loads(resp.read())
                    rtrace = resp.headers.get("x-blackbox-trace-id")
                leg("replay/same-trace", rtrace == t_llm,
                    f"replay pinned trace {rtrace[:16] if rtrace else '—'}… == {t_llm[:16]}…")
                leg("replay/real-app", rr.get("content") == "matrix ok",
                    f"real app re-executed through the replay sandbox (cache={rr.get('cache')})")
            except urllib.error.HTTPError as e:
                leg("replay/real-app", False, f"replayed /llm -> {e.code}: {e.read()!r:.300}")
            except Exception as e:
                leg("replay/real-app", False, f"replay request failed: {e!r}")

        # ---------------- leg 4: baggage parity (@sentry/node v8+) ---------
        print("[4] baggage: sentry-trace_id + sentry-sampled on the W3C bus")
        s, h, body = http("POST", f"{INGRESS}/echo")
        tid = h.get("x-blackbox-trace-id", "")
        bg = body.get("baggage", "")
        st1 = body.get("sentry-trace", "")
        leg("baggage/injected",
            s == 200 and f"sentry-trace_id={tid}" in bg and "sentry-sampled=true" in bg,
            f"proxy injected baggage: {bg!r}")
        leg("baggage/parity-sentry-trace",
            len(tid) == 32 and st1.split("-")[0] == tid,
            "sentry-trace + baggage + x-blackbox-trace-id all carry one id")

        s, h, body = http("POST", f"{INGRESS}/echo",
                          headers={"baggage": "userId=42,session=abc"})
        tid2 = h.get("x-blackbox-trace-id", "")
        bg2 = body.get("baggage", "")
        leg("baggage/caller-preserved",
            bg2 == f"userId=42,session=abc,sentry-trace_id={tid2},sentry-sampled=true",
            f"caller entries kept + blackbox entries appended: {bg2!r}")

        s, _, body = http("POST", f"{INGRESS}/echo",
                          headers={"baggage": "sentry-trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,foo=bar"})
        leg("baggage/no-duplicate",
            body.get("baggage") == "sentry-trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,foo=bar",
            f"sentry-trace_id never duplicated: {body.get('baggage')!r}")
    finally:
        cleanup()

    print("\n=== MATRIX SUMMARY ===")
    failed = 0
    for name, ok, detail in RESULTS:
        print(f"  {'✓' if ok else '✗'} {name:28s} {detail}")
        failed += 0 if ok else 1
    total = len(RESULTS)
    print(f"\n  {total - failed}/{total} legs green")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        cleanup()
