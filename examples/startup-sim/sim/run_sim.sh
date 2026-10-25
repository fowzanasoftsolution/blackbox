#!/bin/sh
# Startup-in-a-Box — one-shot orchestrator for the 60-second multi-persona
# traffic & chaos simulation. Boots the two hermetic provider mocks, launches
# Buggy-Sheep Inc. under `blackbox run` (supervised, shielded, durably
# queueing), runs the personas, then tears everything down.
#
# Usage:   sh sim/run_sim.sh [path-to-blackbox-binary]
# Output:  CASE_STUDY.md (path overridable via CASE_STUDY_PATH), plus the
#          full driver log on stdout. Exit 0 = every assertion passed.
set -eu

cd "$(dirname "$0")/.."
BB_BIN="${1:-${BLACKBOX_BIN:-blackbox}}"
CASE_STUDY_PATH="${CASE_STUDY_PATH:-CASE_STUDY.md}"
export CASE_STUDY_PATH

echo "== startup-sim =="
echo "blackbox binary: $BB_BIN"
$BB_BIN --version || true

export PAYMENT_URL="${PAYMENT_URL:-http://127.0.0.1:9912}"
# the APP reaches the provider through the egress proxy under this name
export PAYMENT_API_URL="$PAYMENT_URL"
export MOCK_OPENAI_URL="${MOCK_OPENAI_URL:-http://127.0.0.1:9911}"
export STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-whsec_startup_sim}"
# driver inputs: the binary + data dir (for `blackbox replay`)
export BLACKBOX_BIN="$BB_BIN"
export DATA_DIR="$(pwd)/.sim/data"
export SHOP_DB="$(pwd)/.sim-shop.db"
rm -f "$SHOP_DB" "$SHOP_DB-wal" "$SHOP_DB-shm"

# Restore the pristine v0.9 (buggy) shop code — the sim hot-patches it in place.
[ -f app/shop.py.orig ] || cp app/shop.py app/shop.py.orig
cp app/shop.py.orig app/shop.py

PY="${PYTHON:-python3}"
$PY -c "import fastapi, uvicorn, sentry_sdk, openai" 2>/dev/null \
  || { echo "missing deps: pip install fastapi uvicorn sentry-sdk openai" >&2; exit 2; }

# ---- provider mocks (the "internet": LLM + payment) -----------------------
mkdir -p .sim
$PY -m uvicorn --app-dir sim mock_openai:app --host 127.0.0.1 --port 9911 \
  > .sim/mock_openai.log 2>&1 &
MOCK1=$!
$PY -m uvicorn --app-dir app payment_mock:app --host 127.0.0.1 --port 9912 \
  > .sim/payment_mock.log 2>&1 &
MOCK2=$!
trap 'kill $MOCK1 $MOCK2 $BB_PID 2>/dev/null || true' EXIT INT TERM
sleep 1.5

# ---- boot blackbox + the supervised app -----------------------------------
rm -rf .sim/data child.pid status.json
$BB_BIN run \
  --upstream-port 3000 \
  --listen 127.0.0.1:8080 \
  --admin-listen 127.0.0.1:9690 \
  --egress-listen 127.0.0.1:9700 \
  --data .sim/data \
  --webhooks "/webhooks/*" \
  --rps 50 --burst 25 \
  --mem-budget-mb 256 \
  --pid-file child.pid \
  --status-file status.json \
  -- "$PY" -m uvicorn --app-dir app shop:app --host 127.0.0.1 --port 3000 \
  > .sim/blackbox_run.log 2>&1 &
BB_PID=$!

# ---- wait for the node + app ---------------------------------------------
wait_ok() {
  $PY - "$1" <<'PYEOF'
import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=2)
except Exception:
    sys.exit(1)
PYEOF
}
for i in $(seq 1 60); do
  [ -f status.json ] && wait_ok "http://127.0.0.1:8080/healthz" && break
  sleep 0.5
done
[ -f status.json ] || { echo "blackbox did not write status.json" >&2; tail -20 .sim/blackbox_run.log; exit 3; }
wait_ok "http://127.0.0.1:8080/healthz" || { echo "app never became healthy" >&2; tail -30 .sim/blackbox_run.log; exit 3; }

INGRESS="http://$(python3 -c "import json;print(json.load(open('status.json'))['ingress'])")"
ADMIN="http://$(python3 -c "import json;print(json.load(open('status.json'))['admin'])")"
export INGRESS ADMIN
echo "ingress=$INGRESS admin=$ADMIN"

# ---- the simulation -------------------------------------------------------
RC=0
PYTHONUNBUFFERED=1 python3 sim/generate.py || RC=$?

# ---- teardown + supervisor story ------------------------------------------
kill -TERM $BB_PID 2>/dev/null || true
sleep 2
echo "---- blackbox run log (tail) ----"
tail -25 .sim/blackbox_run.log || true

exit $RC
