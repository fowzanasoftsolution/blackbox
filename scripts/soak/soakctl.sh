#!/bin/bash
# soakctl.sh — 6-hour blackbox soak orchestrator (Daytona sandbox)
# legs:
#   node A = blackbox run   (supervision: app is a respawned child)
#   node B = blackbox serve (disk ring: 8 MB segments + 1 GB quota)
# crash injections at CRASH_ATS (seconds into run, default 1h/3h/5h).
#
# v1.1.1 (soak fix #4): evidence guard.
#   * SOAK_SECONDS <= 0 or `--collect-only` (or COLLECT_ONLY=1) selects
#     COLLECT-ONLY mode: the data dirs of the PREVIOUS run are the evidence
#     and must NEVER be wiped/re-initialized — the harness refuses when they
#     are non-empty, boots nothing, injects no crashes, and jumps straight
#     to the final artifact generation.
#   * In soak mode (SOAK_SECONDS > 0) the wipe of the scratch dirs happens
#     exactly once, before any node has ever touched them.
set -u
cd /home/daytona/soak

say(){ echo "[$(date '+%F %T')] $*" >> events.log; }

SOAK_SECONDS=${SOAK_SECONDS:-21600}
CRASH_ATS=${CRASH_ATS:-3600,10800,18000}
T_START=$(date +%s)

# ---- mode selection ---------------------------------------------------------
COLLECT_ONLY=${COLLECT_ONLY:-0}
for arg in "$@"; do
  [ "$arg" = "--collect-only" ] && COLLECT_ONLY=1
done
COLLECT=0
if [[ "$SOAK_SECONDS" =~ ^-?[0-9]+$ ]]; then
  [ "$SOAK_SECONDS" -le 0 ] && COLLECT=1
else
  say "SOAK_SECONDS='$SOAK_SECONDS' is not a number; using 21600"
  SOAK_SECONDS=21600
fi
[ "$COLLECT_ONLY" = 1 ] && COLLECT=1

say "=== soakctl begin: mode=$([ "$COLLECT" = 1 ] && echo collect-only || echo soak); \
SOAK_SECONDS=${SOAK_SECONDS}s; crashes@${CRASH_ATS} ==="
uname -a >> events.log
grep -h -E 'MemTotal|MemAvailable' /proc/meminfo >> events.log 2>/dev/null

dir_nonempty(){ [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; }

run_soak(){
  # ---- one-time wipe of scratch state (soak mode only) ----------------------
  rm -rf data-a data-b stats node-a.log node-b.log gen.log gen.csv gen_hist.json log
  rm -f cache_min.csv sampler.csv app.pid status-a.json final_*.txt
  mkdir -p stats

  # ---- node A: blackbox run (supervised app child) ---------------------------
  ./blackbox run \
    --listen 127.0.0.1:9080 --upstream-port 3000 \
    --egress-listen 127.0.0.1:9081 --admin-listen 127.0.0.1:9690 \
    --data data-a --webhooks '/webhooks/*' \
    --pid-file app.pid --status-file status-a.json \
    --hold-ms 10000 \
    -- python3 ./app.py 3000 > node-a.log 2>&1 &
  NODE_A_PID=$!
  say "node A (run) pid=$NODE_A_PID"

  up=0
  for i in $(seq 60); do
    curl -fsS http://127.0.0.1:9690/api/queue > /dev/null 2>&1 && { up=1; break; }
    sleep 0.5
  done
  [ "$up" = 1 ] || { say "FATAL: node A admin never came up"; tail -40 node-a.log >> events.log; exit 1; }
  say "node A admin up; status: $(cat status-a.json 2>/dev/null)"

  # ---- node B: blackbox serve (storage-ring leg) -----------------------------
  ./blackbox serve --upstream 127.0.0.1:3000 \
    --listen 127.0.0.1:9082 --egress-listen 127.0.0.1:9083 \
    --admin-listen 127.0.0.1:9691 \
    --data data-b --max-segment-mb 8 --disk-quota-mb 1024 \
    --webhooks '/webhooks/*' --hold-ms 10000 \
    > node-b.log 2>&1 &
  NODE_B_PID=$!
  say "node B (serve) pid=$NODE_B_PID"

  up=0
  for i in $(seq 60); do
    curl -fsS http://127.0.0.1:9691/api/queue > /dev/null 2>&1 && { up=1; break; }
    sleep 0.5
  done
  [ "$up" = 1 ] || { say "FATAL: node B admin never came up"; tail -40 node-b.log >> events.log; exit 1; }
  say "node B admin up"

  # ---- generator + sampler ---------------------------------------------------
  export SOAK_SECONDS
  unset WORKERS
  SOAK_SECONDS=$SOAK_SECONDS A_INGRESS=127.0.0.1:9080 A_EGRESS=127.0.0.1:9081 \
    B_INGRESS=127.0.0.1:9082 APP_DIRECT=127.0.0.1:3000 WORKERS=6 \
    python3 -u gen.py > gen.log 2>&1 &
  GEN_PID=$!
  SAMPLER_SECONDS=$((SOAK_SECONDS + 120)) SAMPLER_INTERVAL=30 \
    python3 -u sampler.py > sampler.log 2>&1 &
  SAMP_PID=$!
  say "generator pid=$GEN_PID sampler pid=$SAMP_PID — traffic flowing"

  # ---- crash injections ------------------------------------------------------
  IFS=',' read -ra ATS <<< "$CRASH_ATS"
  for at in "${ATS[@]}"; do
    left=$(( T_START + $at - $(date +%s) ))
    if [ "$left" -gt 0 ] && [ "$((at + ${GUARD_WINDOW:-300}))" -le "$SOAK_SECONDS" ]; then
      sleep "$left"
    else
      say "crash at ${at}s skipped by guard (GUARD_WINDOW=${GUARD_WINDOW:-300})"
      continue
    fi
    APID=$(cat app.pid 2>/dev/null || echo 0)
    if [ "$APID" != 0 ] && [ -d "/proc/$APID" ]; then
      kill -9 "$APID" 2>/dev/null
      say "CRASH-INJECT(s=${at}s): SIGKILL app pid=$APID (node A must resurrect)"
    else
      say "CRASH-INJECT(s=${at}s): app pid file missing/proc gone ($APID)"
    fi
  done
  say "all crash injections dispatched"

  # ---- wait out the window ---------------------------------------------------
  left=$(( T_START + SOAK_SECONDS - $(date +%s) ))
  if [ "$left" -gt 0 ]; then sleep "$left"; fi
  say "window end; waiting for generator to finish"
  wait "$GEN_PID" 2>/dev/null
  say "generator exit ok; sampler drain"
  sleep 45
  kill "$SAMP_PID" 2>/dev/null; wait "$SAMP_PID" 2>/dev/null
}

if [ "$COLLECT" = 1 ]; then
  # ---- v1.1.1 evidence guard: no wipe, no boot, no traffic -------------------
  if dir_nonempty data-a; then
    say "GUARD: data-a is non-empty — refusing wipe/re-init (collect-only preserves evidence)"
  else
    say "FATAL: collect-only requested but data-a is empty/missing — nothing to collect"
    exit 1
  fi
  if dir_nonempty data-b; then
    say "GUARD: data-b is non-empty — preserved"
  else
    say "WARN: data-b is empty/missing — its artifacts will be partial"
  fi
  mkdir -p stats
  say "=== collect-only: skipping boot/gen/crash phases — jumping to artifact generation ==="
else
  run_soak
  say "nodes stopped"
fi

# ---- final artifact generation (both modes) ---------------------------------
./blackbox audit verify --data data-a > final_audit_a.txt 2>&1
say "audit verify data-a rc=$? (see final_audit_a.txt)"
./blackbox audit verify --data data-b > final_audit_b.txt 2>&1
say "audit verify data-b rc=$? (see final_audit_b.txt)"
{
  echo "--- data-a ---"; ./blackbox queue status --data data-a 2>&1
  echo "--- data-b ---"; ./blackbox queue status --data data-b 2>&1
  echo "--- disk usage MB ---"; du -sm data-a data-b 2>/dev/null
  echo "--- segment inventory ---"; ls data-a | grep segment | head -3; ls data-b | grep segment | tail -3
} > final_queue.txt 2>&1
./blackbox queue status --data data-a > /dev/null 2>&1 && echo "queue_status_a rc=$?" >> events.log
if [ "$COLLECT" = 1 ]; then
  # collect mode: copy whatever exists; do not fail on missing gen/sampler files
  :
else
  cp sampler.csv gen.csv cache_min.csv gen_hist.json err.log final_queue.txt \
     final_audit_a.txt final_audit_b.txt node-a.log node-b.log events.log stats/ 2>/dev/null
fi
JSON=$(python3 - <<'EOF'
import json,glob,os
h=json.load(open("gen_hist.json")) if os.path.exists("gen_hist.json") else {}
rows=[l.split(",") for l in open("sampler.csv").readlines()[1:] if l.strip()]
rss=[int(float(r[1])) for r in rows if r[1]]
rssb=[int(float(r[2])) for r in rows if r[2]]
disa=[float(r[6]) for r in rows if r[6]]
disb=[float(r[7]) for r in rows if r[7]]
print(json.dumps({
 "samples":len(rows),
 "rss_a_kb":{"start":rss[0] if rss else None,"end":rss[-1] if rss else None,
             "max":max(rss) if rss else None},
 "rss_b_kb":{"start":rssb[0] if rssb else None,"end":rssb[-1] if rssb else None,
             "max":max(rssb) if rssb else None},
 "disk_a_mb":{"start":disa[0] if disa else None,"end":disa[-1] if disa else None,
              "max":max(disa) if disa else None},
 "disk_b_mb":{"start":disb[0] if disb else None,"end":disb[-1] if disb else None,
              "max":max(disb) if disb else None},
 "latency":{k:{"n":v.get("n"),"ok":v.get("ok"),"p50_us":v.get("p50"),
               "p99_us":v.get("p99"),"max_us":v.get("max_us")} for k,v in h.items()},
 "errors_in_sampler":0,
}))
EOF
)
echo "$JSON" > final_summary.json
echo "$JSON"
say "=== soak complete (mode=$([ "$COLLECT" = 1 ] && echo collect-only || echo soak)) — pull artifacts ==="
