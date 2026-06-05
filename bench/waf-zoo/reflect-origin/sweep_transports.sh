#!/usr/bin/env bash
# Transport-evasion sweep: for each CRS paranoia level, bring the reflect zoo up
# and probe the transport matrix (transport_probe.py) to find delivery channels
# where the WAF returns 200 AND the executable payload reflects raw.
#
# Disposable-host only (axiomexec): brings up docker, force-recreates the WAF per
# PL, tears everything down at the end. Never run on the dev box.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
BASE="http://127.0.0.1:18106"
PARANOIAS="${PARANOIAS:-1 2 4}"
OUT="$HERE/transport_results.tsv"

compose() { docker compose -f "$COMPOSE" "$@"; }

waf_up() {
  local pl="$1"
  PARANOIA="$pl" compose up -d --force-recreate >/dev/null 2>&1
  # Wait for the WAF to answer (a benign GET returns 200/404, not a connection refusal).
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/?ctx=body&q=hello" 2>/dev/null)"
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  echo "WAF failed to come up at PL=$pl" >&2
  return 1
}

: > "$OUT"
header_written=0
for pl in $PARANOIAS; do
  echo "=== PL=$pl: bringing zoo up ===" >&2
  waf_up "$pl" || continue
  if [ "$header_written" = 0 ]; then
    python3 "$HERE/transport_probe.py" --base "$BASE" --ctx body --pl "$pl" | tee -a "$OUT"
    header_written=1
  else
    python3 "$HERE/transport_probe.py" --base "$BASE" --ctx body --pl "$pl" | grep -v '^pl	ctx' | tee -a "$OUT"
  fi
done

echo "=== tearing down ===" >&2
compose down >/dev/null 2>&1
echo "TRANSPORT_SWEEP_DONE" >&2
echo "--- channels where WAF=200 AND payload reflected (the bypass channels) ---" >&2
awk -F'\t' 'NR>1 && $5==1' "$OUT" >&2 || true
