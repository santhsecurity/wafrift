#!/usr/bin/env bash
# Negative-control verification for the app-transform execution result.
#
# The app-transform sweep shows base64/hex/zlib/base58/chain blobs EXECUTE
# through CRS. The obvious reviewer challenge: "is the WAF even working, or does
# everything execute?" This isolates the cause by firing the SAME executable
# corpus, through the SAME exploit harness and detonation oracle, with NO
# app-transform — i.e. the raw payloads CRS is designed to catch — and asserting
# ~0 executions. A near-zero raw count next to the sweep's many transform-borne
# executions proves the win is the opaque-decoder property, not a broken WAF.
#
# Run at the standard paranoia level (PL2) after the main sweep, before cleanup.
# Disposable-host only (axiomexec).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
BASE="http://127.0.0.1:18106"
PL="${PL:-2}"
SEED="$HERE/corpus_xss.txt"
WAFRIFT="$HERE/wafrift"
export WAFRIFT_DETONATE_BIN="${WAFRIFT_DETONATE_BIN:-$HERE/detonate}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36'
# Raw reflection contexts: the payload reaches the sink with NO decode step, so
# CRS sees the live XSS signature it is built to block. One per render class.
RENDERS="${RENDERS:-body attr attr_sq js js_sq uri}"

compose() { docker compose -f "$COMPOSE" "$@"; }

PARANOIA="$PL" compose up -d --force-recreate >/dev/null 2>&1
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "User-Agent: $UA" -H 'Accept: text/html' "$BASE/?ctx=body&q=hi" 2>/dev/null)"
  [ "$code" = "200" ] && break
  sleep 1
done

printf 'pl\tctx\tfired\tbypassed\treflected\texecuting\n'
total=0
for r in $RENDERS; do
  # No --app-transform: wafrift fires the raw executable catalog + its own
  # evasion variants straight at the render context. CRS should block them.
  out="$("$WAFRIFT" exploit \
    --target "$BASE/?ctx=$r" --param q \
    --seed-payloads "$SEED" \
    --detonate-engine chrome --all --max-fires 0 --delay-ms 0 2>&1)"
  stats="$(printf '%s\n' "$out" | grep -oE 'fired=[0-9]+ bypassed=[0-9]+ reflected=[0-9]+ EXECUTING=[0-9]+' | tail -1)"
  fired=$(echo "$stats"  | sed -E 's/.*fired=([0-9]+).*/\1/')
  byp=$(echo "$stats"    | sed -E 's/.*bypassed=([0-9]+).*/\1/')
  refl=$(echo "$stats"   | sed -E 's/.*reflected=([0-9]+).*/\1/')
  exe=$(echo "$stats"    | sed -E 's/.*EXECUTING=([0-9]+).*/\1/')
  fired=${fired:-0}; byp=${byp:-0}; refl=${refl:-0}; exe=${exe:-0}
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$PL" "raw:$r" "$fired" "$byp" "$refl" "$exe"
  total=$((total + exe))
done
compose down >/dev/null 2>&1
echo "NEGCTL_VERIFY_DONE raw_executing=$total (expect ~0 — CRS blocks the un-transformed corpus)"
