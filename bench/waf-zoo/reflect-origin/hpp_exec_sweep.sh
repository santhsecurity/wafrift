#!/usr/bin/env bash
# HTTP Parameter Pollution EXECUTION sweep: for each CRS paranoia level, run
# `wafrift exploit --split-param` against the reflect-origin `ctx=hpp` sink
# (which concatenates all repeated `q=` values), seeding the real-world XSS
# corpus, and detonation-prove every reassembled payload that fires. Sums the
# confirmed executions per PL.
#
# Distinct from transform_exec_sweep (the app-transform/encoding axis): here
# nothing is encoded — the payload is split into inert fragments delivered as
# repeated params, and an HPP-joining app reassembles live markup. Disposable
# host only (axiomexec).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
BASE="http://127.0.0.1:18106"
PARANOIAS="${PARANOIAS:-1 2 4}"
SEED="$HERE/corpus_xss.txt"
# Use the HPP-capable binary if present, else the default deployed one.
WAFRIFT="${WAFRIFT:-$HERE/wafrift-hpp}"
[ -x "$WAFRIFT" ] || WAFRIFT="$HERE/wafrift"
export WAFRIFT_DETONATE_BIN="${WAFRIFT_DETONATE_BIN:-$HERE/detonate}"
OUT="${OUT:-$HERE/hpp_exec_results.tsv}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36'

compose() { docker compose -f "$COMPOSE" "$@"; }

waf_up() {
  local pl="$1"
  PARANOIA="$pl" compose up -d --force-recreate >/dev/null 2>&1
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "User-Agent: $UA" -H 'Accept: text/html' "$BASE/?ctx=hpp&q=hi" 2>/dev/null)"
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  echo "WAF failed to come up at PL=$pl" >&2
  return 1
}

printf 'pl\tctx\tfired\tbypassed\treflected\texecuting\n' > "$OUT"
total_exec=0
for pl in $PARANOIAS; do
  echo "=== PL=$pl ===" >&2
  waf_up "$pl" || continue
  out="$("$WAFRIFT" exploit \
    --target "$BASE/?ctx=hpp" --param q \
    --split-param --seed-payloads "$SEED" \
    --detonate-engine chrome --all --max-fires 0 --delay-ms 0 2>&1)"
  stats="$(printf '%s\n' "$out" | grep -oE 'fired=[0-9]+ bypassed=[0-9]+ reflected=[0-9]+ EXECUTING=[0-9]+' | tail -1)"
  fired=$(echo "$stats" | sed -E 's/.*fired=([0-9]+).*/\1/')
  byp=$(echo "$stats"   | sed -E 's/.*bypassed=([0-9]+).*/\1/')
  refl=$(echo "$stats"  | sed -E 's/.*reflected=([0-9]+).*/\1/')
  exe=$(echo "$stats"   | sed -E 's/.*EXECUTING=([0-9]+).*/\1/')
  fired=${fired:-0}; byp=${byp:-0}; refl=${refl:-0}; exe=${exe:-0}
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pl" "hpp" "$fired" "$byp" "$refl" "$exe" | tee -a "$OUT" >&2
  total_exec=$((total_exec + exe))
done

compose down >/dev/null 2>&1
echo "HPP_EXEC_SWEEP_DONE total_executing=$total_exec" >&2
column -t "$OUT" >&2
