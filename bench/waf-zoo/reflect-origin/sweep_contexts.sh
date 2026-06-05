#!/usr/bin/env bash
# Multi-context execution sweep against OWASP CRS.
#
# For each paranoia level and each reflection context the origin exposes, runs
# `wafrift exploit --detonate-engine chrome --all` and records the honest
# bypass-vs-execute split. Answers: does a payload that BYPASSES CRS actually
# EXECUTE once it lands in the context a real app reflects into (body, quoted
# attribute, JS string, double-decode, javascript: URI) — not just the body+
# innerHTML context the first-generation origin modelled.
#
# Run on a DISPOSABLE host (axiomexec / santhserver), never the dev box: it
# stands up a WAF zoo and spawns many headless-Chrome detonations.
#
# Env:
#   WAFRIFT_BIN          path to the wafrift binary      (default: wafrift on PATH)
#   WAFRIFT_DETONATE_BIN path to the detonate binary     (default: detonate on PATH)
#   WAFRIFT_CHROME_BIN   path to google-chrome/chromium  (default: PATH search)
#   PARANOIAS            space-separated PLs to sweep     (default: "1 2 4")
#   CONTEXTS             space-separated ctx names        (default: all)
#   MAX_FIRES            fire budget per context          (default: 6000)
#   CONCURRENCY          contexts run in parallel per PL  (default: 4)
#   OUTDIR               where logs/results land          (default: ./sweep-out)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
WAFRIFT_BIN="${WAFRIFT_BIN:-wafrift}"
PORT=18106
BASE="http://127.0.0.1:${PORT}"
PARANOIAS="${PARANOIAS:-1 2 4}"
CONTEXTS="${CONTEXTS:-body attr attr_sq js js_sq dd uri}"
MAX_FIRES="${MAX_FIRES:-6000}"
CONCURRENCY="${CONCURRENCY:-4}"
OUTDIR="${OUTDIR:-${HERE}/sweep-out}"
mkdir -p "$OUTDIR"
RESULTS="${OUTDIR}/results.tsv"
: > "$RESULTS"
echo -e "paranoia\tcontext\tfired\tbypassed\treflected\texecuting" >> "$RESULTS"

waf_up() {
  PARANOIA="$1" docker compose -f "${HERE}/docker-compose.yml" up -d --force-recreate wafrift-reflect-waf >/dev/null 2>&1
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/?q=hi" 2>/dev/null)" = "200" ] && return 0
    sleep 1
  done
  return 1
}

run_ctx() { # paranoia ctx
  local pl="$1" ctx="$2" log="${OUTDIR}/pl${1}_${2}.log"
  "$WAFRIFT_BIN" exploit \
    --target "${BASE}/?ctx=${ctx}" --param q \
    --detonate-engine chrome --all \
    --max-fires "$MAX_FIRES" --delay-ms 0 --timeout-secs 15 \
    > "$log" 2>&1
  # The summary line: "fired=N bypassed=N reflected=N EXECUTING=N"
  local line
  line="$(grep -oE 'fired=[0-9]+ bypassed=[0-9]+ reflected=[0-9]+ EXECUTING=[0-9]+' "$log" | tail -1)"
  local f b r e
  f="$(sed -nE 's/.*fired=([0-9]+).*/\1/p'     <<<"$line")"
  b="$(sed -nE 's/.*bypassed=([0-9]+).*/\1/p'  <<<"$line")"
  r="$(sed -nE 's/.*reflected=([0-9]+).*/\1/p' <<<"$line")"
  e="$(sed -nE 's/.*EXECUTING=([0-9]+).*/\1/p' <<<"$line")"
  echo -e "${pl}\t${ctx}\t${f:-NA}\t${b:-NA}\t${r:-NA}\t${e:-NA}" >> "$RESULTS"
  echo "[sweep] PL${pl} ctx=${ctx}: fired=${f:-?} bypassed=${b:-?} reflected=${r:-?} EXECUTING=${e:-?}"
}

for pl in $PARANOIAS; do
  echo "[sweep] === bringing up CRS PL${pl} ==="
  if ! waf_up "$pl"; then echo "[sweep] WAF failed to come up at PL${pl}"; continue; fi
  running=0
  for ctx in $CONTEXTS; do
    run_ctx "$pl" "$ctx" &
    running=$((running+1))
    if [ "$running" -ge "$CONCURRENCY" ]; then wait -n 2>/dev/null || wait; running=$((running-1)); fi
  done
  wait
done

docker compose -f "${HERE}/docker-compose.yml" down >/dev/null 2>&1
echo "[sweep] DONE — results:"
column -t "$RESULTS"
