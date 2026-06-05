#!/usr/bin/env bash
# App-transform EXECUTION sweep: for each CRS paranoia level and each WAF-opaque
# app transform, run `wafrift exploit --app-transform <T>` against the matching
# decode context, seeding the real-world XSS corpus, and detonate-prove every
# bypass in a real browser. Sums the confirmed executions.
#
# Each transform is fired at the reflect-origin `ctx` whose decoder inverts it
# (b64/b64url -> ctx=b64, hex/hex0x -> ctx=hex, b32 -> ctx=b32, rot13 ->
# ctx=rot13): an application applies ONE decoder, so a transform only weaponises
# against the param that decodes it. Disposable-host only (axiomexec).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$HERE/docker-compose.yml"
BASE="http://127.0.0.1:18106"
PARANOIAS="${PARANOIAS:-1 2 4}"
TRANSFORMS="${TRANSFORMS:-b64 b64url hex hex0x b32 rot13 zb64 b58 b64x2}"
# Render contexts the decoded value can land in — an app that decodes a value
# may drop it into body, a quoted attribute, a JS string, or a javascript: URI.
# Each unlocks a different vector class (body innerHTML vs attribute-breakout vs
# JS-string-breakout), so sweeping them is what turns one transform into many
# confirmed executions.
RENDERS="${RENDERS:-body attr attr_sq js js_sq uri title textarea style}"
SEED="${SEED:-$HERE/corpus_xss.txt}"
WAFRIFT="$HERE/wafrift"
export WAFRIFT_DETONATE_BIN="${WAFRIFT_DETONATE_BIN:-$HERE/detonate}"
OUT="${OUT:-$HERE/transform_exec_results.tsv}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36'

# The origin ctx token whose DECODER inverts transform $1: b64/b64url -> b64
# decoder, hex/hex0x -> hex decoder, etc.
decoder_for() {
  case "$1" in
    b64|b64url) echo b64 ;;
    hex|hex0x)  echo hex ;;
    b32)        echo b32 ;;
    rot13)      echo rot13 ;;
    zb64)       echo zb64 ;;
    zhex)       echo zhex ;;
    b58)        echo b58 ;;
    b64x2)      echo b64x2 ;;
    *)          echo b64 ;;
  esac
}

compose() { docker compose -f "$COMPOSE" "$@"; }

waf_up() {
  local pl="$1"
  PARANOIA="$pl" compose up -d --force-recreate >/dev/null 2>&1
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "User-Agent: $UA" -H 'Accept: text/html' "$BASE/?ctx=body&q=hi" 2>/dev/null)"
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  echo "WAF failed to come up at PL=$pl" >&2
  return 1
}

printf 'pl\ttransform\tctx\tfired\tbypassed\treflected\texecuting\n' > "$OUT"
total_exec=0
for pl in $PARANOIAS; do
  echo "=== PL=$pl ===" >&2
  waf_up "$pl" || continue
  for t in $TRANSFORMS; do
    dec="$(decoder_for "$t")"
    for r in $RENDERS; do
      ctx="$dec.$r"
      out="$("$WAFRIFT" exploit \
        --target "$BASE/?ctx=$ctx" --param q \
        --app-transform "$t" --seed-payloads "$SEED" \
        --detonate-engine chrome --all --max-fires 0 --delay-ms 0 2>&1)"
      stats="$(printf '%s\n' "$out" | grep -oE 'fired=[0-9]+ bypassed=[0-9]+ reflected=[0-9]+ EXECUTING=[0-9]+' | tail -1)"
      fired=$(echo "$stats" | sed -E 's/.*fired=([0-9]+).*/\1/')
      byp=$(echo "$stats"   | sed -E 's/.*bypassed=([0-9]+).*/\1/')
      refl=$(echo "$stats"  | sed -E 's/.*reflected=([0-9]+).*/\1/')
      exe=$(echo "$stats"   | sed -E 's/.*EXECUTING=([0-9]+).*/\1/')
      fired=${fired:-0}; byp=${byp:-0}; refl=${refl:-0}; exe=${exe:-0}
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pl" "$t" "$ctx" "$fired" "$byp" "$refl" "$exe" | tee -a "$OUT" >&2
      total_exec=$((total_exec + exe))
    done
  done
done

compose down >/dev/null 2>&1
echo "TRANSFORM_EXEC_SWEEP_DONE total_executing=$total_exec" >&2
column -t "$OUT" >&2
