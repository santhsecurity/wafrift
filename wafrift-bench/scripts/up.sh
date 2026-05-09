#!/usr/bin/env bash
# wafrift-bench/scripts/up.sh [stack-name]
# Bring up one or all WAF testbed stacks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGETS_DIR="$ROOT/wafrift-bench/targets"
STACKS=( modsec-pl1 modsec-pl2 modsec-pl3 modsec-pl4 coraza bunkerweb naxsi )

if [ $# -gt 0 ]; then
  STACKS=( "$@" )
fi

for stack in "${STACKS[@]}"; do
  if [ ! -d "$TARGETS_DIR/$stack" ]; then
    echo "skip: no such stack $stack" >&2
    continue
  fi
  echo "[$stack] docker compose up -d"
  (cd "$TARGETS_DIR/$stack" && docker compose up -d)
done

echo
echo "Health probe (waiting up to 60s per port)..."
declare -A PORT=( [modsec-pl1]=18081 [modsec-pl2]=18082 [modsec-pl3]=18083 [modsec-pl4]=18084 [coraza]=18085 [bunkerweb]=18086 [naxsi]=18087 )
TIMEOUTS=()
for stack in "${STACKS[@]}"; do
  port="${PORT[$stack]:-}"
  [ -z "$port" ] && continue
  ready=false
  for i in $(seq 1 60); do
    if curl -sf -o /dev/null "http://127.0.0.1:$port/get" 2>/dev/null \
       || curl -sfo /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null | grep -qE '^(200|403|406)$'; then
      echo "  [$stack] up on :$port"
      ready=true
      break
    fi
    sleep 1
  done
  if [ "$ready" != "true" ]; then
    echo "  [$stack] TIMEOUT on :$port — see 'docker logs wafrift-${stack}' for details" >&2
    TIMEOUTS+=("$stack")
  fi
done

if [ ${#TIMEOUTS[@]} -gt 0 ]; then
  echo
  echo "FAIL: ${#TIMEOUTS[@]} stack(s) failed health probe: ${TIMEOUTS[*]}" >&2
  echo "      Bench runs against these targets will hang or report 100% block rate." >&2
  exit 2
fi
