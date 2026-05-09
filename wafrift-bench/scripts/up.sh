#!/usr/bin/env bash
# wafrift-bench/scripts/up.sh [stack-name]
# Bring up one or all WAF testbed stacks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGETS_DIR="$ROOT/wafrift-bench/targets"
STACKS=( modsec-pl1 modsec-pl2 modsec-pl3 modsec-pl4 coraza bunkerweb )

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
declare -A PORT=( [modsec-pl1]=18081 [modsec-pl2]=18082 [modsec-pl3]=18083 [modsec-pl4]=18084 [coraza]=18085 [bunkerweb]=18086 )
for stack in "${STACKS[@]}"; do
  port="${PORT[$stack]:-}"
  [ -z "$port" ] && continue
  for i in $(seq 1 60); do
    if curl -sf -o /dev/null "http://127.0.0.1:$port/get" 2>/dev/null \
       || curl -sfo /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null | grep -qE '^(200|403|406)$'; then
      echo "  [$stack] up on :$port"
      break
    fi
    [ "$i" -eq 60 ] && echo "  [$stack] TIMEOUT on :$port" >&2
    sleep 1
  done
done
