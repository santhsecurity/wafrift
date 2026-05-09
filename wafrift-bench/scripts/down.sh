#!/usr/bin/env bash
# wafrift-bench/scripts/down.sh [stack-name]
# Tear down one or all WAF testbed stacks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGETS_DIR="$ROOT/wafrift-bench/targets"
STACKS=( modsec-pl1 modsec-pl2 modsec-pl3 modsec-pl4 coraza naxsi )

if [ $# -gt 0 ]; then
  STACKS=( "$@" )
fi

for stack in "${STACKS[@]}"; do
  if [ ! -d "$TARGETS_DIR/$stack" ]; then continue; fi
  echo "[$stack] docker compose down"
  (cd "$TARGETS_DIR/$stack" && docker compose down -v 2>/dev/null) || true
done

# Belt-and-braces cleanup if compose lost track
docker stop wafrift-pl1 wafrift-pl2 wafrift-pl3 wafrift-pl4 \
            wafrift-coraza wafrift-naxsi 2>/dev/null || true
docker rm   wafrift-pl1 wafrift-pl2 wafrift-pl3 wafrift-pl4 \
            wafrift-coraza wafrift-naxsi 2>/dev/null || true
