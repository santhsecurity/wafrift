#!/usr/bin/env bash
# waf-zoo/down.sh [stack-name ...]
#
# Tear down one or all WAF zoo stacks.
#
# Usage:
#   ./bench/waf-zoo/down.sh                     # tear down all stacks
#   ./bench/waf-zoo/down.sh modsec-aws coraza   # tear down specific stacks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALL_STACKS=( modsec-aws modsec-azure coraza naxsi shadowdaemon )

if [ $# -gt 0 ]; then
    STACKS=( "$@" )
else
    STACKS=( "${ALL_STACKS[@]}" )
fi

for stack in "${STACKS[@]}"; do
    compose_file="$SCRIPT_DIR/$stack/docker-compose.yml"
    [ -f "$compose_file" ] || continue
    echo "[$stack] docker compose down -v"
    docker compose -f "$compose_file" down -v 2>/dev/null || true
done

# Belt-and-braces: stop any stray containers that compose lost track of.
docker stop \
    wafrift-modsec-aws  wafrift-modsec-aws-backend \
    wafrift-modsec-azure wafrift-modsec-azure-backend \
    wafrift-zoo-coraza  wafrift-zoo-coraza-backend \
    wafrift-zoo-naxsi   wafrift-zoo-naxsi-backend \
    wafrift-zoo-shadowd wafrift-zoo-shadowd-php \
    2>/dev/null || true

docker rm \
    wafrift-modsec-aws  wafrift-modsec-aws-backend \
    wafrift-modsec-azure wafrift-modsec-azure-backend \
    wafrift-zoo-coraza  wafrift-zoo-coraza-backend \
    wafrift-zoo-naxsi   wafrift-zoo-naxsi-backend \
    wafrift-zoo-shadowd wafrift-zoo-shadowd-php \
    2>/dev/null || true
