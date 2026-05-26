#!/usr/bin/env bash
# waf-zoo/up.sh [stack-name ...]
#
# Bring up one or all WAF zoo stacks and wait for each to pass a health probe.
#
# Usage:
#   ./bench/waf-zoo/up.sh                       # bring up all stacks
#   ./bench/waf-zoo/up.sh modsec-aws coraza     # bring up specific stacks
#
# Ports:
#   modsec-aws=18101  modsec-azure=18102  coraza=18103
#   naxsi=18104       shadowdaemon=18105
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -A STACKS_PORT=(
    [modsec-aws]=18101
    [modsec-azure]=18102
    [coraza]=18103
    [naxsi]=18104
    [shadowdaemon]=18105
)

# Build the list of stacks to bring up.
if [ $# -gt 0 ]; then
    STACKS=( "$@" )
else
    STACKS=( modsec-aws modsec-azure coraza naxsi shadowdaemon )
fi

for stack in "${STACKS[@]}"; do
    compose_file="$SCRIPT_DIR/$stack/docker-compose.yml"
    if [ ! -f "$compose_file" ]; then
        echo "skip: no compose file for stack '$stack'" >&2
        continue
    fi
    echo "[$stack] docker compose up -d"
    # naxsi must be built from source on first run.
    if [ "$stack" = "naxsi" ]; then
        docker compose -f "$compose_file" up -d --build
    else
        docker compose -f "$compose_file" up -d
    fi
done

echo
echo "Health probe (waiting up to 90s per stack)..."
FAILED=()
for stack in "${STACKS[@]}"; do
    port="${STACKS_PORT[$stack]:-}"
    [ -z "$port" ] && continue

    ready=false
    for i in $(seq 1 90); do
        # shadowdaemon returns 200 on /, others return 200 on /get or root.
        code=$(curl -sf -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)
        if echo "$code" | grep -qE '^(200|403|406)$'; then
            echo "  [$stack :$port] up (HTTP $code)"
            ready=true
            break
        fi
        sleep 1
    done

    if [ "$ready" != "true" ]; then
        echo "  [$stack :$port] TIMEOUT — check: docker logs wafrift-zoo-${stack}" >&2
        FAILED+=("$stack")
    fi
done

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo
    echo "FAIL: ${#FAILED[@]} stack(s) failed health probe: ${FAILED[*]}" >&2
    exit 2
fi

echo
echo "All stacks healthy. Run benches with:"
echo "  bench/waf-zoo/run-all-benches.sh"
