#!/usr/bin/env bash
# waf-zoo/modsec-azure/wafrift-bench.sh
# Run wafrift bench-waf against the ModSecurity + Azure AppGW WAF emulation stack.
#
# Usage:
#   ./wafrift-bench.sh                   # all classes, 5 variants
#   ./wafrift-bench.sh --class sql       # SQL only
#   ./wafrift-bench.sh --variants 20     # 20 variants per strategy
#
# The compose stack must be running first:
#   docker compose -f waf-zoo/modsec-azure/docker-compose.yml up -d
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TARGET_URL="http://127.0.0.1:18102"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTPUT="$RESULT_DIR/${TIMESTAMP}-modsec-azure.json"

mkdir -p "$RESULT_DIR"

exec "$REPO_ROOT/target/release/wafrift" bench-waf \
    --base-url "$TARGET_URL" \
    --evade \
    --strategies all \
    --variants "${VARIANTS:-5}" \
    --format json \
    --output "$OUTPUT" \
    "$@"
