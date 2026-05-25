#!/usr/bin/env bash
# waf-zoo/coraza/wafrift-bench.sh
# Run wafrift bench-waf against the Coraza (Go reimplementation of ModSec) stack.
#
# Coraza is worth benching separately from the modsec-pl* stacks because:
#   - Different C/Go HTTP parser → different multipart/chunked encoding bypass surface
#   - Different regex engine (RE2 not PCRE) → different ReDoS behaviour
#   - Used by Fastly NGW, Traefik Enterprise, and several cloud-edge platforms
#
# Usage:
#   ./wafrift-bench.sh                   # all classes, 5 variants
#   ./wafrift-bench.sh --class sql       # SQL only
#   ./wafrift-bench.sh --variants 20     # 20 variants per strategy
#
# The compose stack must be running first:
#   docker compose -f waf-zoo/coraza/docker-compose.yml up -d
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TARGET_URL="http://127.0.0.1:18103"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTPUT="$RESULT_DIR/${TIMESTAMP}-zoo-coraza.json"

mkdir -p "$RESULT_DIR"

exec "$REPO_ROOT/target/release/wafrift" bench-waf \
    --base-url "$TARGET_URL" \
    --evade \
    --strategies all \
    --variants "${VARIANTS:-5}" \
    --format json \
    --output "$OUTPUT" \
    "$@"
