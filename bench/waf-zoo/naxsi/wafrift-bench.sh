#!/usr/bin/env bash
# waf-zoo/naxsi/wafrift-bench.sh
# Run wafrift bench-waf against the Naxsi (positive-security-model WAF) stack.
#
# Naxsi's score-accumulation model means CRS-centric evasion techniques
# (comment injection, encoding tricks, multipart smuggling) have a different
# success profile. Always bench this alongside modsec-pl* for the contrast.
#
# Usage:
#   ./wafrift-bench.sh                   # all classes, 5 variants
#   ./wafrift-bench.sh --class sql       # SQL only
#   ./wafrift-bench.sh --variants 20     # 20 variants per strategy
#
# Stack must be built and running first (first run takes ~5 min to compile nginx):
#   docker compose -f waf-zoo/naxsi/docker-compose.yml up -d --build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TARGET_URL="http://127.0.0.1:18104"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTPUT="$RESULT_DIR/${TIMESTAMP}-zoo-naxsi.json"

mkdir -p "$RESULT_DIR"

exec "$REPO_ROOT/target/release/wafrift" bench-waf \
    --base-url "$TARGET_URL" \
    --evade \
    --strategies all \
    --variants "${VARIANTS:-5}" \
    --format json \
    --output "$OUTPUT" \
    "$@"
