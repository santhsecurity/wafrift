#!/usr/bin/env bash
# waf-zoo/shadowdaemon/wafrift-bench.sh
# Run wafrift bench-waf against the Shadow Daemon WAF stack.
#
# Shadow Daemon differs from ModSec/Coraza/Naxsi in important ways:
#   - Connector sits inside the PHP process, not at the HTTP layer.
#   - Transport-level evasions (chunked encoding, multipart boundary tricks)
#     are neutralised by the PHP SAPI before shadowd sees the parameters.
#   - Shadowd uses its own token grammar (not CRS), so CRS-bypass techniques
#     may not transfer.
#
# The bench backend is the shadowd_php connector demo app (not httpbin).
# The bench harness must detect blocks by response body content ("Forbidden"
# or status 403) rather than relying solely on HTTP status codes, because
# some shadowd versions return 200 with a "blocked" body.
#
# Usage:
#   ./wafrift-bench.sh                   # all classes, 5 variants
#   ./wafrift-bench.sh --class sql       # SQL only
#   ./wafrift-bench.sh --variants 20     # 20 variants per strategy
#
# Stack must be running first:
#   docker compose -f waf-zoo/shadowdaemon/docker-compose.yml up -d
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TARGET_URL="http://127.0.0.1:18105"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTPUT="$RESULT_DIR/${TIMESTAMP}-zoo-shadowdaemon.json"

mkdir -p "$RESULT_DIR"

exec "$REPO_ROOT/target/release/wafrift" bench-waf \
    --base-url "$TARGET_URL" \
    --evade \
    --strategies all \
    --variants "${VARIANTS:-5}" \
    --format json \
    --output "$OUTPUT" \
    "$@"
