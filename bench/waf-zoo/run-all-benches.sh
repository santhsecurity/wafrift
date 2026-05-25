#!/usr/bin/env bash
# waf-zoo/run-all-benches.sh
#
# Run wafrift bench-waf sequentially against all zoo stacks and write per-WAF
# JSON result files to wafrift-bench/results/.
#
# Prerequisites:
#   1. wafrift binary built: cargo build --release -p wafrift-cli
#   2. All stacks up: bench/waf-zoo/up.sh
#
# Usage:
#   bench/waf-zoo/run-all-benches.sh                              # all stacks, default strategies
#   VARIANTS=20 bench/waf-zoo/run-all-benches.sh                  # 20 variants
#   STRATEGIES=all bench/waf-zoo/run-all-benches.sh               # full strategy sweep (slow)
#   STRATEGIES=heavy bench/waf-zoo/run-all-benches.sh             # quick smoke run
#   bench/waf-zoo/run-all-benches.sh modsec-aws coraza            # specific stacks
#
# Defaults match `bench-waf`'s own default: `heavy,equiv-cegis`. That covers
# the two strategies the bench-diff CI gate cares about (payload mutation +
# CEGIS) without burning hours on the full grid.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WAFRIFT="$REPO_ROOT/target/release/wafrift"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"

if [ ! -x "$WAFRIFT" ]; then
    echo "ERROR: wafrift binary not found at $WAFRIFT" >&2
    echo "       Build first: cargo build --release -p wafrift-cli" >&2
    exit 1
fi

declare -A STACKS_PORT=(
    [modsec-aws]=18101
    [modsec-azure]=18102
    [coraza]=18103
    [naxsi]=18104
    [shadowdaemon]=18105
)

if [ $# -gt 0 ]; then
    STACKS=( "$@" )
else
    STACKS=( modsec-aws modsec-azure coraza naxsi shadowdaemon )
fi

mkdir -p "$RESULT_DIR"

PASS=()
FAIL=()

for stack in "${STACKS[@]}"; do
    port="${STACKS_PORT[$stack]:-}"
    if [ -z "$port" ]; then
        echo "[$stack] unknown stack — skip" >&2
        continue
    fi

    output="$RESULT_DIR/${TIMESTAMP}-zoo-${stack}.json"
    echo "[$stack] benching http://127.0.0.1:${port} → $output"

    if "$WAFRIFT" bench-waf \
        --base-url "http://127.0.0.1:${port}" \
        --evade \
        --strategies "${STRATEGIES:-heavy,equiv-cegis}" \
        --variants "${VARIANTS:-5}" \
        --format json \
        --output "$output"; then
        bypass=$(jq -r '.evaded_summary.overall_bypass_rate // "n/a"' "$output" 2>/dev/null || echo "n/a")
        echo "  [$stack] done — bypass_rate=$bypass"
        PASS+=("$stack")
    else
        echo "  [$stack] FAILED" >&2
        FAIL+=("$stack")
    fi
done

echo
echo "Results written to $RESULT_DIR/"
echo "Passed: ${PASS[*]:-none}"
if [ "${#FAIL[@]}" -gt 0 ]; then
    echo "Failed: ${FAIL[*]}" >&2
    exit 1
fi
