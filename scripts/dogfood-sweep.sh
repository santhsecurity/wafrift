#!/usr/bin/env bash
# scripts/dogfood-sweep.sh
#
# Post-merge integration sweep. Runs every wired surface end-to-end,
# captures bench number, diffs against the pre-sweep baseline.
#
# Flow:
#   1. Snapshot pre-sweep state: HEAD, working-tree status, dirty crates.
#   2. cargo build --release --bin wafrift (background)
#   3. cargo test --workspace --release (background)
#   4. cargo clippy --workspace --all-targets --release -- -D warnings (background)
#   5. wafrift --help (must not error)
#   6. wafrift evade --help (must not error — fails if #125 unwired)
#   7. wafrift scan --graphql --help (must not error — fails if #126 unwired)
#   8. wafrift audit --help (must not error — wafmodel defender path)
#   9. wafrift bench-waf against testing.santh.dev with --evade (the
#      headline number).
#  10. Compare against the previous report in wafrift-bench/results/
#      and print +/- delta.
#
# Output: one JSON file at wafrift-bench/results/dogfood-<TIMESTAMP>.json
# with the full report, plus a human-readable diff on stdout.
#
# Usage:
#   scripts/dogfood-sweep.sh                     # full sweep
#   SKIP_BENCH=1 scripts/dogfood-sweep.sh        # don't hit the network
#   BENCH_TARGET=https://x scripts/dogfood-sweep.sh
#   VARIANTS=20 scripts/dogfood-sweep.sh         # bench variants per case

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WAFRIFT="$REPO_ROOT/target/release/wafrift"
RESULT_DIR="$REPO_ROOT/wafrift-bench/results"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
REPORT="$RESULT_DIR/dogfood-${TIMESTAMP}.json"

BENCH_TARGET="${BENCH_TARGET:-https://testing.santh.dev}"
VARIANTS="${VARIANTS:-10}"
SKIP_BENCH="${SKIP_BENCH:-0}"

# Soft-fail mode — don't kill the sweep if a not-yet-wired surface is
# missing. Each subcommand probe is timeboxed so a hang doesn't ruin
# the run.
TIMEBOX="${TIMEBOX:-30}"

mkdir -p "$RESULT_DIR"

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

log()   { printf '%s [dogfood] %b%s%b\n' "$(date -u +%H:%M:%S)" "$YELLOW" "$1" "$RESET" >&2; }
ok()    { printf '%s [dogfood] %b✓ %s%b\n' "$(date -u +%H:%M:%S)" "$GREEN"  "$1" "$RESET" >&2; }
bad()   { printf '%s [dogfood] %b✗ %s%b\n' "$(date -u +%H:%M:%S)" "$RED"    "$1" "$RESET" >&2; }

# --- 1. snapshot ----------------------------------------------------
HEAD_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
HEAD_MSG="$(cd "$REPO_ROOT" && git log -1 --pretty=%s 2>/dev/null || echo unknown)"
DIRTY="$(cd "$REPO_ROOT" && git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

log "HEAD=$HEAD_SHA \"$HEAD_MSG\" (dirty=$DIRTY)"

# --- 2-4. parallel build + lint -------------------------------------
log "starting cargo build/test/clippy in parallel..."
(
    cd "$REPO_ROOT"
    cargo build --release --bin wafrift > "$RESULT_DIR/dogfood-${TIMESTAMP}-build.log" 2>&1
) &
PID_BUILD=$!

(
    cd "$REPO_ROOT"
    cargo test --workspace --release > "$RESULT_DIR/dogfood-${TIMESTAMP}-test.log" 2>&1
) &
PID_TEST=$!

(
    cd "$REPO_ROOT"
    cargo clippy --workspace --all-targets --release -- -D warnings \
        > "$RESULT_DIR/dogfood-${TIMESTAMP}-clippy.log" 2>&1
) &
PID_CLIPPY=$!

wait "$PID_BUILD"     && ok "build green"   || bad "build RED — see $RESULT_DIR/dogfood-${TIMESTAMP}-build.log"
wait "$PID_TEST"      && ok "tests green"   || bad "tests RED — see $RESULT_DIR/dogfood-${TIMESTAMP}-test.log"
wait "$PID_CLIPPY"    && ok "clippy green"  || bad "clippy RED — see $RESULT_DIR/dogfood-${TIMESTAMP}-clippy.log"

if [ ! -x "$WAFRIFT" ]; then
    bad "wafrift binary missing — abort"
    exit 2
fi

# --- 5-8. subcommand reachability probes ---------------------------
SURFACES_OK=()
SURFACES_MISSING=()

probe_subcommand() {
    local name="$1"
    local cmd="$2"
    if timeout "$TIMEBOX" $WAFRIFT $cmd --help > /dev/null 2>&1; then
        ok "$name reachable"
        SURFACES_OK+=( "$name" )
    else
        bad "$name NOT reachable (subcommand missing or panics)"
        SURFACES_MISSING+=( "$name" )
    fi
}

probe_subcommand "wafrift --help"       ""
probe_subcommand "wafrift bench-waf"    "bench-waf"
probe_subcommand "wafrift scan"         "scan"
probe_subcommand "wafrift evade"        "evade"
probe_subcommand "wafrift audit"        "audit"
probe_subcommand "wafrift harden"       "harden"
probe_subcommand "wafrift detect"       "detect"
probe_subcommand "wafrift recon"        "recon"

# --- 9. bench ----------------------------------------------------
if [ "$SKIP_BENCH" = "1" ]; then
    log "SKIP_BENCH=1 — bench step skipped"
    BENCH_JSON="null"
else
    log "running bench-waf against $BENCH_TARGET (variants=$VARIANTS)..."
    BENCH_OUT="$RESULT_DIR/dogfood-${TIMESTAMP}-bench.json"
    if timeout 1800 "$WAFRIFT" bench-waf \
        --base-url "$BENCH_TARGET" \
        --evade \
        --variants "$VARIANTS" \
        --output "$BENCH_OUT" \
        > "$RESULT_DIR/dogfood-${TIMESTAMP}-bench.log" 2>&1; then
        ok "bench complete — see $BENCH_OUT"
        BENCH_JSON="$BENCH_OUT"
    else
        bad "bench failed — see $RESULT_DIR/dogfood-${TIMESTAMP}-bench.log"
        BENCH_JSON="null"
    fi
fi

# --- 10. diff vs previous ----------------------------------------
PREV_BENCH=$(ls -t "$RESULT_DIR"/dogfood-*-bench.json 2>/dev/null | grep -v "$TIMESTAMP" | head -1 || echo "")
if [ -n "$PREV_BENCH" ] && [ -f "$PREV_BENCH" ] && [ "$BENCH_JSON" != "null" ]; then
    log "diffing against $PREV_BENCH"
    PREV_RATE=$(grep -oE '"bypass_rate"[[:space:]]*:[[:space:]]*[0-9.]+' "$PREV_BENCH" | head -1 | grep -oE '[0-9.]+$' || echo "0")
    CURR_RATE=$(grep -oE '"bypass_rate"[[:space:]]*:[[:space:]]*[0-9.]+' "$BENCH_JSON" | head -1 | grep -oE '[0-9.]+$' || echo "0")
    printf "  PREV: %s\n" "$PREV_RATE"
    printf "  CURR: %s\n" "$CURR_RATE"
else
    log "no previous bench to diff against"
    PREV_RATE="null"
    CURR_RATE="null"
fi

# --- 11. summary report -----------------------------------------
cat > "$REPORT" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "head_sha": "$HEAD_SHA",
  "head_msg": "$(printf '%s' "$HEAD_MSG" | sed 's/"/\\"/g')",
  "dirty_paths": $DIRTY,
  "surfaces_reachable": [$(printf '"%s",' "${SURFACES_OK[@]}" | sed 's/,$//')],
  "surfaces_missing": [$(printf '"%s",' "${SURFACES_MISSING[@]}" | sed 's/,$//')],
  "bench_target": "$BENCH_TARGET",
  "bench_variants": $VARIANTS,
  "bench_json": "$BENCH_JSON",
  "bench_rate_prev": $([ "$PREV_RATE" = "null" ] && echo null || echo "$PREV_RATE"),
  "bench_rate_curr": $([ "$CURR_RATE" = "null" ] && echo null || echo "$CURR_RATE")
}
EOF

echo
echo "=== dogfood sweep complete ==="
echo "report: $REPORT"
echo "reachable surfaces: ${#SURFACES_OK[@]}/$((${#SURFACES_OK[@]} + ${#SURFACES_MISSING[@]}))"
echo "missing surfaces:   ${SURFACES_MISSING[*]:-<none>}"
if [ "$BENCH_JSON" != "null" ]; then
    echo "bench rate:         prev=$PREV_RATE  curr=$CURR_RATE"
fi
