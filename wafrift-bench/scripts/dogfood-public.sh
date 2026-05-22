#!/usr/bin/env bash
# Endless dogfood loop against safe public targets — runs every
# new wafrift subcommand and grep-filters for errors / divergences.
#
# Public targets we trust to be both reachable AND safe to probe
# at low rate-limits:
#   - https://httpbin.org/ — HTTP test harness, no WAF, accepts everything
#   - https://countries.trevorblades.com/graphql — public GraphQL playground
#
# DO NOT change to a target you don't own. The probes ARE adversarial
# (Origin: attacker.example, dup-Authorization, alias bombing, etc.);
# they're benign against httpbin's accept-all design and the
# countries-GraphQL public demo but would be ABUSE against a real
# customer.

set -uo pipefail

WAFRIFT="${WAFRIFT:-cargo run --bin wafrift --quiet --}"
DELAY="${DELAY_MS:-100}"

run_probe() {
    local cmd="$1"
    shift
    echo "─── ${cmd} $* ───"
    # shellcheck disable=SC2086
    $WAFRIFT $cmd "$@" 2>&1 | tail -40
    echo
}

while true; do
    echo "════════════════════════ $(date) ════════════════════════"

    # The parser-diff family — fast, safe.
    run_probe attack       https://httpbin.org/get --format json --quiet --probe-timeout-secs 30
    run_probe parser-diff  https://httpbin.org/get --quiet --delay-ms "$DELAY"
    run_probe header-diff  https://httpbin.org/headers --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe body-diff    https://httpbin.org/post --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe query-diff   https://httpbin.org/get --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe cache-diff   https://httpbin.org/cache --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe h2-diff      https://httpbin.org/get --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe method-diff  https://httpbin.org/anything --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe cors-diff    https://httpbin.org/get --format json --quiet --delay-ms "$DELAY" --timeout-secs 5
    run_probe gql-diff     https://countries.trevorblades.com/graphql --format json --quiet --delay-ms "$DELAY" --timeout-secs 5

    # WAF detection / fingerprinting.
    run_probe detect --url https://httpbin.org/get --format json
    run_probe legendary    https://httpbin.org/get --quiet --max-bypass-payloads 3 || true

    echo "════════════════════════ pause 60s ════════════════════════"
    sleep 60
done
