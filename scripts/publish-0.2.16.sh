#!/usr/bin/env bash
# Publish wafrift v0.2.16 to crates.io — MINIMAL set.
#
# Only the two crates scald (and other downstream lib consumers)
# actually need are uploaded: wafrift-types (leaf) then
# wafrift-grammar (depends on types). This deliberately does NOT
# re-publish the other 16 sub-crates: per the consolidation rule we do
# not flood crates.io with internal building blocks every release.
# Their 0.2.15 entries remain valid; nothing external pins 0.2.16 of
# them.
#
# Pre-flight (mandatory, all satisfied before running):
#   1. Full workspace test suite green at 0.2.16.
#   2. Git working tree clean on the 0.2.16 commit.
#   3. Maintainer authorization (publish is irreversible; versions
#      cannot be reused). — authorized 2026-05-18.
#
# Topological: types is the leaf; grammar imports it. The index needs
# a moment to settle between the two or grammar's resolve fails.
#
# Re-runnable: cargo publish refuses to re-publish an existing
# version, so a partial run resumes safely.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
WAIT_BETWEEN_PUBLISH="${WAIT_BETWEEN_PUBLISH:-50}"

publish() {
    local crate="$1"
    echo
    echo "==> cargo publish -p $crate"
    if cargo publish -p "$crate" 2>&1 | tee "/tmp/publish-${crate}.log"; then
        echo "==> $crate published."
        sleep "$WAIT_BETWEEN_PUBLISH"
    else
        if grep -qE "already uploaded|already exists on crates.io index|crate version .* is already uploaded" "/tmp/publish-${crate}.log"; then
            echo "==> $crate already at this version; skipping."
        else
            echo "==> ERROR: $crate publish failed. See /tmp/publish-${crate}.log"
            exit 1
        fi
    fi
}

publish wafrift-types
publish wafrift-grammar

echo
echo "==> wafrift-types + wafrift-grammar 0.2.16 published."
echo "==> Next: bump scald pins to =0.2.16, cargo update, wire reflected.rs."
