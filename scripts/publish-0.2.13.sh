#!/usr/bin/env bash
# Publish wafrift v0.2.13 to crates.io.
#
# Run from the workspace root. Each `cargo publish` waits up to 60s
# between crates so the index has time to settle (avoids "no matching
# package named X found" on subsequent crates that depend on the prior
# one).
#
# Re-runnable: cargo publish refuses to re-publish an already-published
# version, so a partial run is safe to resume.
#
# WHY THIS ORDER: topological. types is the leaf; everything else
# imports it. CLI-bin crates publish last because they pull in the
# entire stack.
#
# Pre-flight (mandatory before running):
#   1. Workspace test suite green at this version (CARGO_TARGET_DIR
#      separate from any in-flight agent's target).
#   2. Git working tree clean on this version's commit.
#   3. Maintainer authorization (publish is irreversible from
#      crates.io and version numbers cannot be reused).
#
# Usage:
#     scripts/publish-0.2.13.sh                 # publish for real
#     WAIT_BETWEEN_PUBLISH=60 scripts/publish-0.2.13.sh   # slower

set -euo pipefail

WAIT_BETWEEN_PUBLISH="${WAIT_BETWEEN_PUBLISH:-45}"

publish() {
    local crate="$1"
    echo
    echo "==> cargo publish -p $crate"
    if cargo publish -p "$crate" 2>&1 | tee "/tmp/publish-${crate}.log"; then
        echo "==> $crate published."
        sleep "$WAIT_BETWEEN_PUBLISH"
    else
        # If the crate is already at this version, that's fine — just
        # log and continue. Anything else: bail.
        if grep -qE "already uploaded|already exists on crates.io index|crate version .* is already uploaded" "/tmp/publish-${crate}.log"; then
            echo "==> $crate already at this version on crates.io; skipping."
        else
            echo "==> ERROR: $crate publish failed. See /tmp/publish-${crate}.log"
            exit 1
        fi
    fi
}

# Tier 1 — foundation, zero internal deps.
publish wafrift-types
publish wafrift-genome-registry

# Tier 2 — depend only on types.
publish wafrift-encoding
publish wafrift-grammar
publish wafrift-content-type
publish wafrift-smuggling
publish wafrift-fingerprint
publish wafrift-pool

# Tier 3 — depend on tier 1+2.
publish wafrift-detect
publish wafrift-evolution
publish wafrift-oracle

# Tier 4 — strategy pulls in everything above.
publish wafrift-strategy

# Tier 5 — transport depends on strategy + pool.
publish wafrift-transport

# Tier 6 — recon depends on types + transport.
publish wafrift-recon

# Tier 7 — captchaforge-bridge depends on transport.
publish wafrift-captchaforge-bridge

# Tier 8 — proxy + cli + core (the "products"). These pull in the full
# stack and ship the binaries `wafrift` + `wafrift-proxy` to
# practitioners.
publish wafrift-proxy
publish wafrift-cli
publish wafrift-core

echo
echo "==> All v0.2.13 crates published."
echo "==> Next: git tag v0.2.13 && git push origin v0.2.13 (triggers prebuilt-binary release workflow)."
