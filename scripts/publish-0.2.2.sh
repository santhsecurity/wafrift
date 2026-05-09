#!/usr/bin/env bash
# Publish wafrift v0.2.2 to crates.io.
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
        if grep -qE "already uploaded|already exists on crates.io index" "/tmp/publish-${crate}.log"; then
            echo "==> $crate already at this version on crates.io; skipping."
        else
            echo "==> ERROR: $crate publish failed. See /tmp/publish-${crate}.log"
            exit 1
        fi
    fi
}

# Tier 1 — foundation, no internal deps.
publish wafrift-types

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

# Tier 7 — proxy + cli + core (the "products"). These pull in the full
# stack and ship the binaries `wafrift` + `wafrift-proxy` to
# practitioners.
publish wafrift-proxy
publish wafrift-cli
publish wafrift-core

echo
echo "==> All v0.2.2 crates published."
echo "==> Next: git tag v0.2.2 && git push origin v0.2.2 (triggers prebuilt-binary release workflow)."
