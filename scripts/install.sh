#!/usr/bin/env bash
# Durable local install for wafrift + wafrift-proxy.
#
# The dogfood finding: a release binary was symlinked into ~/.local/bin
# and later vanished (cargo clean / tmpfs), leaving a dangling symlink
# and a "command not found" with no hint. This script installs a real
# COPY (not a symlink into target/) to a stable prefix and then VERIFIES
# the installed binaries actually execute — so a broken install fails
# loudly here instead of in the field.
set -euo pipefail

PREFIX="${WAFRIFT_PREFIX:-$HOME/.local/bin}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "wafrift install → ${PREFIX}"
mkdir -p "${PREFIX}"

echo "building release binaries (this may take a few minutes)…"
cargo build --release -p wafrift-cli -p wafrift-proxy --manifest-path "${REPO_ROOT}/Cargo.toml"

install_one() {
  local name="$1" src="${REPO_ROOT}/target/release/$1" dst="${PREFIX}/$1"
  if [[ ! -x "${src}" ]]; then
    echo "ERROR: built binary missing: ${src}" >&2
    exit 1
  fi
  # Copy, never symlink into target/ — that is exactly what rotted last
  # time. A copy survives `cargo clean`.
  install -m 0755 "${src}" "${dst}"
  # Verify the installed copy runs and is the version we just built.
  if ! "${dst}" --version >/dev/null 2>&1; then
    echo "ERROR: installed ${name} does not execute (${dst})" >&2
    exit 1
  fi
  echo "  ✓ ${name} → ${dst} ($("${dst}" --version 2>/dev/null | head -1))"
}

install_one wafrift
install_one wafrift-proxy

case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *) echo "NOTE: ${PREFIX} is not on \$PATH — add: export PATH=\"${PREFIX}:\$PATH\"" ;;
esac

echo "done. 'wafrift --version' and 'wafrift-proxy --version' verified."
