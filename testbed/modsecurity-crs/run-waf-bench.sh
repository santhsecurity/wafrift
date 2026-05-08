#!/usr/bin/env bash
# Start the local ModSecurity CRS stack (if needed) and run the wafrift seed benchmark.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_DIR="$ROOT/testbed/modsecurity-crs"

echo "Starting ModSecurity CRS in $COMPOSE_DIR ..."
(cd "$COMPOSE_DIR" && docker compose up -d)

echo "Waiting for http://127.0.0.1:18080 ..."
for i in $(seq 1 60); do
  if curl -sf -o /dev/null "http://127.0.0.1:18080/"; then
    echo "WAF endpoint is up."
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "Timeout waiting for WAF — check: docker compose -f $COMPOSE_DIR/docker-compose.yml logs" >&2
    exit 1
  fi
  sleep 1
done

export WAFRIFT_MODSEC_URL="${WAFRIFT_MODSEC_URL:-http://127.0.0.1:18080}"
cd "$ROOT"
exec cargo run -p wafrift-cli --quiet -- bench-waf --base-url "$WAFRIFT_MODSEC_URL" "$@"
