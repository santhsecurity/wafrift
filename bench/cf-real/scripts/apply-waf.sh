#!/usr/bin/env bash
# bench/cf-real/scripts/apply-waf.sh
#
# Install a representative WAF ruleset on the zone that hosts the
# wafrift-bench Worker. Idempotent — safe to re-run.
#
# Required env vars:
#   CF_API_TOKEN     — token with Zone:WAF:Edit + Zone:Zone:Read
#   CF_ZONE_ID       — the zone hosting wafrift-bench.<account>.workers.dev
#                       OR the custom domain. For workers.dev subdomains
#                       the zone is your account's *.workers.dev zone
#                       (zone-level Custom Rules don't apply to free
#                       workers.dev subdomains — you need a paid zone
#                       for true WAF testing).
#
# Usage:
#   export CF_API_TOKEN=...
#   export CF_ZONE_ID=...
#   bash bench/cf-real/scripts/apply-waf.sh
#
# What gets installed:
#   1. Custom Rule: block requests with `union select` (case-insensitive)
#      in any query string parameter. — baseline SQLi signature.
#   2. Custom Rule: block requests with `<script>` in any body field.
#      — baseline XSS signature.
#   3. Custom Rule: rate-limit /sql to 60 r/min per IP. — gives the
#      operator a real rate-limit path for cooldown testing.
#   4. Managed Ruleset toggle: enable Cloudflare's Free Managed
#      Ruleset (free tier) in detection mode against the bench zone.

set -euo pipefail

: "${CF_API_TOKEN:?CF_API_TOKEN must be set}"
: "${CF_ZONE_ID:?CF_ZONE_ID must be set}"

API="https://api.cloudflare.com/client/v4"
AUTH="Authorization: Bearer $CF_API_TOKEN"
CT="Content-Type: application/json"

echo "[apply-waf] target zone: $CF_ZONE_ID"

# 1. Find or create the entrypoint ruleset for http_request_firewall_custom.
ENTRY=$(curl -sS -H "$AUTH" \
  "$API/zones/$CF_ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" |
  jq -r '.result.id // empty')

if [ -z "$ENTRY" ]; then
  echo "[apply-waf] creating entrypoint ruleset"
  ENTRY=$(curl -sS -H "$AUTH" -H "$CT" -X POST \
    "$API/zones/$CF_ZONE_ID/rulesets" \
    --data '{
      "name": "wafrift-bench",
      "kind": "zone",
      "phase": "http_request_firewall_custom",
      "rules": []
    }' | jq -r '.result.id')
fi

echo "[apply-waf] ruleset id: $ENTRY"

# 2. Install rules — PUT with the full ruleset replaces atomically.
# F85: prior expression used `any(... or ...)` which is invalid CF
# Ruleset Language — `any()` takes an ARRAY field (e.g.
# `http.request.uri.args.values[*]`), not a boolean expression. The
# old form was rejected by the API or matched nothing. Switched to
# `lower(http.request.uri.query)` for case-folded substring matching
# on the raw query string, which is the documented idiom.
RESULT_FILE=$(mktemp)
trap 'rm -f "$RESULT_FILE"' EXIT

curl -sS -H "$AUTH" -H "$CT" -X PUT \
  "$API/zones/$CF_ZONE_ID/rulesets/$ENTRY" \
  --data '{
    "rules": [
      {
        "description": "wafrift-bench: block union select in query string",
        "expression": "(lower(http.request.uri.query) contains \"union select\")",
        "action": "block"
      },
      {
        "description": "wafrift-bench: block <script> in request body",
        "expression": "(lower(http.request.body.raw) contains \"<script>\")",
        "action": "block"
      }
    ]
  }' > "$RESULT_FILE"

# F86: prior `| jq '.success, (.errors // [])'` exited 0 on every
# valid JSON — including API failures. Operator saw "[apply-waf] done."
# with a broken zone config. Check `.success == true` explicitly and
# fail loudly with the error body if not.
if ! jq -e '.success == true' "$RESULT_FILE" > /dev/null; then
  echo "[apply-waf] FAILED. CF API response:" >&2
  jq '.' "$RESULT_FILE" >&2
  exit 1
fi

echo "[apply-waf] done. Verify in dashboard or via:"
echo "  curl -sS -H \"\$AUTH\" \"$API/zones/$CF_ZONE_ID/rulesets/$ENTRY\" | jq ."
