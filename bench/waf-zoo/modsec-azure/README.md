# waf-zoo/modsec-azure — ModSecurity + Azure AppGW WAF v2 emulation

## What this is

ModSecurity 3 (Apache) running OWASP CRS 4 at Paranoia Level 2, with the rule
exclusions and scoring overrides that mirror **Azure Application Gateway WAF v2
DefaultRuleSet 2.1** — the ruleset deployed by default for Azure AppGW WAF,
Azure Front Door WAF, and Azure CDN WAF customers.

This is an emulation, not the real Azure WAF. The delta from vanilla CRS PL2
is encoded in `modsec-azure-crs.conf`:

- 11 rules disabled by Azure default (920300, 920320, 920350, 920420, 920430,
  921151, 942200, 942260, 942340, 942430, 950130)
- Severity downgrade on 942110 + 942150 to match Azure's lower anomaly-score
  contribution for those rules
- Body inspection limit set to 128 KB (Azure AppGW WAF v2 default)

References:
- https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules

## Port

`18102` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

## Backend

`kennethreitz/httpbin` — echoes the request. 200 + echo = WAF allowed (bypass).
403 / 406 = WAF blocked.

## How to run

```bash
# 1. Start the stack
docker compose -f bench/waf-zoo/modsec-azure/docker-compose.yml up -d

# 2. Smoke test — expect 200 OK
curl -si http://127.0.0.1:18102/get | head -2

# 3. Verify WAF blocks a raw SQLi payload
curl -si "http://127.0.0.1:18102/get?q=1'+OR+'1'='1" | head -2
# Expected: HTTP/1.1 403

# 4. Run the bench
bench/waf-zoo/modsec-azure/wafrift-bench.sh

# 5. Stop
docker compose -f bench/waf-zoo/modsec-azure/docker-compose.yml down -v
```

## Expected container names

| Service | Container name |
|---|---|
| WAF (ModSec + Apache) | `wafrift-modsec-azure` |
| Backend (httpbin) | `wafrift-modsec-azure-backend` |

## Licensing

`owasp/modsecurity-crs` — Apache 2.0.
`kennethreitz/httpbin` — ISC.
No commercial or trial licenses required.
