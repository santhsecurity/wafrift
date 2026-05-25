# waf-zoo/modsec-aws — ModSecurity + AWS WAF Common Rule Set emulation

## What this is

ModSecurity 3 (Apache) running OWASP CRS 4 at Paranoia Level 2, with the rule
exclusions and scoring overrides that mirror **AWSManagedRulesCommonRuleSet
(ACR)** — the default managed rule group applied to AWS ALB/CloudFront/API
Gateway customers.

This is an emulation, not the real AWS WAF (which is a proprietary SaaS). The
delta between vanilla CRS PL2 and ACR is encoded in `modsec-aws-crs.conf`:

- Rules AWS excludes from CRS (too noisy on cloud traffic): 920120, 920300,
  920320, 921151, 942110, 942150, 942410, 942490
- AWS-only rules added on top of CRS: Log4Shell JNDI (9001002), URI-path XSS
  (9001001)

References:
- https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
- https://coreruleset.org/docs/deployment/aws-waf/

## Port

`18101` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

## Backend

`kennethreitz/httpbin` — echoes the request. A 200 with the payload echoed in
the response body means the WAF forwarded it (bypass). A 403 / 406 means block.

## How to run

```bash
# 1. Start the stack
docker compose -f bench/waf-zoo/modsec-aws/docker-compose.yml up -d

# 2. Smoke test — expect 200 OK from httpbin
curl -si http://127.0.0.1:18101/get | head -2

# 3. Verify WAF blocks a raw SQLi payload
curl -si "http://127.0.0.1:18101/get?q=1'+OR+'1'='1" | head -2
# Expected: HTTP/1.1 403

# 4. Run the bench
bench/waf-zoo/modsec-aws/wafrift-bench.sh

# 5. Stop
docker compose -f bench/waf-zoo/modsec-aws/docker-compose.yml down -v
```

## Expected container names

| Service | Container name |
|---|---|
| WAF (ModSec + Apache) | `wafrift-modsec-aws` |
| Backend (httpbin) | `wafrift-modsec-aws-backend` |

## Licensing

`owasp/modsecurity-crs` — Apache 2.0.
`kennethreitz/httpbin` — ISC.
No commercial or trial licenses required.
