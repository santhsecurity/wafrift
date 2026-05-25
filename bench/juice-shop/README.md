# wafrift bench/juice-shop

OWASP Juice Shop as the **e2e pentest target** for wafrift dogfooding.

This is *separate* from `bench/cf-real/` — that one measures pure WAF
bypass against an echo Worker. This one measures whether wafrift can
discover endpoints, plant payloads, and report findings against a
real vulnerable web app.

## Start / stop

```powershell
docker compose -f bench/juice-shop/docker-compose.yml up -d
docker compose -f bench/juice-shop/docker-compose.yml down
```

Listens on `http://127.0.0.1:3000` ONLY — never on `0.0.0.0`.

## Suggested wafrift runs

```powershell
# 1. Endpoint discovery
cargo run --release -p cli -- discover --target http://127.0.0.1:3000

# 2. Active attack pass (no WAF in front)
cargo run --release -p cli -- attack --target http://127.0.0.1:3000 \
  --techniques sqli,xss,nosql,path-traversal

# 3. Same target, but route through a stack of WAF rules
#    (CRS via local modsecurity, or via the CF bench in front)
```

## What to look for

- Discovery finds `/rest/products/search`, `/rest/user/login`, `/api/Quantitys`
- Attack reports SQLi on `/rest/products/search?q=`
- Attack reports XSS on `/#/search?q=`
- No false positives on `/rest/user/whoami` (auth endpoint, no params)
- The whole pipeline finishes in under 2 minutes for the default profile

If any of those break — that's a fix.

## Footnote

When CF zone is on Pro and the bench Worker is deployed, we can put
Juice Shop *behind* a Cloudflare Tunnel and aim wafrift at the
tunneled URL — that exercises the discover → bypass → exploit chain
in one shot. Not the default flow because tunneled bandwidth is
metered.
