# waf-zoo/coraza — Coraza WAF (Go reimplementation of ModSecurity)

## What this is

[Coraza](https://coraza.io/) is the OWASP Coraza project's Go reimplementation
of the ModSecurity engine. It runs the same OWASP CRS rule language but the
underlying HTTP parser, regex engine (RE2 instead of PCRE), and multi-part body
handling differ from `libmodsecurity3`. This produces a distinct bypass surface:
techniques that slip past `libmodsecurity3` may be caught by Coraza, and vice
versa.

Coraza is the WAF engine behind Fastly Next-Gen WAF, Traefik Enterprise WAF,
and several cloud-edge platforms. Benching against it measures real-world
exposure beyond the ModSec-specific modsec-pl* stacks.

Stack: `coraza-caddy` (Caddy reverse proxy + `coraza_waf` middleware plugin +
OWASP CRS). SecRuleEngine is forced to `On` (blocking mode) in the Caddyfile.

## Port

`18103` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

Note: `wafrift-bench/targets/coraza` uses port 18085. This stack is a separate
zoo entry with a different image (ghcr.io vs the deprecated jptosso namespace)
and is independently managed.

## Backend

`kennethreitz/httpbin` — echoes the request. 200 + echo = WAF allowed (bypass).
403 = WAF blocked.

## How to run

```bash
# 1. Start the stack
docker compose -f bench/waf-zoo/coraza/docker-compose.yml up -d

# 2. Smoke test — expect 200 OK
curl -si http://127.0.0.1:18103/get | head -2

# 3. Verify WAF blocks a raw SQLi payload
curl -si "http://127.0.0.1:18103/get?q=1'+OR+'1'='1" | head -2
# Expected: HTTP/1.1 403

# 4. Run the bench
bench/waf-zoo/coraza/wafrift-bench.sh

# 5. Stop
docker compose -f bench/waf-zoo/coraza/docker-compose.yml down -v
```

## Container names

| Service | Container name |
|---|---|
| WAF (Coraza + Caddy) | `wafrift-zoo-coraza` |
| Backend (httpbin) | `wafrift-zoo-coraza-backend` |

## Tuning Paranoia Level

Edit `Caddyfile` and add inside the `directives` block, before the CRS includes:

```caddy
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2"
```

## Licensing

`ghcr.io/corazawaf/coraza-caddy` — Apache 2.0 (OWASP Coraza project).
`kennethreitz/httpbin` — ISC.
No commercial or trial licenses required.
