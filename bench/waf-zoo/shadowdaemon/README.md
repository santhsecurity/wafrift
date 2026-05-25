# waf-zoo/shadowdaemon — Shadow Daemon WAF

## What this is

[Shadow Daemon](https://shadowd.zecure.org/) (`shadowd`) is an open-source WAF
with a three-component architecture that differs fundamentally from
ModSec/Coraza/Naxsi:

- **Connector** — a language-specific library (PHP/Perl/Python/Node) embedded
  directly inside the web application process. It intercepts incoming request
  parameters _after_ the app server has parsed them, then sends the parsed
  parameter map to the daemon for scoring.
- **Daemon** (`shadowd`) — scores the parsed parameters against a signature
  database and returns a block/allow decision.
- **Dashboard** — web UI for rule management (not needed for bench purposes).

Because the connector runs _after_ HTTP parsing, transport-layer evasion
techniques (chunked encoding, multipart boundary manipulation, HTTP/2 smuggling)
are neutralised by the PHP SAPI before shadowd ever sees the parameters. The
relevant bypass surface is at the **parameter grammar** level: SQL/XSS/CMDI
patterns that the shadowd token engine scores below its block threshold.

This stack uses the official `shadowd` daemon image + `shadowd_php` demo app
(nginx + PHP with the connector installed). The bench sends payloads to the PHP
app's parameter endpoint.

## Port

`18105` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

## Important: different backend

This stack does NOT use httpbin. It uses `zecure/shadowd_php`, a PHP echo
application with the shadowd connector pre-installed. The block detection
logic differs:

- **Block**: HTTP 403, or HTTP 200 with body containing `Forbidden`
- **Bypass**: HTTP 200 with the submitted parameter echoed in the response body

## How to run

```bash
# 1. Start the stack
docker compose -f bench/waf-zoo/shadowdaemon/docker-compose.yml up -d

# 2. Wait for shadowd to be ready (~10s on first start)
docker logs wafrift-zoo-shadowd 2>&1 | tail -5

# 3. Smoke test — expect 200 OK from the PHP demo app
curl -si http://127.0.0.1:18105/ | head -2

# 4. Verify WAF blocks a raw SQLi payload submitted as a POST parameter
curl -si -X POST http://127.0.0.1:18105/ -d "q=1' OR '1'='1" | head -4
# Expected: HTTP/1.1 403  (or 200 with "Forbidden" body)

# 5. Run the bench
bench/waf-zoo/shadowdaemon/wafrift-bench.sh

# 6. Stop
docker compose -f bench/waf-zoo/shadowdaemon/docker-compose.yml down -v
```

## Container names

| Service | Container name |
|---|---|
| Shadow Daemon daemon | `wafrift-zoo-shadowd` |
| PHP connector app | `wafrift-zoo-shadowd-php` |

## Licensing

`zecure/shadowd` — GPLv2 (https://github.com/zecure/shadowd/blob/master/LICENSE).
`zecure/shadowd_php` — LGPLv2.1 connector, Apache 2.0 demo app.
`kennethreitz/httpbin` — not used in this stack.
No commercial or trial licenses required.

**GPLv2 note**: `shadowd` is GPLv2. This bench stack runs it as an unmodified
Docker image for local security research. Redistribution of modified shadowd
binaries requires GPLv2 source disclosure.
