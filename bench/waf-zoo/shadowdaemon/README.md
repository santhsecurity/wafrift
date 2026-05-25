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
- **Database** (PostgreSQL) — stores profiles, rules, and request logs.

Because the connector runs _after_ HTTP parsing, transport-layer evasion
techniques (chunked encoding, multipart boundary manipulation, HTTP/2 smuggling)
are neutralised by the PHP SAPI before shadowd ever sees the parameters. The
relevant bypass surface is at the **parameter grammar** level: SQL/XSS/CMDI
patterns that the shadowd signature engine scores below its block threshold.

## Stack components

| Container | Image | Role |
|---|---|---|
| `wafrift-zoo-shadowd` | `zecure/shadowd` (pinned SHA) | Scoring daemon |
| `wafrift-zoo-shadowd-db` | `postgres:16-alpine` | Rule/profile state |
| `wafrift-zoo-shadowd-php` | Built from `Dockerfile` | nginx + PHP-FPM + connector |

The PHP app (`echo.php`) reflects all GET/POST parameters back as JSON on allow,
and the connector calls `exit(403)` on block before echo.php runs.

## Port

`18105` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

## First-run setup required

shadowd needs a profile and ruleset before it starts scoring. On first start:

```bash
# 1. Start the stack (first run builds the PHP app ~2 min)
docker compose -f bench/waf-zoo/shadowdaemon/docker-compose.yml up -d --build

# 2. Wait for the DB and shadowd to initialise (~15s)
docker logs wafrift-zoo-shadowd 2>&1 | tail -5

# 3. Import the default Shadow Daemon blacklist rules via the CLI
#    (shadowd ships a database migration + default rule import script)
docker exec wafrift-zoo-shadowd shadowd --import-rules

# 4. Smoke test
curl -si http://127.0.0.1:18105/ | head -2
# Expected: HTTP/1.1 200

# 5. Verify block on SQLi
curl -si -X POST http://127.0.0.1:18105/ -d "q=1' OR '1'='1" | head -2
# Expected: HTTP/1.1 403
```

## How to run the bench

```bash
bench/waf-zoo/shadowdaemon/wafrift-bench.sh
```

## Stopping

```bash
docker compose -f bench/waf-zoo/shadowdaemon/docker-compose.yml down -v
```

## Licensing

`zecure/shadowd` — GPLv2 (https://github.com/zecure/shadowd/blob/master/LICENSE).
`shadowd/php_connector` — LGPLv2.1.
`postgres:16-alpine` — PostgreSQL License (permissive).
No commercial or trial licenses required.

**GPLv2 note**: `shadowd` is GPLv2. This bench stack runs it as an unmodified
Docker image for local security research. Redistribution of modified shadowd
binaries requires GPLv2 source disclosure.
