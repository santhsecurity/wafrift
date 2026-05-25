# waf-zoo/naxsi — Naxsi (positive-security WAF for nginx)

## What this is

[Naxsi](https://github.com/wargio/naxsi) is an nginx module that implements a
positive-security / score-accumulation WAF model. Instead of matching request
strings against a ruleset of attack signatures, Naxsi assigns character-class
scores to each request component and blocks if any category score crosses a
threshold (`$SQL >= 4`, `$XSS >= 4`, etc.).

This fundamentally different model means:

- CRS-centric evasion techniques (comment injection, encoding tricks, multipart
  smuggling) often have zero effect on Naxsi's scores.
- Some payloads that evade CRS regex matching still accumulate enough Naxsi
  score tokens to trigger a block.
- Other payloads that CRS catches miss Naxsi's scoring entirely.

Benching wafrift against Naxsi surfaces a different bypass landscape than
any of the modsec-pl* targets.

## No published Docker image

No official Naxsi Docker image is published. This stack builds nginx + naxsi
from source at pinned tags (nginx 1.27.4, naxsi 1.6). The first `docker compose
up --build` takes ~5 minutes. Subsequent starts are instant (layer cache).

## Port

`18104` — does not conflict with any other waf-zoo or wafrift-bench/targets stack.

Note: `wafrift-bench/targets/naxsi` uses port 18087. This stack uses a distinct
image name (`wafrift/zoo-naxsi`) and container name prefix (`wafrift-zoo-naxsi`)
so both can run simultaneously.

## Backend

`kennethreitz/httpbin` — echoes the request. 200 + echo = WAF allowed (bypass).
403 = WAF blocked via `/RequestDenied` routing.

## How to run

```bash
# 1. Build and start (first run ~5 min)
docker compose -f bench/waf-zoo/naxsi/docker-compose.yml up -d --build

# 2. Smoke test — expect 200 OK
curl -si http://127.0.0.1:18104/get | head -2

# 3. Verify WAF blocks a raw SQLi payload
curl -si "http://127.0.0.1:18104/get?q=1'+OR+'1'='1" | head -2
# Expected: HTTP/1.1 403

# 4. Verify block on XSS
curl -si "http://127.0.0.1:18104/get?q=<script>alert(1)</script>" | head -2
# Expected: HTTP/1.1 403

# 5. Run the bench
bench/waf-zoo/naxsi/wafrift-bench.sh

# 6. Stop
docker compose -f bench/waf-zoo/naxsi/docker-compose.yml down -v
```

## Adjusting thresholds

Edit `naxsi.conf`. Lower thresholds = more blocking = fewer bypasses.
`CheckRule "$SQL >= 2" BLOCK` is the tightest useful value before FP rate
becomes high.

## Container names

| Service | Container name |
|---|---|
| WAF (nginx + naxsi) | `wafrift-zoo-naxsi` |
| Backend (httpbin) | `wafrift-zoo-naxsi-backend` |

## Licensing

nginx — BSD 2-clause.
Naxsi — GPLv3 (wargio/naxsi fork; see https://github.com/wargio/naxsi/blob/main/LICENSE).
`kennethreitz/httpbin` — ISC.
No commercial or trial licenses required.

**GPLv3 note**: Naxsi is compiled into nginx as a dynamic module at build time.
The resulting binary is a GPLv3-covered work. This bench stack is for local
security research only; do not redistribute the built image without complying
with GPLv3 source-disclosure requirements.
