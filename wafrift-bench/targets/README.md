# wafrift-bench/targets — local WAF stacks

Each subdirectory is a self-contained docker-compose stack that runs
**one** WAF in front of an `httpbin` backend so wafrift can attack a
real upstream and measure the response.

| Stack | Container | Port | What it is |
|---|---|---|---|
| `modsec-pl1` | `wafrift-pl1` | `18081` | ModSecurity + OWASP CRS at Paranoia Level 1 (default) |
| `modsec-pl2` | `wafrift-pl2` | `18082` | ModSecurity + CRS at PL 2 |
| `modsec-pl3` | `wafrift-pl3` | `18083` | ModSecurity + CRS at PL 3 |
| `modsec-pl4` | `wafrift-pl4` | `18084` | ModSecurity + CRS at PL 4 (most aggressive) |
| `coraza` | `wafrift-coraza` | `18085` | Coraza (Go reimplementation of ModSec) + CRS |
| `naxsi` | `wafrift-naxsi` | `18086` | Naxsi (positive security model, nginx) |

## Bring everything up

```bash
wafrift-bench/scripts/up.sh                 # all stacks
wafrift-bench/scripts/up.sh modsec-pl1      # one stack
```

## Tear down

```bash
wafrift-bench/scripts/down.sh
docker stop wafrift-pl1 wafrift-pl2 wafrift-pl3 wafrift-pl4 \
  wafrift-coraza wafrift-naxsi 2>/dev/null; true
```

## Why httpbin as the backend

`httpbin` echoes the request back, including method/path/headers/body.
The bench harness inspects that echo to confirm the WAF *forwarded*
the payload — i.e., a 200 with the payload echoed = WAF allowed; a 403
or 406 = WAF blocked. No semantic backend behavior involved, which
keeps the bench deterministic.

## Adding a new WAF

1. Create `wafrift-bench/targets/<name>/docker-compose.yml` exposing port `1808N`.
2. Container name **must** start with `wafrift-` so the tear-down rule
   in CI catches it.
3. The compose stack must include the same `httpbin` backend.
4. Document baseline behavior (PL, rule set, scoring threshold) here.
