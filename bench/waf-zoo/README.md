# waf-zoo — Additional WAF bench targets

A collection of Docker-compose stacks for benching wafrift against WAF engines
beyond the OWASP CRS modsec-pl* stacks in `wafrift-bench/targets/`.

Each subdirectory is a self-contained, reproducible stack with pinned image
SHAs. All stacks use the same backend (httpbin or shadowdaemon's PHP demo app)
so bypass-rate differences are attributable to the WAF, not the backend.

## Stacks

| Directory | Port | WAF | Engine / Model |
|---|---|---|---|
| `modsec-aws/` | 18101 | ModSecurity + AWS WAF CRS emulation | CRS PL2 + AWS exclusions |
| `modsec-azure/` | 18102 | ModSecurity + Azure AppGW WAF v2 emulation | CRS PL2 + Azure exclusions |
| `coraza/` | 18103 | Coraza (Go reimplementation of ModSec) | CRS PL1, RE2 regex — build from source (xcaddy) |
| `naxsi/` | 18104 | Naxsi (nginx module, built from source) | Positive-security / score accumulation |
| `shadowdaemon/` | 18105 | Shadow Daemon | Connector-model, token grammar — build from source |

Ports 18101–18105 do not conflict with `wafrift-bench/targets/` ports 18081–18087.

## Quick start: bring up everything

```bash
# From the repo root:

# Build + start all stacks
# naxsi: ~5 min first run (nginx compile)
# coraza: ~3-5 min first run (xcaddy + coraza_waf compile)
# shadowdaemon: ~2 min first run (PHP connector Composer install)
bench/waf-zoo/up.sh

# Smoke test each stack
for port in 18101 18102 18103 18104 18105; do
    echo -n "  :$port  "
    curl -si "http://127.0.0.1:$port/" 2>/dev/null | head -1
done

# Run wafrift bench against every stack (requires: cargo build --release -p wafrift-cli)
bench/waf-zoo/run-all-benches.sh

# Tear everything down
bench/waf-zoo/down.sh
```

## Quick start: single stack

```bash
# Start one stack
docker compose -f bench/waf-zoo/modsec-aws/docker-compose.yml up -d

# Bench it
wafrift bench-waf --base-url http://127.0.0.1:18101 --evade --variants 10 \
    --format json --output wafrift-bench/results/$(date -u +%Y%m%d)-zoo-modsec-aws.json

# Or use the per-stack convenience script
bench/waf-zoo/modsec-aws/wafrift-bench.sh

# Stop it
docker compose -f bench/waf-zoo/modsec-aws/docker-compose.yml down -v
```

## Bring up the whole zoo at once (compose include)

```bash
docker compose -f bench/waf-zoo/docker-compose.yml up -d
docker compose -f bench/waf-zoo/docker-compose.yml down -v
```

## Expected output schema

The bench writes one JSON file per (WAF, timestamp) run to
`wafrift-bench/results/`. The schema is identical to the modsec-pl* stacks:

```jsonc
{
  "raw_block_rate": 0.97,
  "evaded_summary": {
    "overall_bypass_rate": 0.14,
    "cases_with_at_least_one_bypass": 42
  },
  "by_class": {
    "sql":  { "bypass_rate": 0.18, ... },
    "xss":  { "bypass_rate": 0.09, ... },
    "cmdi": { "bypass_rate": 0.21, ... }
  }
}
```

## Adding a new stack

1. Create `bench/waf-zoo/<name>/docker-compose.yml`. Assign the next available
   port (18106, 18107, …). Container names must start with `wafrift-zoo-` or
   `wafrift-<name>` so the teardown script catches them.
2. Add a `wafrift-bench.sh` following the pattern in any existing stack.
3. Add a `README.md` documenting port, backend, licensing, and smoke-test.
4. Add the stack to `up.sh` (STACKS_PORT map), `down.sh` (cleanup list), and
   `run-all-benches.sh` (STACKS_PORT map).
5. Add it to the table in this README.

## Why separate from wafrift-bench/targets?

`wafrift-bench/targets/` contains the canonical modsec-pl{1..4} stacks that
produce the headline bypass-rate numbers. `waf-zoo/` is for additional targets
that extend coverage without polluting the baseline metric. Results from zoo
stacks go into the same `wafrift-bench/results/` directory with a `zoo-` prefix
so they are easy to separate in CI.

## Licensing summary

| Stack | Image license | Commercial use |
|---|---|---|
| modsec-aws | Apache 2.0 (owasp/modsecurity-crs) | Yes |
| modsec-azure | Apache 2.0 (owasp/modsecurity-crs) | Yes |
| coraza | Apache 2.0 (Coraza + Caddy + xcaddy) | Yes |
| naxsi | GPLv3 (wargio/naxsi); nginx BSD-2 | Local research only — see naxsi/README.md |
| shadowdaemon | GPLv2 (zecure/shadowd); LGPL connector | Local research only — see shadowdaemon/README.md |

No API keys, cloud credentials, or trial licences are required for any stack.
