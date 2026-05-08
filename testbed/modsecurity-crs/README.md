# ModSecurity CRS testbed

Use this stack when you want a **real** open-source WAF in front of a default backend for manual `wafrift scan` runs or benchmarks.

## Quick start

```bash
docker compose up -d
curl -sS -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:18080/?q=1"
curl -sS -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:18080/?q=' OR 1=1--"
```

The second request often returns **403** once CRS SQLi rules fire (exact behavior depends on CRS version and paranoia level).

## Environment for ignored tests

```bash
export WAFRIFT_MODSEC_URL=http://127.0.0.1:18080
```

Then run the optional CLI integration test (see `crates/cli/tests/modsec_local.rs`).

## Reproducible benchmark (seed corpus)

From the **workspace root** (`web/wafrift`):

```bash
./testbed/modsecurity-crs/run-waf-bench.sh
```

This brings Compose up, waits for `http://127.0.0.1:18080`, then runs `wafrift bench-waf` with the built-in JSON seed list (`crates/cli/bench_payloads/default.json`). Override the base URL with `WAFRIFT_MODSEC_URL` or pass flags after the script (they are forwarded to `bench-waf`), for example:

```bash
WAFRIFT_MODSEC_URL=http://127.0.0.1:18080 \
  cargo run -p wafrift-cli -- bench-waf --format json
```

Use `--payloads /path/to/cases.json` to supply your own case list (same schema as the default file). Exit code **2** means at least one row failed its `expect` field (`allowed` / `blocked` / `any`); CRS tuning can change which rules fire, so treat strict expectations as regression checks when your stack is pinned.

## CI

Continuous integration does **not** start Docker here; it uses unit tests, wire mocks, and corpus tests in-tree. Treat this folder as **developer / benchmark** infrastructure.
