# sqlmap diff harness

**Purpose.** Prove that wafrift is a strict superset of sqlmap's `--tamper=all`
coverage against ModSecurity CRS PL=4. Specifically, answer three questions:

1. Which SQL-injection corpus payloads does **wafrift bypass but sqlmap does not**?
2. Which does **sqlmap bypass but wafrift does not**? (regressions to fix)
3. Which does **neither** bypass? (hard cases; both tools hit the wall)

## WAF target

| Item | Value |
|---|---|
| Docker image | `owasp/modsecurity-crs:4-apache-202604040104` |
| Paranoia level | 4 (`ANOMALY_INBOUND=5`, `BLOCKING_PARANOIA=4`) |
| Port | 18084 |
| Compose file | `wafrift-bench/targets/modsec-pl4/docker-compose.yml` |

## Methodology

### sqlmap side

sqlmap is run in `--batch --level=5 --risk=3 --tamper=all` mode against
a synthetic injection endpoint provided by the httpbin backend. For each
corpus payload we:

1. Construct an httpbin URL with the raw payload in `?q=<payload>`.
2. Run `sqlmap --url <url> --param-filter=q --tamper=all --batch
   --technique=B --dbms=mysql --output-dir=/tmp/sqlmap-out` (Boolean
   blind; avoids time-based noise).
3. Parse `sqlmap`'s output: a **bypass** is any tamper that generates a
   variant that receives HTTP 200 from the backend (not 403/406/WAF-body).
4. Record which tampers fired per payload.

### wafrift side

```bash
wafrift bench-waf \
    --base-url http://127.0.0.1:18084 \
    --corpus wafrift-bench/corpus \
    --class sql \
    --evade --strategies heavy,equiv-cegis \
    --format json \
    --output bench/sqlmap-diff/wafrift-pl4-sql.json
```

A **bypass** is `evaded.variants_bypassed > 0` for a case. The oracle gate
is always on: only structurally valid SQL payloads count.

### Diff

The `run.sh` script merges the two result sets and produces three lists:

- `wafrift_only.txt` — case IDs bypassed by wafrift, blocked by sqlmap
- `sqlmap_only.txt` — case IDs bypassed by sqlmap, blocked by wafrift
- `both.txt` — bypassed by both
- `neither.txt` — blocked by both

## Current status

> **TODO (next bench day):** Run `run.sh` and commit the output tables.
> Track at: https://github.com/santhsecurity/wafrift/issues (open an issue
> titled "sqlmap diff bench run — PL4 SQL corpus").

The harness and methodology are committed; the diff tables are pending a
bench-day run. Once committed, this README will be updated with the actual
numbers and the issue link above will be closed.

## Interpreting results

- `wafrift_only` is the value proposition: bypasses a customer can get from
  wafrift that they cannot get from `sqlmap --tamper=all`. This is the
  "strict superset" claim's evidence base.
- `sqlmap_only` must be empty or explained. If sqlmap finds a bypass wafrift
  misses, that is a gap to close — file an issue and add a corpus regression.
- `neither` is expected to shrink over time as wafrift adds evasion techniques.
