# wafrift-bench v0.2.1 — Coraza + Naxsi-from-source results

Run on 2026-05-09. Same 579-case corpus, same 11 evasion strategies, 5 variants/case/strategy → **19 881 variants per WAF**.

## Headline

| WAF | raw block rate | bypass rate | cases with ≥1 bypass | cases with oracle-valid bypass |
|---|---:|---:|---:|---:|
| **Coraza** (Coraza-WAF v3.4 default rules) | 99.83 % | **0.07 %** (14/19 881) | **1 / 579** | 1 / 579 |
| **Naxsi 1.6** (wargio fork, `$SQL≥4 BLOCK` thresholds) | 92.55 % | **7.45 %** (1 482/19 881) | **568 / 579** | 80 / 579 |

Coraza is brutally strict on this corpus: **only the SSRF class produced a single bypass** (oracle-valid), and the 14 raw bypasses cluster in 1 SSRF case. Naxsi at the configured thresholds lets through 98 % of cases — but only 14 % of those bypasses are oracle-valid, so the practical attack-shaped rate is closer to 14 % of cases, still substantially weaker than Coraza.

## Per-class bypass rate (raw / oracle-valid)

| Class | Coraza | Naxsi |
|---|---:|---:|
| sql | 0.0 % / 0.0 % | TBD — see naxsi-bench-021.json `by_class` |
| xss | 0.0 % / 0.0 % | TBD |
| cmdi | 0.0 % / 0.0 % | TBD |
| ssrf | **1.0 % / 0.9 %** | TBD |
| ssti | 0.0 % / 0.0 % | TBD |
| path | 0.0 % / 0.0 % | TBD |
| ldap | 0.0 % / 0.0 % | TBD |
| nosql | 0.0 % / 0.0 % | TBD |
| xxe | 0.0 % / 0.0 % | TBD |
| log4shell | 0.0 % / 0.0 % | TBD |

(Coraza per-class numbers from `coraza-bench-021.json`; Naxsi numbers in `naxsi-bench-021.json`.)

## Methodology notes

- Both targets were stood up via `wafrift-bench/scripts/up.sh {coraza,naxsi}`.
- Naxsi 1.6 had a build-time submodule issue (the release tarball ships an empty `libinjection/` directory); the Dockerfile now uses `git clone --recurse-submodules` instead. The `naxsi.conf` `CheckRule` syntax was also updated to the wargio 1.6 form: `CheckRule "$VAR >= N" BLOCK;`.
- Bench command: `wafrift bench-waf --base-url <url> --strategies all --variants 5 --evade --output <file> --summary-only --skip-healthcheck`.
- Adaptive throttle (default 50 consecutive errors → 2s pause, half-speed) was active.
- Oracle gate (`--oracle-gate`) was OFF for the bypass count, ON for the `oracle_valid_*` columns — every "bypassed" variant was independently re-checked by the wafrift-oracle for structural attack validity.

## Reproduce

```bash
git clone https://github.com/santhsecurity/wafrift && cd wafrift
wafrift-bench/scripts/up.sh coraza naxsi
cargo build --release -p wafrift-cli
./target/release/wafrift bench-waf --base-url http://127.0.0.1:18085 \
    --strategies all --variants 5 --evade --skip-healthcheck \
    --output coraza.json --summary-only
./target/release/wafrift bench-waf --base-url http://127.0.0.1:18087 \
    --strategies all --variants 5 --evade --skip-healthcheck \
    --output naxsi.json --summary-only
./target/release/wafrift bench-diff --baseline naxsi.json --current coraza.json
```

## Differential signal

Naxsi vs Coraza on the same corpus: Coraza catches everything our 19k-variant sweep can throw at it for SQL/XSS/CMDI/SSTI/path/LDAP/NoSQL/XXE/log4shell classes. Naxsi at sane thresholds lets through 98 % of cases at the variant level but most are syntactically broken; the oracle-validated rate (14 %) is the realistic "real attack" success rate. Both are stronger than the ModSec-CRS PL=4 numbers in `final-modsec-pl4.json` (27 % bypass) — Coraza dramatically so, naxsi modestly so.
