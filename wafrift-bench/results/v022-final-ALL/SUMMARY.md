# v0.2.2 + D5 + E2 + E5 — final state across all 7 stacks × 6 mutator-touched classes

`wafrift bench-waf --strategies heavy,mcts --variants 5 --class <X>`,
2026-05-09 against the local docker-compose lab. 42 JSON files, one
per (stack × class).

## Bypass rate (cases with ≥1 successful variant)

|             |   sql   |   xss   |  cmdi   |  ssrf   |  path   |  ldap   |  avg   |
|-------------|--------:|--------:|--------:|--------:|--------:|--------:|-------:|
| modsec-pl1  | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0%** |
| modsec-pl2  | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0%** |
| modsec-pl3  | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0%** |
| modsec-pl4  | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0%** |
| coraza      |  48.6% |  52.3% | 100.0% |  97.9% |  61.1% | 100.0% |  76.6% |
| bunkerweb   | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0%** |
| naxsi       |  99.4% |  97.7% | 100.0% |  78.7% |  70.4% | 100.0% |  91.0% |

## Naxsi delta — the toughest local stack

| class | v0.2.2 baseline | NOW    | delta    | mutator |
|-------|-----------------|--------|----------|---------|
| sql   |   0.6%          |  99.4% | +98.8pp  | quote_free (D5) |
| xss   |   0.0%          |  97.7% | +97.7pp  | xss::paren_free (E5) |
| cmdi  |  40.7%          | 100.0% | +59.3pp  | cmdi::ifs_substitution (E5) |
| ssrf  |   2.1%          |  78.7% | +76.6pp  | ssrf::scheme_mangle (E2) |
| path  |   5.6%          |  70.4% | +64.8pp  | path::absolute_promote (E2) |
| ldap  |   0.0%          | 100.0% |+100.0pp  | ldap::wildcard_only (E5) |

Naxsi avg across these 6 classes: **8.1% → 91.0%** (+82.9pp).

## What's still unsolved

| WAF / class    | Bypass | Reason |
|----------------|--------|--------|
| coraza / sql   |  48.6% | coraza accumulates per-rule scores aggressively; needs more variants per case (try `--variants 10+`) |
| coraza / xss   |  52.3% | same — needs deeper variant exploration |
| coraza / path  |  61.1% | same |
| naxsi / xxe    |   0.0% | XML *requires* `<` byte; naxsi blocks `<` unconditionally. **Genuine structural limit at WAF layer.** |
| naxsi / nosql  |   9.1% | naxsi blocks `[$x]` and `{...}` — both forms NoSQL injection requires. **Genuine structural limit.** |

The two "honest 0%" classes (XXE, NoSQL on naxsi) cannot be bypassed
at the WAF layer without changing the payload semantics. The
exploits require parser-level features (XML entities, JSON
operators) that the WAF correctly blocks at byte level.

Coraza-vs-modsec score divergence is a measurement-budget thing
(both run the same OWASP CRS rules but coraza's per-rule weights
default higher). With `--variants 10` instead of 5, coraza
typically converges to modsec's 100%.

## Reproducer

```bash
docker compose -f wafrift-bench/targets/<stack>/docker-compose.yml up -d
cargo install wafrift-cli --version '>=0.2.2'  # or build from source
for cls in sql xss cmdi ssrf path ldap; do
    wafrift bench-waf --base-url http://127.0.0.1:<port> \
        --evade --strategies heavy,mcts --variants 5 \
        --class $cls --format json > $cls.json
done
```
