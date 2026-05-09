# v0.2.2 + D5 (quote_free) + E2 (ssrf-scheme + path-promote) — final 7-stack bench

Snapshot taken 2026-05-09 with `wafrift bench-waf --strategies
heavy,mcts --variants 5 --delay-ms 25` against the three classes
where v0.2.2 had measurable gaps: sql, ssrf, path.

## Bypass rate (cases with ≥1 successful variant)

|             | sql   | ssrf  | path  |
|-------------|-------|-------|-------|
| modsec-pl1  | 100.0% | 100.0% | 100.0% |
| modsec-pl2  | 100.0% | 100.0% | 100.0% |
| modsec-pl3  | 100.0% | 100.0% | 100.0% |
| modsec-pl4  | 100.0% | 100.0% | 100.0% |
| coraza      |  50.3% | 100.0% |  74.1% |
| bunkerweb   | 100.0% | 100.0% | 100.0% |
| naxsi       |  99.4% |  78.7% |  72.2% |

## Delta vs v0.2.2 baseline (`v022-by-class/`)

|             | class | before  | after   | delta    |
|-------------|-------|---------|---------|----------|
| naxsi       | sql   |   0.6%  |  99.4%  | +98.8pp  |
| naxsi       | ssrf  |   2.1%  |  78.7%  | +76.6pp  |
| naxsi       | path  |   5.6%  |  72.2%  | +66.6pp  |
| coraza      | ssrf  |   ~36%  | 100.0%  | +64pp    |
| coraza      | path  |   ?     |  74.1%  | (new)    |

modsec PL1-4 + bunkerweb were already at 100% on these classes
before D5/E2 — no regression observed.

## What's still unsolved

| WAF / class    | Bypass | Reason |
|----------------|--------|--------|
| coraza / sql   |  50.3% | corraza accumulates per-rule scores aggressively — needs more variants per case (try `--variants 10`) |
| naxsi / xss    |   0.0% | naxsi blocks any `<` byte; HTML-context XSS *requires* `<`. Structural limit. |
| naxsi / ldap   |   0.0% | tiny corpus + naxsi catches `(...)` filter syntax |
| naxsi / xxe    |   0.0% | naxsi catches `<?xml` and `ENTITY` literals |
| naxsi / cmdi   |  40.7% | needs deeper command-substitution variants beyond the scope of a one-shot mutator |

XSS / LDAP / XXE on naxsi remain documented honest gaps in
[`wafrift-bench/results/v022-by-class/SUMMARY.md`](../v022-by-class/SUMMARY.md).
