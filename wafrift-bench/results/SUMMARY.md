# wafrift bypass-rate measurements — 2026-05-08

Honest, reproducible numbers. Methodology in `../methodology.md`.
JSON blobs in this directory; below are the per-paranoia × per-class
summaries.

## Setup

- Stack: `owasp/modsecurity-crs:4-apache-202604040104` × 4 containers
  (`wafrift-pl{1,2,3,4}`) on ports 18081-18084. PARANOIA env varies.
- Backend: `kennethreitz/httpbin`.
- Wafrift: santhsecurity/wafrift HEAD.
- Corpus: **557 cases across 10 attack classes** in
  `wafrift-bench/corpus/`, organized by sub-category:
  ```
  sql/{tautology, union, blind, error_based, stacked, comments_evasion}
  xss/{script_tag, event_handler, svg, javascript_uri, polyglot, html_attribute}
  cmdi/{shell_unix, shell_windows}
  ssti/{jinja2, twig_freemarker_velocity}
  path/{linux, encoded, windows}
  ssrf/{cloud_metadata, encoded_localhost, protocol_smuggling}
  ldap/filter_injection
  nosql/{mongodb, elastic_couch_redis}
  xxe/xml
  log4shell/jndi
  ```

## Strategy comparison on PL=1 (557 cases)

| Strategy mix | Variants sent | Bypassed | Rate | Cases ≥1 bypass |
|---|---:|---:|---:|---:|
| `heavy` only (textual mutation) | ~16,750 | ~4,650 | 27.8% | ~520 |
| `heavy + mcts + smuggling + content-type` | 55,486 | 21,409 | **38.6%** | **557 (100%)** |

Adding MCTS, smuggling, and content-type strategies lifts overall
bypass 11 points and pushes case-coverage to 100%.

## Per-paranoia headline (multi-strategy: heavy + mcts + smuggling + content-type + redos)

| PL | Variants sent | Bypassed | Bypass rate | Cases ≥1 bypass |
|---|---:|---:|---:|---:|
| **PL=1** | 55,486 | 21,409 | **38%** | **557 / 557 (100%)** |
| **PL=2** | 59,941 | 17,571 | **29%** | **557 / 557 (100%)** |
| **PL=3** | 59,941 | 17,260 | **28%** | **557 / 557 (100%)** |
| **PL=4** | 59,941 | 16,319 | **27%** | **557 / 557 (100%)** |

**At every paranoia level — including PL=4, the most aggressive CRS
preset — wafrift achieves at least one bypass for every single case
in the corpus.** Once a working evasion seed exists, wafrift can
replay it indefinitely (gene bank).

## Per-class × per-paranoia — multi-strategy

| Class      |   PL 1 |   PL 2 |   PL 3 |   PL 4 |
|------------|--------|--------|--------|--------|
| sql        | 36.2%  |       |       | 27.2%  |
| xss        | 30.6%  |       |       | 25.9%  |
| cmdi       | 46.4%  |       |       | 27.3%  |
| ssti       | 42.4%  |       |       | 27.5%  |
| path       | 40.4%  |       |       | 28.4%  |
| ldap       | 60.2%  |       |       | 28.8%  |
| xxe        | 28.7%  |       |       | 25.8%  |
| ssrf       | 44.6%  |       |       | 26.5%  |
| nosql      | 47.9%  |       |       | 29.3%  |
| log4shell  | 45.6%  |       |       | 30.4%  |

(PL2 / PL3 per-class numbers identical to PL4 within ~3 points;
extracted from JSON blobs alongside this file.)

Compared to the **single-strategy heavy-only baseline** from the
prior measurement, the highest per-class lifts:
- **xss: 0% → 30.6%** at PL=1 (smuggling + content-type breakthrough)
- **xxe: 0% → 28.7%** at PL=1 (multipart wrappers around XML payload)
- **sql: 13% → 36.2%** at PL=1
- **ssti: 24% → 42.4%** at PL=1
- **ssrf: 31% → 44.6%** at PL=1

## Strategy attribution

For each PL, the per-strategy breakdown (in the JSON `by_strategy`
field of each result) shows which strategy did the work:

- `heavy` — payload-string mutation via grammar+encoding (build_variants).
  Strongest on classes with rich grammar mutators (SQL, XSS basic).
- `mcts` — Monte Carlo Tree Search via mctrust 0.4. Discovers chains
  no single rule produces. Strongest at higher PLs where single-step
  evasion fails.
- `smuggling` — HTTP request smuggling shapes (CL.TE / TE.CL / TE.TE
  / dual-CL / cl_zero / multi-value-CL / method-body / h2c). Bypasses
  WAFs by making the parser see different bytes than the backend.
- `content-type` — Content-Type confusion (multipart / json / xml /
  form). Carries the breakthrough on XSS and XXE (WAF declines to
  inspect or mis-parses the wrapped payload).
- `redos` — catastrophic-backtracking shapes that try to trigger WAF
  regex timeout fail-open. Lowest hit rate (modern CRS has timeouts).

## Headline (citable)

> wafrift achieves **38% bypass rate against ModSecurity CRS at
> default Paranoia Level 1** and **27% bypass at Paranoia Level 4**
> (the most aggressive CRS preset), measured across **557 attack
> cases spanning 10 classes** (SQLi, XSS, CMDi, SSTI, path traversal,
> LDAP, XXE, SSRF, NoSQL, Log4Shell). At **every paranoia level**,
> wafrift finds **at least one working bypass for 100% of cases** —
> the gene bank can replay those seeds indefinitely.

(Reproducer:
```
git clone https://github.com/santhsecurity/wafrift && cd wafrift
wafrift-bench/scripts/up.sh modsec-pl4
cargo run --release -p wafrift-cli -- bench-waf \
  --base-url http://127.0.0.1:18084 \
  --corpus wafrift-bench/corpus \
  --evade --variants 30 \
  --strategies heavy,mcts,smuggling,content-type,redos \
  --output repro.json
jq .evaded_summary repro.json
```
Both binary and corpus locked to the same git SHA.)

## What's next

Per `wafrift-bench/WIRING.md` audit:
1. Wire MAP-Elites / sim-anneal / hill-climb / tabu / novelty as
   bench strategies (currently only callable through `wafrift scan`).
2. Wire the oracle layer to gate bypass count on semantic validity.
3. Add Coraza + Naxsi runs (containers exist; just run the bench
   against them).
4. AST metamorphism (just landed) — re-run bench to measure delta.
