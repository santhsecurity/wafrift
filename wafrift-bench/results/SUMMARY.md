> # ⚠️ RETRACTED — THESE NUMBERS WERE RIGGED (correction 2026-05-17)
>
> The bench harness counted **every non-403 response as a "bypass"**:
> the `--oracle-gate` flag was off by default and never read in the hot
> loop, the per-strategy `oracle_valid` counter was incremented
> *unconditionally* for mcts/smuggling/content-type, differential
> *fingerprint probes* were fed straight into the headline, and any
> `400`/`502` (the evasion breaking the request, attack never executed)
> counted as a win. The "Oracle gate: on / 91% oracle-valid" line below
> is **false** — it was never on.
>
> **Honest re-measurement** (modsec CRS PL1, oracle + reached-app gated,
> the corrected harness in `crates/cli/src/bench_waf.rs`):
>
> | metric | value |
> |---|---|
> | raw block rate (WAF works) | **96.4 %** |
> | **TRUE verified bypass rate** | **≈ 4.7 %** (258 / 5454) |
> | distinct cases with ≥1 verified bypass | 255 |
> | "not blocked but NOT a working attack" (the old rig) | 21.6 % |
> | old inflated headline this file shipped | 26–34 % |
> | smuggling strategy, verified | **0 %** |
>
> **LDAP class, de-rigged oracle, equiv-cegis vs live CRS** (the gap
> that was pinned at 0 %): **25.0 % TRUE verified bypass** — identical
> on PL1 (88/352) and PL3 (88/352), **0.0 % not-blocked-but-not-an-attack**
> (zero false bypasses). Raw block rate 100 %. Every verified bypass is
> the sound delivery-shape axis — `multipart_file` (44) + `path_segment`
> (44): CRS's LDAP rule is ARGS/body-scoped, so the same RFC-4515-sound
> filter-break that 403s in the query sails through an upload part or
> path segment. The LDAP oracle was rebuilt (see `ROBUSTNESS_AUDIT.md`)
> so this number is honest, not the prior 0 % rig.
>
> **Full honest per-class × per-WAF matrix** (de-rigged oracle,
> equiv-cegis, live containers; TRUE verified-bypass %, oracle +
> reached-app gated; raw JSON in `wafrift-bench/results/honest-*-0.2.16.json`):
>
> | class | pl1 | pl3 | coraza | naxsi | bunkerweb |
> |---|---|---|---|---|---|
> | sql  | 25.6 | 21.3 | 20.9 | 12.6 | 21.1 |
> | xss  | 18.5 | 18.5 | 12.1 | 12.1 | 12.1 |
> | cmdi | 26.0 | 17.6 | 24.8 | 14.0 | 22.3 |
> | path | 23.2 | 23.0 | 12.6 | 12.0 | 12.2 |
> | ssti | 61.8 | 19.9 | 59.4 | 38.5 | 56.0 |
> | ldap | 33.3 | 33.3 | 33.3 | 16.7 | 33.3 |
>
> The 4.8–9.2 % per-WAF "not-blocked-but-not-an-attack" is **not** a
> rig: it is honestly EXCLUDED from the bypass % (degraded transport +
> the documented conservative SQL oracle). A non-zero value is expected
> and correct — the de-rig's whole job is to separate it out, not to
> count it. xss is the lone weak lane and is delivery-shape only
> (payload-string xss = 0 % vs CRS); raising it is tracked in
> `docs/scald-delivery-integration.md`.
>
> Caveat: even 4.7 % is approximate — the SQL oracle splices into a
> numeric context, so it under-counts quote-context SQLi and over-counts
> any parseable-but-benign expression. See `ROBUSTNESS_AUDIT.md`.
> The de-rig is pinned by `bench_waf::tests::verified_bypass_*`.
>
> Everything below this line is the retracted pre-correction record,
> kept only so the rigged claims remain auditable.

---

# wafrift bypass-rate measurements — 2026-05-08

Reproducible numbers from the multi-strategy bench harness in
`wafrift-bench/`. Methodology in `../methodology.md`. Raw JSON in
this directory; below are headline tables.

## Setup

- **Wafrift**: `santhsecurity/wafrift` HEAD (v0.2.0).
- **Corpus**: 579 cases across 11 attack classes
  (`sql / xss / cmdi / ssti / path / ldap / xxe / ssrf / nosql /
  log4shell / cve_pocs`). cve_pocs is the held-out test set per
  methodology — 22 real CVE PoCs (log4shell, struts2, weblogic,
  spring4shell, follina, etc.) never used to tune wafrift.
- **Strategies** (10): `heavy + mcts + smuggling + content-type +
  redos + hill-climb + sim-anneal + tabu + novelty + map-elites`.
- **Variants per case per strategy**: 5.
- **Oracle gate**: on. Each "bypass" filtered through the per-class
  semantic-validity oracle (sql / xss / cmdi / ssti / path / ldap /
  ssrf / nosql / xxe / log4shell). Only structurally-valid attack
  payloads count.
- **Targets**: ModSec CRS at PL=1 + PL=4 + Coraza CRS.

## Headline

| WAF | Variants sent | Bypassed | Bypass rate | Oracle-valid | Cases ≥1 bypass |
|---|---:|---:|---:|---:|---:|
| **modsec-pl1** | 17,370 | 5,920 | **34%** | 91% | **579 / 579 (100%)** |
| **modsec-pl4** | 17,370 | 4,043 | **23%** | 100% | **579 / 579 (100%)** |
| **coraza** | 17,370 | 49 | **<1%** | 92% | **1 / 579** |

**modsec-pl1 → pl4** drops the bypass rate from 34% to 23% but
case-coverage stays 100% — every attack type still has at least
one working evasion at the most paranoid CRS preset. **Coraza CRS
4.0.0-rc1 is a different story**: only 1 case got through across
~17k variants. Coraza ships libinjection and a newer CRS rule set
than the ModSec image we test, and it shows.

## Per-class bypass on modsec-pl1

| Class | Cases | Bypass rate |
|---|---:|---:|
| ssti | 47 | **55%** |
| ssrf | 46 | **47%** |
| cmdi | 56 | 47% |
| nosql | 22 | 37% |
| ldap | 11 | 36% |
| path | 49 | 32% |
| log4shell | 23 | 29% |
| sql | 173 | 28% |
| xss | 130 | 27% |
| xxe | 10 | 26% |
| cve_pocs | 22 | (mixed-class, see JSON) |

## Per-strategy bypass on modsec-pl1

These two are the workhorse:

| Strategy | Variants | Bypass rate |
|---|---:|---:|
| **content-type** | 2,895 | **84%** |
| **mcts** | 2,895 | **84%** |
| heavy (build_variants) | 2,895 | 15% |
| redos | 2,895 | 12% |
| hill-climb | 579 | 11% |
| sim-anneal | 579 | 11% |
| tabu | 579 | 11% |
| novelty | 579 | 11% |
| map-elites | 579 | 11% |
| smuggling | 2,895 | <1% |

**content-type confusion + MCTS are doing the heavy lifting on
modsec-pl1.** smuggling is essentially a no-op against this
particular ModSec setup (the WAF parser is sufficiently strict that
none of the smuggled-prefix shapes land). evolution-loop algorithms
all converge to roughly the same ~11% — they're learning a similar
gene-pool subset.

## Reproducer

```bash
git clone https://github.com/santhsecurity/wafrift && cd wafrift
wafrift-bench/scripts/up.sh modsec-pl1
cargo run --release -p wafrift-cli -- bench-waf \
    --base-url http://127.0.0.1:18081 \
    --corpus wafrift-bench/corpus \
    --evade --variants 5 \
    --strategies heavy,mcts,smuggling,content-type,redos,hill-climb,sim-anneal,tabu,novelty,map-elites \
    --oracle-gate \
    --output repro.json
jq .evaded_summary repro.json
```

## What the numbers don't say

- **Bench measures bypass; doesn't measure exploit success.** Even
  oracle-valid bypassed payloads aren't proof the backend would
  honor the SQL/XSS/etc — only that the WAF accepted the request and
  the payload retained its attack semantics structurally.
- **Coraza is from a single image** (`jptosso/coraza-caddy:latest`)
  with default Caddy config + OWASP CRS 4.0.0-rc1. Different Coraza
  configs (custom rules, paranoia overrides) will show different
  numbers.
- **`smuggling` strategy at 0%** doesn't mean wafrift can't smuggle —
  it means the smuggled-prefix HTTP framing tricks don't survive
  reqwest's HTTP/1.1 normalization on send. The smuggling crate
  itself produces correct payloads (16 variants per request); the
  bench is sending them via reqwest which re-frames them.
- **PL=2 + PL=3 not measured** in this run for runtime reasons.
  Earlier (5-strategy, 50-variant) runs are in
  `modsec-pl{2,3}-multi.json` for the curve-shape view.

## What's next

Per `wafrift-bench/WIRING.md`: differential probing as bench
strategy, custom rules pack as bench strategy, lineage persistence
in bench JSON, naxsi-from-source Dockerfile, more attack-class
oracles (log4shell oracle is structural-only — could check JNDI
lookup expressibility too).
