# wafrift-bench — honest WAF bypass-rate benchmark

This directory ships everything needed to measure wafrift's bypass rate
against real WAFs running locally in docker, with a corpus organized by
attack class so users can pick what they care about.

```
wafrift-bench/
├── corpus/        # payloads, organized by attack class
│   ├── sql/       # SQL injection (tautology / union / blind / error / stacked)
│   ├── xss/       # cross-site scripting (reflected / stored / dom / polyglot)
│   ├── cmdi/      # command injection (shell / eval / windows)
│   ├── ssti/      # template injection (jinja2 / twig / freemarker / velocity / erb)
│   ├── path/      # path traversal (linux / windows / encoded)
│   ├── ldap/      # LDAP filter injection
│   ├── xxe/       # XML external entity
│   ├── ssrf/      # server-side request forgery
│   ├── nosql/     # NoSQL operator injection
│   ├── log4shell/ # JNDI lookup obfuscation
│   └── cve_pocs/  # known-CVE PoC payloads
├── targets/       # docker-compose stacks for local WAFs
│   ├── modsec-pl{1..4}/
│   ├── coraza/
│   └── naxsi/
├── scripts/
│   ├── up.sh      # bring stacks up
│   └── down.sh    # tear stacks down
└── results/       # per-(target, date) JSON results

```

## Quick start

```bash
# 1. Bring up a WAF target
wafrift-bench/scripts/up.sh modsec-pl1     # one stack
wafrift-bench/scripts/up.sh                # all stacks

# 2. Baseline (raw payloads only — verifies WAF blocks naive inputs)
wafrift bench-waf --base-url http://127.0.0.1:18081

# 3. Real bench: measure wafrift's bypass rate
wafrift bench-waf --base-url http://127.0.0.1:18081 --evade --variants 10

# 4. Restrict to a single attack class
wafrift bench-waf --base-url http://127.0.0.1:18081 --evade --class sql

# 5. Try all strategies
wafrift bench-waf --base-url http://127.0.0.1:18081 --evade \
  --strategies light,medium,heavy,mcts --variants 5

# 6. JSON for CI / regression tracking
wafrift bench-waf --base-url http://127.0.0.1:18081 --evade \
  --format json --output wafrift-bench/results/$(date -u +%Y%m%d)-modsec-pl1.json
```

## Reading the output

For each case the bench reports:

| Field | Meaning |
|---|---|
| `raw_blocked` | Did the WAF block the **raw** unevaded payload? `true` = WAF works. |
| `evaded.variants_total` | How many evaded variants we sent (`strategies × variants`). |
| `evaded.variants_bypassed` | How many slipped past the WAF (HTTP not 403/406, not WAF page). |
| `evaded.bypass_rate` | `bypassed / total` for this case. |
| `evaded.by_strategy` | Same numbers split per strategy. |
| `evaded.bypass_techniques` | Which evasion descriptions correlated with the bypass. |

Aggregate:

| Field | Meaning |
|---|---|
| `raw_block_rate` | % of cases the WAF blocked raw. Should be ~100% on a working WAF. |
| `evaded_summary.overall_bypass_rate` | wafrift's bypass rate across the whole corpus. |
| `evaded_summary.cases_with_at_least_one_bypass` | How many cases ever bypassed. The "got a seed, can replay" number. |
| `by_class.<class>` | Per-attack-class breakdown of all of the above. |

## Methodology rules

1. **Raw must be blocked first.** Cases the WAF allows raw are not informative
   for evasion measurement — exclude them from bypass-rate denominators
   (the report includes them but they should not be counted as wafrift wins).
2. **N variants per strategy.** A single bypass is a finding, not a rate.
   Default 5 variants × 1 strategy. Bump for tighter intervals.
3. **Train/test split.** Don't tune wafrift on the same corpus you bench on.
   The `corpus/cve_pocs/` set is reserved as a **held-out** set never used
   for wafrift training.
4. **Per-WAF, not aggregate.** Always report bypass% per (WAF, paranoia)
   pair. CRS-PL1 and CRS-PL4 are different products.
5. **Honest baseline.** If the WAF doesn't block the raw payload,
   wafrift had nothing to bypass — exclude that case.

## Adding a payload

1. Pick the attack class subdir (`corpus/<class>/`).
2. Create a TOML file or extend an existing one. Schema:
   ```toml
   schema = 1

   [[case]]
   id = "unique_id_within_corpus"
   class = "sql"  # or xss / cmdi / ssti / path / ldap / xxe / ssrf / nosql / log4shell
   payload = "the raw evil string"
   description = "short note"        # optional
   mode = "body_form_q"              # optional, default body_form_q.
   #                                   alternatives: url_query_q, raw_body
   ```
3. Done. The next bench run picks it up.

## Adding a WAF target

See `targets/README.md` for the protocol. Container name **must** start
with `wafrift-` so cleanup is unambiguous.

## Why this matters

Without this directory, wafrift's "bypass rate" is a marketing claim.
With it, every claim has a reproducer:

```bash
git clone https://github.com/santhsecurity/wafrift && cd wafrift
wafrift-bench/scripts/up.sh modsec-pl4
cargo run --release -p wafrift-cli -- bench-waf \
  --base-url http://127.0.0.1:18084 --evade --variants 10 \
  --output wafrift-bench/results/repro.json
jq '.evaded_summary.overall_bypass_rate' wafrift-bench/results/repro.json
```
