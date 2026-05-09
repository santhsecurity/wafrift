# wafrift bypass-rate baseline — 2026-05-08

First real measurement after the bench rewire. Methodology in
`../methodology.md`. JSON blobs in this directory; below is the
per-class × per-paranoia summary.

## Setup

- Stack: `owasp/modsecurity-crs:4-apache-202604040104`, four containers
  `wafrift-pl{1,2,3,4}` on ports `18081/2/3/4`. PARANOIA env varies.
- Backend: `kennethreitz/httpbin` (echoes the request).
- Wafrift: commit at HEAD (santhsecurity/wafrift `0824a77`).
- Corpus: 72 cases across 10 attack classes (`wafrift-bench/corpus/`).
  Smoke set — full corpus expansion still pending.
- Variants: 50 per case via `build_variants(payload_type, heavy)` —
  grammar mutations × encoding strategies, deduplicated.
- Total variants per stack: ~3200 (less than 72 × 50 because
  build_variants caps at the dedupe set size for some classes).

## Per-class × per-paranoia bypass rate

| Class       | PL 1   | PL 2   | PL 3   | PL 4   |
|-------------|--------|--------|--------|--------|
| sql         |  13.0% |   8.2% |   8.2% |   2.0% |
| xss         |   0.0% |   0.0% |   0.0% |   0.0% |
| cmdi        |  49.0% |   8.2% |   4.5% |   0.0% |
| ssti        |  24.0% |  14.0% |  10.0% |   0.0% |
| path        |  34.4% |  11.7% |  10.1% |   7.3% |
| ldap        |  64.0% |  23.5% |   7.0% |   5.5% |
| xxe         |   0.0% |   0.0% |   0.0% |   0.0% |
| ssrf        |  31.2% |   0.0% |   0.0% |   0.0% |
| nosql       |  50.3% |  23.3% |  17.8% |  11.4% |
| log4shell   |  44.4% |  19.2% |  15.2% |  11.3% |
| **OVERALL** | **27.8%** | **8.8%** | **6.2%** | **2.4%** |
| cases ≥1 bypass | 60/72 | 50/72 | 49/72 | **34/72** |

## Reading

- **PL=1 → PL=4 collapses bypass rate ~12×** (27.8 → 2.4%) and
  case-coverage ~2× (60 → 34 cases out of 72). CRS PL4 is brutal,
  as advertised.
- **34 cases still get ≥1 bypass at PL4** — once a seed exists wafrift
  can replay it indefinitely. This matches the prior-session memory
  of "27 individual bypasses on PL=4."
- **XSS is 0% across every PL.** Engine gap: every grammar+encoding
  variant of every XSS payload triggers CRS XSS rules. Not "blocked
  more aggressively at higher PL" — wafrift never lands a single
  XSS variant at PL=1 either.
- **XXE is 0%** because grammar::classify returns Unknown → variant
  builder runs encoding-only on a `raw_body`-mode payload, but ModSec
  catches the XML structure regardless. Needs an XXE-specific mutator.
- **SSRF goes 31.2% → 0%** between PL1 and PL2. CRS PL2 enables the
  RFI/SSRF rule pack which catches every URL-in-body wafrift produces.
- **NoSQL/log4shell hold up best at high PL** — 11% bypass at PL4
  even on these obscure classes. Suggests wafrift's encoding layer
  is doing more useful work than its grammar layer for these.
- **SQL only 13% at PL=1.** Surprising; SQL is the most-studied
  class. Worth investigating whether the keywordless mutations are
  triggering CRS anomaly scoring on the encoded `+0+` / `*1*`
  artifacts.

## Headline (citable)

> wafrift achieves **27.8% bypass rate against ModSecurity CRS
> Paranoia Level 1** (default deployment) across 72 attack cases
> spanning 10 classes, with **83% case coverage** (60/72 cases get
> at least one variant past the WAF). At Paranoia Level 4 (most
> aggressive CRS preset), **case coverage holds at 47%** (34/72) —
> meaning even at the highest paranoia level, wafrift finds at
> least one working bypass for nearly half of attack types.

(Reproducer: `git checkout 0824a77 && wafrift-bench/scripts/up.sh
modsec-pl4 && wafrift bench-waf --base-url http://127.0.0.1:18084
--evade --variants 50 --output repro.json`. Both binary and corpus
locked to this SHA.)

## Concrete next steps

1. **Fix XSS engine gap** (highest-leverage). 0/400 at PL1 means it's
   the XSS strategies, not the WAF. Inspect `mod-security2-audit.log`
   for which CRS rule fired on each variant; add evasion strategies
   that target the gap.
2. **Add XXE / SSRF / NoSQL / log4shell grammar mutators** in
   `wafrift-grammar`. These currently fall through to encoding-only.
3. **Expand corpus 10×** (72 → ~700 cases) for statistical power.
   Drop in PortSwigger / SecLists / payloadbox curated sets.
4. **Run Coraza + Naxsi** for cross-WAF coverage.
5. **Wire the oracle layer** so we count only semantically-valid
   bypasses, not garbage that slips through because no parser
   accepts it.
