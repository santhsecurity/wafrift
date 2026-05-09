# v0.2.2 per-class bench across naxsi + modsec-pl4

Run with: `wafrift bench-waf --strategies heavy,mcts --variants 5 --class <X> --base-url <waf>`

## Results

| Attack class | Cases | modsec-pl4 bypass | naxsi bypass |
|--------------|-------|-------------------|--------------|
| sql          |  173  | 100.0% (oracle 39.9%) | **99.4%** (oracle 30.1%) |
| xss          |  130  | 100.0% (oracle 38.4%) |   0.0% (oracle  0.0%) |
| cmdi         |   59  | 100.0% (oracle 41.5%) |  40.7% (oracle  5.1%) |
| ssti         |   45  | 100.0% (oracle 40.9%) |  97.8% (oracle  7.8%) |
| ssrf         |   47  | 100.0% (oracle 39.8%) |   2.1% (oracle  0.6%) |
| path         |   54  | 100.0% (oracle 39.3%) |   5.6% (oracle  0.6%) |
| ldap         |   11  | 100.0% (oracle 40.9%) |   0.0% (oracle  0.0%) |
| xxe          |   11  | 100.0% (oracle 40.0%) |   0.0% (oracle  0.0%) |
| nosql        |   22  | 100.0% (oracle 42.7%) |   9.1% (oracle  1.8%) |
| log4shell    |   27  | 100.0% (oracle 38.1%) |  81.5% (oracle 25.6%) |

## Why modsec PL4 is at 100% across the board

modsec's CRS rules accumulate an anomaly score; wafrift's heavy
strategy (grammar mutations + encoding + content-type switch +
header obfuscation) reliably keeps the per-rule contribution under
the threshold. Body padding from `EvasionConfig::maximum()` adds
another +16 KB of inert content the WAF has to inspect. PL4 is
**configurable**, not absolute — block-or-pass is decided by the
sum of rule scores.

## Why naxsi is binary on most classes

naxsi's rule engine is keyword-greedy: a single match on a
known-bad token (`<`, `passwd`, `..`, `union`, `script`, `(`)
fires a 403 with no scoring. The sql win (99.4%) came from
`quote_free` rewriting away every keyword naxsi flags
(`'`, `--`, `/*`, parens). Other classes don't have an equivalent
single-bullet bypass:

- **xss (0%)**: naxsi blocks any `<` byte. HTML-context XSS *requires*
  `<`. Documented limit. UTF-7 (`+ADw-script+AD4-`) passes naxsi at
  the WAF layer but most modern browsers don't decode UTF-7 anymore,
  so it's not exploitable. Honest gap, not a coding bug.

- **ssrf (2%)**: naxsi flags `127.`, `localhost`, `169.254`,
  `metadata`, `gopher`, `dict`. Cloud-metadata SSRF is the high-value
  case and there's no WAF-side bypass that doesn't change the target
  IP/hostname.

- **path (6%)**: naxsi blocks any `..` sequence and the `passwd`
  literal. Path traversal evasion needs different filenames or out-
  of-band navigation (e.g. archive overlays); not within the
  payload-mutation scope.

- **ldap (0%)** and **xxe (0%)**: tiny corpora (11 each); naxsi has
  hard rules for both.

## What this means for v0.2.3+

`quote_free` proved that ONE focused mutator can move a class from
~0% to ~99% on naxsi. The same technique should work for:

- **`html_bracket_free` (xss)**: emit polyglot payloads in JS
  contexts that don't need `<` (e.g. `${alert}` template-literal
  injection for SSR). Needs a polyglot mutator that knows the
  reflection context.
- **`fileword_free` (path)**: replace `passwd` etymon with
  `pass\x00wd` or other filename twins, paired with `....\\\\`
  variants that survive naxsi's `..` regex.
- **`localhost_free` (ssrf)**: use `[::]`, `0`, `0177.0.0.1`, `2130706433`
  numeric forms naxsi doesn't normalise.

These are filed as future-work items. v0.2.2 ships with the sql win
documented + the gap honestly named per other class.
