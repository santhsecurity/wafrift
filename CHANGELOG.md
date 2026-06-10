# Changelog

All notable changes to wafrift are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.1] - 2026-06-09

### Changed — TLS-impersonate client migrated `rquest` → `wreq`; full crates.io release

The optional `tls-impersonate` browser-ClientHello client moved off the
`rquest` BoringSSL fork (every `rquest` release was yanked from crates.io and
the crate was git-pinned, which made the published tree unbuildable) to its
maintained crates.io successor `wreq` 5.3.0 / `wreq-util` 2.2.6. The TLS
profile catalogue (`chrome131`, `firefox133`, `safari18`, `okhttp5`, …) and the
`wafrift ja3-diff` subcommand are unchanged; the migration is a transport-layer
rename only.

With the dead git dependency removed, the whole shared-lib closure
(`scanclient`, `guise`, `pocgen`, `erroracle`, `interactsh`, `santh-bogon`,
`santh-ctlog`, `secir`, `authjar`, …) and every `wafrift-*` crate now publish
to crates.io, so `cargo install wafrift-cli` (which installs the `wafrift`
binary) works. wafrift's shared-lib
dependencies are version-pinned (resolved from crates.io), making a standalone
checkout of the repository build without the monorepo's local lib paths.

### Added — default genome warm-start bank

A brand-new install no longer starts cold. `wafrift scan` against a WAF
with no prior history now warm-starts from a bundled default genome of
proven *generic* technique-records (URL / case / HTML-entity / overlong-
UTF8 encodings, content-type delivery vectors), so the first scan fires
known winners instead of discovering from zero. Materialized write-through
via `GeneBank::load_or_default` under `~/.wafrift/genomes/`; an operator's
existing genome is never clobbered. Shipped content is technique-keys +
priors only — never target-specific payloads.

The default is now **WAF-class-aware** (§6 GENERALIZATION): a Cloudflare-
fronted target (`load_or_default` routes by `WafClass`) warm-starts from a
delivery-vector-heavy Cloudflare set (JSON dup-key / multipart / CBOR / YAML
content-type confusion + overlong-UTF8 / hex), while CRS / ModSec / Coraza /
naxsi / unknown targets get the broadly-effective generic encodings. Adding a
new class default is one JSON file + one match arm.

### Added — `ml-evasion` strategy (ML-WAF boundary attack in the autonomous loop)

`wafrift bench-waf --strategies ml-evasion --waf-name "<WAF>"` (and
`wafrift hunt --waf-name "<WAF>"`, which auto-adds it) route ML-backed
targets — AWS/Cloudflare/Akamai bot-management, Datadome — through a
manifold-projected **structural-mutation** strategy, the paradigm-correct
shape for a learned classifier (rule-decompilation like `equiv-cegis` doesn't
apply to a WAF with no rules). Each candidate is a semantics-preserving
mutation of the payload that must stay a *working* attack
(`wafmodel::is_attack_payload` is the manifold projection — a mutation that
stops being an attack is a discarded sample, never a counted bypass); the
candidate is fired at the live target and only verified bypasses are credited.
A non-ML-backed `--waf-name` (or none) makes it a clean no-op. The full
*adaptive* decision-boundary descent (`wafmodel::evade_ml`, contract-tested),
which chooses each next mutation from live block/allow feedback, is a tracked
frontier upgrade (`docs/legendary-todo.md`).

### Changed — `scan --corpus`: "scan pointed at bench" (one CLI, two modes)

`wafrift scan --corpus <dir>` now runs the corpus-wide WAF bench measurement
(raw block-rate + verified bypass-rate) instead of a single-payload scan — the
same measurement `bench-waf` performs, so the normal CLI is "pointed at bench"
and the dev/QA `bench-waf` command stays hidden. **Metric-safe:** it delegates
to the UNCHANGED `run_bench_waf` engine (the anti-rig bypass-rate core is
untouched), mapping the scan target / timeout / `--i-have-permission` across,
and gates non-allowlisted targets exactly like the bench-waf arm (§15).
`--payload` is ignored in this mode; single-payload scan is unchanged.

### Changed — unified `wafrift diff <kind>` surface

The eleven parser-disagreement commands (`parser-diff`, `header-diff`,
`body-diff`, `query-diff`, `cache-diff`, `h2-diff`, `method-diff`,
`gql-diff`, `jwt-diff`, `cors-diff`, `trailer-diff`) plus the `attack`
orchestrator are now grouped under one verb — `wafrift diff <kind>`
(`diff header`, `diff all`, …). Top-level `--help` drops from 53 to 41
commands. **Backwards-compatible (LAW 2):** every flat name and `attack`
keep working as deprecated hidden aliases — no existing script, pipeline,
or doc breaks. The `tmin` alias of `distill` was likewise hidden.

The dev/QA benchmark commands `bench-waf`, `bench-diff`, and `corpus` are
also hidden from the top-level menu — they're tooling, not pentester
commands (still callable, LAW 2; the bench harness / CI / `hunt`-internals
are unaffected). Net visible surface: **53 → 38** commands.

### Fixed

- **`bench-waf` permission gate (§15 / least-privilege).** `bench-waf` fired
  attack payloads at any `--base-url` with no acknowledgment, unlike `scan` /
  `hunt` (which gate non-allowlisted targets behind `--i-have-permission`) —
  an inconsistency surfaced by dogfooding. It now reuses the canonical
  `permission::assert_permitted` to refuse (exit 2) a non-allowlisted explicit
  `--base-url` without `--i-have-permission`. Lab / CI / CumulusFire targets are
  on the built-in allowlist (unaffected); only external explicit targets now
  require the flag. Gated in the CLI dispatch arm — `hunt`'s internal bench
  rounds gate at the campaign level.

- **Unbounded rule-corpus `blocked` growth (§15) + O(n²) dedup + 62 MB saves
  (§1).** A hunted per-target corpus accumulated *every unique blocked payload*
  per rule bucket with no count cap — the live CumulusFire corpus reached 62 MB,
  creeping toward the 128 MiB load cap (past which `load_or_default` silently
  drops the whole corpus), while each `save_atomic` rewrote all 62 MB and the
  per-insert dedup scanned the whole bucket (O(n²) over a long hunt). Blocked
  payloads are a rule-coverage *sample*, not harvest material, so
  `record_block` now caps them at 512/bucket (bypasses stay uncapped) and
  `load_or_default` truncates over-cap buckets — an existing bloated corpus
  self-reclaims on the next save. Found by dogfooding the live hunt corpus (§13).

- **Redirect-SSRF on the core `EvasionClient`.** The main evasion client
  followed redirects via bare `reqwest::redirect::Policy::limited` — no
  bogon check — so a hostile target could `302 → http://169.254.169.254/`
  and pull cloud metadata (or pivot into RFC1918) through the scanner, even
  though the CLI diff commands already bogon-guarded theirs. The canonical
  `safe_redirect_policy` (bogon-refusal + cross-origin halt + hop cap) now
  lives in `wafrift-transport` (§7: one impl, in the HTTP layer where it
  belongs); `EvasionClient` uses it and `cli::helpers` delegates to it.
  Legit redirects to the real origin still follow — only metadata /
  internal / cross-origin hops are refused. (§15 SSRF.)
- **Decompression-bomb defence on the public `EvasionResponse`.**
  `EvasionResponse::bytes()` / `text()` did a raw, unbounded
  `reqwest::Response::bytes()/.text()` — and reqwest auto-decompresses
  gzip/br with no size cap, so a hostile target could OOM the scanner with
  a ~1 KB bomb that expands to gigabytes. They now drain chunk-by-chunk,
  capped at 64 MiB (matching the transport client's internal bounded
  reader); a source-level anti-rig test pins the bound against regression.
  (§15 — the one public reader that bypassed the codebase's own rule.)
- Stale `wafrift_strategy` doctest imported `EvasionConfig` from the wrong
  crate; corrected to `wafrift_types::EvasionConfig` so the example (an
  executable contract) compiles again.
- `equiv-cegis` learn phase — header-channel membership queries carrying
  RFC 7230 obs-text (high-byte) payloads were rejected by reqwest's
  `&str` header path as "builder errors", silently dropping that L\*
  learning signal (observed flooding live `hunt` runs). They now build
  via `HeaderValue::from_bytes`, so high-byte evasion payloads form real
  queries; only genuinely-unsendable NUL/CR/LF are excluded.

### Internal

- §7 dedup: the `SystemTime::now()…as_secs().unwrap_or(0)` idiom
  (5 hand-rolled copies in `hunt_cmd`) collapsed into a single
  `helpers::now_unix_secs()`.
- §7 dedup / §4 elegance: the 22 copy-pasted diff-family dispatch blocks in
  `main.rs` (each: layer `.wafrift.toml` http defaults → `block_on` the async
  runner — once per flat `<kind>-diff` alias AND once per `diff <kind>`
  subcommand) collapsed into a single generic `run_http_diff` helper, so the
  layering rule lives in one place. Pure-internal; the CLI surface and every
  command's behaviour are byte-identical (manpage-sync + e2e pin it).
- §11: removed `wafrift_strategy::evade_ml_backed` — a test-only pub wrapper
  with no production caller (scan/bench route via
  `apply_ml_evasion_if_applicable` through `ml_evasion_probe_payload`). Dropped
  the fn + re-export + 3 redundant tests; re-pointed the 4 `mlwaf_routing`
  integration tests. The `EvasionResult` adapter is re-addable trivially if the
  proxy ever needs request-level ML-evasion.

## [0.3.0] - 2026-05-28

### Added — Bounty-harvest pipeline (`wafrift harvest` + `wafrift submit`)

`hunt` and `bench-waf` now record every confirmed bypass's winning wire
payload + response evidence to a per-target corpus under `~/.wafrift`
(across the `equiv`, `equiv-adaptive`, and `equiv-cegis` strategies plus
the payload-mutation strategies — previously only the latter recorded).
Two new commands turn that corpus into reviewed bounty submissions:

- `wafrift harvest` — dedupes the corpus, RE-VERIFIES each candidate
  against the live target (capturing a fresh request + response so the
  report carries proof, not a stale hit), and writes one review-ready
  HackerOne Markdown report per still-working bypass. Control-byte
  payloads get byte-exact `$'…'` curl reproductions; a corrupt corpus is
  a hard error (never silently treated as empty). NEVER submits.
- `wafrift submit --report <file> --confirm` — files exactly ONE reviewed
  report; dry-run without `--confirm`; refuses unverified reports. There
  is no automatic or batch submission path (bounty-program ban risk).

### Removed

- `hunt --auto-submit` / `--dry-run-submit` and the 24h auto-file loop.
  Auto-filing machine-generated reports at a bounty program is a fast
  ban; filing is now the deliberate, one-at-a-time `wafrift submit` step.

### Fixed

- `trailer-diff --url https://…` no longer panics ("no process-level
  CryptoProvider available", exit 101) on the first https target — the
  rustls crypto provider is now installed once at startup, covering all
  raw-TLS paths (trailer-diff / ja3-diff / scan).
- `body-diff` / `query-diff` `--format json` now include an
  `error_details` array (probe identity + message), not just an error
  count, so CI consumers can see which probes failed and why.

### Added — Info-gain payload scheduler (`bench-waf --budget` / `--history-file` / `--fair-class` / `--list-schedule` / `--history-merge`)

Operators with capped request budgets now get the most informative
payloads first. Five new flags on `wafrift bench-waf`:

- `--budget N` — cap the corpus to the top-N payloads ranked by
  expected info gain. Cold-start payloads (no prior observations)
  start with maximum entropy = 1 bit and naturally lead the schedule;
  payloads with biased history (always-blocked or always-passing)
  fall to the tail.
- `--history-file PATH` — persist Beta-Bernoulli posteriors across
  runs. The file is JSON-shaped per `info_gain_sched::History`;
  missing file → cold start; written atomically via `write_atomic`
  at end of run with the current run's observations folded in.
  Updated independently of `--budget`, so an operator can build
  history during full-corpus runs and use `--budget` later to scope
  down a follow-up.
- `--fair-class` — enforce per-class fairness when `--budget` would
  otherwise produce a class-skewed schedule (e.g. 95%-SQL corpus
  → all-SQL schedule). Each class receives `budget / num_classes`
  slots; within each class payloads are ordered by descending info
  gain.
- `--list-schedule` — preview the schedule that the current args
  would run WITHOUT firing any HTTP request. Prints a table of
  `rank, id, info_gain, theta, theta_ci_95, n_trials` (text by
  default; JSON array of `ScheduleEntry` with `--format json`).
  Pairs with `--history-file` to debug what the next real bench
  would actually pick before spending request budget.
- `--history-merge PATH` (repeatable) — fold additional history
  JSON files into the working history before scheduling. Useful
  for operators running parallel WAF assessments who want to
  aggregate posteriors via `History::merge`.

The selection criterion is the binary Shannon entropy of the
estimated block probability, shared with bench-waf's C-14 case
quality scoring via the new `wafrift_types::entropy::{binary_shannon,
shannon}` primitives (single canonical home, satisfying CLAUDE.md §7
DEDUP). The diagnostic preview path also surfaces Wald 95% credible
intervals on theta via `PayloadStats::theta_ci_95` so operators
can distinguish "I'm confident at 0.5" from "I have 2 trials at 0.5".

Tests: 62 unit (`info_gain_sched::tests`), 19 unit
(`entropy::tests`), 22 e2e (`info_gain_sched_e2e.rs`) — 103 total.
The triangle — `--help` documents every flag, integration tests parse
every flag and exercise the preview JSON shape, and the schedule
reaches the bench loop via `run_bench_waf_async`'s filter branch —
closes per §9 WIRING. Hot-path sort switched to `sort_unstable_by`
with pre-computed `(info_gain, n_trials)` keys (~7% improvement on
10k-payload corpora) per §1 SPEED. Magic numbers `Z_SCORE_95` and
`BETA11_PRIOR_PSEUDO_TRIALS` named per §6 GENERALIZATION. `shannon`
n-ary hardened to skip `p > 1` and clamp to `>= 0` per §15 AUDIT
(prevents negative-entropy poisoning of sort keys). Schedule
execution preserves info-gain order in the bench loop so an operator
who Ctrl-C's mid-bench gets the most-informative results first.

### Changed — §7 DEDUP: extract `wafrift()` test helper into `tests/common/mod.rs`

38 e2e test files each carried a byte-for-byte copy of:
```rust
fn wafrift(args: &[&str]) -> (i32, String, String) { ... }
```
The canonical definition now lives in `crates/cli/tests/common/mod.rs`
alongside the existing `wait_for_server` helper. Each test file now:
- declares `mod common; use common::wafrift;`
- drops the local definition and the now-unused `use std::process::Command;`
A single tuning of the binary invocation (env var, timeout policy,
arg prefix) now propagates to all 38 tests atomically.

### Changed — §1 SPEED: pre-size mutation Vecs in grammar equiv modules

10 `generate()` functions in `crates/grammar/src/grammar/equiv/` each
allocated `Vec::new()` for their output and for the inner-loop `rules`
Vec (up to 8 tags per iteration, allocated on every attempt):
- `let mut out: Vec<EquivPayload> = Vec::new()` → `Vec::with_capacity(cfg.max)`
- `let mut rules: Vec<&'static str> = Vec::new()` → `Vec::with_capacity(8)`
Also applied to `path_traversal.rs` and `unicode_norm.rs`.

### Changed — §6 GENERALIZATION: name the attempt-budget constants

The loop termination `attempts < cfg.max * 24 + 64` was a bare magic
number repeated in 10 `generate()` functions. Two named constants in
`equiv/mod.rs` replace all 10 occurrences:
- `ATTEMPT_BUDGET_MULTIPLIER = 24`
- `ATTEMPT_BUDGET_FLOOR = 64`
A tuning now lands in one place and propagates everywhere.

### Changed — §1 SPEED: eliminate Vec allocation in `sql/strings.rs`

`CHAR(...)`, `CHR(...)`, and `NCHAR(...)` string-split variants each
used `collect::<Vec<_>>().join(sep)` — allocating a 10-element Vec
just to join it. Replaced by `char_fn_join` helper that writes
directly to a pre-sized `String` via `write!`. Zero intermediate Vec.

### Added — §11 UTILIZATION / §4 INNOVATION: wire CfgMutator into mutation pipeline

`cfg_convergence::CfgMutator` (BWAFSQLi-paper Boltzmann-annealing
grammar) was a complete implementation with zero production callers.
Now wired into `mutate_as(PayloadType::Sql)` and
`mutate_as(PayloadType::Xss)`:
- SQL: emits up to 4 CFG variants (boolean-OR, boolean-AND,
  string-terminator, numeric-OR templates)
- XSS: emits up to 3 CFG variants (img-onerror, svg-onload,
  details-toggle templates)
Seeds are FNV-folded from the payload for determinism across runs.
4 new tests pin the anti-rig invariants.

### Fixed — §11 UTILIZATION: CFG convergence variants now reliably appear in output

Two bugs prevented `CfgMutator` from ever emitting variants in practice:

1. **Budget starvation**: `sql::mutate()` / `xss::mutate()` were called
   with the full `max_mutations` budget, leaving zero slots for the CFG
   block (which was guarded by `results.len() < max_mutations`). Fixed
   by reserving 4 slots for SQL CFG and 3 slots for XSS CFG before
   calling the base mutators (`base_budget = max_mutations.saturating_sub(N)`).

2. **Boltzmann overflow → wrong fallback**: when `temperature ≤ min_temp`
   and a production had a high bypass score (e.g. 20.0), the Boltzmann
   weight `exp(20.0 / 0.01) = exp(2000)` overflowed to `+Inf`. The
   original fallback was **uniform** random sampling, which broke the
   convergence guarantee. Fixed: overflow path now does **argmax**
   (same as T=0), which is the semantically-correct cold-temperature
   behaviour.

3. **Invalid XSS `{tag_open}` productions**: `%3C`, `\x3c`, `<`,
   `&#60;`, `&lt;` were in the default XSS productions but are
   encoding-layer forms, not raw grammar mutations. The
   `still_executes_xss` oracle validator doesn't normalise these
   (only `\uXXXX` JS escapes are handled), so those forms always
   failed semantic validation. Replaced with literal `<`, `\t<`,
   ` <`, `\n<` variants.

4. **Unicode-norm XSS variants missing semantic filter**: the
   `unicode_norm::mutate` block in the XSS arm of `mutate_as` was not
   validating with `still_executes_xss`. Fullwidth-Unicode variants
   (e.g. `ｆｅｔｃｈ`) don't preserve structured exfil markers in the
   oracle normaliser, causing them to fail the scald soundness invariant.
   Fixed by adding `equiv::xss::still_executes_xss` filter before push.

### Changed — §8 ARCHITECTURE: narrow pub(crate) visibility for internal grammar modules

Three grammar sub-modules have zero external callers (neither from
other crates nor from integration tests) — narrowed to `pub(crate)`:
- `grammar::jndi` — internal dispatch target in `mutate_as`
- `grammar::ssi` — internal dispatch target in `mutate_as`
- `grammar::unicode_norm` — internal to the XSS arm of `mutate_as`

`cfg_convergence` was also narrowed (`pub(crate)`) since no downstream
crate imports `wafrift_grammar::grammar::cfg_convergence::*`.

### Changed — §1 SPEED: `synthesize()` featurize calls O(2 log N) → O(N)

`wafmodel::synthesize()` used `Iterator::min_by` with a closure that
called `featurize()` **twice per comparison** (O(2 log N) total, ~120
calls for N=52 candidates). Replaced with a `.map(score)` + `.reduce`
pattern that featurizes each candidate exactly once (O(N)).

### Changed — §1 SPEED: pre-size `pipelines` Vec in strategy/planner.rs

`plan_pipelines()` allocated `Vec::new()` for a collection capped at 4
entries (1 cached + 3 preset). Changed to `Vec::with_capacity(4)`.

### Added — `pg_chr_decompose` tamper (Postgres/Oracle CHR() + pipe-concat)

26th builtin `TamperStrategy`. Sibling to `sql_char_decompose` targeting
Postgres + Oracle dialects with their unary `CHR()` function joined by
the SQL-standard `||` pipe operator.

Input  `'admin'`  →  output  `(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))`

For ASCII payloads (the common case) both MySQL `CHAR()` and Postgres
`CHR()` behave identically. Tampers ship in pairs so the bench can
exercise both dialects without round-tripping a syntax-detector.

Tests: 5 unit (admin decomposition, empty literal, WHERE-clause embed,
distinct-from-char_decompose, unbalanced quote), 1 proptest never-panics.

### Added — `sql_char_decompose` tamper (CHAR()-codepoint literal decomposition)

25th builtin `TamperStrategy`. Sibling to `sql_concat_split` but with a
distinct shape: every single-quoted SQL string literal becomes a
`CHAR(N1,N2,...)` function call where each arg is the integer codepoint
of the original char.

Input  `'admin'`  →  output  `CHAR(97,100,109,105,110)`

Why both: blocklists evolve, and `sql_concat_split` produces visible
`'a','d',...` single-char tokens that a future rule could pattern-match
on (sqlmap's `concat2concatws` tamper got fingerprinted within months of
shipping). `sql_char_decompose` contains NO single-quoted ASCII tokens
at all — it's an entirely different syntax shape that bypasses both
literal-substring rules and CONCAT-shaped rules.

Supported by MySQL, MariaDB, MSSQL (native `CHAR()`). Postgres/Oracle
use `CHR()` — sibling `chr_decompose` could ship later.

Tests: 9 unit (admin/password/path-literal split, distinct-from-concat,
real injection payload, edge cases), 1 proptest never-panics.

### Added — 94 new auth-bypass header probes (gateway-identity + header-smuggle-LWS)

`wafrift bypass-probe` corpus expanded with two new families:

**Gateway-injected-identity** (90 probes = 18 headers × 5 values):
Cloud API gateways inject identity headers AFTER authenticating the caller —
backends that read them without re-verifying the upstream signature are
trivially bypassed if the WAF doesn't strip the gateway-namespaced
headers from external traffic. Covers Cloudflare Access
(`Cf-Access-Authenticated-User-Email`, `Cf-Access-Jwt-Assertion`), GCP IAP
(`X-Goog-*`), AWS ALB OIDC (`X-Amzn-Oidc-*`), Azure App Service Easy Auth
(`X-Ms-Client-Principal-*`), Authentik, oauth2-proxy
(`X-Auth-Request-User`), Traefik forwardAuth (`X-Forwarded-User`), Grafana
(`X-Webauth-User`). Spoofed values: `admin`, `admin@example.com`, `root`,
`root@localhost`, `administrator@internal`.

**Header-smuggling-LWS** (4 probes): single-char obfuscations of
`X-Real-IP` — leading space, trailing tab, U+00AD soft hyphen,
underscore-swap. Tests the WAF↔backend normalisation gap (nginx DROPS
underscored variants, Apache PASSES THROUGH — Akamai / Imperva tier).

Bypass-probe corpus is now 230 probes (was 136). Tests in
`crates/encoding/src/auth_bypass.rs` confirm both new families surface in
`auth_bypass_probes()` output.

### Added — `sql_concat_split` tamper (literal-substring decomposition)

24th builtin `TamperStrategy`. Every single-quoted SQL string literal is
rewritten to a `CONCAT('a','b',...)` expression — one char per argument.

Input  `' UNION SELECT 'admin','password' FROM users--`
Output `' UNION SELECT CONCAT('a','d','m','i','n'),CONCAT('p','a','s','s','w','o','r','d') FROM users--`

Mechanism: CRS and most commercial WAF blocklists scan for literal
danger-string substrings — `'admin'`, `'password'`, `'union'`, `'or 1'`,
`'/etc/passwd'`. CONCAT-splitting decomposes the substring into one-
character literals that no literal-string regex matches. The DB
evaluates `CONCAT(...)` to the original string at runtime, so the
attack succeeds. Works against MySQL, MariaDB, PostgreSQL, MSSQL —
all ship CONCAT as a scalar function. Oracle uses binary-only CONCAT
so chained 1-char Oracle calls need a nested form — out of scope here.

Tests: 10 unit (admin/password split, embedded in WHERE clause,
empty literal, unbalanced quote passthrough, multiple literals,
keyword preservation, real injection payload), 1 proptest never-panics.

### Added — 3 new WAF detect rules (open-appsec, Datadog ASM, Aikido Zen)

- **open-appsec** (`crates/detect/rules/detect/open_appsec.toml`) —
  Check Point's open-source ML-driven WAF (open-appsec.io), deployable
  as a Kubernetes ingress or NGINX module. Fingerprinted by
  `x-checkpoint-appsec` + `x-cp-appsec-incident-id` UUID header and the
  "open-appsec Web Application & API Protection" block-page literal.

- **Datadog ASM** (`crates/detect/rules/detect/datadog_asm.toml`) —
  Datadog's in-process WAF/RASP via dd-trace agent instrumentation
  (Java/Python/Node/.NET/Go/Ruby/PHP). Fingerprinted by the hardcoded
  `"You've been blocked"` JSON error envelope + `x-datadog-appsec-event`
  header. Anti-overlap noted with DataDome (different vendor).

- **Aikido Zen** (`crates/detect/rules/detect/aikido_zen.toml`) —
  Aikido's open-source runtime app security agent (aikido.dev/zen),
  auto-instrumented across Node / Python / Django / Express / NestJS /
  Laravel / Rails. Fingerprinted by the `x-aikido-blocked` header +
  `x-aikido-event-id` UUID + the "Aikido Runtime detected" body literal
  + the `"blocked_by":"aikido"` JSON envelope.

Detect corpus is now 167 rules (was 164).

### Added — `math_bold` tamper (Math Alphanumeric Symbols NFKC bypass)

23rd builtin `TamperStrategy`. Replaces ASCII letters and digits with their
Math Bold counterparts in the Unicode `U+1D400` block:

- `A`–`Z` → `U+1D400`–`U+1D419` (𝐀…𝐙)
- `a`–`z` → `U+1D41A`–`U+1D433` (𝐚…𝐳)
- `0`–`9` → `U+1D7CE`–`U+1D7D7` (𝟎…𝟗)

Mechanism: every codepoint in this range NFKC-normalises back to plain
ASCII. Backends that normalise (Postgres ICU, MySQL `utf8mb4_0900_ai_ci`,
Java `Normalizer`, .NET `String.Normalize`, Python `unicodedata.normalize`,
Go `golang.org/x/text/unicode/norm`) see the original `SELECT` / `UNION`
/ `script` keyword and execute / render it. WAFs scanning bytes for ASCII
keywords see `U+1D4xx` codepoints — no keyword match.

Distinct from existing `fullwidth_encode` (U+FF00 block) / `bracket_confusable`
(U+FF1C-FF1E only). WAFs that ship a "fullwidth keyword" blocklist (now
standard since ~2020) often do NOT also block U+1D400. Different code
range, different gap.

New SQL corpus file: `wafrift-bench/corpus/sql/math_bold_nfkc_2026.toml`
(12 cases: tautology, UNION SELECT, stacked DDL, time-based blind for both
MySQL and Postgres, EXTRACTVALUE error-based, information_schema dump,
LOAD_FILE LFI).

Tests: 8 unit (per-range encoding, mixed alphanumeric, punctuation preserved,
distinct-from-fullwidth), 1 proptest never-panics. All green.

### Added — `html_entity_variants` tamper (case + decimal + zero-pad rotation)

22nd builtin `TamperStrategy`. Rotates each output character through four
browser-tolerant HTML entity forms:

1. `&#xHH;`    — canonical lowercase-x hex
2. `&#XHH;`    — uppercase-X hex
3. `&#DD;`     — decimal
4. `&#000DD;`  — decimal with leading zeros

Targets WAF regexes that anchor on a single canonical form (`&#x[0-9a-f]+;`)
with case-sensitive `x` and required `;`. Browsers decode all four variants
identically — a payload of `&#X3c;&#115;&#00062;` reaches the DOM as `<s>`
while the regex only saw three of its four anchor patterns. Wired into
`TamperRegistry::with_defaults()` so it ships in every default scan / evade
run.

Tests: 7 unit (per-form encoding, deterministic, distinct-from-canonical),
1 proptest never-panics, second-pass cap entry at 10× (10-byte zero-padded
form drives the expansion bound). All green.

### Fixed — 6 duplicate corpus case IDs across 4 files

Sonnet stress-test pass found cross-file duplicates that would
silently drop entries in any ID-keyed merge (gene-bank dedup,
scoreboard rollup, bench-diff regression checks). Renamed the
later occurrences:

- `cmdi/{encoding_evasion,shell_unix}.toml` — `backtick_id`
- `xss/{event_handler,modern_event_handlers}.toml` — `object_onerror`, `embed_onerror`
- `cve_pocs/{2024_2025,real_world_2026}.toml` — `cve_2024_4577_php_cgi_arg_injection`
- `ssti/{ruby_dotnet_php,twig_freemarker_velocity}.toml` — `smarty_php_block`, `erb_eval`

New `crates/cli/tests/bench_corpus_stress.rs` (9 tests) pins the
unique-ID invariant + builds every request + asserts non-empty
wire bytes for all 817 corpus cases.

### Added — 53 stress / proptest / soak tests across the workspace

Sonnet sweep added (all green on first run):

- `crates/encoding/tests/tamper_proptest.rs` (29) — proptest fuzz
  of all 19 builtin `TamperStrategy` impls covering arbitrary
  UTF-8, ASCII controls, multi-byte, 512 KB random blobs, UTF-8
  boundary codepoints, and idempotency properties.
- `crates/strategy/tests/gene_bank_soak.rs` (4) — `WafGenome`
  round-tripped 10,000× through serde_json with zero drift.
- `crates/cli/tests/bench_corpus_stress.rs` (9) — corpus soak.
- `crates/proxy/tests/proxy_concurrency_stress.rs` (1) — 200
  concurrent clients × 50 requests each, no hangs, no panics.
- `crates/cli/src/raw_request.rs` (10 unit tests) — adversarial
  inputs (1 MB single line, 100K `§§` markers, embedded NULs,
  missing Host, port 0, 256 KB header values).

### Added — `tracing-subscriber` instrumentation across the CLI

Pre-fix every wafrift command had zero `tracing::*` calls; the
operator's `RUST_LOG` knob was completely inert. Now:

- `main()` initialises `tracing_subscriber::fmt` with an
  `EnvFilter` (default `warn`, idempotent, stderr).
- `scan`, `smuggle`, `bypass-probe` instrumented with key
  decision-point events under their respective targets
  (`wafrift::scan`, `wafrift::smuggle`, `wafrift::bypass_probe`).
  `RUST_LOG=wafrift=info` surfaces bypass-found + WAF-detect +
  rate-limit-abort events; `=debug` adds per-probe metrics.

### Added — `mxss_namespace_wrap` tamper (DOMPurify mXSS via MathML namespace)

CVE-2025-26791 class: wraps an HTML payload in the MathML
text-integration-point harness that DOMPurify ≤3.2.4 fails to
neutralise. The wire bytes contain NO `<script` token, so WAFs
pattern-matching the raw input pass it through; the dangerous DOM
is created by the browser AFTER WAF inspection when re-serialising
across XML namespaces. Wired into `TamperRegistry::with_defaults()`.

### Added — 3 new WAF detect rules

- **ngrok WAF** (`crates/detect/rules/detect/ngrok.toml`) — Coraza
  + CRS under the hood; fingerprinted by `ngrok-error-code` header
  + `ERR_NGROK_3200` body marker.
- **Akamai Adaptive Security Engine** (`crates/detect/rules/detect/akamai_ase.toml`)
  — Kona Rule Set's 2025 successor; fingerprinted by
  `x-akamai-request-id` + the new `Reference #` block-page format
  distinct from KRS.
- **Microsoft Defender for Cloud Apps** (`crates/detect/rules/detect/msdefender_cloud.toml`)
  — formerly MCAS; fingerprinted by `x-ms-cpim-*` headers and
  redirects to `*.mcas.ms` / `*.access.mcas.ms`.

Detect corpus is now 165 rules (was 162).

### Added — `wafrift ja3-diff` per-browser TLS-fingerprint differential scanner

Gated behind the `tls-impersonate` cargo feature (pulls in
BoringSSL). Sends the same probe through N browser-emulating
TLS clients (Chrome 120/131, Firefox 133, Safari 17.5/18,
Edge 131, OkHttp 5) plus a reqwest baseline, then flags any
profile whose status / body diverges — direct evidence the WAF
in front of the target JA3/JA4-fingerprints the ClientHello.

Build with `cargo install wafrift-cli --features tls-impersonate`.
Wires the previously-dead `wafrift_fingerprint::tls_fingerprint`
module (8 pub fns whose only consumer used to be its own tests).

### Fixed — proxy SSRF bypass via HTTP-redirect to bogon IP

P0 found by Sonnet dogfood pass 2 (2026-05): the proxy's upstream
reqwest client had no redirect policy, so it followed up to 10
redirects by default. An attacker controlling any public origin
the proxy was allowed to reach could return `Location: http://
169.254.169.254/...` (or any RFC1918 / loopback / link-local) and
the proxy would silently follow — bypassing both
`assert_forward_url_allowed` (called on the original URL only) and
`BogonFilteringResolver` (DNS-only). Now: `Policy::none()` — the
downstream client follows redirects itself, its policies apply.

### Added — honest config wiring across `wafrift scan`

`.wafrift.toml` had four fields parsed-and-ignored
(`output.report_layers`, `output.quiet`, `scan.concurrency`,
`http.timeout_secs`, `http.user_agent`). All now flow through:

- `--concurrency N` (overrides the dynamic 8/4 default)
- `--timeout-secs N` (overrides `DEFAULT_REQUEST_TIMEOUT_SECS`)
- `--quiet` (suppresses startup banner in addition to body)
- `--report-layers` (existing flag — now also reads from config)
- `--callback-timeout-secs N` (OOB callback wait, default 5 s)
- `--exploit-cap N` (max exploit-chain fires, default 500)
- `--adaptive-pause-secs N` (bench-waf throttle pause, default 2 s)

`http.user_agent` now flows through every command's HTTP client via
a shared `crate::config::shared_user_agent()` helper (10 cmd files
de-duplicated).

### Added — `wafrift detect` accepts positional URL

`wafrift detect <URL>` (the modern form every other wafrift cmd
uses) now works alongside `wafrift detect --url <URL>` (kept for
backwards-compat). The "No WAF confidently detected" output also
gains a `hint: --differential` line.

### Fixed — `wafrift scan --from-discovery --format json` invalid JSON

Each sub-job wrote its own top-level JSON object to stdout, so N
endpoints produced N back-to-back root objects (`jq .` errored at
the second). Now: per-job JSON is collected via tmpfiles and emitted
as a single `{"discovery_scan": {"jobs": [...]}}` envelope.

### Fixed — `wafrift scan --format json` emitted stray newlines

A `println!("\n")` after the intel-phase rendering was outside the
`if scan_text {}` guard, so `--format json` mode prefixed the JSON
blob with blank lines — `jq .` rejected the input.

### Fixed — `iis_unicode_encode` malformed for non-BMP code points

`iis_unicode_encode("😀")` emitted `%u1F600` (5 hex digits — invalid
IIS `%u` encoding; IIS rejects it). Now emits the UTF-16 surrogate
pair `%uD83D%uDE00` like real IIS does. Silent correctness bug:
prior output looked encoded but bypassed nothing.

### Fixed — silent IO error swallowing in proxy NDJSON audit logger

`writeln!()` + `flush()` failures in `RequestLogger::log_entry`
were dropped via `let _ = ...`. If disk filled up the audit trail
silently lost entries while the proxy reported healthy. Now: every
IO error surfaces through a throttled `warn!`.

### Fixed — bench-waf `record_feedback` errors silently discarded

`engine.record_feedback(idx, ...)` returns `EvolutionError` variants
(`InvalidChromosomeIndex`, `TargetHealthCritical`) that were both
swallowed via `let _ = ...`. Now: errors print a warn line with
case id + strategy + chromosome index so operators see the bias
source.

### Fixed — proxy gene-bank flush task could die silently on panic

A serializer panic in `save_gene_bank` killed the periodic-flush
task, the JoinHandle was dropped, and the proxy stopped flushing —
operator-invisible slow degradation. Now: each flush iteration
runs under `catch_unwind` with `warn!` on panic; loop continues.

### Fixed — `bench-waf` healthcheck ignored `--timeout-secs`

The healthcheck always used a hardcoded 10 s timeout, so an
operator setting `--timeout-secs 30` for a slow origin still got a
false "healthcheck failed" if the origin took 10–30 s. Now: uses
`max(args.timeout_secs, 5)` so the operator's setting takes effect
while keeping a sane floor.

### Fixed — `bypass-probe` curl reproducers broke on quoted input

Three curl-line format strings in `bypass_probe.rs` interpolated
header values and URLs into bare single-quote delimiters without
escaping — any `'` in the operator's URL or rewrite-probe value
produced an unparseable curl line. Now uses the shared
`helpers::shell_single_quote`.

### Fixed — integer overflow in `HostState::bump_success_for_technique`

Plain `stat.1 += 1` on u32 counters would panic in debug or
silently wrap to 0 in release after 2^32 successes — a long-running
proxy session could quietly reset technique stats. Now uses
`saturating_add` to match the already-fixed block-path. Regression
tests pin both paths at `u32::MAX - 1` + multiple bumps.

### Fixed — log injection via client-controlled Host header in proxy

CONNECT request's `inner` host header was written to `warn!` via
`%inner` without control-character filtering. An attacker could
send `Host: evil\nFAKE_LOG_ENTRY` to inject arbitrary log lines.
Now strips control chars before logging.

### Fixed — `wafrift evade --format json` was the only command emitting NDJSON

P1 found by Sonnet dogfood pass 4 (2026-05): every other wafrift
command produces a top-level JSON object on `--format json`, but
`evade` emitted one object per line (NDJSON), then a trailing
`{"explain": [...]}` object.  Scripts doing the natural `wafrift
evade --format json | jq .field` got nothing back and quietly
broke.  Enterprise evaluators with downstream pipelines saw the
inconsistency as a blocker.

Now:
- `--format json` produces a SINGLE top-level object:
  `{"variants": [...], "explain": {...}}`.  Matches every other
  command — `jq .variants[]` works.
- `--format jsonl` is the new opt-in for the legacy NDJSON form
  (streams variants line-by-line for large runs that don't fit in
  memory).
- `--quiet` still works and now aliases to `--format json` (the
  wrapped form).

Pre-2026-05 scripts that depended on `--quiet` producing NDJSON
need to switch to `--format jsonl`.

### Fixed — `wafrift evade` exit 1 on no-variants broke CI pipelines

P2 from the same dogfood pass: when an operator selected a
tamper that's not applicable to their payload shape (e.g.
`--only tamper/postgres_dollar_quote` on a payload with no `'`),
`evade` exited 1 with "No variants generated" — treating a
LEGITIMATE no-op outcome as an error.  CI pipelines that watched
for non-zero exit codes would fail every such run.

Now: no-variants exits 0 with an empty `variants` array and an
explanatory `note` field.  Pipelines treat the outcome as a
benign "this tamper didn't apply" rather than a failure.

### Improved — `wafrift detect` error chain now walks the reqwest source tree

P3 from Sonnet dogfood pass 4: `detect --url <invalid-host>`
previously reported just `request to X failed: error sending
request` — the actual DNS / TCP / TLS cause was buried in
reqwest's source chain and never surfaced.  Sysadmins reading
the error had to guess whether it was NXDOMAIN, TCP-refused, or
cert validation.

`fetch_for_detect` now walks `e.source()` recursively and
appends ` — caused by: ...` for each layer.  A typical NXDOMAIN
on Windows now reads:

```
Probe error: request to http://nonexistent.invalid.local/ failed: \
  error sending request for url (http://nonexistent.invalid.local/) — \
  caused by: client error (Connect) — \
  caused by: dns error — \
  caused by: No such host is known. (os error 11001)
```

Two regression tests guard the source-chain walk
(`fetch_for_detect_connection_refused_error_walks_source_chain`,
`fetch_for_detect_nxdomain_surfaces_dns_layer_cause`).

### Fixed — `wafrift attack` silently dropped its h2-diff sub-probe

P0 found by Sonnet dogfood pass 3 (2026-05): `attack` passed
`--concurrency N` (plus `--proxy`, `-H/--header`) to every
sub-probe via `push_common_flags`, but `h2-diff` doesn't accept
those flags.  Clap exited h2-diff with code 2 on every invocation
and the orchestrator catalogued the error as `{ "error":
"subprobe h2-diff exited 2 ..." }` and continued — silently
losing the H1/H2 differential probe on EVERY `wafrift attack`
run since the command was added.

New `push_h2_flags` helper carries only the flags h2-diff
actually accepts (`--format`, `--delay-ms`, `--timeout-secs`,
`--insecure`).  Six regression-guard tests in
`attack_cmd::tests::subprobe_args_h2_*` lock the contract.

### Added — `--url` alias for `discover` and `--body` alias for `body-diff`

CLI consistency fixes from the same dogfood pass:

- `wafrift discover --target <URL>` was the only command using
  `--target` while every other command used `--url`.  Added
  `--url` as a clap alias on the `target` arg so both forms work.
- `wafrift body-diff --baseline-body '<...>'` now also accepts
  `--body '<...>'` as a shorter alias — the natural form every
  pentester reaches for first.

### Improved — `compress --input` error message points to `--stdin`

P1: `wafrift compress --input "test"` previously gave the raw OS
error `open test: The system cannot find the file specified`
with no hint that `--input` expected a PATH (not a payload
string).  Now appends:
`Hint: '--input' expects a PATH to a file. For inline payloads
use 'echo "X" | wafrift compress --stdin'.`

### Added — Bench corpus expansion (+63 cases, hard real-world)

Two new corpus files targeting the upgraded confidence bar:

**`wafrift-bench/corpus/sql/frontier_tamper_2026.toml`** (28 cases):
Manual SQLi payload forms of the 6 frontier 2026 tampers —
zero-width Unicode injection, Postgres dollar-quote (with
arbitrary tag / Unicode tag / long-tag variants), MySQL
version-gated comment wrap (single + nested + version-specific
keywords), hex-literal keyword (in WHERE / OR / UNION /
long-string contexts), BEL separator (mixed with tab), and
combined-tamper compositions (zero-width inside dollar-quote;
hex literal inside version-gated comment).

**`wafrift-bench/corpus/xss/frontier_tamper_2026.toml`** (11
cases): Fullwidth bracket confusables (script / img / svg /
iframe / meta-refresh), zero-width injection inside attribute
values + URI schemes (`javascript:`), and bracket-confusable +
zero-width compositions.

**`wafrift-bench/corpus/cve_pocs/real_world_2026.toml`** (24
cases): Live CVE PoCs and 2024-2026 WAF bypass research —
CVE-2024-7593 (Ivanti vTM), CVE-2024-4577 (PHP CGI with
soft-hyphen variant), ProxyShell-style `@` smuggling, UTF-16LE
XXE with BOM, parameter-entity billion-laughs, CL.0 smuggling
with chunk extensions, TE.TE obs-fold, GraphQL aliasing,
modern SSTI (Jinja2 sandbox escape + FreeMarker), Log4Shell
with nested `${env:}` and `${sys:}` lookups, DOM-clobbering
XSS, mXSS via `<noscript>` reparse, second-order SQLi, gopher
SSRF to Redis, nip.io DNS-rebinding, overlong-UTF-8 path
traversal, cache-deception via static-extension routing, and
userinfo-smuggling open-redirect.

Corpus-integrity gate (`cargo test -p wafrift-cli --test
bench_corpus_integrity`) verifies the new files pass the
class-matches-directory invariant.

### Fixed — PowerShell pipe injects UTF-8 BOM that corrupts tamper outputs

`Write-Output "x" | wafrift evade --stdin` on PowerShell silently
prepends a UTF-8 BOM (`\xEF\xBB\xBF`) to stdin.  Without
stripping it, the BOM travels through every tamper output as an
invisible 3-byte prefix and the operator wonders why their
payload looks subtly wrong on Windows.

`resolve_payload` now strips a leading BOM from stdin
unconditionally — cmd, bash, zsh, and PowerShell pipes all
converge on the same byte stream.

### Added — `--explain` trace now surfaces tamper outcomes

When the operator runs `wafrift evade --only tamper --explain`,
the trace previously listed only the encoding strategies — every
tamper's invocation was invisible.  The explain output now adds
a per-tamper line with one of three outcome statuses:

- ✓ **Applied** — the tamper transformed the payload into a new
  unique variant.
- · **Idempotent** — the tamper produced byte-identical output
  (e.g. `postgres_dollar_quote` on a payload without `'`,
  `bracket_confusable` on a payload without `<>`).
- · **Duplicate of existing** — the tamper output collided with
  an already-produced variant.

JSON output follows the same shape: `{ "technique":
"tamper/zero_width_inject", "status": "applied", "detail": {} }`.

New `TamperExplainEntry` + `TamperOutcome` types in
`crates/cli/src/explain.rs` with 11 tests covering record /
fold / multi-outcome / JSON shape.

### Fixed — vendor ranking: ASN-named CDN now wins over header-derived component

`wafrift detect` previously surfaced "CacheWall" (the wafw00f
Varnish rule) as the primary vendor on Fastly-fronted sites
(reddit.com, nytimes.com) because the Varnish header scored
higher than the Fastly CNAME/ASN signal in the sort.  Varnish is
Fastly's underlying tech — the CacheWall hit is a Fastly
artefact, not an independent vendor.

New subsumption table in `detect_cmd::run_detect`: when a
DNS-derived parent vendor (Fastly via CNAME/PTR/ASN) co-exists
with its header-derived child (CacheWall via Varnish header),
the child's confidence rolls into the parent and the child row
drops out.  Result:

- `reddit.com` now shows **Fastly @ 1.0** (was "CacheWall @ 0.4")
- `nytimes.com` shows **Envoy + Fastly** (correct stack)
- `spotify.com` shows **Fastly + Envoy + GCP App Armor**

### Fixed — evade text output now escapes invisible byte transforms

Tampers like `bell_separator` (BEL 0x07), `null_byte` (NUL),
`zero_width_inject` (U+200B / U+200C / U+200D / U+FEFF) produce
real byte-level transforms that the terminal silently swallows.
Operator running `wafrift evade --only tamper/bell_separator`
saw `Payload: UNIONSELECT1` and concluded nothing changed (the
BEL bytes were invisible).

New `visualize_invisible_bytes` helper escapes:
- ASCII control bytes → `\xNN` (BEL, NUL, DEL, etc.)
- Common zero-width Unicode → `\u{200B}` / `\u{200C}` / etc.

Result: `UNION\x07SELECT\x071` and
`S\u{200B}E\u{200C}L\u{200D}E\u{FEFF}CT` are now visible in text
mode.  JSON output is unaffected (serde already escapes these).

### Removed — `keyword_comment_split` tamper (broken)

Inserted `/**/` between every pair of adjacent ASCII letters
(`SELECT` → `S/**/E/**/L/**/E/**/C/**/T`) on the assumption
MySQL strips C-style comments before tokenisation.  That's
wrong: MySQL treats `/* */` as WHITESPACE, so the result lexes
as six separate identifiers — `S`, `E`, `L`, `E`, `C`, `T`.
The tamper would have broken every real query it touched.

Regression guard test added so the broken tamper can't
accidentally come back.

### Added — `wafrift evade --only tamper/...` wiring

The 6 frontier 2026 tampers existed only in the `TamperRegistry`
and only ran inside `wafrift scan`.  `wafrift evade` produced
ZERO variants for `--only tamper/zero_width_inject`.

Closed the wiring: when an `evade --only` selector matches a
`tamper/*` path, evade now invokes the tamper registry directly
and appends one tamper variant per allowed tamper to the output
list.  Default-mode evade (no `--only`) still doesn't fire
tampers — they remain opt-in to preserve backwards
compatibility of the default 12 variants per medium-level run.

### Added — 6 frontier 2026 tamper strategies

`crates/encoding/src/tamper/builtins.rs`:

- **`zero_width_inject`** — interleaves U+200B / U+200C / U+200D
  / U+FEFF between alphabetic chars.
- **`postgres_dollar_quote`** — wraps single-quoted SQL string
  literals in `$tag$ ... $tag$`.
- **`mysql_versioned_comment_wrap`** — wraps payload in
  `/*!50000 ... */`.
- **`bracket_confusable`** — replaces `<` / `>` with U+FF1C /
  U+FF1E fullwidth confusables.
- **`hex_literal_keyword`** — converts `'admin'` to
  `0x61646d696e`.
- **`bell_separator`** — replaces ASCII space with BEL (U+0007).

Each ships with 5+ tests covering empty input, multibyte input,
idempotency, cross-tamper invariants.

### Added — `tamper/*` selectors in `wafrift techniques list`

The CLI's technique filter previously knew only `encoding/*` and
`grammar` families.  Added `tamper` as a third family so
`techniques list` surfaces all 18 registered tampers and
`--only tamper/<name>` / `--exclude tamper/<name>` selectors
validate at parse time.

### Added — DNS-layer detection module modularization

`crates/detect/src/dns_fingerprint.rs` (964 lines) split into
the canonical 4-way module dir:
- `mod.rs` — public API + re-exports.
- `types.rs` — `DnsProbe`, `CnameHop`, `AsnInfo`, `DnsProbeError`.
- `probe.rs` — async `probe_cname_chain` + `lookup_asn`.
- `rules.rs` — `CnameRuleEngine` + TOML parsing.
- `tests.rs` — 11 new tests added on top of the existing 17.

### Added — TUI test density ramp

`crates/proxy/src/tui/`:
- `render_chrome.rs`: 0 → 17 tests (TestBackend, header / tabs /
  footer / key hints rendering).
- `render_overview.rs`: 0 → 14 tests (counters, latency
  percentiles, status ribbon, TLS section, narrow-width safety).
- `render_hosts.rs`: 1 → 12 tests (table headers, truncation,
  bypass-rate formatting, top-N capping).
- `render_intercept.rs`: 2 → 11 tests (empty-state hints, mode
  banner, waiting color bands).

Plus ~60 new tests across `encoding::tamper`, `target_context`,
`technique_filter`, `detect::dns_fingerprint`, `evade_cmd`,
`grammar::sql::tautology`.  Workspace count: 1917 → 2066, all
green.

### Added — BGP ASN-origin lookup (the final detection axis)

After CNAME chain + PTR, `wafrift detect` now resolves the BGP
origin AS of the leaf IP via cymru.com's `origin.asn.cymru.com`
DNS service.  The ASN organisation name (e.g. `AMAZON-02`,
`CLOUDFLARENET`, `STRIPE-AS`) is the LAST signal an origin can
strip — it lives at L4 in the public BGP table, controlled by the
RIR not the application owner.  Catches what every other axis
misses:

- **Stripe** (`stripe.com`): bare `Server: nginx`, no CNAME, no
  PTR.  ASN reveals `AMAZON-02 - Amazon.com, Inc., US` (AS 16509)
  — Stripe is AWS-hosted.
- **Dropbox** (`dropbox.com`): `Server: envoy`, custom
  `dropbox-dns.com` CNAME, no PTR.  ASN reveals
  `DROPBOX - Dropbox, Inc., US` (AS 19679).
- **Slack**: quadruple-confirmed AWS (CNAME + PTR + ASN + Envoy).
- **Harvard**: ASN `AUTOMATTIC` confirms the WordPress VIP CNAME
  detection.

Catalog: 9 new ASN-anchored rules in `rules/detect/cname/cname.toml`
(Amazon, Cloudflare, Fastly, Akamai, Google, Microsoft, Dropbox,
Imperva, GitHub).  Stripe's existing rule was extended to match
the `STRIPE-AS` ASN tag in addition to the `s.stripe.com` PTR.

Implementation:
- `dns_fingerprint::lookup_asn` does a two-stage TXT lookup:
  `<reverse-octet>.origin.asn.cymru.com` returns the ASN number;
  `AS<number>.asn.cymru.com` returns the org name.  Both bounded
  to the same per-query timeout as the CNAME and PTR resolvers.
- `DnsProbe` gains an `asn: Option<AsnInfo>` field carrying
  `{ number, name }`.  The org name is a first-class participant
  in `all_hosts()` / `tagged_hosts()` so any rule pattern fires on
  it the same way as on a hostname.
- Indicator strings now carry source attribution: `cname:` /
  `ptr:` / `asn:` prefixes so the operator can see WHICH layer
  produced each detection.
- 24-site coverage: 28/29 sites detect at least one vendor (was
  27/29 — Stripe was the holdout).  Only network-error sites
  (bestbuy.com refusing reqwest's TLS handshake) remain undetected.

### Fixed — DNS PTR detection swallowed when forward chain empty

`run_detect` gated CNAME-rule matching on `!probe.chain.is_empty()`,
which meant origin-direct hosts (Slack, Stripe, Dropbox) had their
PTR record captured but never matched against the catalog.  Result:
Slack's `ec2-35-81-85-251.us-west-2.compute.amazonaws.com` PTR was
visible in JSON output but never produced an AWS detection.  Now
detection runs whenever ANY DNS signal exists — forward chain OR
PTR.

### Added — DNS PTR (reverse-DNS) detection axis

After resolving the forward CNAME chain, `wafrift detect` now also
issues a reverse-DNS lookup on the leaf IP and matches the
returned PTR record against the same CNAME rule catalog.  PTR is
the only vendor anchor available for sites that:

1. Strip every HTTP-layer banner (Server, Via, X-Cache, …).
2. Run origin-direct with no public CNAME chain.

eBay's PTR (live capture, 2026-05-21):
`23.209.84.185 → a23-209-84-185.deploy.static.akamaitechnologies.com`
— fires the new `Akamai (PTR)` rule, so eBay's Akamai backing is
identified TWICE (once via CNAME chain, once via PTR), giving the
operator two independent confirmations.

Catalogue additions (7 new PTR-anchored rules in
`rules/detect/cname/cname.toml`):
- `Stripe (origin-direct)` matches `*.s.stripe.com` PTR.  Stripe
  strips PTR on most of its anycast IPs, but the few that leak
  surface here.
- `Akamai (PTR)` matches `*.deploy.static.akamaitechnologies.com`.
- `Cloudflare (PTR)` matches `*.r.cloudflare.com` (PoP names).
- `AWS EC2 / NLB` matches `*.compute-N.amazonaws.com` and
  `ec2-N-N-N-N.*` forms.
- `Google Cloud (PTR)` matches `*.bc.googleusercontent.com`.

Output exposure:
- JSON: `dns.final_ptr` carries the resolved PTR, `null` when the
  IP has no reverse record (Stripe's main IPs).
- Text: "CNAME chain:" tree gains a `PTR → <name>` line.

Test coverage: PTR-only detection path, PTR-missing fallback,
real-world eBay PTR canary.

### Added — DNS-CNAME chain detection (new orthogonal detection axis)

`wafrift detect --url <X>` now resolves the target's full CNAME
chain via `hickory-resolver` (1.1.1.1 anycast) and matches every
hop against a 17-vendor catalog under `rules/detect/cname/`.  The
chain is reported in JSON output under `dns.chain[]` and rendered
as a tree under the "CNAME chain:" header in text mode.

Why this is a new detection axis, not just a rule expansion:

- HTTP-level detection fails when the origin strips every CDN /
  WAF marker header.  eBay returned only `Server: ebay-proxy-server`
  with no other clue.  Its DNS chain ends at
  `e88167.a.akamaiedge.net` — Akamai was hiding behind an in-house
  proxy banner all along.
- Same pattern on Netflix (`Server: envoy` → DNS reveals `*.elb.us-west-2.amazonaws.com`,
  AWS NLB), Airbnb (`Server: nginx` → Akamai), PayPal (CacheWall
  header → DNS reveals `*.map.fastly.net`, so the Varnish is actually
  Fastly).
- DNS is at L4, well below the application layer — the origin can't
  rewrite the CNAME chain the same way it can rewrite the Server
  header.

24-site real-world dogfood, before vs after:
- eBay: `Envoy` only → `Akamai + Envoy`
- Airbnb: `Envoy` only → `Akamai + Envoy`
- Netflix: `Envoy` only → `AWS ELB + Envoy`
- PayPal: `CacheWall` (Varnish) only → `Fastly + CacheWall`
- Microsoft / Salesforce / Tesla: Kona only → `Akamai + Kona SiteDefender`
- Reddit / NYT / Spotify: Fastly now confirmed via BOTH headers AND
  CNAME chain (with the chain rendered showing the 3-hop path).
- Stripe / Dropbox remain uncovered — origin truly direct or
  internally-routed DNS with no public CDN signal.

Architecture:

- `wafrift_detect::dns_fingerprint::probe_cname_chain` resolves the
  chain bounded to 12 hops + 8s per query.  Cycle-safe (HashSet
  guard) and timeout-safe (`tokio::time::timeout` per lookup).
- `wafrift_detect::dns_fingerprint::CnameRuleEngine` mirrors the
  HTTP detection engine's TOML schema (rules under
  `rules/detect/cname/`).  Auto-(?i) wrap on every host regex —
  same case-insensitivity invariant as the HTTP layer.
- `crate::detect_cmd::fetch_cname_chain` runs the resolver inside a
  one-shot tokio runtime so the sync `run_detect` flow doesn't
  need to become async end-to-end.
- CNAME-derived hits are MERGED into the existing `detected[]`
  vector when the rule name canonicalises onto an existing entry
  (e.g. `Fastly (CNAME)` → `Fastly`), or appended as a new entry
  when the CNAME identifies a different vendor than what the
  headers showed (e.g. eBay's `Envoy` header + Akamai CNAME).

Tests (15 new, all green):
- Pattern matching: CSV-joined chain, intermediate-hop match,
  case-insensitive host names, multi-vendor chain layering.
- Catalogue invariants: every embedded rule compiles + the canonical
  Fastly / Akamai / Cloudfront CNAMEs fire.
- Error surfaces: malformed TOML, broken regex, empty chain.

### Fixed — detection: case-insensitive matching enforced by default

`classifier::detect` (the public CLI entry point) has historically
lowercased every header VALUE and the response body before handing
them to the rule engine for matching.  Meanwhile the catalog under
`rules/detect/*.toml` is mostly authored as literal vendor banners
in canonical case (`Cloudflare`, `BinarySec`, `KEMP-LM`, the
Fastly POP-code regex `[A-Z]{3}`).  The two layers disagreed, so
any rule with an uppercase character class or capitalized literal
silently failed to match real traffic.  Most visibly: Fastly went
undetected on every multi-hop site (nytimes, Spotify, etc.) because
the cache-tag regex required `[A-Z]{3}` but received the
lowercased value.

The fix forces case-insensitive compilation for every detection
regex via a new `compile_ci_regex` helper that prepends `(?i)`
unless the author already declared an outer case flag (`(?i)`,
`(?-i)`, `(?i-`, `(?-i-`).  Rule authors can opt out via `(?-i)`,
preserved verbatim.  The catalog had no such opt-outs, so this is
universally safe.

Verified end-to-end:
- nytimes.com now surfaces BOTH `Envoy` AND `Fastly` at 1.0
  confidence (was missing Fastly entirely).
- Spotify surfaces THREE layers: Envoy + Fastly + Google Cloud App
  Armor.
- Salesforce / Tesla / Microsoft (AkamaiGHost banner) now fire
  Kona SiteDefender (banner casing was the blocker).
- 24-site dogfood sweep: 20/24 detect a WAF; the four
  non-detections (stripe, dropbox, ebay, reddit) genuinely hide
  behind a generic `nginx` / `envoy` / `snooserv` / custom proxy
  banner with no vendor signal in the response.

Tests covering the fix and its blast radius:
- `ci_wrapper_*` (9 tests) — explicit-flag opt-out, multi-flag
  groups, anchored patterns, escaped metacharacters, Unicode
  metaclasses, empty alternation, broken patterns.
- `every_embedded_rule_compiles` / `every_header_regex_in_catalog_is_case_insensitive`
  — catalog-wide invariants that prove no future rule can quietly
  reintroduce the bug class.
- `every_literal_header_rule_in_catalog_matches_capitalized_value`
  / `lowercase_input_must_match_uppercase_pattern_for_every_rule`
  — synthesise inputs FROM the rules themselves (no hardcoded
  vendor names), so any new rule whose literal value doesn't fire
  via the public API breaks the build.
- Real-traffic shape regressions (`csv_joined_multi_hop_header_value_*`,
  `multi_waf_chain_returns_every_layer_not_just_the_top`,
  `detection_is_stable_under_random_header_casing`,
  `unknown_vendor_banner_does_not_false_positive`).
- Edge-case panic-safety: non-ASCII bytes, empty inputs, 100 KiB
  header values, repeated header names.

### Added — bench corpus expansion (+111 cases, 607 → 718)

Seven new corpus files filling gaps surfaced during dogfooding:

- `corpus/ldap/encoding_evasion.toml` (+12 cases) — URL-encoded,
  double-URL-encoded, RFC 4515 hex-escape, whitespace-folded,
  extensible-match-OID, fullwidth-Unicode LDAP variants.
- `corpus/xxe/encoding_evasion.toml` (+12 cases) — UTF-16/EBCDIC
  encoding declarations, DOCTYPE whitespace + comment +
  case-folded variants, parameter-entity OOB exfil chains, jar:/
  netdoc:/expect: scheme abuse, Unicode entity-name evasion.
- `corpus/log4shell/nested_lookups.toml` (+13 cases) — ${lower:}/
  ${upper:}/${env:}/${sys:}/${date:'j'} nested lookups, RMI/LDAPS/
  CORBA/DNS protocols, decimal/hex/octal IP host encodings,
  userinfo `@` decoy hosts.
- `corpus/nosql/advanced_operators.toml` (+10 cases) — $regex
  extraction, $where JS, $expr/$strLenCP, $or/$and nesting,
  CouchDB Mango selectors.
- `corpus/cmdi/encoding_evasion.toml` (+15 cases) — $IFS variable
  expansion, brace-expansion, backslash-newline, quoted-empty-string
  obfuscation, backtick command-sub, hex-via-printf, tab/CR
  separators, pure-glob attacks.
- `corpus/cve_pocs/2024_2025.toml` (+11 cases) — Jenkins Args4j
  (CVE-2024-23897), runc (CVE-2024-21626), xz-backdoor
  (CVE-2024-3094), PHP CGI argument injection (CVE-2024-4577),
  regreSSHion (CVE-2024-6387), ScreenConnect (CVE-2024-1709),
  Ivanti vTM (CVE-2024-7593), Gladinet (CVE-2025-30406), Cleo Harmony
  (CVE-2024-50623), Rejetto HFS (CVE-2024-23692), CrushFTP
  (CVE-2024-4040).
- `corpus/ssti/ruby_dotnet_php.toml` (+19 cases) — ERB (Ruby) RCE
  via backtick / system / IO.popen / eval, Slim, Razor (.NET)
  reflective Process.Start, Smarty {php} block + static-method
  abuse, Twig filter chain + sandbox escape, Handlebars constructor-
  walking, Velocity reflective Runtime.exec.

Additional cases appended to `corpus/ssrf/cloud_metadata.toml`
(+14): IMDSv2 token endpoint, decimal/hex/octal IP encodings of
169.254.169.254, Hetzner / Oracle OCI metadata, localhost service
probes (Redis, Elasticsearch, Docker socket, Consul, etcd), DNS-
rebinding hostname tricks (nip.io, xip.io).

- `corpus/xss/modern_event_handlers.toml` (+21 cases) — Pointer
  Events (onpointer{move,down,enter}, ongotpointercapture), media
  events (onloadstart, onplay+autoplay, oncanplay, onstalled),
  lazy-loading image errors, <object>/<iframe srcdoc>/<embed>
  carriers, drag-and-drop (ondragstart/ondrop), HTML invokers
  (onbeforetoggle/ontoggle/oncancel), modern scroll/animation
  (onscrollend, onanimationend with inline keyframes), web-
  components (onslotchange).
- `corpus/sql/dialect_quirks.toml` (+19 cases) — PostgreSQL
  $tag$-quoted strings + E'' escape, MSSQL bracket identifiers +
  N'' Unicode literals + WAITFOR DELAY + xp_dirtree OOB, SQLite
  ATTACH + load_extension, Oracle DUAL + UTL_HTTP OOB + CHR
  concat, MySQL hex/binary literals + NATURAL JOIN, Unicode +
  smart-quote variants.

**Total: 607 → 758 cases (+151) across 9 new files.** All
`bench_corpus_integrity` tests pass (5/5).

### Fixed — dogfood findings (real-world WAF detection)

- **`wafrift detect --format json`** now works. Previously fell back
  to the legacy `--quiet` flag (which emitted JSON as a side
  effect); operators expecting the uniform `--format` flag (used
  by every other subcommand) got an "unexpected argument" error.
  Fixed by accepting `--format json` as a synonym for `--quiet`'s
  JSON path. Found during real-target dogfood against
  `https://httpbin.org/get`.

- **Fastly detection** — previously zero hits on
  `https://www.fastly.com/` because the existing rule required
  either `X-Fastly-Request-ID` or a `^cache-`-anchored
  `X-Served-By`. Real Fastly responses commonly send `X-Served-By`
  as a multi-hop CSV (`cache-sjc10026-SJC, cache-...`) where the
  anchored regex fails. Added: un-anchored cache-tag match, the
  signature `Server: Artisanal bits` banner (weight 0.7), and the
  Varnish `X-Timer: S...,VS0,VE1` shape.

- **Akamai detection** — previously zero hits on
  `https://www.akamai.com/` 403 because the existing rule only
  matched `Server: AkamaiGHost` / `X-Akamai-Transformed`. Akamai's
  own marketing site has rotated to a newer header set:
  `X-Akam-SW-Version`, `Akamai-GRN`, `Server-Timing: ak_p`,
  `Report-To: go-mpulse.net`. Added all five tells.
  `Server: AkamaiNetStorage` added (weight 0.4) to catch
  Akamai-fronted static-asset CDNs (`microsoft.com` is one).

- **F5 Distributed Cloud (Volterra)** — entirely new rule file
  `f5_distributed_cloud.toml`. F5's modern WAF/CDN serves with
  `Server: volt-adc` and `X-Volterra-*` headers; wafrift's older
  `f5bigip{asm,ltm}` rules never fire on Distributed Cloud.
  Captured live on `https://www.f5.com/`.

After fixes (2026-05-21): cloudflare.com → Cloudflare (1.0),
aws.amazon.com → CloudFront (1.0), akamai.com → Kona SiteDefender
(1.0, 6 indicators), fastly.com → Fastly (0.7), imperva.com →
Incapsula (1.0), f5.com → F5 Distributed Cloud (1.0), discord.com
→ Cloudflare (1.0), shopify.com → Cloudflare (1.0), microsoft.com
→ Kona SiteDefender via AkamaiNetStorage (0.4). 9/9 known-WAF
public sites detected correctly.

### Added — three more parser-diff family members

- **`wafrift method-diff <URL>`** — 15 HTTP method variants (POST/
  PUT/DELETE/PATCH, HEAD/OPTIONS/TRACE, WebDAV PROPFIND/MKCOL/
  MOVE/COPY/LOCK, custom token, lowercase `get`, H2 preface `PRI`).
- **`wafrift gql-diff <URL>`** — 10 GraphQL parser / cost-limit
  probes (introspection-full, introspection-type, alias bombing,
  batched operations, mutation-as-query, field duplication,
  fragment nesting, alt-content-type, GET-shaped query,
  operation-name spoof).
- **`wafrift jwt-diff <URL> --token <jwt>`** — 11 JWT validation
  probes (alg:none case-family x4, empty-sig-original-alg, kid
  traversal, kid SQL injection, jku attacker-URL, expired exp,
  future nbf, role elevation).
- **`wafrift cors-diff <URL>`** — 10 CORS misconfiguration probes
  (arbitrary-origin reflection, null origin, suffix/prefix
  confusion, trailing-dot host, http downgrade, userinfo `@`
  injection, wildcard reflection, preflight arbitrary-header,
  preflight DELETE).

### Added — orchestrator extended

- `wafrift attack` now runs ALL SEVEN parser-diff family probes
  concurrently (added method-diff alongside the original url-path,
  headers, body, query, cache, h2). gql-diff and jwt-diff stay
  out of the default orchestrator (GraphQL- and JWT-specific —
  call directly).

### Added — bench_waf modularization

- Test block extracted from `crates/cli/src/bench_waf.rs` into
  `crates/cli/src/bench_waf_tests.rs` (607 lines moved); main
  file shrinks 2494 → 1891. Production code unchanged.

### Added — endless dogfood harness

- `crates/cli/tests/dogfood_session.rs` (11 tests) drives every
  new subcommand through a header/body/query/cache-aware mock via
  the real `wafrift` binary. Verified flake-free over 5 back-to-
  back iterations.
- `wafrift-bench/scripts/dogfood-public.sh` — loop script that
  exercises every command against safe public targets (httpbin.org
  + countries-graphql) every 60s. Useful as a continuous-uptime
  smoke alarm.

### Real-world dogfood results

- **httpbin.org**: `cors-diff` found 10 high-severity CORS misconfigs
  (reflects every Origin into ACAO + sets ACAC:true on every probe
  — textbook credentials leak). `method-diff` found 9 high
  divergences (multiple methods produce distinct body shapes).
  `attack` orchestrator found 17 divergences across families.
- **countries.trevorblades.com/graphql**: `gql-diff` found
  alias-bombing produces +164% body delta (one of the canonical
  cost-limit evasion patterns).

### Added — parser-disagreement family (the WAFFLE-2024 frontier line)

Five new subcommands that find WAF↔origin / WAF↔cache parser
disagreements, exposing bypass seams that don't require any payload
mutation. Each has a curated probe catalogue, JSON output for piping
into report tooling, and a `curl -i` reproducer per finding.

- **`wafrift parser-diff <URL>`** (already existed; sibling commands
  below are new). URL-path parser disagreements (semicolon-strip,
  backslash-as-separator, NUL truncation, double-URL-decode,
  fullwidth slash, dot-segment, percent-case, empty-segment,
  trailing-dot).
- **`wafrift header-diff <URL>`** — 17 request-header probes
  (dup-XFF, dup-Authorization, header-name case mix, Host
  smuggling, X-Original-Host rebind, X-Rewrite-URL, X-Real-IP
  localhost spoof, IP-spoof family, trailing-whitespace,
  NUL truncation, X-HTTP-Method-Override).
- **`wafrift body-diff <URL>`** — 8 request-body probes (JSON
  dup-key first/last wins, BOM-prefix, UTF-7 charset smuggling,
  form-urlencoded HPP, JSON-as-form, form-as-JSON, JSONC
  comments, multipart boundary collision).
- **`wafrift query-diff <URL>`** — 11 query-string probes (HPP
  first/last, array bracket notation, comma split, empty-value
  HPP, missing-value, percent-encoded keys, NUL truncation,
  semicolon separator, encoded `#`, trailing-dot keys).
- **`wafrift cache-diff <URL>`** — cache-key confusion / poisoning
  surface (Host header case, X-Forwarded-Host injection, trailing
  slash, query parameter order, param name case, UTM tracker
  strip, fragment leak, Cookie variation). Compares FNV-1a body
  hashes + `Age`/`X-Cache`/`CF-Cache-Status` headers to detect
  cache-key collisions.
- **`wafrift h2-diff <URL>`** — HTTP/1.1 vs HTTP/2 differential
  scanner. Fires the same logical request via both protocols
  (4 probes: baseline, payload-in-query, dup-param, long-query)
  and reports response divergence. Catches the common pattern of
  WAF rule corpus authored against H1 wire format + H2→H1
  downgrade translation bugs. Required adding the `http2` feature
  to workspace reqwest.
- **`wafrift method-diff <URL>`** — HTTP method parser-disagreement
  scanner. 15 method variants (POST/PUT/DELETE/PATCH, HEAD/OPTIONS/
  TRACE, WebDAV PROPFIND/MKCOL/MOVE/COPY/LOCK, custom token, lower-
  case `get`, H2 preface `PRI`). Catches WAF rules that only fire
  on GET/POST while the origin routes the unusual verb somewhere
  meaningful.
- **`wafrift gql-diff <URL>`** — GraphQL parser / cost-limit
  disagreement scanner. 10 probes covering introspection-full,
  introspection-type, alias bombing, batched operations, mutation-
  as-query, field duplication, fragment nesting, alt-content-type,
  GET-shaped query, operation-name spoof. Targets `/graphql`-style
  endpoints where REST WAFs see only `POST /graphql` and miss the
  structure inside.
- **`wafrift attack <URL>`** — unified orchestrator. Spawns ALL
  seven parser-diff family probes (url-path, headers, body, query,
  cache, h2, method) concurrently as subprocesses, merges their
  JSON into one structured report with per-family + cross-family
  divergence totals. The end-to-end pentester command — one call,
  every parser-disagreement seam surfaced. (`gql-diff` is excluded
  from the default `attack` orchestrator because it's GraphQL-
  specific; run it directly against `/graphql` endpoints.)

### Added — adversarial distillation (Zeller ddmin)

- **`wafrift distill <URL> --payload "<bypass>"`** — minimum-edit-
  distance reducer for known-working bypass payloads. Runs Zeller's
  ddmin recursively (subset-pass + complement-pass + granularity
  doubling) to find the smallest substring that STILL bypasses.
  Useful for pentest reports — shorter payloads are easier for
  clients to reproduce and reveal which payload features the WAF
  actually objected to vs. were noise. Capped at `--max-fires`
  for rate-limit defence.

### Added — Burp raw-request scan mode

- **`wafrift scan -r <FILE> --payload "<x>"`** — load a Burp-saved
  raw HTTP request (Copy → Save raw → File), substitute `§§`
  marker with each variant payload, fire through pentest pivot
  (`--proxy` / `-H`), emit JSON with `bypass_variants[i].repro_curl`
  per finding.
- **`--auto-distill`** flag on `wafrift scan` (raw mode) — after
  finding bypasses, automatically run ddmin per bypass; emits
  `minimal_payload` + `minimal_repro_curl` per bypass entry.

### Added — `repro_curl` in report findings

- `wafrift report` JSON / markdown output now includes a
  `curl -i` reproducer per finding alongside the existing
  `wafrift replay` invocation. Schema version bumped 1 → 2.

### Refactored — single source of truth

- `helpers::shell_single_quote` — canonical Bourne shell quote;
  `report.rs` + `raw_request.rs` + `header_diff_cmd` +
  `body_diff_cmd` + `cache_diff_cmd` + `query_diff_cmd` all route
  through it (one bash round-trip test exercises every caller).
- `helpers::parse_header_pair` — canonical colon-split + trim
  primitive shared by `helpers::parse_headers` (slice form) and
  `scan::pentest_client::parse_header` (typed
  HeaderName/HeaderValue form).
- `parser_diff_common` — canonical `body_delta_pct`, `severity_of`,
  `status_class`; consumed by every member of the parser-diff
  family (one classification rule change reaches every
  sub-command in one edit).

### Added — Oracle feedback loop + stateful grammar API (R56 pass-21)

- `CfgMutatorState` — public struct (`wafrift-grammar`) holding
  persistent SQL and XSS `CfgMutator` instances. Pass it across
  probe rounds so Boltzmann bypass scores accumulate; bypassing
  productions get `+5.0`, blocked ones get `-1.0` per `feedback()`.
- `mutate_as_with_state(payload, type, max, &mut CfgMutatorState)`
  — stateful variant of `mutate_as`; uses the persistent mutators
  from `state` rather than building fresh ones per call. The
  original `mutate_as` is unchanged (LAW 2).
- `feedback(state, payload_type, rules_applied, bypassed)` — wire
  probe results back into the convergence-annealing scores. Only
  rules with `cfg_` prefix are rewarded; non-CFG rules are ignored.
- Re-exported `CfgMutatorState`, `mutate_as_with_state`, `feedback`
  at the crate root of `wafrift-grammar` so callers don't need to
  import the internal `grammar::cfg_convergence` module.
- 8 new tests covering: SQL/XSS stateful variants, cfg variant
  inclusion, reward score mutation, temperature persistence across
  calls, type contract equivalence, non-CFG rule no-op, and
  `Default` == `new()`.

### Fixed — SSRF redirect gaps (R56 pass-20/21)

- `bank_registry::build_registry_client` — added
  `safe_redirect_policy(5)`. The registry URL is operator-supplied;
  a hostile registry returning `302 → 169.254.169.254/` would have
  been followed under reqwest's default `Policy::limited(10)`.
- `bench_waf` — added `safe_redirect_policy(5)` to the bench HTTP
  client (closed in R56 pass-20; previous session).
- `discover_cmd` — wired `HasHttpConfig` impl + `--timeout-secs` /
  `--insecure` flags + `apply_http_defaults` dispatch (closed in
  R56 pass-20).

### Fixed — WIRING / §9 coherence (R56 pass-20)

- `--report-layers` text panel now surfaces `retry_after_responses`
  / `max_retry_after_obeyed_ms` alongside the layer summary.
  GAP_CLOSURE_ROADMAP item 7 marked CLOSED.

### Removed — doc + dead-code clutter

- Deleted `docs/archive/` (4 files, ~2699 lines of stale planning
  docs).
- Deleted retracted `wafrift-bench/results/SUMMARY.md` (numbers
  were rigged — explicitly flagged at the top of the file).
- Deleted stale `wafrift-bench/results/v022-*/SUMMARY.md` +
  `BENCH_021_NOTES.md` (~234 lines of ancient bench summaries).
- Deleted `scan/state.rs` (100-line scaffold, never constructed).
- Deleted `detect_cmd::_ensure_arc_in_scope` + stale `Arc` import.
- Deleted `smuggle_cmd::_ASSERT_VARIANT_LINKAGE` doc-link hack.
- Narrowed `listener_cmd` `#[allow(dead_code)]` to `#[cfg(test)]`
  on the three Registry methods only used in tests.
- Trimmed `raw_request.rs` module-level `#![allow(dead_code)]`
  (the parse side now has a real caller: `scan -r` mode).
- Removed `#[allow(dead_code)]` from `CfgMutator::reward`,
  `reward_by_name`, `batch_expand`, and `Production::name` — all
  now have live non-test callers via `CfgMutatorState`.

## [0.2.17] — 2026-05-18

### Added

- Two sound **raw delivery channels** for the joint `(payload ×
  delivery)` equivalence algebra: `DeliveryShape::HeaderValue { name }`
  and `DeliveryShape::Cookie { name }`. Reflected `X-Forwarded-Host` /
  cookie XSS is a real class that a CRS-class WAF covers more weakly in
  `REQUEST_HEADERS` / `REQUEST_COOKIES` than in ARGS at PL1 — these are
  the channels scald's WAF-evasion tier was missing. Each carries the
  **exact** payload bytes (no encoding — the backend XSS sink must see
  literal markup) and is gated by `DeliveryShape::transport_legal`: a
  per-channel RFC constraint (RFC 9110 field-value for headers —
  including the §5.5 rule that recipients strip leading/trailing
  OWS, so an edge-whitespace payload would arrive trimmed and is
  rejected as unsound; RFC 6265 cookie-octet for cookies). They flow
  to scald automatically —
  `xss_delivered` + `to_request` already iterate every shape, so no
  scald code change is needed beyond repinning.

### Fixed / Hardened

- **Request-smuggling guard.** `DeliveryShape::to_request` hard-strips
  CR/LF/NUL (and the request-`Cookie:` pair separator `;`) from
  raw-channel values, so even a careless direct caller can never turn a
  payload into header injection / request smuggling. Provably a no-op
  on generator-produced members (they are pre-filtered).
- **Cross-class delivery soundness gate.** The new raw shapes live in
  the *shared* `delivery_set`, so a shared `enforce_transport_legal`
  finalizer now runs at the tail of all 10 class generators
  (sql/xss/cmdi/path/ssti/ldap/ssrf/nosql/log4shell/xxe). Without it a
  CR/LF/`;`/space-bearing SQLi/etc. payload could be emitted paired
  with a raw channel whose renderer strips those bytes — i.e.
  `member.payload` would differ from what reaches the backend (an
  unsound, rigged member). XSS additionally guards inline (re-samples
  instead of dropping, preserving recall).
- **`HppSplit` documentation corrected to the truthful mechanism.**
  The variant previously claimed "the backend concatenates a+b" (a
  payload-splitting model) but the implementation emits benign decoy
  values followed by the intact payload in the *last* occurrence — a
  last-occurrence-pollution evasion, sound on last-wins backends
  (PHP/Express/Spring/Rails) and explicitly NOT sound on first-wins or
  value-concatenating (legacy ASP.NET) backends. Now documented
  accurately and pinned by a test.

### Tests

- Full per-rule contract for the new channels: exact-byte render,
  negative precision, adversarial smuggle battery, 4000-case proptest
  (legality + no-smuggle + bounded), cross-thread determinism, and a
  scald-shaped consumption e2e.
- `delivery_roundtrip_tests`: every encoding shape
  (query/form/json±CT/multipart-field/file/path) and every legal raw
  channel recovers the exact payload bytes a conforming backend would
  parse, over a byte-class-adversarial corpus (CRLF, percent,
  multibyte, control bytes, quotes, backslash).
- `every_emitted_member_is_transport_legal_for_its_delivery` across all
  10 classes × 4 seeds × 3 caps.

## [0.2.16] — 2026-05-18

### Added

- **Delivery-aware XSS public API for scald**: `xss_delivered(payload,
  max)` and `DeliveryShape::to_request(target, payload)` — one source
  of truth for the joint `(payload × delivery)` algebra. Honest basis:
  payload-string XSS obfuscation is ≈0% vs a CRS-class WAF (it
  normalises every encoding); the delivery shape (multipart-file /
  path-segment / JSON-without-Content-Type) is the lever that bypasses
  it.
- equiv generators extended **6 → 10 classes**: added sound `ssrf`,
  `nosql`, `log4shell`, `xxe` with independent anti-rig soundness
  oracles (`still_targets` / `still_injects` / `still_executes` /
  `still_exfils`).

### Fixed

- Multibyte / char-boundary panics in `log4shell::innermost`, the
  `xxe` URI scan, and `ssti::rw_string_split` (a byte index was used as
  a char index on non-ASCII input).
- `url_with_pair` / `FormBody` now percent-encode the parameter
  **name** (a name containing space / `&` / `#` previously corrupted
  the request structure).
- RFC 7578 collision-safe multipart boundary (`effective_boundary`):
  an attacker payload echoing the constant boundary can no longer forge
  multipart structure in the request wafrift builds.
- LDAP soundness oracle rebuilt (host-closer count decoupled from
  prefix depth; `%00`/NUL truncation; escape-tolerant parse); three
  rigged tests that asserted a benign filter was "valid" corrected.

## [0.2.15] — 2026-05-17

### Fixed

- **`evade --explain` printed dozens of repeat "folded" lines for the
  same strategy.** `build_variants_explained` iterates encoding
  strategies inside the grammar-mutation loop, so a strategy that
  produced a duplicate on every grammar mutation got recorded
  dozens of times. `ExplainTrace::record` now folds repeat
  observations of the same (strategy, outcome-variant) into a
  single entry — the trace becomes a summary again instead of
  scroll noise. Found via smoke-testing `evade --target-context
  header --explain`.

## [0.2.14] — 2026-05-17

### Fixed

- **`crates/cli/src/main.rs` — `evade --only` at low levels silently dropped
  techniques.** `wafrift evade --only encoding/base64/standard` returned
  "No variants generated" at the default `--level medium` because the
  medium-level pool was the first 6 strategies sorted by aggressiveness
  and base64 sat past that cut. Explicit `--only` now overrides the
  level-based pool; `--level` still bounds the variant count via
  `max_mutations_for_level`.

### Added — `evade` UX (2026-05-17 dogfooding sweep)

- **`--stdin`** — read payload from stdin for piped workflows:
  `echo 'X' | wafrift evade --stdin --only encoding/base64/standard`.
  Mutually exclusive with `--payload`; refuses to run on an interactive
  terminal so it can't hang silently.
- **`--target-context {header,body,query-param,cookie}`** — filter
  techniques whose output is unusable in the chosen HTTP context.
  Conservative rules: compression / NUL-byte / chunked-split blocked in
  text contexts; parameter-pollution blocked in header/cookie (allowed
  in body for `application/x-www-form-urlencoded`).
- **`--explain`** — per-technique trace showing which strategies ran,
  which were skipped, and why (applied / duplicate /
  not-applicable-to-context / encoding-error). Rendered as colored
  text or, in `--quiet` mode, a trailing `{"explain":[...]}` JSON object
  after the NDJSON variants.
- **`--output` now writes the JSON error blob on the empty-variants
  path** instead of dropping it.

### Internal

- `crates/cli/src/target_context.rs` — `TargetContext` + applicability rules.
- `crates/cli/src/explain.rs` — `ExplainTrace` (text + JSON renderer).
- `helpers::strategy_pool(level, explicit_selection)` — drives the bug
  fix above; widens to the full strategy set when `--only` is set.
- `helpers::build_variants` now delegates to `build_variants_explained`
  (eliminated ~95 lines of duplicated encoding/grammar logic).
- New e2e + unit tests cover all of the above.

## [0.2.13] — 2026-05-11

### Fixed — proxy adversarial sweep (6 defects)

- **CRITICAL `crates/proxy/src/mitm.rs:214`** — leaf certs for IP
  literals (`https://127.0.0.1`, `https://[::1]`) used dNSName SAN
  instead of iPAddress SAN, causing browser TLS errors on every MITM
  of a private IP. Fixed: detect IP literals in `leaf_params_for` and
  push `SanType::IpAddress`. Locked with `mitm_ip_san.rs` (135 LOC,
  IPv4 + IPv6 + DNS-name negative twin).
- **HIGH `crates/proxy/src/main.rs:1759`** — stealth upstream response
  path parsed only the first `Connection` header, leaking hop-by-hop
  tokens from subsequent `Connection` headers to the client. Fixed:
  replace inline `.find()` with `collect_connection_header_names()`
  in new `crates/proxy/src/hop_by_hop.rs`.
- **HIGH `crates/proxy/src/main.rs:479`** — gene-bank loader silently
  discarded pre-schema-v0.1 flat-HashMap files, destroying all saved
  discovery on upgrade. Fixed: backward-compat fallback that
  deserializes flat HashMap and wraps it.
- **HIGH `crates/proxy/src/main.rs:598`** — `restore_gene_bank`
  bypassed the 10K host memory cap, allowing a malicious gene-bank
  to exhaust proxy RAM on startup. Fixed: evict oldest hosts until
  `len <= 10_000` after restore.
- **MEDIUM `crates/proxy/src/main.rs:626`** — `--max-evade-retries`
  had no upper bound; arbitrary u32 values created per-request retry
  storms that pinned CPU. Fixed: cap at 10 in `validate_args` with
  actionable error message.
- **MEDIUM `crates/proxy/src/tui/state.rs:382`** — `State::hosts`
  grew without bound, leaking memory during long engagements with
  high host cardinality. Fixed: cap at `MAX_TUI_HOSTS = 4096` and
  evict lowest-sent on overflow.
- **LOW `crates/proxy/src/main.rs:570`** — `save_gene_bank` left
  tempfiles behind when disk-full or I/O errors aborted the flush.
  Fixed: wrap write in a closure; delete tempfile on any error.
- New tests: `evade_retry_cap.rs` (53 LOC), `mitm_ip_san.rs` (135 LOC),
  `proxy_tests.rs` (179 LOC inline) — proving + adversarial pairs for
  every defect.

### Already shipped between 0.2.12 and 0.2.13 (recap)

The following landed on main between the 0.2.12 release and this bump
and were credited in earlier in-line patches; recapped here so the
version bump's CHANGELOG is comprehensive:

- **CRITICAL Cloudflare false-block fix** (commit `fbedf30`,
  `crates/transport/src/signal.rs`): `SoftBlock` now requires a body-
  marker hit, not just a vendor-identifying header. Pre-fix every
  Cloudflare-fronted 200 OK was classified as "blocked" — Pages,
  Workers, `example.com` itself all showed `Cloudflare 5 SENT 5
  BLOCKED 0 BYPASSED 0.0%` while every request had returned 200.
  Locked with `cloudflare_200_not_blocked.rs` (3 tests).
- **TUI premium UX** (commit `fbedf30`): selected menu item now
  renders with `▶ ` glyph + REVERSED video (the original
  `fg(Black)/bg(Cyan)/Bold` styling produced no observable terminal
  escapes — pentesters had to read the right pane to figure out what
  was selected). Right pane became per-action (Scan / Gene Bank /
  Evade / Detect / Probe). New `?` modal help overlay. Footer
  keybind row expanded to 4 chips, every chip bold for legibility.
- **`wafrift-proxy --version`** (commit `6bdd2da`): clap derive's
  `version` attribute was missing; trivial fix.
- **README probe-count truth** (commit `6bdd2da`): "184+ probes" →
  "136 auth-bypass header probes plus path-routing variants and
  HTTP method overrides" in three places.
- **Manpage drift gate** (commit `e6d3b3b`): `manpage_in_sync.rs`
  regression test catches `docs/man/wafrift.1` drift before merge —
  the manpage shipped stale at three previous releases.

### Tests

- 283 / 283 wafrift-proxy tests green (was 280 before the proxy
  adversarial sweep).
- Workspace test suite remains green at the level previously verified
  for 0.2.12.

## [0.2.12] — 2026-05-10

### Changed — workspace polish + organization sweep

- **Pedantic clippy clean across the workspace.** 936 → ~440
  pedantic warnings; `clippy::doc_markdown` cleared from 287 → 0
  (every identifier in every public docstring is now backticked,
  so docs.rs renders cleanly). Mechanical rewrites included
  `format!("{}", x)` → `format!("{x}")`, `.map(...).unwrap_or(...)`
  → `.map_or(...)`, redundant closure → method-reference,
  `single_char_pattern`, `manual_let_else`, `unnested_or_patterns`,
  `if_not_else`, `implicit_clone`, `format_push_string` → `write!`.
  142 files touched (autofix-driven).
- **Documentation sync.**
  - `README.md` "What's new" section retitled from
    `Unreleased / v0.2.3-dev` to `v0.2.12` and rewritten to reflect
    the audit-driven hardening sweep that landed across v0.2.4 →
    v0.2.11. Earlier `v0.2.3` content kept under "Earlier changes".
  - `README.md` crates.io badge fixed (pointed at the non-existent
    `wafrift` crate; now correctly tracks `wafrift-cli`).
  - `README.md` install commands updated from
    `cargo install wafrift` / `cargo install wafrift-cli --version
    '>=0.2.2'` to the current version pin.
  - `docs/man/wafrift.1` version bumped 0.2.1 → 0.2.12 (the manpage
    title bar and `.SH VERSION` block both lied about the binary
    version).
  - `CHANGELOG.md` `[0.2.4]` through `[0.2.11]` retroactively filled
    in (each release shipped real fixes, but the changelog had not
    been updated since v0.2.3).
- **Three thin crate READMEs expanded for crates.io credibility.**
  `wafrift-types`, `wafrift-content-type`, `wafrift-pool` were
  one-paragraph stubs (3 lines each). Each now ships a structured
  README that lists what's in the crate, the public API shape,
  stability commitments, and a usage snippet. These are the pages
  that show on crates.io for each subcrate; thin READMEs were a
  credibility hit.
- **`run_interactive` (cli/main.rs):** hoisted `use ratatui::*` to
  function top so the early-return-on-no-TTY check no longer breaks
  the `items_after_statements` lint (15 warnings → 0).
- **`run_evade` / `run_detect` / `run_probe` (cli/main.rs):**
  `#[allow(clippy::needless_pass_by_value)]` — clap-derived `Args`
  structs are idiomatically taken by value, and these functions
  consume the argument exactly once.

### Fixed

- **`crates/proxy/src/main.rs:1894`** was the lone caller of the
  v0.2.9-deprecated `wafrift_transport::challenge::classify(body,
  headers)`. Switched to `classify_with_status(body, headers,
  status_code)` so the proxy's challenge-detection path is
  status-aware (was already gated on `status_code == 503 ||
  status_code == 403` so behaviour is unchanged; this clears the
  last `#[warn(deprecated)]` warning in the workspace build).
- **`crates/proxy/tests/captchaforge_install.rs`:**
  `captchaforge_install_must_fail_with_actionable_hint` hung
  forever under `cargo test --workspace --all-features` because
  the test premise (binary should reject `--captchaforge` without
  the feature) is invalidated when the feature is enabled — the
  proxy then accepts the flag and runs indefinitely while the test
  awaits `child.wait()`. Test now `#[cfg(not(feature =
  "captchaforge"))]`-gated. The companion
  `captchaforge_install_must_not_fail_without_flag` still runs in
  both build modes.

### Fixed — SSRF NUL-in-host engine gap (CVE-2017-15046 family)

- **`crates/oracle/src/ssrf.rs nul_in_authority_salvage`.**
  `url::Url::parse` rejects `http://127.0.0.1%00.evil.com/` (and
  the literal-NUL twin) as malformed authority, so `SsrfOracle`
  was classifying these as not-SSRF-shaped — meaning the evasion
  engine never emitted them as variants even though they are real
  attacks against permissive backends that terminate hostname
  parsing at NUL but report the full host to the allowlist.
  Added a salvage fallback: when the raw payload fails to parse,
  locate the first encoded or literal NUL after the `://`
  boundary, strip it and the suffix, re-parse the prefix, and
  accept iff the parsed host is itself an SSRF indicator
  (loopback, metadata host, or RFC1918 prefix). Stricter than the
  looser `has_ssrf_structure` so the existing `"0."` substring FP
  cannot be used to promote public hosts.

  Tests: 9 in `ssrf_loopback_bypass_corpus.rs`, including 2 NUL-
  bypass shapes (encoded + literal) plus a negative twin that
  asserts `http://example.com%00.evil.com/` is still rejected.

### Added — doctest coverage across 16 library crates

- **1 → 28 runnable doctests** on every public-API surface.
  Workspace went from a single oracle XSS example (pre-existing)
  to 28 across `wafrift-types`, `-encoding`, `-grammar`,
  `-content-type`, `-smuggling`, `-fingerprint`, `-detect`,
  `-evolution`, `-strategy`, `-pool`, `-oracle`, `-recon`,
  `-transport`, `-genome-registry`, `-core`. Each tests a real
  public-API shape against assertions, so docs.rs renders working
  examples AND `cargo test --doc` catches API drift.
  `wafrift-captchaforge-bridge` ships one `ignore`d doctest
  because chromiumoxide → boring-sys2 → libstdc++ doesn't always
  link on minimal dev boxes (CI runners and `apt install
  libstdc++-dev` resolve it).

### Changed — Tier-B TOML migration (16 const lists across 7 files)

- **Hardcoded `const X: &[&str]` lists moved to community-extensible
  TOML data.** Loaded once via `OnceLock` + `include_str!` so
  there's no runtime filesystem dependency and `cargo install`
  still produces a self-contained binary. Per CLAUDE.md "Tier B
  — community knowledge (TOML data files only, never CLI)".
  - `crates/detect/rules/blocking/indicators.toml` — 13 WAF
    block-page body indicators (`BLOCK_INDICATORS`).
  - `crates/oracle/rules/xss/structure.toml` — 70-entry XSS
    validation taxonomy (`XSS_TAGS`, `XSS_EVENTS`,
    `XSS_EXEC_SINKS`, `JS_URI_SCHEMES`, `DANGEROUS_SINKS`).
  - `crates/grammar/rules/xss/payloads.toml` — 42-entry XSS
    mutator corpus (`EXEC_FUNCTIONS`, `URI_SCHEMES`,
    `SVG_PAYLOADS`, `MATHML_PAYLOADS`, `MARKDOWN_PAYLOADS`).
  - `crates/oracle/rules/ssrf/schemes.toml` — 10 URL schemes the
    SSRF oracle accepts as network-request-shaped
    (`URL_SCHEMES`).
  - `crates/oracle/rules/ssti/markers.toml` — 20 SSTI
    introspection markers (`INTROSPECTION_MARKERS`).
  - `crates/oracle/rules/ldap/grammar.toml` — 16-entry LDAP
    grammar (`LDAP_OPERATORS`, `LDAP_ATTRIBUTES`).
  - `crates/oracle/rules/h2/goaway.toml` — 4 HTTP/2 GOAWAY reason
    phrases (`WAF_GOAWAY_REASONS`).

### Fixed — pentester acceptance: SIGPIPE handling

- **`wafrift --quiet evade ... | head` no longer panics with
  "failed printing to stdout: Broken pipe".** Both binaries
  (`wafrift` and `wafrift-proxy`) install
  `signal(SIGPIPE, SIG_DFL)` at the top of `main()` — the
  canonical Unix CLI idiom that `cat`, `ls`, `grep` all use.
  Process exits silently on EPIPE instead of panicking. libc dep
  gated to `[target.'cfg(unix)'.dependencies]` so Windows builds
  are unaffected. Locked with
  `crates/cli/tests/sigpipe_does_not_panic.rs`.

### Added — manpage drift gate + cargo audit + dead-code cleanup

- **`crates/cli/tests/manpage_in_sync.rs`** — new regression test
  runs `wafrift man` and byte-compares to `docs/man/wafrift.1`,
  with a one-line "regenerate with X" hint on failure. The
  manpage shipped stale at three prior releases (0.2.1, 0.2.11,
  initial 0.2.12) before this gate.
- **`.github/workflows/ci.yml`** — new `audit` job runs
  `cargo audit` on every CI to surface RustSec advisories.
  `continue-on-error: true` so transitive-dep findings (e.g.
  RUSTSEC-2026-0002 in `lru 0.13.0` via `rquest 5.1.0`) don't
  block PRs but stay visible.
- **`workspace.package.rust-version` 1.85 → 1.88.** CI was already
  on 1.88; the workspace metadata claimed 1.85 was supported when
  CI never actually proved it. Synced to truth.
- **5 `#[allow(dead_code)]` markers** on public API surface in
  `crates/detect/src/waf_detect/rules.rs` dropped (the methods
  are `pub use`-exported from the crate root; the allows were
  hiding the wrong thing from clippy).
- **`crates/oracle/src/test_url.rs`** orphan file deleted. URL
  corpus salvaged into a real integration test
  (`ssrf_loopback_bypass_corpus.rs`).

### Changed — README: Burp Suite / Caido / mitmproxy chaining recipe

- New "Burp Suite / Caido / mitmproxy chaining" section under
  Operator reference. Documents the canonical
  `Browser → Burp:8080 → wafrift-proxy:8181 → Target` layout,
  explains the 8080 port collision (Burp owns 8080 by default;
  pick a different port for wafrift-proxy), and shows the
  upstream-proxy configuration for all three intercepting
  proxies. Plus the `wafrift import-curl` no-chain workflow.

### Changed — workspace housekeeping

- **License files (`LICENSE-MIT`, `LICENSE-APACHE`) copied into
  every crate directory** so each crates.io tarball ships its
  own license texts. Compliance scanners that check per-crate
  license presence no longer flag wafrift-* crates as
  unlicensed.
- **Vendored TOML rules re-synced** with the in-workspace
  master copies (`rules/sql/operators.toml`, `rules/cmd/oracle.toml`,
  `rules/detect/cloudfront.toml`, `rules/detect/fortigate.toml`
  had drifted with 2026-05-10 audit notes only in the crate copies).
- **Smoke-alarm encoding tests** in `crates/core/tests/encoding_depth.rs`
  and `encoding_adversarial.rs` (12 sites) hardened to byte-
  precise %-encoded character assertions with span-count and
  pass-through checks.

2926 / 2926 workspace tests green at v0.2.12.

## [0.2.11] — 2026-05-10

### Fixed — swarm audit batch 8 (CRITICAL + HIGH)

- **`transport/challenge` — PSL supercookie guard.** Cookie
  `Domain=` attribute had no Public Suffix List check. Bare eTLDs
  (`Domain=co.uk`, `Domain=github.io`, `Domain=netlify.app`) were
  silently accepted — a captured cookie would then replay on every
  site under that suffix (RFC 6265 §5.2.3). Added
  `is_safe_cookie_domain` using the embedded `psl` crate (no
  hardcoded eTLD blocklist that goes stale). Real second-level
  domains still pass; bare eTLDs are rejected.
- **`grammar/xss` — `has_xss_signals` precision.** Pre-fix this
  fired on benign substrings (`confirm(` in API docs,
  `window.onerror` in security write-ups, `<select>` HTML), so the
  mutator emitted XSS variants from non-XSS input. Replaced with a
  2-point threshold: STRONG signals (`<tag attr=`, `javascript:`
  URL, `on*=`) score 2, WEAK (bare exec function names) score 1.
  Need ≥ 2 to count.
- **`transport/stealth` — DNS-rebinding via hostname.** `StealthClient`
  resolved hostnames inside `rquest`, so a TOCTOU attacker could
  flip the A record between bogon-check and connect. Now
  pre-resolves with `tokio::net::lookup_host`, filters via
  `is_bogon_ip`, then builds a per-request `rquest` client with
  `.resolve_to_addrs()` pinning the connection to the
  already-vetted `SocketAddr`s.

### Fixed — swarm audit batch 9 (test rigour)

- **`content-type` — replaced 30 hollow tests** (`auto_0..auto_29`,
  each only `assert!(!variants.is_empty())`) with a single rigorous
  structural test that drives the same payload set through
  `generate_variants_from_body` AND validates body shape per
  Content-Type variant: multipart bodies have boundary= + correct
  framing + end marker; `application/json` bodies parse as strict
  JSON (with comment stripping for `JsonWithComments`);
  `application/xml` bodies declare `<?xml` preamble and carry both
  fields.
- **`smuggling` — 3 hollow tests hardened.**
  `cache_buster_non_empty` → `cache_buster_unique_and_numeric` now
  asserts uniqueness across 100 calls + base-10 parseability.
  `concurrency_stress_*` now asserts each payload contains the Host
  header and ends with the request terminator.
  `multibyte_utf8_split_path_no_panic` →
  `multibyte_utf8_path_round_trips_in_payload` now asserts the
  literal Japanese characters survive into the wire bytes.

### Changed

- README "What's new" section retitled from `Unreleased / v0.2.3-dev`
  to `v0.2.11`.
- 23 pedantic clippy warnings cleared in `wafrift-cli` (mostly
  `items_after_statements` from `use ratatui::*` after the
  no-TTY early-return; hoisted `use` to function top).
- 2892 / 2892 workspace tests green.

## [0.2.10] — 2026-05-10

### Fixed

- **`evolution/engine` — `prune_stale_in_flight` repays budget on
  dropped evals.** Stale in-flight evaluations leaked from the
  budget counter when pruned. Now repays the budget correctly so
  long-running searches don't drift.
- **`transport/challenge` — `refresh_solver_pending` +
  warn-on-eviction.** Solver entries get an explicit refresh path
  (RAII guard pattern), and evictions log a `warn!` rather than
  silently dropping work.
- **`strategy/host_state` — `total_attempted` lifted u32 → u64.**
  Long-running scans against very-high-traffic hosts could overflow
  `u32` (~4.3 B). u64 buys 4 G× headroom.
- **`transport/challenge` — per-host fairness in global prompt cap.**
  One noisy host could starve every other host's challenge prompts
  by exhausting the global cap. Now reserves slots per-host.
- **`transport/challenge` — `classify()` deprecated in favour of
  `classify_with_status`.** Status-aware classification kills 200-OK
  false positives where a body matched a challenge signature but
  the response was actually a real success page.

## [0.2.9] — 2026-05-10

### Added — swarm audit batches 6 + 7

- **`EvasionConfig.allow_private_upstream`** (default `false`)
  blocks RFC1918 / loopback / link-local SSRF unless explicitly
  opted in. Tests that need wiremock (binds 127.0.0.1) flip the
  flag.
- **MCTS** improvements (mctrust 0.4) — higher-precision UCB1
  scoring + body-budget enforcement.
- **`grammar/xss` exec sequence** — better signal weighting.
- **`transport/challenge` HttpOnly + Forwarded RFC7239 honesty,
  DoublePercent encoding correctness.**

## [0.2.8] — 2026-05-10

### Fixed — swarm audit batches 4 + 5

- **`transport/challenge`** — request-splitting CRLF / NUL / `;` in
  cookie values rejected.
- **`proxy` SSRF** — bogon filter applied before connect.
- **MITM cert builder** — leaf-params extracted to a single helper
  to remove duplication across public methods.
- **`HostState` caps + AST walk + crypto perms** hardened.

## [0.2.7] — 2026-05-10

### Fixed — swarm audit batch 3

- **`encoding`** CRITICALs (URL fragment destruction, double path
  encoding, DoS guard).
- **`grammar`** dead-vector pruning.
- **`classify`** false-positive sweep.
- **`grammar` `mutate_as`** — `max_mutations` contract enforced in
  SQL + XSS branches.

## [0.2.6] — 2026-05-10

### Fixed

- **`proxy/intercept`** — GC dead senders on register; expose
  `gc_dead_senders` for tests.

## [0.2.5] — 2026-05-10

### Fixed — swarm audit batch 2 + audit-fix re-publish

- **`smuggling/safety`** + **`content-type/unicode`** hardening.
- **`proxy/rate_limit`** — buckets HashMap capped at
  `MAX_TRACKED_HOSTS = 4096` (DoS).
- **`genome-registry/signing`** — `secret_hex` validated on
  `Deserialize`.
- **`content-type`** — `unique_boundary` wired into all multipart
  variants.
- **`strategy/learning_cache`** — atomic save + corrupt-file
  recovery.
- **`grammar/classifier`** — whole-word shell-cmd match; drop CMDi
  fallthrough on no-separator path.

## [0.2.4] — 2026-05-10

### Fixed — oracle CRITICALs

- **`oracle/cmdi`** — OOM on adversarial input fixed.
- **`oracle/ssrf`** — `"0"` indicator FP fixed.

## [0.2.3] — 2026-05-10

### Added — community genome registry + ed25519 signing (#111)

- New `wafrift-genome-registry` crate (zero network dependencies):
  bundle wire format, ed25519 sign + verify, trust-list at
  `~/.wafrift/trusted-keys.toml`. Deterministic canonical encoding
  (genomes sorted by name) so two senders building the same pack
  produce byte-equal signatures. 22 unit tests covering signing,
  bundle round-trip, and trust-list lifecycle.

### Added — TUI evade-mutation diff (#109) and replay (#110)

- The detail pane now shows a third side: the diff between the
  request as the client sent it and the request that wafrift's evade
  pipeline put on the wire. Added headers tagged `+ name:` (green),
  removed `- name:` (red), changed `~ name:` (yellow) with arrow
  separator. Body delta line classifies as `mutated` or
  `byte-identical` with a directional arrow.
- New `R` keybinding writes a `/tmp/wafrift-replay-N.curl`
  reproducer; when `WAFRIFT_REPLAY_AUTOEXEC=1` is set, also re-fires
  via bash and reports the upstream exit code in the toast.

### Added — managed-challenge solver (#115)

- New `wafrift-transport::challenge` module: per-host clearance
  cookie capture/replay (cf_clearance / _abck / aws-waf-token),
  classifier for CloudflareManaged / Turnstile / Hcaptcha /
  Recaptcha / AwsWaf / AkamaiBmp / Unknown, and a dispatcher
  returning ReplayWithCookie / Wait / EscalateToOperator. Operator
  prompts are throttled per-host (5min cooldown).
- Wired into proxy: every response is scanned for clearance cookies
  and recorded; subsequent requests to the same host get the cookie
  folded into their `Cookie` header (appended, never replacing).

### Added — URL/query-param body-evasion (#114)

- `wafrift-proxy --mutate-url` (off by default). When set, every
  query parameter VALUE is aggressively percent-encoded; names,
  scheme, host, port, and path are left intact. Operators must opt
  in because mutating URLs changes upstream routing semantics.
- New `wafrift-encoding::url_mutate` module with four strategies
  (PercentEncodeAggressive / DoublePercentEncode / NonCanonicalSpaces
  / Hpp). 17 unit tests; 8 plumbing tests.

### Added — wafw00f attribution + regression test (#117)

- The 160-WAF detection catalog under `crates/detect/rules/detect/`
  is now properly attributed to [wafw00f](https://github.com/EnableSecurity/wafw00f)
  (BSD-3-Clause) plus selective contributions from
  [identYwaf](https://github.com/stamparm/identYwaf) (MIT). Top-level
  README + `wafrift-detect/README` + module-level rustdoc. Regression
  test refuses to ship a rule file without a `source =` field.

### Fixed — evolution engine internals (#112, #113)

- `EvolutionEngine::diversity_score()` previously returned a
  hardcoded 0.5; the engine could not adapt mutation pressure.
  Replaced with a real metric: pairwise gene-mismatch over
  `algorithm.population_snapshot()` ∪ in-flight chromosomes; falls
  back to gene-pool exploration entropy when the live population
  has fewer than two members. SearchAlgorithm trait gains
  `population_snapshot()` (default impl returns `best().into_iter()`)
  with overrides on NoveltySearch and MapElites. 17 integration
  tests.
- `EvolutionEngine::clone()` previously round-tripped the algorithm
  state through serde_json (`checkpoint` → `restore`), spiking
  allocations on populated MapElites grids and novelty archives.
  SearchAlgorithm trait gains `clone_box()` overridden by every
  in-tree algorithm with `Box::new(self.clone())`. New
  `pub type SharedEngine = Arc<tokio::sync::RwLock<EvolutionEngine>>`
  for the canonical shared-state pattern. Perf gates: populated
  MapElites engine clones in <50ms, NoveltySearch <100ms. 12
  integration tests covering correctness, perf, SharedEngine
  semantics, and backward compat.

### Added — Tsai-class differential probing (May 9-10, 2026)

- **`wafrift bypass-probe URL`** — new top-level subcommand. Ports the
  gossan `bypass403::probe` algorithm and wires it to wafrift's much
  larger probe surface. For every URL, fires:
    - 136 auth-bypass header probes (`X-Original-URL`, `X-Rewrite-URL`,
      `X-Forwarded-For` with 7 trusted IPs, method-override family,
      scheme-trust family, host-trust family)
    - All `path_traversal::mutate` variants — ~48 per target —
      including ProxyShell `?@`, semicolon path-param, double-encoded
      slash, IIS null-truncation, fullwidth-dot Unicode
    - HTTP method overrides on the wire (GET → POST/PUT/DELETE/PATCH/
      HEAD/OPTIONS/PROPFIND)
  Each probe is classified vs the baseline GET; status-flips from
  401/403 → 200/302 surface as HIGH-severity findings with reproduce-
  it `curl` one-liners. `--paths-file` walks a list (one path per
  line). `--concurrency N` (default 8) bounds in-flight probes via a
  `Semaphore`. `--min-severity low|medium|high` filters output.
  `--format json` produces a pipeable `{"results": [...]}` envelope.

- **`wafrift_grammar::ssrf::parser_confusion_authority`** — Orange Tsai
  2017 family. Generates 14 parser-disagreement variants per
  `(cover, target)` pair using the user's input host as cover and
  rotating 6 SSRF targets through the userinfo position. Covers
  basic userinfo, the GitLab CVE-2018-19571 fragment-userinfo
  pattern (`cover#@target`), Tsai canonical (`cover &@target`),
  port-then-userinfo, backslash family, `%40` / `%2540` encoded `@`,
  query-userinfo, path-relative jump, newline / null in authority.
  Live: every variant fires bypasses 40-80% on bench-waf naxsi.

- **`wafrift_encoding::auth_bypass`** — new module. `auth_bypass_probes
  (target_path)` returns 136 `(header, value)` probes covering five
  families: URL-rewrite (X-Original-URL etc., 6 headers), IP-trust
  spoofing (12 headers × 7 trusted IPs), host-trust override,
  method-override (GET-past-WAF → PUT/DELETE), scheme-trust. Pure
  library; `bypass-probe` is the consumer.

- **`wafrift_grammar::path_traversal`: routing-disagreement family**
  — 16 new variants targeting frontend/backend canonicalisation
  disagreement: Tomcat semicolon-strip (`/public/..;/etc/passwd`),
  double-encoded slash, overlong UTF-8 slash, ProxyShell `?@`,
  IIS null-truncation, trailing-dot/space, fullwidth-dot Unicode.

- **Bench corpus expansion: 579 → 607 cases.**
    - `wafrift-bench/corpus/ssrf/parser_confusion_authority.toml`
      (12 canonical Tsai cases)
    - `wafrift-bench/corpus/path/routing_disagreement.toml`
      (16 routing-disagreement cases)

### Added — TUI rewrite as MITM live viewer

- **Three tabs**: Flow (default), Overview, Hosts. Switch via `Tab`,
  `1`/`2`/`3`, or `f`/`o`/`h`.
- **Flow tab** — bounded ring of 500 requests with per-row coloring
  by outcome (BYPASS bright-green, BLOCK bright-red, PASS white).
  `j`/`k` (or `↑`/`↓`) navigate; `g`/`G` jump to first/last; `Enter`
  toggles a side detail pane that shows the full inspection: outgoing
  request line + every post-evasion header + body excerpt; incoming
  status (color-graded by 2xx/3xx/4xx/5xx) + every response header +
  body excerpt; summary block with WAF, attempts, latency, body
  padding, TLS profile, technique chain, total response size.
- **Two sparklines** under the request list — req/s and bypasses/s
  over the last 60 seconds, with live max-value annotation.
- **Overview tab** — counters, TLS rotation gauge, WAFs identified
  with per-product host counts.
- **Hosts tab** — per-host bypass table sortable by sent count, with
  bypass-rate color grading (≥75% green, ≥25% yellow, else gray) and
  identified WAF column.
- **Footer key-help bar** — context-sensitive bindings per tab.
- **Memory cap**: 500 records × ~2 KB = ~1 MB worst-case. Body
  excerpts capped at 1 KB per direction (`MAX_BODY_EXCERPT`).
- **No emojis.** Pure Unicode box-drawing.
- **11 new unit tests** covering the new state model, navigation
  clamp, severity → colour mapping, tab cycle, WAFs-seen counter,
  reset preserving uptime + tab.

### Fixed — proxy lifecycle, hot path, MITM panic

- **Critical: global `state.lock()` held across `evade()` /
  `evade_smart()`.** A single 100 KB POST burned 8+ seconds under
  the lock and serialised every other concurrent request behind it;
  the proxy then OOM-killed under load. Snapshotted host state into
  an `EvadePlan`, drop the lock, then run evasion outside.
  Concurrent burst 50/50 → all HTTP 200 after the fix.

- **MCTS body-size blowup.** `evade_mcts` ran 500 iterations and
  cloned the full request body each iteration. On a 1 MB body that
  was a gigabyte of allocations. Added `MCTS_BODY_BUDGET = 16 KiB`
  and `GRAMMAR_MUTATION_BODY_BUDGET = 64 KiB`. Bodies above the
  threshold skip the expensive mutation and only get header / URL
  evasion.

- **`--mitm` HTTPS aborted the worker thread.** rustls 0.23 panics
  with "no default CryptoProvider installed" on the first TLS
  handshake. Installing `aws_lc_rs::default_provider().install_default()`
  at process start fixes the MITM path end-to-end (verified against
  example.com).

- **`--insecure` now warns at startup.** `--insecure-open-upstream`
  already emitted a startup WARN; `--insecure` (TLS-cert-disable)
  was silent. Both flags are dangerous; both should warn.

- **Concurrent gene-bank race fix.** Atomic-write tmp filename now
  PID + nanosecond suffixed so multiple proxies pointed at the same
  gene-bank don't race on the same `<path>.tmp` (one rename
  succeeded; the other got ENOENT). Verified: 4 proxies, 100
  concurrent reqs, periodic flush → zero "flush failed" warnings.

- **Three more UTF-8 split panics in mutators.** `cmd.rs`
  `obfuscate_path` (`&file[..2]` on a `★shadow` filename),
  `cmd.rs` indirection-description truncate, and
  `binary_search.rs` `&trigger[..50]`. All fixed via
  `char_indices()`.

- **`origin_hints.rs` `ips[0]` panic** when DNS returned zero IPs.
  Now returns a clean error.

- **Eleven misplaced test blocks** across the workspace (cassandra,
  cmd_windows, elastic, mongo, redis, encoding/layered, strategy/
  pipeline + planner + waf_presets, oracle/signal_status_code,
  cli/origin_hints) — `#[test]` fns appended after the closing `}`
  of `mod tests`. They compiled but lived outside `#[cfg(test)]`
  and polluted the production binary. Wrapped back inside.

- **TUI channel was unbounded.** Switched to bounded `mpsc::channel
  (10_000)` with `try_send` and a `TUI_DROPPED` atomic counter so
  the request hot path never blocks on a stalled terminal.

### Diagnostics

- **`cargo clippy --workspace --all-targets -- -D warnings`** is
  CLEAN (was 5 warnings).
- **Hot-path unwrap audit**: 20 production hits, all on test code or
  hardcoded constants where unwrap is provably safe.
- **Credential leak**: `Authorization` and `Cookie` headers sent
  through the proxy do NOT appear in any log line (verified live).
- **`cargo audit`**: 1 transitive advisory — `lru 0.13.0` via
  `rquest 5.x` (RUSTSEC-2026-0002, unsound `IterMut`). Not a
  security vuln; wafrift doesn't use the lint-tripped pattern.

### Added — naxsi-class WAF closures (D5+E2)

- **`wafrift_grammar::sql::quote_free`** — quote / comment / paren-free
  SQL injection rewrites (`1' OR '1'='1` → `1 OR 1=1`,
  `1 OR 1 IS NOT NULL`, etc). URL-decodes the input first so encoded
  forms (`1%27%20OR%20%271%27%3D%271`) trigger the rewrite. Promoted
  to priority 1 in `sql::mutate` so the first 5 variants always
  include 5 quote-free candidates. naxsi sql: **0.6% → 99.4%** case
  bypass, **0.2% → 30.0%** oracle-valid.

- **`wafrift_grammar::ssrf` scheme-mangling** — emits scheme-mangled
  variants (`http:/X` single-slash, `//X` protocol-relative, bare
  `X`, `http:////X` quad-slash, plus protocol-relative + integer/
  octal IPs) that bypass naxsi's `http://<IP>` rule while still
  resolving via Python urllib3 / Java URL / Go net/url / libcurl
  normalisation. naxsi ssrf: **2.1% → 78.7%** case bypass.

- **`wafrift_grammar::path_traversal` absolute-target promotion** —
  16 high-value LFI targets that don't contain `..` or `passwd`
  (`/proc/self/environ`, `/.ssh/id_rsa`, `/.git/config`,
  `/var/log/auth.log`, etc) emitted FIRST in the variant list
  (refactored from BTreeSet to insertion-ordered Vec + HashSet
  dedup so `take(--variants 5)` actually reaches them). naxsi path:
  **5.6% → 70.4%** case bypass.

### Added — defensive hardening

- **`MAX_USEFUL_PAD = 8 MiB` ceiling on `body_padding::pad`** —
  silently clamps `requested_bytes >= 8 MiB` so a caller passing
  `usize::MAX` (deliberate or arithmetic underflow) doesn't OOM the
  process. 8 MiB is well above any documented cloud-WAF inspection
  window (Cloudflare Enterprise: 128 KiB).

- **5 new adversarial tests** across `body_padding` + `quote_free`:
  pathological-size clamping, malformed Content-Type strings, empty
  inputs with huge pads, URL-encoded shape detection, NUL-byte in
  payload. None panic; output may be empty. 19 + 12 tests pass.

### Fixed

- **rquest 5.x migration.** All rquest 4.x versions were yanked from
  crates.io between v0.2.2 release prep and CI run, breaking every
  build. Migrated `crates/transport/src/stealth.rs` to
  `rquest::ClientBuilder::emulation()` + `rquest_util::Emulation`
  (the new home for browser profiles after 5.0 split them out).
  Public `ImpersonateProfile` enum names are stable for CLI compat.

- **CI YAML parser fix.** Workflow file had an unquoted `stealth::`
  in a `- run:` value; YAML parser saw it as a nested mapping and
  rejected the file (CI ran zero jobs since c1699b4). Quoted the
  value.

- **MSRV 1.85 lock fix.** `gene_bank/mod.rs` used
  `std::fs::File::lock` which is gated behind unstable `file_lock`
  (Rust 1.89+). Switched to `fs4::FileExt::lock` (workspace dep
  already present, stable since fs4 1.0).

- **Per-class baseline `wafrift-bench/results/v022-by-class/`** —
  20 JSON files (10 classes × 2 WAFs) + SUMMARY.md documenting where
  naxsi has structural gaps that need new mutators (xss/ldap/xxe
  block on class-defining tokens; honest documentation rather than
  silent failure).

## [0.2.2] — 2026-05-09

### Added — three EvilWAF / nowafplsV2 gaps closed (body padding, TLS rotation, TUI)

- **`wafrift_evolution::body_padding`** — content-type-aware request
  body padder (`Technique::BodyPadding(usize)`). Cloud WAFs only
  inspect the leading N bytes (Cloudflare Pro 8 KB, AWS WAF 16 KB,
  Akamai 8 KB). Padding past that window makes the rule engine miss
  the malicious payload while the origin parses the body correctly.
  JSON / form-urlencoded / multipart all supported with structurally-
  valid splicing; opaque content-types skipped honestly. 14 unit
  tests cover roundtrips, edge cases, and case-sensitive boundary
  parameter handling. Wired into `wafrift-proxy
  --body-padding-bytes <N>`.

- **`wafrift-proxy --tls-impersonate-rotate p1,p2,p3`** — round-robin
  pool of `StealthClient`s. `UpstreamClient::StealthPool { clients,
  cursor }` advances an `AtomicUsize` cursor on every send so each
  upstream request lands on a different browser ClientHello
  fingerprint. Defeats per-fingerprint rate limits and reputation
  systems (Cloudflare bot-management, Akamai BMP, PerimeterX). 3
  unit tests prove cursor distribution + feature-disabled path +
  empty-slice rejection. Mutually exclusive with `--tls-impersonate`
  (clap-enforced).

- **`wafrift-proxy --no-conn-reuse`** — flips
  `pool_max_idle_per_host(0)` so every upstream forward opens a fresh
  TCP connection. Kernel picks a new ephemeral source port each time;
  defeats per-source-port rate limits and 5-tuple reputation. Trade-
  off (one TCP+TLS handshake per request) is explicit, never default.

- **`wafrift-proxy --tui`** — real-time terminal dashboard
  (ratatui + crossterm). Header (bind/mode/stealth/padding/conn-
  reuse), per-pane counters (Total / Bypassed % / Blocked / Errors /
  Padded bodies / Avg latency), TLS rotation distribution with
  per-profile bars, top-5 hosts table (sent/blocked/bypassed/top
  technique), 200-line scrollback of recent requests with
  BYPASS / BLOCK colour coding and `+pad` / TLS-profile tags.
  `q` / Esc / Ctrl-C trigger graceful shutdown (gene bank flushes
  on the same code path SIGINT uses); `r` resets counters; `c`
  clears the recent stream. Tracing logs route to a file when --tui
  is on so the dashboard owns the terminal alternate-screen.
  Verified live: 180-request stress through proxy → modsec-pl1 +
  modsec-pl3 + naxsi shows 119 bypassed (66.1%), 60 padded bodies,
  every POST tagged `+pad` in the recent stream.

### Added — body-padding wired into the evolution chain (D1+D2)

- `wafrift_evolution::body_padding::fill` switched from
  `b'A'.repeat(n)` to a deterministic xorshift64* over `[a-z0-9]`.
  Defeats Naxsi's BIG_REQUEST + RX heuristics that flag long
  single-character runs. Live verification across 7 stacks: 16 KB
  pure padding now passes through modsec-pl1, modsec-pl2, coraza,
  and bunkerweb cleanly (where run-of-A previously triggered them).

- `EvasionConfig.body_padding_bytes: usize` field; `maximum()` builder
  defaults to 16 * 1024 (AWS-WAF-default tier). `strategy::evade()`
  now applies body padding as Step 3, AFTER every other body-mutating
  layer, recording `Technique::BodyPadding(actual_added)` so the
  gene-bank credits padding-as-winner like any other technique.
  `EvasionLayer::BodyPadding` variant added with prerequisites
  `[Encoding, ContentType, Grammar]`.

- bench-waf v0.2.2 baseline pinned for all 7 local stacks
  (modsec PL1-4 + coraza + bunkerweb + naxsi) at
  `wafrift-bench/results/v022-*.json`. Highlights with the mcts
  strategy + body-padding-via-maximum:

  ```
  modsec-pl1   raw 94.2%   bypassed 100.0%   oracle-valid 86.1%
  modsec-pl2   raw 99.4%   bypassed 100.0%   oracle-valid 85.2%
  modsec-pl3   raw 99.4%   bypassed 100.0%   oracle-valid 82.7%
  modsec-pl4   raw 100.0%  bypassed 100.0%   oracle-valid 83.8%
  coraza       raw 94.8%   bypassed  35.8%   oracle-valid 16.2%
  bunkerweb    raw 94.2%   bypassed 100.0%   oracle-valid 86.7%
  naxsi        raw 99.4%   bypassed   0.6%   oracle-valid  0.2%
  ```

### Honest limitations on local stress test

- Self-hosted modsec PL1-PL4 + Naxsi all inspect the FULL request
  body up to Apache `LimitRequestBody`. Body-padding evades cloud
  WAFs (paid SaaS with hard inspection caps) but not local instances
  configured to inspect everything. Manual verification: modsec-pl1
  returns 200 on `_wafrift_pad=A*16384&id=42` and httpbin echoes the
  full padded body back unchanged → padding is structurally valid
  and the proxy attaches it correctly; the local WAFs simply read
  past 16 KB.
- TCP raw-options rotation (EvilWAF's third TCP-layer evasion) is NOT
  implemented — would require `CAP_NET_RAW` and the proxy currently
  uses pure userspace networking. Filed as honest gap, not silently
  shipped.

### Added — EvilWAF JA3/JA4 parity (closed previously-documented gap)

- **`wafrift_transport::stealth::StealthClient`** wraps `rquest`
  (forked BoringSSL) behind the `tls-impersonate` cargo feature.
  Wire-identical Chrome / Firefox / Safari / Edge ClientHello bytes
  on every upstream forward — closes the JA3/JA4 + h2 SETTINGS gap
  vs Cloudflare / Akamai / Sigsci / Imperva-Bot. 7 profiles plus
  `chrome` / `firefox` / `safari` / `edge` "latest of family"
  aliases. Default builds are unaffected (no boring-sys); opt-in
  via `cargo install wafrift-proxy --features tls-impersonate`.

- **`wafrift-proxy --tls-impersonate <profile>`** — practitioner-
  facing CLI flag. Process-wide `OnceLock<StealthClient>` set at
  startup; `forward_wafrift_request` and `forward_passthrough` each
  branch on it, so the existing reqwest path runs unchanged when the
  flag is absent. Without the cargo feature, the flag is parsed but
  exits cleanly at startup with an actionable rebuild-instructions
  error (no silent half-works).

- **`crates/proxy/src/upstream.rs` — `UpstreamClient` enum**: typed
  wrapper exposed for library consumers building their own
  forwarders. `from_reqwest()` / `stealth(profile)` constructors,
  unified `send()` API, `tls_stack_name()` for log lines and
  `/_wafrift/status` output.

- **CI**: dedicated `tls-impersonate` job (`continue-on-error: true`
  — boring-sys C build is brittle across runner images, so the
  default lane stays green even if this one churns). Installs
  `ninja-build` + uses ubuntu-latest's bundled cmake/clang/golang.
  Default `ci` job no longer passes `--all-features` (would have
  required boring-sys deps for non-stealth users).

- **`docs/TLS_PARITY.md`** rewritten side-by-side comparing the two
  transports; **`docs/GAP_CLOSURE_ROADMAP.md`** definition-of-done
  updated to reflect that EvilWAF parity is implemented, not
  aspirational.

### Added — intelligence loops + audit-grade explanations

- **Rich response classification (H1).** New `wafrift_transport::signal`
  module replaces the binary `is_waf_block` with a structured
  `BlockClass` (`HardBlock | SoftBlock | RateLimit | Challenge | Pass`)
  + matched-WAF + prioritize/avoid lists + inspection model. The proxy
  now reads per-WAF profile recommendations from
  `rules/responses/*.toml` (or compiled-in fallback) and biases
  technique selection accordingly via `HostState::record_signal`.
  Crucially: rate-limits and JS challenges no longer penalize the
  active technique — they trigger backoff instead.

- **`wafrift discover` subcommand.** Endpoint discovery from one of
  three sources, output as JSON pipeable into `wafrift scan
  --from-discovery`:
    - `--spec api.json` — OpenAPI 2.0 (Swagger) + 3.x JSON parser
      with media-type-aware injection-context inference
      (`application/json` → `JsonString`, `application/xml` → `XmlText`,
      etc.) and path-templating extraction (`/users/{id}` → `Path`).
    - `--target ... --introspect` — POST a GraphQL `__schema` query,
      emit one endpoint per top-level field on Query / Mutation /
      Subscription with args as `Body` injection points.
    - `--target ... --mine-params --wordlist params.txt` — differential
      parameter mining: collect baseline (status / body length /
      latency envelope), probe each candidate, flag hits whose response
      diverges beyond configured thresholds.

- **Per-finding rule attribution + audit explanations (Phase 2C).**
  - `wafrift_detect::explain::explain_block(payload, waf)` returns the
    list of `RuleAttribution`s a payload would have triggered. 16
    OWASP-CRS-shaped rule families (SQLI/XSS/CMDI/LFI/RFI/SSTI/SSRF/
    PROTO), per-WAF confidence bias from the matched profile's
    inspection model.
  - `wafrift_strategy::explain::explain_bypass(original, bypass,
    techniques, waf, mode)` runs both payloads through `explain_block`,
    set-diffs the rule lists to identify which techniques actually
    removed the match, then narrates. Three modes: `Minimal` (one
    line), `Standard` (rule IDs + technique chain), `Educational`
    (per-technique 'why this works' paragraph for training material).
  - Real Myers-LCS character-level diff for payloads ≤ 1024 chars.

- **OOB confirmation oracle (Phase 2A).**
  `OobOracle::{confirm, confirm_background}` register a canary against
  the configured provider trait, poll until interaction or timeout,
  return `Confirmed | Timeout | Error`. `embed::embed_canary` injects
  per payload-type (SQL `LOAD_FILE`, CMDi `nslookup`, SSRF/XSS via URL).

- **JWT manipulation primitives (Phase 1B).**
  `wafrift_transport::jwt::manipulate(token, &JwtManipulation, key)`
  supports `StripAlg` (alg:none confusion), `Hs256WithKey` (RS256→HS256
  symmetric-key downgrade), `JwkEmbed` (header JWK injection).

- **Cookie-jar persistence + CSRF helpers (Phase 1B).**
  `session::{load_jar, save_jar, extract_csrf, inject_csrf}` —
  newline-delimited "Set-Cookie | https://origin/" disk format,
  regex-based CSRF extraction, header/query/body injection per
  `CsrfInjectionLocation`.

- **Modern body formats (Phase 2B).** `content_type::formats::{protobuf,
  messagepack, grpc_web}` — minimal but correct serializers for moving
  payloads out of WAF-inspected positions. Protobuf uses real varint
  length-prefix (previously truncated payloads >255 bytes silently).

- **Context-aware encoding (Phase 1A).**
  `wafrift_encoding::contextual::encode_in_context(payload, strategy,
  context)` applies strategy then escapes structurally per
  `InjectionContext` (JSON `\"` and control-char escapes, XML `&amp;
  &lt; &gt; &quot;`, URL percent, header CR/LF guard, multipart
  filename guard, etc.). Per-context max-size guards.

- **Response-profiles compiled into the binary.**
  `ResponseProfileDb::compiled_in()` `include_str!`s
  `crates/transport/rules/responses/profiles.toml` so `cargo install
  wafrift-proxy` users get all 7 reference WAF profiles
  (Cloudflare / ModSec / AWS / Imperva / F5 / Akamai / Sucuri) at
  startup — no manual file management.

### Robustness

- **`recon::discover_subdomains_ct` 30 s timeout.** crt.sh routinely
  takes 10-20 s and occasionally hangs entirely; the previous
  `reqwest::Client::new()` had no timeout, making `wafrift discover`
  a self-DoS for any blocked-up upstream.

- **`detect::response_fingerprint::extract_title` regex hoisted to
  `once_cell::Lazy`.** Was being compiled per response (~50 µs per call
  in a hot path).

- **15 `saturating_add(1)` sites.** Proxy/strategy/learning-cache u32
  counters previously wrapped silently after ~5 days at 10 k req/s
  — now plateau at `u32::MAX` for honest dashboards.

- **`detect::suggest_evasion` no longer `Box::leak`s every call.** Was
  leaking ~360 MB/hour at 1 k req/s. Switched to `Vec<String>`
  (zero external callers; API change invisible).

- **Tier B unblocked: 5 hardcoded marker tables → community TOML.**
  Oracle block / challenge / rate-limit / success markers, rule-id
  prefixes / categories / vendors, polyglot payloads, differential
  probes — all now live in `rules/*.toml` with per-crate `build.rs`
  generating Rust constants. Adding a new WAF block-marker is a
  one-line PR with no Rust knowledge.

### Fixed (in source — release pending)

- **`wafrift-grammar` / `wafrift-oracle` / `wafrift-strategy` rule files
  vendored into each crate.** Previously, `include_str!` reached up to
  `<workspace>/rules/...`, which `cargo publish` strips. The grammar
  crate could not be packaged at all; oracle and strategy depended on
  grammar so they cascaded. Files now live in `crates/<x>/rules/...`
  and the include paths point in-crate.

- **`wafrift-detect` build.rs prefers vendored rule copy.**
  v0.2.0 of `wafrift-detect` on crates.io was packaged with the legacy
  `../../rules/detect` path that resolved outside the published crate
  directory; the build script's fallback wrote a one-line empty
  rule-set so the build succeeded but the published artifact ships an
  empty WAF detection database. Source is now fixed (build.rs prefers
  the in-crate `crates/detect/rules/detect/` copy), but the registry
  artifact at `wafrift-detect@0.2.0` is still empty and needs a
  coordinated 0.2.1 bump across detect + every consumer that pins
  `detect = 0.2.0`. Open and unfinished — see internal task #52.

### Added

- **Release-readiness pass for cybersec practitioners (latest round).**
  - **`wafrift seed`** — pre-load gene-bank with known-working techniques
    (`--waf <name>` writes the per-WAF GeneBank, `--host <hostname>`
    writes the proxy gene-bank). Day-one practitioner workflow:
    skip discovery if you already know what beats the target.
  - **`wafrift import-curl`** — feed a curl invocation (e.g. from Burp's
    "Copy as cURL") + a payload/param into the scan engine. Tokeniser
    handles single/double quotes, multi-line `\\\n` continuations, and
    the no-op flags Chromium/Burp emit (`-i`, `--compressed`, etc.).
    Reads from `--curl-file` or `--from-stdin`.
  - **`wafrift bank list / export / import`** — manage gene-banks as
    first-class objects. `export` packs the proxy gene-bank + every
    per-WAF GeneBank into a self-describing JSON envelope (with
    `schema_version` + `wafrift_version`); `import` merges by
    default (union of techniques, dedupe) or `--replace` overwrites.
    Lets teams share findings: scp the envelope, `wafrift bank import`.
  - **`wafrift man`** — emits a troff(1) man page via clap_mangen.
    `wafrift man --output /usr/local/share/man/man1/wafrift.1` and
    `man wafrift` works. `--sub <subcommand>` for per-command pages.
  - **CTF / pentest quickstart** added to README — five concrete recipes
    (SQLi login bypass, SSTI, SSRF-to-internal, LFI/path-traversal,
    XXE) with single-command shapes.
  - **Lawful-use clause** added to `SECURITY.md`, new `CODE_OF_CONDUCT.md`,
    and `README.md` bottom. Codifies authorisation requirement,
    operator-bears-liability transfer, and the project's policy of
    refusing support for unauthorised testing.
  - **`Dockerfile` + `.dockerignore`** for one-step `docker run
    santhsecurity/wafrift`. Multi-stage build, non-root runtime user,
    tini PID 1, OCI image-spec labels.
  - **`.github/workflows/release.yml`** — on tag push, builds Linux
    x86_64 + aarch64, macOS x86_64 + arm64, Windows x86_64 binaries;
    SHA-256 checksum per artefact; attaches to GitHub Release.
    Practitioners on Kali / CTF VMs without a Rust toolchain can
    download a binary directly.
  - **scan text output** now prints the full evaded payload (was
    truncated to 120 chars) plus a copy-paste curl reproduce line, so
    the practitioner doesn't have to re-run anything to get the wire
    bytes for Burp/sqlmap.

- **Practitioner-shaped proxy + CLI surface (this round).**
  - `wafrift-proxy --only-host / --skip-host / --only-path / --skip-path
    / --only-method` — request-level scope filter with a tiny ASCII glob
    grammar (`*`, `?`). Out-of-scope requests are forwarded verbatim
    with no evasion, no gene-bank update, no detection — so dropping
    the proxy in front of Burp doesn't break login flows, oauth
    callbacks, or static assets. SSRF policy still applies.
  - `wafrift-proxy --max-rps-per-host / --max-rps-per-host-burst` —
    per-host token-bucket rate limiter so accidental hammering during
    exploration can't DoS a target. Default unlimited.
  - **`wafrift replay`** — re-fire a saved bypass against a target to
    prove reproducibility. Pulls the technique pool from explicit
    `--technique`, the proxy's gene bank (`--from-host`), or the per-WAF
    GeneBank (`--from-waf`). Exits `2` when the replay is blocked,
    `0` when it bypasses — directly usable as a CI regression gate.
  - **`wafrift report`** — render a pentest-ready markdown writeup from
    the proxy gene bank: per-host WAF, working/blocked techniques, and
    a copy-paste `wafrift replay` command for each finding. Supports
    `--only-host` host-glob filtering and `--output <file>`.
  - **`wafrift init`** — scaffold a commented `.wafrift.toml` so first-
    run isn't `--help` archaeology. Refuses to overwrite without
    `--force`. Every key shipped commented-out so the unmodified file
    is a pure no-op.
  - **`/_wafrift/findings.md`** — new live findings endpoint on the
    proxy (loopback-bind + peer-loopback gated, same as
    `/_wafrift/status`). `curl http://127.0.0.1:8080/_wafrift/findings.md`
    during a session for a markdown writeup of everything discovered
    so far.

- **`wafrift bench-waf --validate-only`** — corpus integrity check
  without standing up a WAF. Verifies every case has a unique id +
  non-empty payload + a known class (one of sql/xss/cmdi/ssti/path/
  ldap/ssrf/nosql/xxe/log4shell/cve_pocs); reports counts and exits
  4 on errors. Caught a real `tab_separated` id collision between
  `corpus/sql/comments_evasion.toml` and `corpus/cmdi/shell_unix.toml`
  on first run; renamed to `tab_separated_cmdi`.

- **`wafrift bench-diff`** — new subcommand. Compares two
  `bench-waf --output` JSON blobs; exits `3` if overall bypass rate
  drops more than `--bypass-drop-pp` (default 2pp), warns if
  `raw_block_rate` falls below `--raw-block-floor` (default 0.95,
  flags WAF-stack-changed not wafrift-bug). CI gate matching the
  methodology.md regression rules.

- **`wafrift-bench/targets/naxsi/`** — vendored naxsi-from-source
  bench target. Builds nginx 1.27.4 + naxsi 1.6 from source (no
  public naxsi docker image exists), bench-grade `naxsi.conf`
  (LearningMode off, denial → 403), exposed on `:18087`.
  `wafrift-bench/scripts/{up,down}.sh` updated to handle it. Cold
  build ~5 min, warm sub-second. Closes the naxsi-from-source open
  item in `wafrift-bench/WIRING.md`.

- **`bench-waf --lineage-output PATH`** — persists every
  evolution-strategy bypass (hill-climb / sim-anneal / tabu / novelty /
  map-elites) as a `wafrift_evolution::lineage::BypassEntry` and saves
  the deduplicated `BypassCorpus` JSONL on bench completion. Gene
  tuple is enough to reconstruct the wire payload exactly; the lineage
  trace records every mutation step. Closes the lineage-persistence
  open item in `wafrift-bench/WIRING.md`.

- **`bench-waf --strategies all`** — keyword that expands to every
  selectable strategy. Avoids having to type the 11-element comma list
  by hand and stays in sync with `ALL_STRATEGIES` (guarded by a unit
  test so that adding a new strategy without registering it would fail
  the build).

- **`bench-waf --strategies differential`** — wires
  `wafrift-evolution::differential::generate_probes` into the bench as
  an 11th selectable strategy. Sends class-filtered rule-fingerprint
  probes (sql/nosql → SQL probes, xss → XSS, cmdi/ssti → CMD,
  path → CMD path, others → baseline-only) and reports which probes the
  WAF lets through. The inverse of bypass-rate measurement: lets you
  see where your WAF has rule-coverage gaps. Closes the last open item
  in `wafrift-bench/WIRING.md`.

## [0.2.0] — 2026-05-08

Major bench + wiring rewrite. Introduces a real, reproducible
multi-strategy WAF benchmark and closes every dormant-crate gap from
the v0.1 audit.

### Added

- **`wafrift-bench/`** — production bypass-rate benchmark.
  - 557-case TOML corpus organized by attack class (sql / xss / cmdi /
    ssti / path / ssrf / ldap / nosql / xxe / log4shell), each split into
    sub-categories per attack family.
  - 6 docker-compose stacks: ModSec CRS PL=1/2/3/4, Coraza, BunkerWeb.
  - `wafrift bench-waf` with **10 selectable strategies**:
    `light` / `medium` / `heavy` (build_variants), `mcts` (mctrust 0.4),
    `smuggling` (CL.TE/TE.CL/TE.TE/dual-CL), `content-type`
    (multipart/json/xml), `redos` (catastrophic backtracking),
    `hill-climb` / `sim-anneal` / `tabu` / `novelty` / `map-elites`
    (feedback-driven evolution loops).
  - `--oracle-gate` per-class semantic-validity check on bypassed
    variants (sql / xss / cmdi / ssti / path / ldap / ssrf / nosql / xxe /
    log4shell) to filter "WAF allowed but parser would reject" garbage.
- **`crates/grammar/src/grammar/sql/ast_metamorph.rs`** — lift SQLi
  fragment via sqlparser, apply 7 semantic-preserving transforms
  (commute_or, commute_eq, identity_add_zero, identity_mul_one,
  eq_to_like, double_negation, paren_wrap), lower back. Wired through
  `sql::mutate` so AST variants flow into `build_variants` automatically.
- **`wafrift_strategy::evade_smart()`** — active-loop default that
  switches to MCTS once the host has block telemetry, falls back to
  classic `evade()` pipeline. Used by `wafrift-proxy` in discovery mode.
- **`wafrift-proxy --max-evade-retries N`** — multi-variant retry on
  WAF block. Each retry's recorded block bumps escalation so the next
  evade attempt picks heavier shapes.
- **`wafrift recon` CLI subcommand** — origin discovery via crt.sh + DNS
  (was dormant — `recon_cmd.rs` existed but never declared as a module
  and the CLI subcommand wasn't registered).

### Changed

- **`wafrift-cli`** now depends on `wafrift-fingerprint` + `wafrift-recon`
  directly. The `proxy-pool` feature is on by default — wafrift-pool
  HTTP/SOCKS rotation is live without flag jumping.
- **`wafrift-core`** re-exports the previously-missing crates: oracle,
  transport, pool, recon. Library consumers get the full surface from
  one dependency.
- **`wafrift-grammar`** promotes `sqlparser` from dev-dep to dep.
- **`mctrust`** dependency bumped to 0.4.0 (replaces 0.2.x API:
  `GameState`→`Outcome`, `GameSearch`→`TreeSearch`, `best_sequence`→
  `principal_variation`).

### Headline numbers

(modsec-pl1, all 10 strategies, 20 variants per case, --oracle-gate)

- 46k variants sent, 36% bypass rate, 95% of bypasses are oracle-valid.
- **557 of 557 corpus cases get at least one bypass at every paranoia
  level (PL=1 → PL=4).** At PL=4 (most aggressive CRS preset) the
  variant-level rate is ~27% — lower than PL=1's 36% but case-coverage
  stays 100%, meaning every attack type still has at least one working
  evasion for the gene bank to replay.

## [0.1.0] — 2026-05-08

First public release.

### Architecture

- **Evasion technique crates**: encoding, grammar, content-type, smuggling, fingerprint.
- **Intelligence crates**: detect (WAF fingerprinting), evolution (bypass discovery).
- **Pipeline**: strategy (planner, gene bank, learning cache) + oracle (typed multi-signal verdict classifier).
- **Transport**: evasion-aware HTTP client, connection pool, forward proxy with optional HTTPS MITM.
- **Tier B TOML rule system**: community-contributable WAF signatures, evasion pipelines, smuggling probes.
- **CLI**: interactive TUI + `scan` / `evade` / `detect` / `egress-example` / `recon` / `origin-hints` headless commands; `wafrift-proxy` forward proxy binary.

### Detection & evasion

- TOML-driven WAF detection: 160+ WAFs covered via community-extensible `rules/detect/*.toml` (parity with WAFW00F + identYwaf).
- Active WAF probing: benign + known-blocked baseline probes, response-drift classifier.
- Ambiguity handling in `detect()`: returns ranked `Vec<DetectedWaf>` with confidence scores and tie-breaking rules.
- Grammar dialects: MySQL/Postgres/MSSQL/Oracle/SQLite SQL, NoSQL (Mongo/Elastic/Redis), bash/sh/cmd.exe/PowerShell, SSTI for 7 engines.
- Grammar parser-validated equivalence: `sqlparser-rs` AST comparison proves SQL variant equivalence.
- Smuggling safety invariants: per-request poison canaries, exponential backoff on 5xx, circuit breaker. Probe templates under `rules/smuggling/`.

### Evolution & learning

- Search algorithms: hill-climb, simulated annealing, tabu search, novelty search, MAP-Elites.
- Lineage tracking: every discovered bypass serialized with its full transformation tree; replayable and shareable.
- Budget / termination / circuit-breaker: hard request budgets, plateau detection, target-health monitoring.
- Strategy learning cache: successful bypass pipelines persisted per WAF across scanner runs (gene bank in `~/.wafrift/genomes/`).

### Oracle

- Typed verdict enum: `Blocked | Allowed | RateLimited | ChallengeRequired | ServerError | Partial | Ambiguous`.
- Multi-signal fusion: calibration drift, connection, gzip body markers, headers, status, response time, H2 GOAWAY.
- Per-class oracles: SQL, XSS, CMDI, SSRF, SSTI, LDAP, path traversal.
- Final verdict includes the full collected signal list.
- H2 GOAWAY reason matching is case-insensitive; CMDI/SSRF tolerate trailing null / UTF-8 replacement noise; SSTI avoids Smarty false positives on `{{}}`.

### Proxy & transport

- Forward proxy (`wafrift-proxy`) for sqlmap / ffuf / browser integration.
- HTTPS MITM v1 with CA generation (`--write-mitm-ca-dir`, `--mitm --mitm-ca-dir`); CA-signed leaves; hop-by-hop header stripping on both directions.
- Egress: rotating proxies, Tor / SOCKS presets, source-port / local-bind rotation.
- TLS fingerprint profiles documented in `wafrift-fingerprint`; rustls-vs-browser JA3 caveat tracked in `docs/TLS_PARITY.md`.

### CLI fine-grained controls

- `--only` / `--exclude` flags on `evade` and `scan`, taking comma-separated hierarchical technique paths (`encoding/url`, `encoding/url/double`, `grammar`, ...).
- `wafrift techniques list` enumerates the selectable tree.
- Unknown selectors fail fast with a pointer to `techniques list` rather than silently dropping.
- The `--exclude grammar` selector is the structured replacement for the legacy `--encoding-only` shorthand (still supported).

### Tooling & release engineering

- CI workflow: fmt + clippy + build + test + doc with `-D warnings`.
- MSRV job (`cargo check` on Rust **1.88**, aligned with current `reqwest` / `idna` stack).
- `testbed/modsecurity-crs/` — optional Docker Compose for local ModSecurity/CRS benchmarking.
- `crates/cli/tests/modsec_local.rs` — ignored smoke test gated on `WAFRIFT_MODSEC_URL`.
- Full Cargo.toml metadata for every crate (description, license, repository, keywords, categories).
- Workspace `Cargo.toml`: internal crates use `workspace = true` dependencies with `version` fields for crates.io-compatible publishing; `mctrust` is a workspace member.

### Licensing

- Dual licensed: **MIT OR Apache-2.0**, aligning with the Rust ecosystem norm and providing an explicit patent grant.

### Notable fixes during stabilization

- Encoding semantic drift: URL over-encoding of unreserved chars, UTF-7 naive mock replaced with RFC 2152 implementation, unicode/HTML-entity context gating, layered encoding size cap.
- Encoding panics on multi-byte UTF-8 header values (`line_fold`, `multi_line_fold`, `null_byte_inject`).
- Encoding OOM on adversarially large payloads (input + output size caps).
- Workspace `proptest` dependency (subcrates referenced it without a workspace root entry, blocking `cargo metadata`).
- `LearningCache` JSON keys: string keys (fixes `HashMap<CacheKey, _>` JSON round-trip).
- `is_text_payload`: binary bodies without `Content-Type` are no longer treated as UTF-8 text.
- `wafrift-smuggling` tests: missing `HashSet` import under `unsafe-probes`.
- Encoding / grammar / oracle / strategy tests aligned with stochastic strategies and serde JSON map keys.
