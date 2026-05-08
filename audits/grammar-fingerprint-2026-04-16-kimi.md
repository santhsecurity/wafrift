# Deep Audit: `crates/grammar/` + `crates/fingerprint/`

**Auditor:** Kimi  
**Date:** 2026-04-16  
**Scope:** Read-only source review. Output only = this file.  
**Laws Applied:** 1 (No stubs), 3 (Test everything), 4 (Every finding critical), 5 (Actionable errors), 6 (TOML extensibility), 7 (Never postpone).

---

## Executive Summary

| Crate | Verdict | Critical Count |
|-------|---------|----------------|
| `wafrift-grammar` | **Functional but shallow.** Heuristic string replacement masquerades as semantic equivalence. Major coverage gaps (NoSQL, MathML, Markdown, true cmd.exe). No property-based validation. Runtime panics on malformed TOML. | 9 |
| `wafrift-fingerprint` | **Scope mismatch with its own name.** Contains ZERO WAF rule signatures, ZERO payload-to-rule mapping, and ZERO rule-trigger prediction. It is purely a browser/TLS impersonation data crate. The capability described in architecture docs (evolution targeting specific rules) does not exist. | 4 |

**Cross-cutting systemic issue:** The `oracle` crate exists to validate semantics, but there is no bridge that runs every grammar mutation through its corresponding oracle. The property-test requirement from the task ("for every grammar-variant pair claiming equivalence, assert a parsed AST comparison") is **completely absent** from the codebase.

---

## Part 1 — Audit of `crates/grammar/`

### 1.1 Grammar Coverage Matrix

| Attack Class | Dialects/Contexts Claimed | Actually Implemented | Status |
|--------------|--------------------------|----------------------|--------|
| **SQL** | MySQL, Postgres, MSSQL, Oracle, SQLite | Generic keyword swaps (tautologies, `LIKE`, `REGEXP`, `CHR` vs `NCHAR`). No dialect-specific parser. MySQL conditional comments are present, but PG dollar-quoting and MSSQL `WAITFOR` are just string literals in arrays. | **PARTIAL** |
| **NoSQL** | Mongo, Elastic, Redis, Cassandra | **MISSING ENTIRELY.** Not a single file, test, or TOML entry. | **CRITICAL GAP** |
| **CMD** | bash/sh/cmd.exe/powershell | Bash/sh tricks only (`${IFS}`, backslash obfuscation, `/dev/tcp`). `cmd.exe` syntax (`^` escaping, `set /a`, `for /f`) is absent. PowerShell is limited to `powershell -e` and `iex`. No real cmd.exe grammar. | **PARTIAL** |
| **XSS** | HTML/SVG/MathML/Markdown | HTML and SVG are well covered (17 tag/event combos, 15 exec functions, SVG animate). **MathML and Markdown contexts are completely absent.** | **PARTIAL** |
| **SSTI** | Jinja2, Twig, Velocity, Handlebars, Pug, Freemarker, Mustache, EJS, etc. | 15 engines loaded from `rules/templates.toml`. Good surface coverage. | **OK** |
| **SSRF** | gopher, dict, file, AWS IMDS, GCE metadata, DNS rebinding | Schemes detected. 11 cloud metadata endpoints. IPv4 integer/octal/hex encodings. DNS rebinding (`nip.io`, `xip.io`). | **OK** |
| **Path Traversal** | Unix/Windows, encoded dot-dot-slash | Single/double encoding, null-byte, backslash, overlong UTF-8, `..;/`, UNC, `/proc/self/root`. | **OK** |
| **LDAP** | — | Null-byte, wildcard, boolean confusion, Unicode fullwidth, balancing attacks. | **OK** |

**Finding 1.1.1 — Missing NoSQL grammar (CRITICAL)**
- **Evidence:** No source files, no `nosql` module, no TOML rules, no tests.
- **Impact:** At internet scale, NoSQL injection (Mongo `$ne`, Elastic query DSL) is a top-10 OWASP category. A WAF bypass tool that cannot mutate NoSQL payloads is blind to a massive attack surface.
- **Fix:** Add `grammar/nosql.rs` with MongoDB operator mutations (`$ne` → `$nin`, `$where` → `$expr`, JSON injection), Elastic query DSL obfuscation, and Redis command concatenation. Add `rules/nosql/operators.toml`.

**Finding 1.1.2 — Missing MathML and Markdown XSS contexts (CRITICAL)**
- **Evidence:** `xss.rs` only handles HTML, SVG, and generic URI schemes. No `<math>`, `<mtext>`, or Markdown payload variants.
- **Impact:** MathML XSS (`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`) and Markdown XSS (`[x](javascript:alert(1))`) are well-known WAF bypass vectors.
- **Fix:** Add MathML parser-differential payloads to `TAG_EVENT_COMBOS` or a new `MATHML_PAYLOADS` array. Add Markdown-specific payloads (link injection, HTML-in-Markdown).

**Finding 1.1.3 — cmd.exe grammar is essentially absent (CRITICAL)**
- **Evidence:** `cmd.rs` has Windows command *aliases* (`type` instead of `cat`, `dir` instead of `ls`) but no `cmd.exe`-specific syntax (`^` caret escaping, `cmd /c`, `for /f`, `set /p`).
- **Impact:** A WAF tuned for Windows (e.g., Azure WAF on IIS) will see through bash-centric obfuscation.
- **Fix:** Add a dedicated `cmd_windows.rs` module with `cmd.exe` caret insertion, quote escaping, and `for` loop indirection.

---

### 1.2 Equivalence Proof / Semantic Correctness

**Finding 1.2.1 — No formal equivalence proofs; only substring replacement (CRITICAL)**
- **Evidence:**
  - `sql/operators.rs:replace_equality` scans for the first bare `=` and replaces it with `" LIKE "`.
  - `sql/tautology.rs:replace_tautology` does `lower.find(pattern)` and splices a replacement string.
  - `cmd.rs:obfuscate_command` inserts `\`, `''`, or `""` into command names based on bash folklore.
- **Impact:** These are **textual**, not semantic, transforms. Example: replacing `=` with `LIKE` inside `' OR 1=1--` produces `' OR 1 LIKE 1--`, but if the original payload was `' OR col=val--`, the replacement becomes `' OR col LIKE val--`, which is semantically different for numeric columns or when `val` contains wildcards.
- **Fix:** Integrate the existing `wafrift-oracle` crate into grammar tests. Every mutation that claims equivalence must pass `oracle_for(payload_type).is_semantically_valid(original, mutated)`. Add a property test that generates random SQL expressions, mutates them, and asserts `sqlparser-rs` parses both to equivalent ASTs.

**Finding 1.2.2 — `replace_logical_operator` is case-blind and position-naive (CRITICAL)**
- **Evidence:** `operators.rs:24` does `let position = lower.find(&search)?;` then splices at that byte index. It replaces the **first** occurrence of ` or ` regardless of whether it is inside a string literal.
- **Impact:** Payload `"password = ' or else' AND 1=1"` would have the ` or ` inside the string literal replaced, breaking the payload.
- **Fix:** Re-implement `replace_logical_operator` with a tiny state machine that tracks `in_string` (single/double quotes) and only replaces operators outside quoted regions.

---

### 1.3 Composition with Encoding

**Finding 1.3.1 — Grammar crate has zero dependency on encoding; no internal composition matrix (CRITICAL)**
- **Evidence:** `Cargo.toml` depends only on `wafrift-types`, `rand`, `serde`, `toml`. No `wafrift-encoding`. The architecture diagram in `grammar/mod.rs` shows a "Combiner" box, but that combiner lives in `crates/strategy/src/strategy.rs` (`apply_grammar_mutations` then `apply_layered_encoding`).
- **Impact:** There is no test matrix covering `(grammar_variant × encoding)` compositions. A grammar mutation that introduces spaces (`' OR 'a' LIKE 'a'`) may be broken by a subsequent URL-encoding step that encodes the spaces differently than expected, or vice versa.
- **Fix:** Add an integration test in `crates/core/tests/` or `crates/strategy/tests/` that enumerates ~10 grammar mutations × ~10 encodings = 100 combinations per payload class, feeding each through the full pipeline and asserting the oracle still validates the output.

---

### 1.4 Generator-Style API

**Finding 1.4.1 — No diversity parameter; no coverage-guided generator (CRITICAL)**
- **Evidence:** The public API is `mutate(payload: &str, max_mutations: usize) -> Vec<GrammarMutation>`. The only control knob is a hard count cap.
- **Impact:** Callers cannot request "mutations that touch nodes I haven't seen before." The generator is stateless and pure-random, so repeated calls to `mutate(..., 5)` may return the same 5 mutations every time (deterministic iteration order over arrays, with randomness only in `replace_logical_operator` and `push_combined_whitespace_mutations`).
- **Fix:** Redesign the API to accept a `MutationRequest { max_count: usize, diversity: DiversityPolicy, exclude: HashSet<String> }` where `DiversityPolicy` can be `Random`, `CoverageGuided(Corpus)`, or `RuleTargeted(&[&str])`. Track which `rules_applied` combinations have been emitted.

---

### 1.5 Polyglot Payloads

**Finding 1.5.1 — Polyglot support is limited to XSS and SSTI; SQL/CMD have none (CRITICAL)**
- **Evidence:**
  - XSS has 7 hand-crafted polyglots in `xss.rs` (Strategy 7).
  - SSTI has the `"${{<%[%'\"}}%\\."` polyglot in `rules/templates.toml`.
  - SQL, CMD, LDAP, SSRF, Path Traversal do not generate any explicitly polyglot payloads.
- **Impact:** A polyglot payload that works as both SQL and XSS (e.g., in a parameter reflected into SQL and also into HTML) is a powerful bypass vector. The tool cannot generate them.
- **Fix:** Add a `polyglot` module that composes delimiter-sets from multiple payload types (e.g., `'; DROP TABLE users; -- <script>alert(1)</script>`) and tests them against both oracles.

---

### 1.6 Panics, Casts, OOM, Regex Backtracking

**Finding 1.6.1 — Runtime panics on malformed embedded TOML (CRITICAL)**
- **Evidence:** Three locations use `.expect("Failed to parse ... TOML")` inside `OnceLock` initializers:
  1. `grammar/sql/common.rs:71-74`
  2. `grammar/cmd.rs:74-77`
  3. `grammar/template.rs:93-96`
- **Impact:** If a user edits `rules/sql/operators.toml` with a syntax error and recompiles, the binary will **panic at first access** (i.e., at runtime) with no graceful degradation. This violates Law 5 (actionable errors) and Law 3 (crash recovery).
- **Fix:** Replace `expect` with `match` that returns a `Result` or falls back to hard-coded defaults. Example:
  ```rust
  RULES.get_or_init(|| {
      toml::from_str(SQL_OPERATORS_TOML).unwrap_or_else(|e| {
          eprintln!("warn: invalid TOML in rules/sql/operators.toml: {e}");
          SqlOperatorRules::default()
      })
  })
  ```

**Finding 1.6.2 — No regex used, so no regex backtracking risk (OK)**
- The grammar crate uses only `str::contains`, `str::find`, `str::replace`, and manual char iteration. This is actually a strength from a DoS perspective.

**Finding 1.6.3 — `max_mutations` prevents unbounded generation, but intermediate vectors can over-allocate (MEDIUM)**
- **Evidence:** `sql/mod.rs` builds `results` with `Vec::new()` and pushes unchecked until `results.len() >= max_mutations`, but some helpers like `split_string_concat` build large intermediate vectors before the cap is applied.
- **Impact:** Minor; `split_string_concat` on a 20-char string generates ~25 variants. Not an OOM vector, but not bounded early either.
- **Fix:** Pass the remaining budget into helpers like `push_string_mutations` so they stop allocating once the cap is reached.

---

### 1.7 Test Quality

**Finding 1.7.1 — No property-based or oracle-backed tests in grammar crate (CRITICAL)**
- **Evidence:** All tests are hard-coded substring checks (`assert!(payload.contains("LIKE"))`). There is no `proptest`, no `quickcheck`, and no invocation of `wafrift-oracle` from inside `wafrift-grammar`.
- **Impact:** Semantic drift is inevitable without automated verification. A future refactor could change `replace_equality` to insert `IS` instead of `LIKE`, and tests would still pass if they only check for structural difference.
- **Fix:** Add a property test (e.g., using `proptest`) that:
  1. Generates random SQL injection payloads.
  2. Mutates them.
  3. Asserts `SqlOracle::generic().is_semantically_valid(original, mutated)`.
  4. Asserts `sqlparser-rs` parses both to equivalent ASTs.

**Finding 1.7.2 — XSS test `no_mutations_for_non_xss` is logically inverted (CRITICAL)**
- **Evidence:** `xss.rs:466-472`:
  ```rust
  let mutations = mutate("hello world", 10);
  assert!(
      !mutations.is_empty(),
      "should still produce tag/event variants"
  );
  ```
- **Impact:** The test *asserts that a non-XSS input produces mutations*. This means the XSS mutator is completely indifferent to input content. It will happily return `<img src=x onerror=alert(1)>` for the string `"hello world"`, which is not a mutation of the input but a replacement. This breaks the semantic-equivalence contract.
- **Fix:** Change the assertion to `assert!(mutations.is_empty())` and then fix `xss::mutate` to return empty when no XSS signals are detected (or at least derive mutations from the input structure).

**Finding 1.7.3 — TOML parse failure path is untested (CRITICAL)**
- **Evidence:** No test corrupts the embedded TOML and verifies behavior.
- **Fix:** Add an adversarial test that temporarily injects invalid TOML into the `OnceLock` (or tests the fallback path directly) and asserts graceful degradation.

---

## Part 2 — Audit of `crates/fingerprint/`

### 2.1 WAF Ruleset Coverage

**Finding 2.1.1 — Crate contains ZERO WAF rule signatures (CRITICAL)**
- **Evidence:** The crate has 4 source files:
  - `lib.rs` — module declarations
  - `fingerprint.rs` — 6 browser `BrowserProfile` structs
  - `tls_fingerprint.rs` — 9 TLS `TlsProfile` structs (JA3/JA4 constants)
  - `tls_fingerprint_tests.rs` — unit tests for TLS constants
- There is no `rules/` subdirectory, no CRS rule IDs, no AWS WAF rule names, no Cloudflare managed rule lists, no Imperva signatures.
- **Impact:** The architecture docs (strategy pipeline, evolution advisor) implicitly assume the existence of a component that can predict which WAF rule a payload triggers. That component is **not this crate**, and as far as this audit can determine, it does not exist anywhere in the codebase.
- **Fix:** Either **rename this crate** to `wafrift-impersonation` or `wafrift-browser-profiles` to reflect reality, OR implement the actual fingerprinting capability by adding a `rules/waf/` TOML directory with CRS/AWS/Cloudflare signatures and a matching engine.

### 2.2 Payload-to-Rule Association

**Finding 2.2.1 — No payload inspection; no rule inference (CRITICAL)**
- **Evidence:** The crate exports `random_profile()`, `apply_profile()`, `profile_for()`, `build_cipher_suites()`, `compute_ja3_string()`. None accept a payload string. None return a rule ID.
- **Impact:** The `evolution` and `strategy` crates cannot perform rule-targeted evolution because they have no API to ask "Which rule would this payload trigger?"
- **Fix:** If rule fingerprinting is a project goal, create a new crate `wafrift-rulematch` (or extend `wafrift-detect`) that:
  1. Loads CRS/AWS/Cloudflare regex signatures from TOML.
  2. Exposes `match_rules(payload: &str) -> Vec<RuleMatch>`.
  3. Provides `predict_trigger(payload: &str) -> Option<RuleId>`.

### 2.3 Rule Signatures in TOML

**Finding 2.3.1 — All data is hard-coded as `const`; no TOML extensibility (CRITICAL)**
- **Evidence:** `BrowserProfile` and `TlsProfile` are `&'static` const values. The only TOML in the crate is `Cargo.toml`.
- **Impact:** Community extension is impossible. Updating a Chrome User-Agent or JA3 hash requires a Rust recompile. CRS updates monthly; this crate cannot keep pace.
- **Fix:** Move `PROFILES` and `ALL_PROFILES` into TOML files (`rules/fingerprints/http.toml`, `rules/fingerprints/tls.toml`) and load them at compile time via `include_str!` (with graceful parse failure) or at runtime from a config directory.

### 2.4 Rule Trigger Prediction

**Finding 2.4.1 — Prediction API does not exist (CRITICAL)**
- **Evidence:** No function named `predict`, `trigger`, `match`, or `score` exists in the source.
- **Impact:** The advisor (`crates/evolution/src/advisor.rs`) recommends techniques based on detected WAF *vendor* (Cloudflare, AWS WAF, ModSecurity), but it cannot target a *specific rule* (e.g., "CRS rule 942100 fires on `UNION SELECT`, so avoid that exact regex"). This is a massive gap versus the stated competitive goal.
- **Fix:** Implement a `RulePredictor` trait and at least one concrete implementation using regex signature matching against the payload.

---

### 2.5 Panics, Casts, OOM, Regex Backtracking

**Finding 2.5.1 — Clean; no panics, no regex, no unbounded allocation (OK)**
- The fingerprint crate is pure data. It uses safe arithmetic, fixed-size arrays, and bounded string formatting. This is the one area where it is robust.

---

### 2.6 Public API Consumer Exposure

**Finding 2.6.1 — API is clear but misnamed; consumers are confused by the mismatch (MEDIUM)**
- **Evidence:** `crates/core/src/lib.rs` re-exports `wafrift_fingerprint::fingerprint` and `wafrift_fingerprint::tls_fingerprint`. `crates/strategy/src/strategy.rs` uses it for "fingerprint rotation" (i.e., rotating User-Agents). The name `fingerprint` implies WAF fingerprinting, but the behavior is browser impersonation.
- **Fix:** Rename the re-export in `core` to `browser_profile` and `tls_profile` to make the consumer contract honest.

---

## Part 3 — Audit of Both Crates (Cross-Cutting Concerns)

### 3.1 Panics & Error Handling

| Location | Issue | Severity |
|----------|-------|----------|
| `grammar/sql/common.rs:73` | `.expect` on TOML parse | CRITICAL |
| `grammar/cmd.rs:75` | `.expect` on TOML parse | CRITICAL |
| `grammar/template.rs:94` | `.expect` on TOML parse | CRITICAL |
| `grammar/sql/mod.rs:307` | `rng.gen_range(0..results.len())` on empty `results` would panic, but guarded by `!results.is_empty()` | OK |
| `fingerprint/fingerprint.rs:95` | `rand::random::<usize>() % PROFILES.len()` — could panic if `PROFILES` empty, but guarded | LOW |

### 3.2 Test Gaps

| Missing Test | Why It Matters |
|--------------|----------------|
| Grammar × Encoding composition matrix | Catches pipeline breakage where encoding destroys grammar semantics |
| Oracle validation for every mutation | Catches semantic drift (the #1 correctness guarantee) |
| TOML corruption / parse failure | Catches runtime panic on community-edited rules |
| Concurrent `mutate()` calls | `thread_rng()` and `OnceLock` should be thread-safe, but no stress test exists |
| Fuzzing / property tests | Hard-coded tests only cover happy path |

### 3.3 Public API Clarity for Consumers (`karyx` / `soleno`)

**Finding 3.3.1 — API surface is small but insufficient for advanced consumers (CRITICAL)**
- **Evidence:**
  - Grammar exposes only `classify`, `mutate`, `mutate_as`. No streaming API, no feedback channel, no oracle integration.
  - Fingerprint exposes only `random_profile` and `apply_profile`. No rule matching, no evolution targeting.
- **Impact:** External consumers building on top of WafRift (e.g., `karyx`, `soleno`) will hit the ceiling of these APIs immediately and have to reimplement the missing pieces themselves.
- **Fix:**
  1. For grammar: add `mutate_streaming(payload, request) -> impl Iterator<Item = GrammarMutation>` and `validate_with_oracle(mutation, oracle) -> Result<ValidatedMutation, SemanticDriftError>`.
  2. For fingerprint: if rule fingerprinting is out of scope, document that explicitly in the crate-level doc comment and rename modules to avoid false advertising.

---

## Action Register (Prioritized)

| # | Fix | Owner Crate | Severity |
|---|-----|-------------|----------|
| 1 | **Rename or re-scope `fingerprint`** — It is browser impersonation, not WAF rule fingerprinting. Update `core` re-exports and docs. | `fingerprint` | CRITICAL |
| 2 | **Eliminate all `.expect` on TOML parse** in `grammar`. Fall back to safe defaults with logging. | `grammar` | CRITICAL |
| 3 | **Implement `replace_logical_operator` with string-literal awareness.** Do not replace `or` inside quotes. | `grammar` | CRITICAL |
| 4 | **Add property tests** that feed every grammar mutation through `sqlparser-rs` and `wafrift-oracle`. | `grammar` / `oracle` | CRITICAL |
| 5 | **Add NoSQL grammar module** (`mongo`, `elastic`, `redis`, `cassandra`). | `grammar` | CRITICAL |
| 6 | **Add MathML and Markdown XSS contexts.** | `grammar` | CRITICAL |
| 7 | **Invert/fix `no_mutations_for_non_xss` test** and make XSS mutator input-aware. | `grammar` | CRITICAL |
| 8 | **Add grammar × encoding composition integration tests** (100 combos per class). | `strategy` / `core` | CRITICAL |
| 9 | **Add `cmd_windows.rs`** with true `cmd.exe` syntax (caret escaping, `for` loops). | `grammar` | CRITICAL |
| 10 | **Move fingerprint profiles to TOML** (`rules/fingerprints/*.toml`) for community extensibility. | `fingerprint` | CRITICAL |
| 11 | **If rule fingerprinting is a goal**, create `wafrift-rulematch` with CRS/AWS/Cloudflare regex signatures in TOML. | new crate | CRITICAL |
| 12 | **Add diversity/coverage parameter** to `mutate()` API. | `grammar` | MEDIUM |
| 13 | **Add polyglot generator** for SQL+XSS and CMD+XSS cross-context payloads. | `grammar` | MEDIUM |
| 14 | **Bound intermediate allocations** in `split_string_concat` and `obfuscate_command` by passing remaining budget. | `grammar` | LOW |

---

## Final Verdict

**`wafrift-grammar`** is a competent heuristic payload mutator with good breadth in XSS, SSTI, SSRF, and Path Traversal, but it lacks the depth, formal rigor, and testing culture required for a tool that claims to generate "semantically equivalent variants." The absence of NoSQL, MathML, Markdown, and true cmd.exe support are material gaps. The reliance on substring replacement without string-awareness is a correctness bug waiting to happen. The missing property-test / oracle bridge is the single most important technical debt item.

**`wafrift-fingerprint`** is not a WAF fingerprinting crate. It is a browser and TLS impersonation crate with a misleading name. It contains no rule signatures, no payload-to-rule mapping, no TOML extensibility, and no predictive API. If the project architecture depends on evolution targeting specific WAF rules, that capability is entirely unimplemented. The rename/rescope must happen immediately to prevent downstream consumers from building on a false contract.

**Both crates are missing the deep adversarial testing and formal semantic validation that the task requirements and the project's own laws demand.**
