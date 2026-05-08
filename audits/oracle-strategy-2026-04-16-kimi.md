# Deep Audit: `crates/oracle/` + `crates/strategy/`

**Date:** 2026-04-16  
**Auditor:** kimi  
**Scope:** Read-only source review of `crates/oracle/` and `crates/strategy/`. Only written artifact is this file.  
**Laws Applied:** 1 (No stubs), 2 (Modular), 3 (Test everything), 4 (Every finding critical), 5 (Actionable errors), 6 (TOML extensibility), 7 (Deep refactor now).

---

## 1. Executive Summary

**The `oracle` crate does not implement a WAF-response classifier at all.** It is a *payload-semantic* validator (`PayloadOracle::is_semantically_valid`) that checks whether a mutated payload still looks like SQL/XSS/CMDI/etc. The 7-class verdict enum (`Blocked | Allowed | RateLimited | ChallengeRequired | ServerError | Partial | Ambiguous`) **does not exist anywhere in the codebase**. Response classification is instead scattered across `crates/detect/`, `crates/transport/`, and `crates/types/src/calibration.rs` as ad-hoc boolean heuristics.

**The `strategy` crate is disconnected from any oracle feedback loop.** Its primary entry point `evade()` takes `HostState` (block counters, not verdicts). The MCTS bridge uses the semantic oracle only as a hard `Loss` gate inside tree search; it never learns from WAF responses. There is no typed verdict interface, no per-target calibration, no cost model, and no community-TOML strategy layer.

**Verdict:** These two crates are architecturally misaligned with the scanner's stated correctness guarantees. The oracle cannot misclassify a WAF response because it does not look at responses. The strategy cannot pick the right tool for the right reason because it is never told the reason.

---

## 2. Oracle Findings

### 2.1 Architectural Gap — No Verdict Classification Exists

- **Finding:** `crates/oracle/src/lib.rs` exports `SqlOracle`, `XssOracle`, `CmdiOracle`, `PathOracle`, `LdapOracle`, `SsrfOracle`, `SstiOracle`. Every single one implements `PayloadOracle::is_semantically_valid(&self, original: &str, transformed: &str) -> bool`.
- **Impact:** There is **zero** code that classifies an HTTP response into `Blocked | Allowed | RateLimited | ChallengeRequired | ServerError | Partial | Ambiguous`. The entire correctness guarantee listed in the task description is unimplemented.
- **Fix:** Either rename `crates/oracle/` to `payload-oracle` and create a real `response-oracle` crate, or expand `oracle/` to include a `ResponseOracle` trait with the full verdict taxonomy.

### 2.2 Verdict Classes — Not Covered

| Verdict | Exists in Code? | Where / Notes |
|---------|-----------------|---------------|
| `Blocked` | Partially | `detect::is_blocked_response()`, `transport::is_waf_block()` — boolean only, no nuance. |
| `Allowed` | Missing | Implicitly the negation of `is_blocked_response()`. |
| `RateLimited` | Missing | `429` is lumped into "blocked". No distinction between rate-limit vs. WAF block. |
| `ChallengeRequired` | Missing | `503` + body markers like `challenge-platform` are treated as "blocked", not as a challenge requiring a different strategy (e.g., CAPTCHA solver vs. bypass). |
| `ServerError` | Missing | `500`, `502`, `504` are ignored by block heuristics but not classified. |
| `Partial` | Missing | No concept of soft-block or body-redaction. |
| `Ambiguous` | Missing | `CalibrationResult::Uncertain` exists in `types/src/calibration.rs`, but it is not a verdict and carries no conflict reasons. |

### 2.3 Classification Signals — Unused by Oracle

The oracle crate never sees HTTP traffic, but even the response-classification code elsewhere fails to use the signals the prompt demands:

- **Status codes:** `403/406/418/444/503` — only `403|406|429|503` are handled. `418`, `444` (nginx/Cloudflare close), and `499` are ignored. `401`, `405`, `407`, `502`, `504` are also ignored.
- **Body markers:** Hardcoded English substrings (`"access denied"`, `"captcha"`, etc.) in `transport/src/response.rs` and `detect/src/response_fingerprint.rs`. No per-target learned baselines.
- **Response time anomaly:** Not measured anywhere.
- **Connection behavior (RST vs 200-with-block-page):** Not observed.
- **HTTP/2 GOAWAY frame:** Not observed.

### 2.4 No Learning, No Calibration, No Per-Target Baselines

- **Finding:** The oracle crate has no calibration phase. The `types::calibration` module (`analyze_calibration`) does a one-shot boolean guess (`WafPresent | NoWaf | Uncertain`) based on a single response. It does not record a benign baseline fingerprint vs. a blocked fingerprint for the target.
- **Impact:** Silent blocks (200 OK with replaced body) can only be caught if `response_fingerprint::compare` is explicitly called with a pre-recorded baseline. Nothing in `oracle/` or `strategy/` automates this.
- **Fix:** Add a `CalibrationSession` that stores `(benign_fingerprint, blocked_fingerprint)` per host and feeds a `ResponseOracle` that computes drift internally.

### 2.5 Partial Verdicts / Block Reasons — Absent

- **Finding:** No oracle returns *why* a block happened. The strategy cannot therefore pick a different technique for a different rule trigger.
- **Impact:** If Cloudflare blocks because of a SQL keyword vs. because of an XSS tag, the strategy treats both identically (just "blocked").
- **Fix:** `ResponseOracle` should return `Partial(BlockReason)` or at least `Ambiguous(Vec<Signal>)`.

### 2.6 Semantic Oracle Correctness Bugs (Payload Oracles)

Even within its mis-scoped role, the payload oracle has concrete bugs:

#### 2.6.1 `CmdiOracle` — Broken Word-Boundary Check
```rust
// cmdi.rs:113-118
let has_command = shell_commands().iter().any(|cmd| {
    let cmd_lower = cmd.to_ascii_lowercase();
    lower.contains(&cmd_lower)  // ← substring match, NOT word boundary
});
```
- **Impact:** `category` matches `cat`. `wget` matches inside `twget`. False positives accept broken payloads; false negatives reject valid ones depending on context.
- **Fix:** Use regex with `\b` or manual word-boundary checks.

#### 2.6.2 `CmdiOracle` — `shell_tricks` Computed But Never Used
```rust
let _has_shell_trick = shell_tricks().iter().any(|trick| payload.contains(trick));
```
- **Impact:** Dead logic. The TOML rule field `shell_trick` is loaded for nothing.
- **Fix:** Either use it in the validity formula or remove it from the TOML schema.

#### 2.6.3 `SsrfOracle` — Broken URL Syntax Validation (Gap Test Confirmed)
```rust
// ssrf.rs:150-177
if URL_SCHEMES.iter().any(|s| lower.contains(&format!("{}[", s))) { return true; }
```
`http://[127.0.0.1` passes because it contains `http://[` and the indicator host `127.0.0.1`, even though the URL is structurally invalid (unclosed bracket).
- **Impact:** The MCTS oracle gate will accept payloads that a real HTTP client/server would reject.
- **Fix:** Use a real URL parser (`url::Url`) or at least validate IPv6 bracket pairing.

#### 2.6.4 `SstiOracle` — Missing Smarty Delimiters
- **Finding:** `DELIMITER_PAIRS` lacks bare `{` `}` used by Smarty. The gap test `gap_test_ssti_smarty_delimiters` documents this.
- **Impact:** Valid Smarty SSTI payloads are rejected as inert.
- **Fix:** Add `("{", "}")` with stricter content checks to avoid matching JSON.

#### 2.6.5 `SstiOracle` — Only First Delimiter Pair Checked
```rust
for &(open, close) in DELIMITER_PAIRS {
    if let Some(start_pos) = payload.find(open) {
        let after_open = start_pos + open.len();
        if let Some(close_pos) = payload[after_open..].find(close) {
            if close_pos > 0 { return true; }
        }
    }
}
```
- **Impact:** If the first pair found has empty content, it returns `false` even if a later pair is valid. This is a false negative.
- **Fix:** Continue the loop instead of immediate `return true` on zero content; return true on first non-empty match.

#### 2.6.6 `XssOracle` — Overly Permissive Heuristic
```rust
(has_tag && has_exec) || has_uri || (has_tag && has_event)
```
- **Impact:** A benign HTML snippet like `<div onclick="console.log('hi')">` matches `has_tag && has_event` even though it is not an XSS payload. The oracle has no context of injection point (attribute vs. body).
- **Fix:** Add requirement for a dangerous sink or injection-context marker.

#### 2.6.7 `SqlOracle` — Hardcoded Generic Dialect in MCTS Bridge
```rust
wafrift_oracle::sql::is_valid_expression_injection(&decoded, DatabaseDialect::Generic)
```
- **Impact:** MySQL/PostgreSQL-specific syntax that is valid for those dialects but rejected by `GenericDialect` causes MCTS to score a `Loss`, discarding valid evasion paths.
- **Fix:** Pass the detected DB dialect through the strategy pipeline.

### 2.7 Oracle Test Coverage — Gaps

- **Adversarial tests:** `test_legendary_adversarial.rs` tests empty, null bytes, invalid UTF-8, and ~1MB inputs. Good start.
- **Concurrent access / crash recovery:** **Zero tests.** The oracles use `OnceLock` global caches. There are no race-condition tests, no `proptest` for concurrent initialization, no OOM crash-recovery tests.
- **No regex backtracking:** True (no regex used), but `sqlparser` could stack-overflow on deeply nested input — no test for this.
- **No property tests for semantic equivalence:** The property tests only assert "does not panic". They do not assert that `is_semantically_valid(original, original) == true` or that small destructive mutations are rejected.

---

## 3. Strategy Findings

### 3.1 Strategy Input / Output Mismatch

- **Actual Input:** `evade(request: &Request, state: &HostState, config: &EvasionConfig)`
  - `HostState` contains `blocks: u32`, `successes: u32`, `tried_encodings: Vec<Strategy>`, `last_success: Option<Technique>`, `proven_winners: Vec<String>`.
  - It does **not** contain a WAF fingerprint, a payload type, or prior verdicts.
- **Actual Output:** `EvasionResult { request: Request, techniques: Vec<Technique>, description: String }`
  - This is a *single transformed request*, not an ordered list of evasion pipelines to try.
- **Impact:** The strategy cannot do planning. It applies one fixed combo per escalation level. There is no concept of "try pipeline A, if Blocked try pipeline B".
- **Fix:** Redesign `evade()` to return `Vec<EvasionPipeline>` (ordered by expected success rate) so the caller can iterate.

### 3.2 Learning & Persistence

#### 3.2.1 `GeneBank` — Cross-Target Learning Exists but Is Shallow
- **Finding:** `gene_bank.rs` persists per-WAF technique success rates to `~/.wafrift/genomes/<waf>.json`.
- **Impact:** It only stores **technique names** (e.g., `"DoubleUrlEncode"`) and success rates. It does **not** store ordered pipelines, smuggling variants, or per-payload-type preferences.
- **Fix:** Store full `EvasionPipeline` histories, not just atomic technique names.

#### 3.2.2 `HostState` — In-Memory Only, No Persistence
- **Finding:** Per-host winner pools and blocklists are lost when the process exits.
- **Impact:** Re-scanning the same host later starts from zero discovery.
- **Fix:** Persist `HostState` alongside `GeneBank`.

### 3.3 Pipeline Composition — Incomplete & Hardcoded

#### 3.3.1 MCTS Action Space Omits Smuggling and H2
- **Finding:** `mcts_bridge.rs` exposes four dimensions: `Encode`, `GrammarMutate`, `ContentTypeSwitch`, `HeaderTrick`. `RequestSmuggling` and `H2Evasion` are **not** in the MCTS tree.
- **Impact:** The "intelligent" `evade_mcts()` path can never discover combinations like "encode → smuggle" or "grammar mutate → H2 desync". Those only appear in the static `evade()` Heavy path.
- **Fix:** Add `Smuggle` and `H2Frame` actions to `TechniqueAction` and teach `WafRiftEnv::apply()` how to simulate them.

#### 3.3.2 No Composition Grammar
- **Finding:** The MCTS bridge uses boolean flags (`grammar_applied`, `content_type_applied`, `header_applied`) to prevent duplicates. There is no formal grammar describing valid layer ordering.
- **Impact:** "encoding after grammar" is allowed, but "grammar after encoding" is also allowed (the flags only prevent *duplicate* dimensions, not invalid order). For some payloads, encoding before grammar destroys the structure that grammar expects.
- **Fix:** Define a `PipelineGrammar` (in Rust or TOML) that encodes valid partial orderings.

### 3.4 TOML Extensibility — Not Used by Strategy

- **Finding:** `strategies.d/core.toml` lists 11 tamper strategies with contexts and descriptions. **The strategy crate never reads this file.** `advisor.rs` hardcodes all WAF-specific playbooks in Rust match arms. `strategy.rs` hardcodes escalation-level technique selections.
- **Impact:** Community cannot contribute new strategy orderings without recompiling.
- **Fix:** Load `strategies.d/*.toml` at runtime (or `include_str!` at compile time) and use it to populate `EvasionPlan` and `advisor` logic.

### 3.5 Per-WAF Defaults — Hardcoded, Not Community-Sourced

- **Finding:** `advisor.rs` has a single `adapt_to_waf()` match statement with arms for `Cloudflare`, `AWS WAF`, `ModSecurity`, `Imperva/Incapsula`, `Akamai`, `F5 BIG-IP`, and a catch-all.
- **Impact:** New WAFs require a code change. There is no mechanism for a community member to drop in a new WAF playbook.
- **Fix:** Represent playbooks as TOML (e.g., `rules/wafs/Cloudflare.toml`) and deserialize into `EvasionPlan`.

### 3.6 Cost Estimation / Request Budget — Missing

- **Finding:** No technique has a cost field. No budget is passed into `evade()` or `evade_mcts()`.
- **Impact:** The scanner will happily burn 500 MCTS iterations × `max_depth` requests with no upper bound. In a production scan this is a denial-of-service risk against the target and a quota-burn risk for the operator.
- **Fix:** Add `cost: u32` to `TechniqueAction` and `budget: u32` to `HostState` / search config. Prefer high-hit, low-cost strategies first.

### 3.7 Strategy Bugs

#### 3.7.1 `evade_adaptive` Ignores Host State for Content-Type Switching
```rust
// strategy.rs:346
let state = HostState::default();
if plan.use_content_type_switch {
    apply_content_type_switch(&mut req, &mut techniques, config, &state);
}
```
- **Impact:** `state.tried_content_types` is always empty, so `apply_content_type_switch` will always pick the first variant, never rotating.
- **Fix:** Pass the real `HostState` into `evade_adaptive`.

#### 3.7.2 `evade_mcts` Returns Only One Action, Not a Sequence
```rust
let optimal_action = search.run()?;
// ...
result_env.apply(&optimal_action);
```
- **Impact:** The doc comment says "optimal action sequence", but `GameSearch::run()` returns a single `TechniqueAction`. A multi-step evasion pipeline is never returned.
- **Fix:** Change MCTS integration to return the full root-to-leaf action path (or call `run_sequence()` if `mctrust` supports it; if not, extend `mctrust`).

#### 3.7.3 `apply_layered_encoding` Silently Applies Content-Type Switch
- **Finding:** Inside `apply_layered_encoding`, if `config.content_type_switching` is true, it switches content-type *after* encoding the values. The variant generator (`content_type::generate_variants`) expects raw `key=value` pairs; feeding it already-URL-encoded values may produce double-encoded multipart bodies or JSON strings containing `%XX` literals.
- **Impact:** Content-type switch results are corrupted when combined with layered encoding.
- **Fix:** Generate the content-type variant from the *original* pairs, then encode inside the variant if needed.

#### 3.7.4 `WafRiftEnv::evaluate()` Uses Naive Percent-Decode
```rust
let decoded = v
    .replace("%20", " ")
    .replace("%27", "'")
    ...;
```
- **Impact:** Incomplete decoding means oracle validation is run on a partially-decoded string. This can both miss broken payloads (false positive) and reject valid ones (false negative). Also misses uppercase hex (`%2F` vs `%2f`).
- **Fix:** Use `percent_decode` from the `percent-encoding` crate.

---

## 4. Interface Findings (Oracle ↔ Strategy)

### 4.1 No Typed Verdict Interface

- **Finding:** There is no `Verdict` type shared between oracle and strategy.
- **Impact:** An "invalid verdict" literally cannot be a compile error because verdicts do not exist.
- **Fix:** Define a `wafrift-types::Verdict` enum (with the 7 variants) and make `transport::EvasionResponse` carry it. Make the strategy crate accept `Vec<Verdict>` (history) as input.

### 4.2 Oracle Is Not Consulted for WAF Responses

- **Finding:** The actual call graph is:
  1. `transport` sends request.
  2. `transport` receives response → calls `is_waf_block()` (boolean).
  3. Caller updates `HostState::blocks += 1`.
  4. `strategy::evade()` reads `HostState.blocks` and picks `EscalationLevel`.
  5. `mcts_bridge::WafRiftEnv::evaluate()` calls the *payload* oracle to avoid breaking syntax.
- **Impact:** The payload oracle is a syntax gate, not a response classifier. The strategy never sees oracle output about the *WAF's behavior*.
- **Fix:** Introduce `ResponseOracle` that consumes `(Request, Response)` and emits `Verdict`. Pipe that verdict into `HostState` and strategy selection.

### 4.3 MCTS Reward Function Is Detached from Reality

- **Finding:** `WafRiftEnv::evaluate()` returns:
  - `Loss` if the payload oracle says the syntax is broken.
  - `Win(Reward::new(0.5 + diversity * 0.5))` if `applied_techniques.len() >= max_depth`.
- **Impact:** The reward is based purely on *technique diversity* (how many dimensions were used). It has **zero** correlation with whether the WAF actually allowed the request. A fully diverse payload that gets blocked receives the same MCTS reward as one that bypasses.
- **Fix:** MCTS reward must incorporate the actual `Verdict` from the response oracle. `Allowed` → high reward. `Blocked` → low/negative reward. `ChallengeRequired` → neutral (needs different solver).

---

## 5. Actionable Fix Recommendations

### Immediate (Do Not Postpone)

1. **Create `wafrift-types::verdict::Verdict`** with all 7 variants. Add `reasons: Vec<Signal>` to `Ambiguous` and `Partial`.
2. **Create `crates/response-oracle/`** (or fold into `crates/oracle/`):
   - `ResponseOracle` trait: `classify(status, headers, body, baseline_fp) -> Verdict`.
   - Implement per-target calibration (baseline fingerprint storage).
   - Distinguish `ChallengeRequired` (Cloudflare CAPTCHA, JS challenge) from `Blocked`.
3. **Delete or rename the current `oracle/` crate** to `payload-oracle/` to prevent architectural confusion.
4. **Fix `CmdiOracle` word-boundary bug** and **remove dead `shell_tricks` logic**.
5. **Fix `evade_adaptive` dummy `HostState`** so content-type rotation actually works.
6. **Fix `evade_mcts` single-action bug** — return the full action path, not one node.

### Short-Term (Next Sprint)

7. **Move WAF playbooks out of Rust match arms** into `rules/wafs/<name>.toml`. Load them at startup.
8. **Move tamper strategies out of hardcoded Rust** and consume `strategies.d/*.toml` in `advisor.rs`.
9. **Add `cost: u32` to `TechniqueAction`** and **plumb a `budget: u32`** through `evade()`, `evade_mcts()`, and `HostState`.
10. **Add smuggling & H2 actions to MCTS** so the tree can explore the full combinatorial space.
11. **Replace naive `.replace()` percent-decoding** with `percent_decode` in `mcts_bridge.rs`.
12. **Fix `SstiOracle` Smarty delimiter gap** and first-pair short-circuit bug.
13. **Fix `SsrfOracle` URL validation** by using a real URL parser.

### Medium-Term

14. **Redesign `evade()` to return `Vec<EvasionPipeline>`** ordered by expected value, enabling true planning.
15. **Persist `HostState` to disk** (e.g., `~/.wafrift/hosts/<host>.json`) so per-host learning survives restarts.
16. **Add adversarial concurrency tests** for `OnceLock`-based oracle rule loading.
17. **Add MCTS integration tests with a mock `ResponseOracle`** returning scripted verdicts, verifying that the strategy learns to prefer successful pipelines.

---

## 6. Conclusion

The `oracle` and `strategy` crates, as they exist today, **do not satisfy the correctness guarantees described in the project charter.** The oracle is a syntax checker, not a response classifier. The strategy is an escalation-level state machine with a toy MCTS wrapper, not a planner that consumes verdicts. The interface between them is a boolean `is_semantically_valid` gate inside a tree-search simulator, not a typed verdict channel.

Because misclassification at internet scale corrupts billions of records (Core Law 4), the absence of a `ResponseOracle` is a **show-stopping architectural gap**. The deep refactor (Core Law 7) must happen now: introduce the `Verdict` type, build the `ResponseOracle`, and rewire the strategy engine to plan against verdict histories rather than block counters.
