# wafrift paradigm shift — decompile → solve → dominate

Status: ACTIVE. Owner: CC. Branch: `main` (wafrift's own repo; never feature-branch).
Publish: gated on explicit user authorization (not granted).

## Thesis

Today wafrift is a sound mutation-fuzzer that *searches* a black box. The
paradigm shift makes it a **solver over learned, composed formal models of
the entire request pipeline** — evasion becomes deduction, and the byproduct
(the model) becomes the first WAF formal-auditing product.

Three pillars, each bootstrapped by something wafrift already has.

### P1 — Decompile (`crates/wafmodel` → `wafrift-wafmodel`)

Active-learn the WAF as a symbolic finite automaton (TTT/L\*) over a
`WafOracle`. Repurpose the Phase-C bandit as the *membership-query budget
minimizer* (info-gain equivalence sampling), not the bypass strategy. Emit
the learned automaton as a Tier-B artifact with provenance + PAC bound.
Mine bypasses *offline* by intersecting learned-pass-language with the
attack grammar (pure-Rust always; vyre/GPU optional accel). Fingerprint
ruleset@paranoia with a ~log(rulesets) discriminating probe sequence.

### P2 — Solve (composition + preimage)

Each pipeline stage (cdn-normalize, waf-view, proxy, framework-parse,
sink, browser-parse) is a finite-state transducer wrapping the decoders
wafrift already owns. A bypass is any `x` with `waf_view(x) ∈ pass` ∧
`sink(framework_parse(x))` reconstructs the attack ∧ `transport_legal(x)`.
CEGIS over the composed transducers with the real oracles as
counterexample source. The double-URL-decode trick is *rediscovered from
first principles*, not hard-coded — and so is every other normalization
mismatch. Output flows into `grammar::equiv` as a new generic source:
scald + `wafrift scan` consume it through the SAME `xss_delivered` /
`to_request` API with **zero downstream code change** (same architectural
invariant as 0.2.17 Header/Cookie).

### P3 — Dominate both edges

- **Offense (ML-WAFs):** decision-based boundary attack constrained to
  the executable-attack manifold; the projection-onto-feasible operator
  *is* wafrift's soundness oracle. Paradigm-correct for ML-WAFs, not just
  regex-WAFs.
- **Defense (the dual):** from the learned model, compute holes
  (`model_pass ∩ attack_grammar`), synthesize the *minimal* closing rules,
  verify zero new false positives against a benign corpus, and **prove**
  the class is closed (`intersection = ∅`). Surfaced as
  `wafrift audit` / `wafrift harden`.

## Non-negotiables

- No stubs, no `todo!()`, no `!is_empty()` tests, no rigged payloads. Every
  truth-asserting test names exact strings/counts and has a sanitized
  negative twin (CLAUDE.md test contract, all 10 types per crate).
- Zero-config: works on `cargo install wafrift` with no GPU, no external
  Coraza, no env. GPU/vyre and external engines are optional accel only.
- The learner's correctness is asserted against a ground-truth WAF whose
  language we control (exact equivalence + PAC), not against itself.
- Thousands of tests: generated WAF-config / attack-grammar /
  normalization-mismatch corpora, regression-gated scorecard.
- secbench gets a first-class decompilation/mining/hardening lane.
- Deep end-to-end wiring audit (`WIRING_AUDIT.md`, SEVERITY|file:line|fix).

## Task spine

See task list #14–#34. Order: P0 scaffold → P1 (oracle→SFA→learner→
query-strategy→artifact→miner→fingerprint) → P2 (transducers→solver→
equiv-wire) → P3 (offense, defense, CLI) → tests (truth-suites→contract→
scale fan-out) → secbench lane → wiring audit → workspace+CI green.
End to end. No deferral.
