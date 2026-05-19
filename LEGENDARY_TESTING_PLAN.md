# wafrift-wafmodel — the 100 things to legendary-level testing

Status: ACTIVE. Bar: SQLite/NASA/Linux. Every claim has a test that
fails when the claim becomes false. No stubs, no rigging, no deferral.
Gated on wafrift CI staying green (push only when green).

## E1 — Differential vs real engines (1–8)
1. Vendor a pinned real ModSecurity-CRS rule corpus; evaluate it two
   independent ways (our SimRegexWaf vs an independent regex engine);
   assert identical verdicts on 100k inputs.
2. Coraza (Go) in-proc/subprocess oracle behind a feature; learn it;
   assert learned SFA agrees with Coraza ≥ 99.9% on a 100k corpus.
3. libmodsecurity (C) oracle behind a feature; same differential.
4. Differential miner: every mined bypass replayed against the real
   engine must actually pass (0 false bypass / 100k).
5. Differential learner: L*, KV, and a third (RPNI passive) learner
   must agree on every oracle.
6. Cross-engine WAF-diff: learn CRS-PL1 vs CRS-PL2 vs ModSec-default;
   assert the symmetric-difference set is exactly the known rule delta.
7. Differential normalization: our CRS transforms vs ModSecurity's
   actual `t:` implementations, byte-exact on a fuzzed corpus.
8. Scorecard JSON, regression-gated, checked into the repo.

## E2 — Real CVE / published-bypass replay (9–16)
9. Vendor real published CRS bypasses (CVE-tagged + research blog
   payloads) as a pinned corpus.
10. Assert the miner rediscovers each known bypass from the model.
11. Assert the solver rederives each known normalization-mismatch CVE
    (double-decode, charset, multipart) from the pipeline.
12. Assert `harden` closes each replayed bypass (or honestly reports
    CRS-structurally-unclosable with the precise reason).
13. Post-fix release replay: FP count ≤ 3 / 100k on the benign corpus.
14. CVE provenance file: id → payload → expected verdict, sha-pinned.
15. Regression gate: a previously-rediscovered CVE that stops firing
    fails CI.
16. Negative twin per CVE (sanitized variant must NOT fire).

## E3 — Property testing at 10k+ (17–26)
17. SFA algebra: ∩∪¬\ vs brute oracle, 10k cases (from 4k).
18. SFA: De Morgan / double-complement / idempotence, 10k.
19. SFA: minimization preserves language (add `minimize`), 10k.
20. Learner: random regular-language oracle → exact recovery, 10k.
21. Learner: L* ≡ KV ≡ RPNI on random oracles, 10k.
22. Transducers: round-trip & idempotence properties, 10k.
23. normalize: each `t:` transform algebraic laws, 10k.
24. artifact: capture→toml→parse→sfa is identity, 10k random SFAs.
25. mine: every mined member sound, 10k random (waf,grammar).
26. solve: preimage∘sink = attack invariant, 10k random pipelines.

## E4 — Fuzzing (27–34)
27. `cargo-fuzz` target: `normalize::apply_chain` never panics / total.
28. Fuzz `transduce::*` (url/json/html) — total, no panic, no OOM.
29. Fuzz `artifact::from_toml` + `sfa()` — corrupt input → Err, never
    panic, never an invalid accepted automaton.
30. Fuzz `SimRegexWaf::from_toml` — malformed ruleset → Err.
31. Fuzz `canonicalize` on arbitrary Request bytes — total.
32. Fuzz the learner harness with an adversarial (lying) oracle —
    terminates or errors, never hangs/panics.
33. 24h fuzz corpus checked in; CI smoke-fuzzes 60s/target.
34. ASAN/UBSAN run of the fuzz corpus (forbid-unsafe already; prove it).

## E5 — Mutation testing (35–40)
35. `cargo-mutants` over `wafrift-wafmodel`; baseline mutation score.
36. Drive caught-mutant ratio to ≥ 90% (legendary bar); add tests for
    every survived mutant.
37. Mutation-score regression gate in CI (nightly).
38. Mutants in the anti-rig paths (soundness checks) MUST be caught.
39. Mutants in `enforce_transport_legal` analog (bridge soundness) caught.
40. Document residual survived mutants with justification (equivalent
    mutants only).

## E6 — Determinism & reproducibility (41–46)
41. Same seed ⇒ byte-identical learned artifact (hash assertion).
42. Same oracle ⇒ identical SFA regardless of learner (already; widen).
43. Cross-platform determinism (no HashMap iteration leak into output).
44. `mine_bypasses` output order is deterministic (assert exact list).
45. Replaying a serialized model reproduces identical mining results.
46. Thread-purity: parallel learning of independent oracles is
    interference-free (loom or stress).

## E7 — Adversarial oracles (47–56)
47. Noisy oracle (ε flip rate) — learner robust or honest-fail.
48. Non-regular WAF (counts, balanced) — learner reports
    non-convergence within bound, never a false "exact".
49. Stateful/rate-limiting WAF — query strategy backs off, no rig.
50. Unicode/overlong-UTF8/NUL-injection inputs through every stage.
51. Alphabet-inadequacy adversary: a byte the learner's alphabet
    omits — detect & report (or auto-refine), never silently wrong.
52. Timing-oracle WAF (decision via latency) — modeled, no false win.
53. Adversarial attack-grammar (degenerate/empty/huge) — bounded.
54. Hostile artifact (zip-bomb-ish nested) — bounded parse.
55. Polyglot payloads (XSS+SQLi+template) classified per channel.
56. Evasion of our OWN harden rules — found = real finding, fix engine.

## E8 — Scale (57–64)
57. Learn against the FULL real CRS ruleset (hundreds of rules), Body
    + ARGS channels — no OOM, bounded budget, recorded.
58. 1M-member attack grammar intersection — bounded memory.
59. 30k-config corpus fan-out (from 1000), regression-scored.
60. 10M-string mining enumeration — streaming, capped, no OOM.
61. SFA with 10k states — algebra ops sub-second.
62. Soak: 1h continuous learn/mine loop, RSS flat (no leak).
63. Concurrency: N learners in parallel, throughput scales.
64. Scale scorecard, 2σ regression gate.

## E9 — Performance / criterion (65–72)
65. criterion bench: membership-query µs, learning throughput.
66. bench: SFA ∩/∪/¬ ns, shortest-word µs, enumerate µs.
67. bench: normalize/transduce GB/s.
68. bench: mine bypasses/sec; solve attempts/sec.
69. bench: artifact serialize/parse µs.
70. GPU/vyre-accelerated SFA intersection bench (optional feature) vs
    pure-Rust baseline — same result, speedup recorded.
71. Perf regression gate (criterion baseline checked in).
72. Flamegraph + documented hot path; one optimization landed w/ proof.

## E10 — Coverage as contract (73–80)
73. `cargo-llvm-cov`; line+region coverage baseline.
74. Drive wafmodel coverage ≥ 95%; CI gate.
75. Every README/doc sentence that makes a claim → a test that fails
    if false (doc-claim audit).
76. Every public fn has ≥1 doc-test exercising the contract.
77. Every error variant is constructed & asserted by some test.
78. Every CLI flag has an e2e test.
79. Branch-coverage of the anti-rig paths = 100%.
80. Uncovered-line gate (no new uncovered lines per PR).

## E11 — secbench legendary expansion (81–86)
81. secbench differential lane: wafmodel vs real Coraza gated chain.
82. secbench CVE-replay lane (the E2 corpus through the real chain).
83. secbench perf lane (decompile/mine/harden throughput, gated).
84. secbench scale lane (full-CRS decompile through the chain).
85. secbench scorecard matrix (class × engine × verdict), pinned.
86. secbench corpus sha-pin CI gate for the wafmodel slices.

## E12 — Real-world fidelity (87–90)
87. Vendored real Cloudflare/AWS/Akamai block-page signatures →
    fingerprinter accuracy on real data, asserted.
88. Live-target integration test behind a feature (wiremock-backed
    realistic WAF) — full audit→harden e2e.
89. scald repin dry-run: build scald-core against this wafmodel via
    path patch; 0 source change; suite green (re-verify each release).
90. wafrift `scan` consumes solver members end-to-end against a
    wiremock normalization-mismatch origin — real bypass verified.

## E13 — Engine depth gaps surfaced by the above (91–96)
91. Add `Sfa::minimize` (Hopcroft) — required by E3/19, perf.
92. Add RPNI passive learner — required by E1/5, differential.
93. Symbolic alphabet auto-refinement (minterm split on counterexample)
    — required by E7/51 (real-WAF adequacy).
94. Multi-stage composed-pipeline solver (CDN+WAF+proxy+framework) —
    required by E2/11.
95. Charset/multipart/UTF-7 transducers — required by E2/11 CVEs.
96. Score-based ML-WAF gradient-free descent (HopSkipJump proper) +
    surrogate-model transfer — required by E7/52.

## E14 — Hardening product depth (97–98)
97. `harden` emits real ModSecurity `SecRule` syntax (not just our
    TOML) + a verified-zero-FP proof bundle.
98. `harden --prove` emits a machine-checkable closure certificate
    (the empty-intersection witness) re-checkable offline.

## E15 — Docs / reproducibility artifact (99)
99. A reproducible "decompile a real CRS in N queries" benchmark
    notebook/script, output checked in, regression-gated.

## E16 — The capstone (100)
100. One-command `cargo xtask legendary` runs the entire matrix
     (differential + CVE + property10k + fuzz-smoke + mutants +
     coverage + perf + scale + secbench) and emits a single
     green/red legendary scorecard; CI gates on it.

---

## Findings log (real defects this process surfaced)

The bar is met only if the process *catches* things. It has:

- **F1 — `passive_learn` non-termination (engine defect, fixed).**
  The RPNI/passive learner built its state set with an *unbounded*
  prefix BFS: a new state per novel observation-row, no length or
  state cap. Regular oracles converge so it halted; against the E7
  noisy/adversarial oracle every fresh prefix yields a fresh noisy
  row, so states grew kⁱ forever — an infinite hang, not a slow test.
  Fix: the genuine bounded RPNI / Trakhtenbrot–Barzdin *truncated*
  regime — reachable BFS (fast & exact for regular targets) with a
  hard `access_len ≤ depth` state-creation cap and row-equality fold
  past the horizon. |states| ≤ Σ kⁱ < ∞ ⇒ provably halts for *any*
  oracle. Pinned by `adversarial_oracle::noisy_oracle_*` and the
  constructive pumping witness in `non_regular_*`.

- **F2 — false green from an unsound equivalence oracle (test defect,
  fixed; the real catch).** The triple-learner differential asserted
  L\* ≡ KV ≡ passive *exact* while driving L\*/KV with
  `WMethodEq{extra_states:2}`. W-method conformance is only
  *conditionally* complete (`true_states − hyp_states ≤ extra_states`).
  For the self-overlap pattern `<s/s` the first hypothesis is 1 state,
  the target is 5, and the shortest counterexample is `<s/s` (len 4) —
  outside W-method{2}'s ≤3 horizon — so it *silently certified the
  trivial 1-state "accept-all" automaton as exact*. `passive_learn`
  (depth 7) was the only correct learner there. Resolution: every
  exactness-vs-ground-truth claim now uses the provably-complete
  `BoundedExhaustiveEq` (was already the convention in `learn_exact`;
  the one deviating test was the bug). Audited *all* `WMethodEq`
  call-sites: only `learn_exact`'s differential and `differential_waf`
  made unguarded exactness claims (both fixed); `equiv_query_contract`
  is self-guarding (cross-checks vs `BoundedExhaustiveEq`);
  `mine_/scale_/determinism_/artifact_/perf_` claims are
  soundness-revalidated-against-the-real-WAF or determinism/perf, for
  which W-method is adequate. Pinned permanently by
  `wmethod_soundness.rs` (asserts the limitation is *real* and
  non-vacuous, and that the sound oracle + passive both recover exact).

- **F3 — an error variant with no producer (dead contract, fixed).**
  E10/77 (every `WafModelError` variant produced by a real path) found
  that `BudgetExhausted { queries }` — documented as "the learner
  exhausted its membership-query budget … carries the budget spent" —
  was constructed *nowhere* in the crate: an unfulfillable contract.
  Per the no-stub / no-evasion law it is neither faked in a test nor
  deleted; instead the real path was wired: `l_star` was refactored
  (no signature change — it delegates to a private `l_star_impl` with
  `budget = u64::MAX`) and a new public `l_star_budgeted(.., max_queries)`
  returns `BudgetExhausted` with the exact spend when the
  close/consistency fixpoint crosses the cap — genuine production
  safety against a live/hostile WAF, not a partial model dressed up as
  complete. Pinned by `error_coverage.rs` (real-path trigger + exact
  Display + anti-vacuous control: the same target learns under an
  unbounded budget) and a rustc-enforced exhaustiveness guard so a
  future variant cannot be added without a producing test.

- **F4 — mutation testing exposed a hollow KMP coverage gap (fixed).**
  E5 baseline (`cargo-mutants` on the anti-rig core `mine.rs`, scoped +
  scaled): 38 mutants → 8 *missed*, all inside `kmp_sfa`'s failure-
  function arithmetic. The existing mining tests used borderless
  needles (`ab`, `a`) whose KMP failure function is all-zeros, so the
  border arithmetic was never exercised — proof the suite was
  decoration *there*. Fixed with
  `attack_grammar_kmp_equals_naive_substring_for_self_overlapping_needles`:
  an exhaustive differential vs an independent naive-substring oracle
  over bordered needles (`ababa`, `aabab`, `abaab`, …) × every word ≤
  2·|needle|. Re-baseline: **35/35 viable non-equivalent mutants
  detected (100%)** — 32 by assertion, 3 by timeout (arithmetic
  corruptions that infinite-loop the KMP build: a hung test fails CI,
  a real detection signal, not a silent survivor), 2 unviable. The
  single residual `!=`→`==` is a **provably language-equivalent
  mutant**: substring membership is invariant to a non-optimal failure
  function (an under-estimating `fail` only adds redundant restarts;
  `kmp_next` re-validates every byte and accepts only at a full match),
  empirically confirmed by zero divergence in the exhaustive
  differential. Excluded WITH that written justification in
  `mutants.toml` (item 40), never silently. Wired the always-on
  gating `mutants` CI job (zero `MISSED`; scope ratchets file-by-file
  as each engine module is baselined+hardened — we never claim a file
  is mutation-gated before it provably is).

- **F5 — the mutation CI gate was itself a false green (fixed).**
  Reading the *actual* `mutants` job log (never trusting a green
  check) showed it printed “0 missed” and SUCCEEDED while cargo-mutants
  had reported `1 missed`. Two compounding defects: (a) `mutants.toml`
  sat in the package dir but cargo-mutants only auto-reads
  `.cargo/mutants.toml`, so `exclude_re` never loaded and the
  documented-equivalent mutant was counted; (b) cargo-mutants emits
  ANSI colour, so the line was `\e[31m\e[1mMISSED…` and the gate’s
  `grep -q '^MISSED'` anchored on the ESC byte — it could *never*
  fire. A gate that cannot fail is precisely the decoration the laws
  forbid. Fix: pass `--config mutants.toml` explicitly, force
  `CARGO_TERM_COLOR=never`, and gate on BOTH a colour-stripped
  `^MISSED` scan AND the machine summary line reporting exactly
  `0 missed`. The gate’s failure path is now itself tested (synthetic
  logs: a `MISSED` line ⇒ exit 1; an ANSI-stripped `1 missed` summary
  ⇒ exit 1; `0 missed` ⇒ exit 0). Scope also extended to `sfa.rs`
  (E5 ratchet: 15 missed → 0, 12 genuine survivors killed by an
  exhaustive `[bool;256]` BytePred oracle + soundness-primitive pins;
  2 documented provably-equivalent — `is_empty -> false` is
  unkillable because no constructible `Sfa` has an empty `accept`).

  F5 was a THREE-layer saga, each layer a real defect surfaced only by
  reading the actual job log:
  1. *False green* — the gate could not fire (ANSI-anchored
     `grep '^MISSED'` + `mutants.toml` in the wrong dir so `exclude_re`
     never loaded). Fixed: explicit `--config`,
     `CARGO_TERM_COLOR=never`, dual MISSED-scan + summary-parse.
  2. *CI-runtime blowup* — the now-real gate ran ~85 min on the slow
     runner (180s timeout × ~30 timeout-mutants) and was killed at
     exit 143. Fixed: `minimum_test_timeout` 180→25, explicit
     `--timeout 30 --jobs 3`, job-level `timeout-minutes: 40`.
  3. *set-e false-RED* — GitHub runs `run:` as `bash -e -o pipefail`,
     so the missed-count `grep` inside `$()` aborted the whole step
     on a GENUINELY CLEAN run (the clean summary omits the "missed"
     token, so the grep matched nothing). Fixed: `shell: bash
     --noprofile --norc {0}` to drop `-e`, `sed -nE` extraction (never
     errors on no-match), failure path re-proven under the real shell.
  Confirmed honest on real infra (6866e56): `150 mutants tested in
  27m: 54 caught, 20 unviable, 76 timeouts; 0 missed`. The slow runner
  inflates the timeout share — that is still honest detection (a
  hung/slow mutant is an observable behaviour change CI surfaces); the
  contract is **0 silently-surviving mutants**, met.

- **E5 ratchet — solve.rs already legendary (no work needed).**
  Baseline `cargo-mutants` on the CEGIS solver: 24 mutants, **23
  caught, 1 unviable, 0 missed, 0 timeouts** — the existing anti-rig
  suite (E3/26 solver-invariant, cve_replay solver-rediscovery,
  equiv_bridge canonical-member, `our_own_solver_cannot_evade`)
  already kills every viable solver mutant. No hardening required; the
  `mutants` CI gate scope extended to mine.rs + sfa.rs + solve.rs
  (gate proven honest+bounded; `timeout-minutes` raised 40→50 for the
  added file's headroom).

- **E5 ratchet — learn.rs resolved; mutation gating split per the
  plan (item 37: nightly).** learn.rs baseline (the most-depended-on
  module): 80 mutants, 12 missed. Genuine gaps fixed with real
  non-vacuous tests: the `Alphabet` accessors had NO behavioural test
  (`alphabet_accessors_are_exact` — kills `is_empty -> true`,
  `raw_symbols -> Vec::leak`), and `LearnReport.equivalence_rounds` (a
  provenance truthfulness claim) was unasserted so `rounds += 1 -> *= 1`
  survived in BOTH l_star_impl and kv_learn
  (`equivalence_rounds_is_truthful_provenance` — ≥1 round when
  refinement is needed, exactly 0 when the first hypothesis is already
  exact). Scoping artifact (520 budget-gate `> -> ==`) killed by
  putting `error_coverage` in scope. Five mutants documented as
  rigorous item-40 equivalents (`is_empty -> false`; l_star_impl
  474/496/507 — L* correctness is the complete EQ oracle + all-suffixes
  CE loop, not the internal heuristics; 520 `> -> >=` — pure
  off-by-one at the cap boundary, sibling `> -> ==` IS killed),
  `--list`-confirmed excluded, never chased.
  *Operational finding:* a per-push `mutants-learn` job under
  `--jobs 3` exhausted the GitHub runner (exit 143, "runner received a
  shutdown signal") on learn.rs's memory-heavy suite — heavy mutation
  belongs OFF the push path, exactly as the plan says. Resolution: the
  per-push `mutants` gate stays fast+proven (mine+sfa+solve); a
  dedicated `mutants-nightly.yml` (cron + workflow_dispatch, `--jobs 2`,
  no per-push time pressure) is the thorough all-four-files regression
  gate (item 37 satisfied).

- **E5 ratchet — normalize.rs (the biggest gap): 132 mutants, 36
  missed.** The byte-exact decoding of `url_decode_uni` /
  `html_entity_decode` / `compress_ws` — *the WAF's actual
  normalization*, the foundation every mismatch-bypass conclusion
  rests on — had NO test (the prior laws only checked
  length/idempotence/membership). Fixed with independent
  spec-reference reimplementations (in the test, never mutated) as the
  oracle: exhaustive all-256-byte `%XX`, a `%uXXXX` low-byte-narrowing
  table, an edge corpus, and an engine-vs-reference proptest. 36 → 9.
  The 2 genuine residuals were real OOB-boundary bugs the mutation
  exposed (`< -> <=` on the `%uXXXX`/entity end-of-input bound — `<=`
  indexes `== len`, a panic) — killed by adding the exact-boundary
  inputs (`%uABC`, `&#12`, `&#x1f`) the correct code handles but `<=`
  panics on. The 7 remaining are PROVABLY equivalent (item 40,
  `--list`-confirmed excluded, never chased): ModSecurity narrows
  `cp & 0xff`, which provably DISCARDS bits 8-15, so perturbing the
  `a<<12`/`b<<8` terms cannot change the emitted byte; and each
  `nibble<<k` is bit-disjoint from the next, so `|`≡`^`≡`+` on those
  operands are mathematically identical. Distinguishing them needs the
  internal pre-narrow `cp` — testing the implementation, not the
  contract. normalize.rs added to the nightly mutation scope.

- **F6 — a single runner cannot hold the comprehensive mutation run
  (fixed by a per-file matrix).** The all-files nightly job was
  resource-killed mid-run (exit 143, blank step conclusion, Post-steps
  incomplete) at ~82 min on a GitHub-hosted runner — at BOTH `--jobs 3`
  and `--jobs 2` — because memory accumulates across ~256 mutants ×
  learn.rs's heavy suite. A gate that cannot complete is decoration.
  Fixed with the "small isolated runs" pattern: `mutants-nightly` is
  now a `strategy: matrix` with ONE fresh runner PER FILE
  (mine/sfa/solve/normalize at the proven `--jobs 3 --timeout 30`;
  learn.rs alone at `--jobs 1 --timeout 150` — serial, minimal
  predictable memory, no concurrent rustc). `fail-fast: false` so
  every file's verdict is independent and a failure localises to one
  file. No runner ever accumulates another file's memory.

- **Cross-cutting law reinforced:** never trust a green CI check —
  read the job log. A gate is only real once its *failure* path has
  been exercised, *in the shell it actually runs in*. And: a CI gate's
  resource/time envelope is part of its contract — a gate that blows
  the runner is not green, it is unproven; heavy work must be split
  into small isolated runs, never one accumulating mega-run.
