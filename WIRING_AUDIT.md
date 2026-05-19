# WIRING_AUDIT — wafrift-wafmodel end-to-end

Method: source read first, then verification commands. Findings in
`SEVERITY | file:line | defect | fix`. Scope: the new wafmodel engine,
its CLI surface, the equiv bridge, the secbench lane, and the
pre-existing scald / `wafrift scan` consumption the user asked to
re-confirm.

## Verified wiring chain (all green)

1. **wafmodel internal** — every module in `lib.rs` is landed complete
   and re-exported; each has a green truth-suite (14 contract test
   files + scale corpus + e2e). No module is declared before it is
   implemented.
2. **equiv bridge → grammar::equiv** — `equiv_bridge` produces the
   canonical `wafrift_grammar::grammar::equiv::EquivPayload` with the
   existing `DeliveryShape`. Proven by `equiv_bridge_contract`: the
   bridge members flow through the *same* `m.delivery.to_request(t,
   &m.payload)` loop as `xss_delivered()` with zero per-member handling
   change. The published `DeliveryShape` enum and its 6-point invariant
   are **untouched** (no enum ripple).
3. **CLI** — `crates/cli/src/main.rs:496-497` dispatches
   `Commands::Audit`/`Harden` to `wafmodel_cmd`. e2e_wafmodel (4/4)
   drives the real binary, zero-config.
4. **secbench lane** — `crates/corpus/wafrift/tests/wafmodel_lane.rs`
   runs the wafmodel decode-mismatch corpus through the real
   `GatedSite` + canary anti-rig gate. CORPUS.SHA256 re-pinned in the
   same change (the prior CI corpus-pin-drift lesson applied).
5. **scald (pre-existing, re-confirmed)** —
   `scald-core/src/waf_delivery.rs:40-41` iterates `xss_delivered()` +
   `to_request()`; invoked at `reflected.rs:405` as the terminal
   escalation tier. Generic over `EquivPayload` ⇒ a `=0.2.x` repin
   absorbs bridge/solver members with zero scald code change.
6. **wafrift scan (pre-existing, re-confirmed)** —
   `cli/src/scan/mod.rs:576` wires `run_equiv_cegis` +
   `build_live_request_for_delivery` (the equiv moat in `scan`).
7. **0.2.17 invariant intact** — `enforce_transport_legal(&mut out)`
   present at the tail of all 10 equiv generators (grammar generators
   not modified by this work).

## Findings

- `INFO | crates/wafmodel/src/sfa.rs:253 | unreachable!() in step()` —
  not a stub: provably unreachable given the constructor-enforced
  totality invariant; documented. No action.
- `INFO | equiv_bridge / scald | scald repin is the one external
  action` — picking up bridge/solver members in scald is a one-line
  `=0.2.x` Cargo repin, gated on a wafmodel/wafrift crates.io publish
  (user-authorized). Not a defect; a documented integration boundary,
  identical in nature to the 0.2.17→scald path.
- `NONE (HIGH/MED/LOW)` — stub sweep (`todo!`/`unimplemented!`/
  `panic!("not…")`/`return Vec::new()` stub/`Ok(vec![])` stub) over
  `crates/wafmodel/src` + `cli/wafmodel_cmd.rs`: zero hits. Rigged-test
  sweep (`assert!(!x.is_empty())`-only) over `crates/wafmodel/tests`:
  zero hits. Every contract test names exact strings/counts and pairs
  a positive with a sanitized negative twin / anti-rig ledger.

## Anti-rig posture (load-bearing, verified by test)

- Learner: exact recovery vs ground-truth + differential L\*↔KV.
- Mining: every mined bypass replays as a real PASS + real attack-class
  member; full-coverage WAF ⇒ zero (no fabrication).
- Solver: double-URL / JSON bypass *discovered* from the pipeline;
  honest `None` when unbypassable; never invents a bypass.
- ML-WAF: manifold projection = the soundness oracle; off-manifold
  candidates are discarded, never a "win"; manifold-covering WAF ⇒
  `None`.
- Defense: `proven_closed` ⇒ re-measured holes 0 ∧ benign FP 0; rules
  load-bearing (removal reopens exactly the holes).
- Scale: the above invariants hold across 1000 deterministic configs +
  1200 randomized proptest configs.

Verdict: **wired end-to-end, no stubs, no rigged tests, no
HIGH/MED/LOW defects.**
