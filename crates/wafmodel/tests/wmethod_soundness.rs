//! E1/E7 — pinned finding: **W-method conformance testing is only
//! *conditionally* complete**, and every exactness claim in this crate
//! must therefore be driven by a *provably* complete oracle.
//!
//! History: the triple-learner differential once used
//! `WMethodEq{extra_states:2}` to assert L\* / KV / passive all recover
//! the exact language. For the self-overlapping pattern `<s/s` the
//! first L\* hypothesis has **1** state, the target minimal DFA has
//! **5**, and the shortest counterexample is `<s/s` itself (length 4) —
//! strictly outside W-method{2}'s `state_cover · Σ^{≤3} · W` horizon.
//! W-method found no counterexample and *silently certified the trivial
//! 1-state "accept-everything" automaton as exact*. `passive_learn`
//! (the bounded-RPNI learner) recovered the correct 5-state DFA, so the
//! defect was the differential feeding L\*/KV an oracle too weak to
//! prove the property it asserted — a **false green**, not a learner
//! bug.
//!
//! This test pins all three facts so they can never silently regress:
//!   1. `WMethodEq{2}` genuinely *fails* to recover `<s/s` (the
//!      limitation is real — nobody may over-claim W-method, and the
//!      test is non-vacuous).
//!   2. `BoundedExhaustiveEq` (complete for any fault ≤ `max_len`)
//!      recovers it exactly.
//!   3. `passive_learn` (no equivalence oracle at all — a fixed
//!      complete test-suite, bounded |states|) recovers it exactly and
//!      *terminates*.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, Outcome, Rule, SimRegexWaf, WMethodEq, WafOracle,
    kv_learn, l_star, passive_learn,
};

fn jb(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn waf(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "gt".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}
fn truth(pat: &str, alpha: &Alphabet, w: &[usize]) -> bool {
    matches!(
        waf(pat).classify(&jb(&alpha.concretize(w))).unwrap(),
        Outcome::Pass
    )
}
fn words(k: usize, max: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    let mut fr = vec![vec![]];
    for _ in 0..max {
        let mut nx = Vec::new();
        for w in &fr {
            for s in 0..k {
                let mut e = w.clone();
                e.push(s);
                nx.push(e.clone());
                out.push(e);
            }
        }
        fr = nx;
    }
    out
}

const PAT: &str = "<s/s";

#[test]
fn wmethod2_provably_underlearns_the_self_overlap_pattern() {
    // The limitation is REAL: assert W-method{2} does NOT recover the
    // language (and is in fact the degenerate 1-state hypothesis). If
    // someone strengthens W-method this test must be revisited
    // deliberately — it is not allowed to pass by accident.
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let mut w = waf(PAT);
    let mut wm = WMethodEq { extra_states: 2 };
    let learned = l_star(&mut w, &jb, &alpha, &mut wm).unwrap().sfa;

    // It collapsed to the trivial automaton…
    assert_eq!(
        learned.len(),
        1,
        "W-method{{2}} unexpectedly grew the hypothesis — the pinned \
         under-learning finding changed; re-audit every exactness test"
    );
    // …and the trivial automaton is wrong on the witness `<s/s`.
    // `Alphabet::new` SORTS the distinguished bytes, so the class
    // indices are `/`=0, `<`=1, `s`=2, catch-all=3 ⇒ `<s/s` = [1,2,0,2]
    // (verified: concretize([1,2,0,2]) == b"<s/s").
    let w4 = vec![1usize, 2, 0, 2];
    assert_eq!(alpha.concretize(&w4), b"<s/s", "witness must be `<s/s`");
    assert!(
        learned.accepts(&alpha.concretize(&w4)),
        "1-state hypothesis must accept-all (it does not even know `<s/s`)"
    );
    assert!(
        !truth(PAT, &alpha, &w4),
        "ground truth blocks `<s/s` — the divergence is real"
    );
}

#[test]
fn sound_oracle_and_passive_both_recover_the_exact_language() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');

    // (2) BoundedExhaustiveEq is complete to its depth ⇒ L* & KV exact.
    let mut w1 = waf(PAT);
    let mut e1 = BoundedExhaustiveEq { max_len: 8, max_queries: None };
    let la = l_star(&mut w1, &jb, &alpha, &mut e1).unwrap().sfa;
    let mut w2 = waf(PAT);
    let mut e2 = BoundedExhaustiveEq { max_len: 8, max_queries: None };
    let kv = kv_learn(&mut w2, &jb, &alpha, &mut e2).unwrap().sfa;

    // (3) passive_learn uses NO equivalence oracle — a fixed complete
    // test-suite with |states| ≤ |suite|; it must terminate AND be
    // exact for depth ≥ the Myhill–Nerode bound (4 here; we give 7).
    let mut w3 = waf(PAT);
    let pv = passive_learn(&mut w3, &jb, &alpha, 7).unwrap().sfa;

    // The non-trivial automaton actually distinguishes states.
    assert!(la.len() >= 4, "exact DFA for `<s/s` is ≥4 states");
    assert!(la.equivalent(&kv), "L* and KV must agree (sound oracle)");
    assert!(la.equivalent(&pv), "passive must equal the sound L* result");

    // Exact vs the real WAF on every word up to length 8 (well past
    // the 4-state MN bound) — and the pinned witness is now correct.
    for c in words(alpha.len(), 8) {
        let t = truth(PAT, &alpha, &c);
        let conc = alpha.concretize(&c);
        assert_eq!(la.accepts(&conc), t, "L* {c:?}");
        assert_eq!(kv.accepts(&conc), t, "KV {c:?}");
        assert_eq!(pv.accepts(&conc), t, "passive {c:?}");
    }
    let w4 = vec![1usize, 2, 0, 2]; // `<s/s` (sorted-alphabet indices)
    assert_eq!(alpha.concretize(&w4), b"<s/s");
    assert!(
        !pv.accepts(&alpha.concretize(&w4)),
        "`<s/s` must be blocked"
    );
}
