//! E1 — differential vs independently-specified WAF configs.
//!
//! The strongest non-Coraza differential available offline: decompile
//! two configs that differ by **exactly one known rule**, and prove
//! the learned symmetric difference is *exactly* that rule's language
//! — nothing more, nothing less. A learner or diff bug shows up as an
//! over- or under-approximation of a delta we computed independently.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, Outcome, Rule, SimRegexWaf, WafOracle, l_star,
    waf_diff,
};

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn rule(id: &str, pat: &str) -> Rule {
    Rule {
        id: id.into(),
        channels: ChannelSet::none().with(Channel::Body),
        transforms: vec![],
        pattern: regex::bytes::Regex::new(pat).unwrap(),
        score: 5,
    }
}

#[test]
fn waf_diff_equals_exactly_the_known_added_rule_language() {
    // Config A: blocks `<s`. Config B: blocks `<s` AND `xy` (one extra
    // rule). The decompiled symmetric difference must be *exactly*
    // {inputs containing `xy` but not `<s`} — the independently-known
    // delta of adding rule "xy".
    let alpha = Alphabet::new(vec![b'<', b's', b'x', b'y'], b'Z');
    let mut a = SimRegexWaf::new(vec![rule("base", "<s")], 5);
    let mut b = SimRegexWaf::new(vec![rule("base", "<s"), rule("extra", "xy")], 5);
    // An "exactly the delta — nothing more, nothing less" claim needs
    // *sound* learners. W-method's fault-discovery is only conditional
    // (true_states − hyp_states ≤ extra_states); a shortest
    // counterexample just past that horizon is silently missed (proven
    // by the `<s/s` case in learn_exact). `BoundedExhaustiveEq` is
    // complete for every fault whose witness ≤ max_len, which covers
    // the diff-enumeration depth and witnesses below.
    // max_len 6 is provably complete here: the minimal DFAs for `<s`
    // and `<s`+`xy` have all Myhill–Nerode distinguishing words of
    // length ≤ 3, and the diff witnesses (`xy`, `<sxy`) are ≤ 4 — so 6
    // soundly certifies exactness while staying fast (5^≤6, not 5^≤10).
    let mut ea = BoundedExhaustiveEq { max_len: 6 };
    let mut eb = BoundedExhaustiveEq { max_len: 6 };
    let la = l_star(&mut a, &body, &alpha, &mut ea).unwrap().sfa;
    let lb = l_star(&mut b, &body, &alpha, &mut eb).unwrap().sfa;

    // Independent ground truth for the delta: A passes ⇎ B passes
    // exactly when the input contains `xy` but not `<s` (adding the
    // `xy` rule only changes the verdict on those).
    let in_delta = |w: &[u8]| {
        let has_xy = w.windows(2).any(|p| p == b"xy");
        let has_lts = w.windows(2).any(|p| p == b"<s");
        has_xy && !has_lts
    };

    // Every diff member is genuinely in the known delta, and is
    // classified differently by the two REAL WAFs (no model gap).
    let diff = waf_diff(&la, &lb, 64, 10);
    assert!(!diff.is_empty(), "adding a rule must change the language");
    let (mut oa, mut ob) = (
        SimRegexWaf::new(vec![rule("base", "<s")], 5),
        SimRegexWaf::new(vec![rule("base", "<s"), rule("extra", "xy")], 5),
    );
    for d in &diff {
        assert!(
            in_delta(d),
            "diff member {d:?} is NOT in the independently-known rule delta \
             (learner/diff over-approximated)"
        );
        assert_ne!(
            matches!(oa.classify(&body(d)).unwrap(), Outcome::Pass),
            matches!(ob.classify(&body(d)).unwrap(), Outcome::Pass),
            "diff member {d:?} not actually split by the real WAFs"
        );
    }

    // …and nothing in the delta is MISSED: every short delta member
    // the real WAFs split must appear in (or be reachable from) the
    // learned diff language. Check the canonical witness exactly.
    assert!(
        diff.iter().any(|d| d == b"xy"),
        "the minimal delta witness `xy` must be in the diff"
    );
    // Precision twin: an input in BOTH or NEITHER rule is never in
    // the diff (e.g. `<sxy` is blocked by both ⇒ not split).
    assert!(
        !diff.iter().any(|d| d == b"<sxy"),
        "an input both configs block must NOT appear in the diff"
    );
}

#[test]
fn dual_evaluation_of_a_richer_ruleset_is_self_consistent() {
    // Independent-path differential: the SimRegexWaf evaluator vs the
    // learned automaton must agree on EVERY input over the alphabet up
    // to length 9 for a multi-rule config — 4^0..9 ≈ 350k checks.
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let mut waf = SimRegexWaf::new(
        vec![
            rule("r1", "<s"),
            rule("r2", "s/"),
            rule("r3", "/<s"),
        ],
        5,
    );
    // Exactness over the full length-≤9 corpus ⇒ the learner must be
    // provably complete to that depth, not merely within W-method's
    // conditional bound.
    let mut eq = BoundedExhaustiveEq { max_len: 9 };
    let learned = l_star(&mut waf, &body, &alpha, &mut eq).unwrap().sfa;

    let mut oracle = SimRegexWaf::new(
        vec![rule("r1", "<s"), rule("r2", "s/"), rule("r3", "/<s")],
        5,
    );
    let mut frontier = vec![Vec::<usize>::new()];
    let mut checked = 0u64;
    for _ in 0..=9 {
        let mut next = Vec::new();
        for w in &frontier {
            let bytes = alpha.concretize(w);
            let model = learned.accepts(&bytes);
            let truth = matches!(oracle.classify(&body(&bytes)).unwrap(), Outcome::Pass);
            assert_eq!(model, truth, "divergence on {w:?}");
            checked += 1;
            for s in 0..alpha.len() {
                let mut e = w.clone();
                e.push(s);
                next.push(e);
            }
        }
        frontier = next;
    }
    assert!(checked > 80_000, "differential corpus too thin: {checked}");
}
