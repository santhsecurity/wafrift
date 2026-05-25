//! E3/25 + E3/26 — the anti-rig core at 10k.
//!
//! 25. **Mining soundness**: over 10k random (WAF, attack-grammar)
//!     pairs, *every* mined bypass, when replayed against a FRESH real
//!     WAF, genuinely passes AND is genuinely an attack-class member.
//!     One fake bypass = an engine bug. (We never trust the miner's own
//!     word — re-verify on an independent oracle.)
//! 26. **Solver invariant**: over 10k random sink pipelines, whenever
//!     `solve_bypass` returns `Some(s)`, the structural identity
//!     `sink(s.input) == s.sink_view ⊇ attack` holds AND a FRESH real
//!     WAF actually passes `s.input` (active boundary learning verifies internally; we
//!     re-verify independently — the solver may never fabricate). A
//!     `None` is always acceptable; an Identity sink against a WAF that
//!     blocks the raw attack must be `None` (pinned precision twin —
//!     no invented bypass).

use proptest::prelude::*;
use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, Outcome, Pipeline, Rule, SimRegexWaf, Stage, WafOracle, attack_grammar,
    mine_bypasses, passive_learn, solve_bypass,
};

fn pc() -> u32 {
    std::env::var("WAFMODEL_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

fn waf_lit(token: &[u8], tf: &[Transform]) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "r".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: tf.to_vec(),
            pattern: regex::bytes::Regex::new(&regex::escape(&String::from_utf8_lossy(token)))
                .unwrap(),
            score: 5,
        }],
        5,
    )
}

// ── E3/25 ──
// Deliberately a TINY fixed alphabet {a,b,c}+catch-all with ≤2-byte
// needles: the mining-soundness invariant is identical at any size, so
// we keep every one of the 10k cases ~1ms (a 4-char needle over a
// 6-symbol alphabet at depth 6 makes passive_learn rows ~56k entries —
// 10k of those is ~1.8 h, an unacceptable legendary-lane cost, with no
// extra assurance).
const NEEDLES: [&[u8]; 6] = [b"a", b"b", b"ab", b"bc", b"ca", b"ac"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn every_mined_bypass_is_real_and_in_class(
        ni in 0usize..NEEDLES.len(),
        // A second, possibly-different needle widens the attack class.
        mi in 0usize..NEEDLES.len(),
    ) {
        let needle = NEEDLES[ni];
        let other = NEEDLES[mi];
        let alpha = Alphabet::new(vec![b'a', b'b', b'c'], b'Z');

        // A WAF that inspects (transforms applied) but only blocks the
        // single literal `needle` — so `other` is a genuine hole.
        let mut learn_waf = waf_lit(needle, &[Transform::Lowercase]);
        let learned = passive_learn(&mut learn_waf, &body, &alpha, 5).unwrap().sfa;

        let grammar = attack_grammar(&alpha, &[needle, other]);
        for w in mine_bypasses(&learned, &grammar, 16, 8) {
            // (a) SOUND: a FRESH real WAF must actually pass it.
            let mut fresh = waf_lit(needle, &[Transform::Lowercase]);
            prop_assert_eq!(
                fresh.classify(&body(&w)).unwrap(),
                Outcome::Pass,
                "fake bypass: {:?} does not pass the real WAF", w
            );
            // (b) IN-CLASS: it is genuinely an attack-class member.
            prop_assert!(
                grammar.accepts(&w),
                "mined {:?} is not in the attack class", w
            );
        }
    }
}

// ── E3/26 ──
fn stage(i: u8) -> Stage {
    match i % 5 {
        0 => Stage::Identity,
        1 => Stage::UrlDecode {
            plus_is_space: false,
        },
        2 => Stage::DoubleUrlDecode,
        3 => Stage::JsonUnescape,
        _ => Stage::HtmlEntityDecode,
    }
}
const ATTACKS: [&[u8]; 4] = [b"<script", b"<s/s", b"' or", b"<svg"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn solver_never_fabricates_and_respects_the_sink_identity(
        ai in 0usize..ATTACKS.len(),
        stages in proptest::collection::vec(0u8..5, 1..=3usize),
    ) {
        let attack = ATTACKS[ai];
        let sink = Pipeline(stages.iter().map(|&i| stage(i)).collect());
        // Brittle: a SINGLE urlDecodeUni + lowercase. A multi-decode
        // sink is the mismatch the solver may exploit; a no-op sink is
        // not — either way the invariant below must hold.
        let mut waf = waf_lit(attack, &[Transform::UrlDecodeUni, Transform::Lowercase]);

        if let Some(sol) = solve_bypass(attack, &sink, &mut waf, &body).unwrap() {
            // Control: the raw attack really was blocked.
            prop_assert!(sol.raw_attack_blocked, "vacuous: raw attack not blocked");
            // Structural identity: the sink applied to the solved input
            // reproduces exactly the reported sink view…
            prop_assert_eq!(
                sink.apply(&sol.input), sol.sink_view.clone(),
                "sink(input) != reported sink_view"
            );
            // …and that view actually delivers the attack.
            prop_assert!(
                sol.sink_view.windows(attack.len()).any(|w| w == attack),
                "sink_view {:?} does not contain the attack {:?}",
                sol.sink_view, attack
            );
            // INDEPENDENT re-verification (never trust the solver):
            // a FRESH real WAF must pass the solved input.
            let mut fresh = waf_lit(attack, &[Transform::UrlDecodeUni, Transform::Lowercase]);
            prop_assert_eq!(
                fresh.classify(&body(&sol.input)).unwrap(),
                Outcome::Pass,
                "solver fabricated: fresh WAF blocks the 'bypass' {:?}", sol.input
            );
        }
    }
}

#[test]
fn identity_sink_yields_no_fabricated_bypass_pinned_twin() {
    // Precision twin: with an Identity sink the WAF sees exactly what
    // the sink delivers, so a blocked attack is genuinely unbypassable
    // — the solver MUST return None, never an invented input.
    let attack = b"<script";
    let mut waf = waf_lit(attack, &[Transform::Lowercase]);
    let sink = Pipeline(vec![Stage::Identity]);
    let sol = solve_bypass(attack, &sink, &mut waf, &body).unwrap();
    assert!(
        sol.is_none(),
        "Identity sink must yield no bypass, got {sol:?} (fabrication)"
    );
    // Anti-vacuous: the raw attack truly is blocked here.
    let mut w2 = waf_lit(attack, &[Transform::Lowercase]);
    assert_eq!(w2.classify(&body(attack)).unwrap(), Outcome::Block);
}
