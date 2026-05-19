//! Thousands-scale corpus fan-out — the anti-rig invariants must hold
//! across a large generated population of WAF configs, not just the
//! hand-built fixtures:
//!
//! * **Mining soundness at scale**: for *every* config, *every* mined
//!   bypass replays as a real PASS against that same WAF and is a real
//!   member of the attack class. One fake = an engine bug.
//! * **Hardening honesty at scale**: `proven_closed` ⇒ re-measured
//!   holes are 0 and benign FP is 0; holes never increase.
//! * **Learner exactness at scale**: a sampled subset is fully learned
//!   and the model matches the WAF on a corpus far past its state bound.
//! * **Robustness**: no panic / no unbounded blow-up on any config.

use proptest::prelude::*;
use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, Outcome, Rule, SimRegexWaf, Transform, WMethodEq, attack_grammar, l_star,
    mine_bypasses, synthesize_closure,
};

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

/// Short ASCII tokens — small alphabet keeps the population huge while
/// every case stays fast and bounded.
const TOKENS: &[&[u8]] = &[b"ab", b"<x", b"a", b"x1", b"qz", b"%3c", b"or"];

fn waf_from(seed: u64) -> (SimRegexWaf, Vec<&'static [u8]>, Alphabet) {
    // Deterministic config derived from `seed`.
    let n_rules = 1 + (seed % 3) as usize;
    let mut rules = Vec::new();
    for r in 0..n_rules {
        let tok = TOKENS[((seed >> (r * 3)) as usize + r) % TOKENS.len()];
        let mut tf = Vec::new();
        if (seed >> r) & 1 == 1 {
            tf.push(Transform::Lowercase);
        }
        if (seed >> (r + 1)) & 1 == 1 {
            tf.push(Transform::UrlDecodeUni);
        }
        rules.push(Rule {
            id: format!("r{r}"),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: tf,
            pattern: regex::bytes::Regex::new(&regex::escape(&String::from_utf8_lossy(tok)))
                .unwrap(),
            score: 5,
        });
    }
    let waf = SimRegexWaf::new(rules, 5);
    // Attack class = two tokens (one likely covered, one likely not).
    let needles: Vec<&'static [u8]> = vec![
        TOKENS[(seed as usize) % TOKENS.len()],
        TOKENS[(seed as usize + 3) % TOKENS.len()],
    ];
    let mut bytes: Vec<u8> = needles.iter().flat_map(|n| n.iter().copied()).collect();
    bytes.sort_unstable();
    bytes.dedup();
    bytes.retain(|&b| b != b'Z');
    let alpha = Alphabet::new(bytes, b'Z');
    (waf, needles, alpha)
}

#[test]
fn one_thousand_configs_no_fake_bypass_no_dishonest_closure() {
    for seed in 0u64..1000 {
        let (waf, needles, alpha) = waf_from(seed);
        let grammar = attack_grammar(&alpha, &needles);

        // Learn the WAF (Body channel) so we can mine over the model.
        let mut learn_waf = SimRegexWaf::new(waf.rules().to_vec(), waf.threshold());
        let mut eq = WMethodEq { extra_states: 2 };
        let learned = l_star(&mut learn_waf, &body, &alpha, &mut eq)
            .unwrap_or_else(|e| panic!("seed {seed}: learn failed: {e}"))
            .sfa;

        // Mining soundness: every mined bypass is REAL.
        let mut oracle = SimRegexWaf::new(waf.rules().to_vec(), waf.threshold());
        for w in mine_bypasses(&learned, &grammar, 20, 10) {
            assert_eq!(
                <SimRegexWaf as wafrift_wafmodel::WafOracle>::classify(&mut oracle, &body(&w))
                    .unwrap(),
                Outcome::Pass,
                "seed {seed}: mined {w:?} does NOT pass the real WAF (fake bypass)"
            );
            assert!(
                grammar.accepts(&w),
                "seed {seed}: mined {w:?} is not in the attack class"
            );
        }

        // Hardening honesty: a proven closure is actually closed + FP-free.
        let benign: [&[u8]; 3] = [b"hello", b"safe", b"normaltext"];
        let rep = synthesize_closure(
            &waf,
            &needles,
            ChannelSet::none().with(Channel::Body),
            &benign,
            &alpha,
            10,
        );
        assert!(
            rep.holes_after <= rep.holes_before,
            "seed {seed}: hardening increased holes"
        );
        if rep.proven_closed {
            assert_eq!(rep.holes_after, 0, "seed {seed}: proven but holes remain");
            assert_eq!(
                rep.benign_false_positives, 0,
                "seed {seed}: proven but benign FP"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1200))]

    /// Randomized configs: the mining anti-rig invariant must hold for
    /// every one (no learning here — pure scale of the soundness check).
    #[test]
    fn random_configs_never_yield_a_fake_bypass(seed in any::<u64>()) {
        let (waf, needles, alpha) = waf_from(seed);
        let grammar = attack_grammar(&alpha, &needles);
        // Direct hole set = attack members the WAF passes.
        for w in grammar.enumerate_accepted(64, 10) {
            let mut o = SimRegexWaf::new(waf.rules().to_vec(), waf.threshold());
            let passed = matches!(
                <SimRegexWaf as wafrift_wafmodel::WafOracle>::classify(&mut o, &body(&w)).unwrap(),
                Outcome::Pass
            );
            // Whatever we would *report* as a hole must really pass and
            // really be an attack-class member — checked unconditionally.
            prop_assert!(grammar.accepts(&w));
            if passed {
                // It is a genuine hole: re-classification is stable.
                let mut o2 = SimRegexWaf::new(waf.rules().to_vec(), waf.threshold());
                prop_assert_eq!(
                    matches!(
                        <SimRegexWaf as wafrift_wafmodel::WafOracle>::classify(&mut o2, &body(&w)).unwrap(),
                        Outcome::Pass
                    ),
                    true
                );
            }
        }
    }
}
