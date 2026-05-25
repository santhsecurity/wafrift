//! L* learner termination and correctness -- 3 targeted tests.
//! Mandated tests 10-12.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, ChannelSet, Outcome, Rule, SampledEq, SimRegexWaf, WafOracle,
    l_star,
};

fn json_body(bytes: &[u8]) -> Request {
    Request::post("https://h/p", bytes.to_vec()).header("Content-Type", "application/json")
}

fn waf_with_pattern(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "test".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}

fn truth_waf(waf: &mut SimRegexWaf, alpha: &Alphabet, word: &[usize]) -> bool {
    matches!(
        waf.classify(&json_body(&alpha.concretize(word))).unwrap(),
        Outcome::Pass
    )
}

fn all_words(k: usize, max_len: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    let mut frontier: Vec<Vec<usize>> = vec![vec![]];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for w in &frontier {
            for s in 0..k {
                let mut e = w.clone();
                e.push(s);
                next.push(e.clone());
                out.push(e);
            }
        }
        frontier = next;
    }
    out
}

/// Construct a small reference DFA (accepts strings ending in "ab"),
/// wrap as a black-box oracle, run L*, assert the learned model agrees
/// with the reference on 100+ inputs.
#[test]
fn learn_recovers_known_dfa() {
    // WAF blocks strings ending in "ab" (pattern "ab$").
    // Learned model: passes iff body does NOT end in "ab".
    let alpha = Alphabet::new(vec![b'a', b'b'], b'Z');
    let pat = "ab$";
    let mut oracle = waf_with_pattern(pat);
    let mut eq = BoundedExhaustiveEq { max_len: 8 };
    let report = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap();

    // Verify on the full corpus through length 7.
    let mut check_oracle = waf_with_pattern(pat);
    let corpus = all_words(alpha.len(), 7);
    assert!(corpus.len() > 100, "corpus must have > 100 words");
    let mut matches = 0usize;
    for w in &corpus {
        assert_eq!(
            report.sfa.accepts(&alpha.concretize(w)),
            truth_waf(&mut check_oracle, &alpha, w),
            "L* model disagrees with reference WAF on abstract word {w:?}"
        );
        matches += 1;
    }
    assert!(matches > 100, "checked {matches} words, needed > 100");

    // Spot-checks: alpha ordering is a=0, b=1, Z=2 (catch-all).
    // "ab" ends in "ab" -> blocked -> model rejects.
    assert!(!report.sfa.accepts(&alpha.concretize(&[0, 1])), "'ab' must be rejected");
    // "ba" does not end in "ab" -> passes -> model accepts.
    assert!(report.sfa.accepts(&alpha.concretize(&[1, 0])), "'ba' must be accepted");
    // epsilon does not end in "ab" -> passes -> model accepts.
    assert!(report.sfa.accepts(b""), "epsilon must be accepted");
}

/// With a SampledEq oracle (PAC-bounded), L* terminates and the PAC
/// bound is honest (measured error <= epsilon).
#[test]
fn learn_terminates_under_pac_bound() {
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let pat = "<s";
    let mut oracle = waf_with_pattern(pat);
    let samples_needed = 1000u64;
    let mut eq = SampledEq::new(samples_needed, 8, 0.05, 42);
    let report = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap();

    assert!(report.membership_queries > 0, "learner must have issued queries");

    let bound = eq
        .last_bound()
        .expect("SampledEq must publish a PAC bound after a clean round");
    assert!(
        bound.epsilon > 0.0 && bound.epsilon < 1.0,
        "PAC epsilon must be in (0,1), got {}",
        bound.epsilon
    );
    assert!(
        bound.samples >= samples_needed,
        "bound reports {} samples, expected >= {}",
        bound.samples, samples_needed
    );

    let mut check_oracle = waf_with_pattern(pat);
    let corpus = all_words(alpha.len(), 7);
    let wrong: usize = corpus
        .iter()
        .filter(|w| {
            report.sfa.accepts(&alpha.concretize(w)) != truth_waf(&mut check_oracle, &alpha, w)
        })
        .count();
    let measured = wrong as f64 / corpus.len() as f64;
    assert!(
        measured <= bound.epsilon,
        "measured error {measured:.4} exceeds PAC epsilon {:.4}",
        bound.epsilon
    );
}

/// After L* completes, the learned automaton satisfies closure and
/// consistency: the BoundedExhaustiveEq oracle found no counterexample,
/// which means the hypothesis agrees with the oracle for all words up
/// to max_len. This is the operational closure+consistency invariant.
#[test]
fn learn_observation_table_closed_consistent() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let pat = "<s/";
    let mut oracle = waf_with_pattern(pat);
    let mut eq = BoundedExhaustiveEq { max_len: 7 };
    let report = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap();

    // The EQ oracle returning None means: no word up to length 7
    // distinguishes the hypothesis from the oracle = closed+consistent.
    // Verify independently.
    let mut check_oracle = waf_with_pattern(pat);
    let mut mismatches = 0usize;
    for w in all_words(alpha.len(), 7) {
        if report.sfa.accepts(&alpha.concretize(&w)) != truth_waf(&mut check_oracle, &alpha, &w) {
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "L* returned a hypothesis with {mismatches} disagreements -- \
         table was not closed+consistent"
    );

    // The table must have been refined (non-trivial language).
    assert!(
        report.sfa.len() >= 2,
        "L* must produce >= 2 states for a non-trivial language"
    );

    // Behavioral spot-checks.
    assert!(!report.sfa.accepts(b"<s/"), "blocked pattern must be rejected");
    assert!(report.sfa.accepts(b""), "epsilon must be accepted");
    assert!(report.sfa.accepts(b"<s"), "'<s' (no slash) must be accepted");
}
