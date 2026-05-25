//! Bypass mining and equivalence oracle tests -- 5 targeted tests.
//! Mandated tests 16-20.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::sfa::{BytePred, Sfa};
use wafrift_wafmodel::{
    Alphabet, ChannelSet, EquivalenceOracle, Outcome, PacBound, Rule, SampledEq, SimRegexWaf,
    WafOracle, WMethodEq, attack_grammar, l_star, mine_bypasses, minimal_bypass,
};
use std::collections::HashSet;

fn json_body(bytes: &[u8]) -> Request {
    Request::post("https://h/p", bytes.to_vec()).header("Content-Type", "application/json")
}

fn waf(pat: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "r".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new(pat).unwrap(),
            score: 5,
        }],
        5,
    )
}

/// Given a known language gap containing "x", "xy", "xyz",
/// minimal_bypass returns the shortest ("x").
#[test]
fn minimal_bypass_returns_shortest() {
    let alpha = Alphabet::new(vec![b'x', b'y'], b'A');
    let mut oracle = waf("xy");
    let mut eq = WMethodEq { extra_states: 3 };
    let learned = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap().sfa;

    let attack = attack_grammar(&alpha, &[b"x".as_ref()]);

    assert!(attack.accepts(b"x"), "attack grammar must accept x");
    assert!(learned.accepts(b"x"), "learned model must pass x");
    assert!(!learned.accepts(b"xy"), "xy must be blocked");

    let minimal = minimal_bypass(&learned, &attack).expect("a bypass must exist");

    assert_eq!(minimal.len(), 1,
        "minimal bypass must be single byte x, got {:?}",
        String::from_utf8_lossy(&minimal));
    assert_eq!(minimal, b"x".to_vec(), "minimal bypass must be exactly x");
    assert!(minimal.len() < b"xy".len());
    assert!(minimal.len() < b"xyz".len());
}

/// mine_bypasses returns distinct strings in a single call.
#[test]
fn mine_bypasses_emits_no_duplicates() {
    let alpha = Alphabet::new(vec![b'a', b'b', b'A', b'B'], b'Z');
    let mut oracle = waf("ab");
    let mut eq = WMethodEq { extra_states: 4 };
    let learned = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap().sfa;

    let attack = attack_grammar(&alpha, &[b"Ab".as_ref(), b"aB".as_ref()]);
    let bypasses = mine_bypasses(&learned, &attack, 20, 6);

    assert!(!bypasses.is_empty(), "must find at least one bypass");

    let unique: HashSet<&Vec<u8>> = bypasses.iter().collect();
    assert_eq!(unique.len(), bypasses.len(),
        "mine_bypasses returned {} results but only {} are unique -- DUPLICATES",
        bypasses.len(), unique.len());

    for bypass in &bypasses {
        let s = String::from_utf8_lossy(bypass);
        assert!(s.contains("Ab") || s.contains("aB"),
            "mined word {:?} is not in the attack class", s);
    }

    let bypasses2 = mine_bypasses(&learned, &attack, 20, 6);
    assert_eq!(bypasses, bypasses2, "mine_bypasses must be deterministic");
}

/// attack_grammar terminates on tiny alphabet and returns a usable SFA.
#[test]
fn attack_grammar_terminates_on_finite_alphabet() {
    let alpha = Alphabet::new(vec![b'a', b'b'], b'Z');

    let g1 = attack_grammar(&alpha, &[b"a".as_ref()]);
    assert!(g1.accepts(b"a"));
    assert!(g1.accepts(b"ba"));
    assert!(!g1.accepts(b""));
    assert!(!g1.accepts(b"b"));

    let g2 = attack_grammar(&alpha, &[b"ab".as_ref(), b"ba".as_ref()]);
    assert!(g2.accepts(b"ab"));
    assert!(g2.accepts(b"ba"));
    assert!(!g2.accepts(b"a"));
    assert!(!g2.accepts(b""));

    let g3 = attack_grammar(&alpha, &[]);
    assert!(g3.is_language_empty(), "empty needles must produce empty language");
    assert_eq!(g3.shortest_accepted(), None);

    assert!(g1.len() < 100, "grammar for a has too many states: {}", g1.len());
    assert!(g2.len() < 100, "grammar for ab|ba has too many states: {}", g2.len());

    let words = g1.enumerate_accepted(10, 4);
    assert!(!words.is_empty(), "must enumerate attack words");
    for w in &words {
        assert!(w.iter().any(|&b| b == b'a'));
    }
}

/// SampledEq finds a counterexample when the hypothesis is wrong.
#[test]
fn random_walk_oracle_finds_counterexample_when_one_exists() {
    let alpha = Alphabet::new(vec![b'a', b'b'], b'Z');

    // Universal hypothesis: wrong for any word containing "ab".
    let accept_all = Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]]);

    let mut truth_waf_oracle = waf("ab");
    let mut sampler = SampledEq::new(10_000, 6, 0.05, 0xDEAD_BEEF);
    let mut mq = |w: &[usize]| -> wafrift_wafmodel::Result<bool> {
        Ok(matches!(
            truth_waf_oracle.classify(&json_body(&alpha.concretize(w)))?,
            Outcome::Pass
        ))
    };
    let ce = sampler.find_counterexample(&accept_all, &alpha, &mut mq).unwrap();

    assert!(ce.is_some(), "SampledEq must find a counterexample when hypothesis is wrong");
    let ce_bytes = alpha.concretize(&ce.unwrap());

    let hyp_answer = accept_all.accepts(&ce_bytes);
    let mut check_waf = waf("ab");
    let truth_answer = matches!(
        check_waf.classify(&json_body(&ce_bytes)).unwrap(),
        Outcome::Pass
    );

    assert_ne!(hyp_answer, truth_answer,
        "CE {:?} does not actually distinguish hypothesis from truth",
        String::from_utf8_lossy(&ce_bytes));
    assert!(hyp_answer, "hypothesis (accept-all) must accept the CE");
    assert!(!truth_answer, "truth WAF must reject the CE");
    assert!(ce_bytes.windows(2).any(|w| w == b"ab"),
        "CE must contain ab: {:?}", String::from_utf8_lossy(&ce_bytes));
}

/// PAC bound is monotonic: increasing confidence (lower delta) strictly
/// increases required sample count to achieve the same epsilon.
#[test]
fn pac_bound_query_count_monotonic() {
    let samples = 1000u64;
    let round = 0u64;

    let tight = PacBound::compute(samples, 0.01, round);
    let loose = PacBound::compute(samples, 0.10, round);
    let very_loose = PacBound::compute(samples, 0.50, round);

    assert!(tight.epsilon > loose.epsilon,
        "delta=0.01 must yield larger epsilon than delta=0.10 (tight={}, loose={})",
        tight.epsilon, loose.epsilon);
    assert!(loose.epsilon > very_loose.epsilon,
        "delta=0.10 must yield larger epsilon than delta=0.50 (loose={}, very_loose={})",
        loose.epsilon, very_loose.epsilon);

    let target_eps = 0.05f64;
    let ln2 = std::f64::consts::LN_2;
    let samples_tight = ((1.0f64 / 0.01f64).ln() + (round as f64 + 1.0) * ln2) / target_eps;
    let samples_loose = ((1.0f64 / 0.10f64).ln() + (round as f64 + 1.0) * ln2) / target_eps;
    assert!(samples_tight > samples_loose,
        "achieving eps={target_eps} with delta=0.01 needs more samples ({}) than delta=0.10 ({})",
        samples_tight, samples_loose);

    for (label, bound) in [("tight", tight), ("loose", loose), ("very_loose", very_loose)] {
        assert!(bound.epsilon > 0.0 && bound.epsilon < 1.0,
            "{label} epsilon must be in (0,1), got {}", bound.epsilon);
    }

    let small_n = PacBound::compute(100, 0.05, 0);
    let large_n = PacBound::compute(10_000, 0.05, 0);
    assert!(large_n.epsilon < small_n.epsilon,
        "more samples must yield smaller epsilon: small={}, large={}",
        small_n.epsilon, large_n.epsilon);

    let early_round = PacBound::compute(1000, 0.05, 0);
    let late_round = PacBound::compute(1000, 0.05, 10);
    assert!(late_round.epsilon > early_round.epsilon,
        "more rounds must yield larger epsilon: round=0 eps={}, round=10 eps={}",
        early_round.epsilon, late_round.epsilon);

    assert_eq!(tight.samples, samples);
    assert_eq!(tight.delta, 0.01);
    assert_eq!(tight.round, round);
}
