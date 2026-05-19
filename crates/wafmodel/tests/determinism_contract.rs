//! E6 — determinism & reproducibility. A decompilation is a pure
//! function of (oracle, seed): same inputs ⇒ byte-identical artifact,
//! identical mining, identical results after a serialize/reload round
//! trip. Non-determinism leaking into output (e.g. HashMap iteration
//! order) is an engine bug, asserted away here.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, LearnedModel, Provenance, Rule, SimRegexWaf, Transform, WMethodEq,
    attack_grammar, l_star, mine_bypasses,
};

fn json_body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn waf() -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "941".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<s[^>]*x").unwrap(),
            score: 5,
        }],
        5,
    )
}
fn alpha() -> Alphabet {
    Alphabet::new(vec![b'<', b's', b'x', b'>'], b'Z')
}
fn prov() -> Provenance {
    Provenance {
        oracle_id: "det".into(),
        ruleset_fingerprint: None,
        membership_queries: 0,
        equivalence_rounds: 0,
        pac: None,
    }
}

#[test]
fn same_oracle_and_seed_yield_a_byte_identical_artifact() {
    let a = alpha();
    let mut w1 = waf();
    let mut w2 = waf();
    let mut e1 = WMethodEq { extra_states: 2 };
    let mut e2 = WMethodEq { extra_states: 2 };
    let m1 = l_star(&mut w1, &json_body, &a, &mut e1).unwrap().sfa;
    let m2 = l_star(&mut w2, &json_body, &a, &mut e2).unwrap().sfa;

    let t1 = LearnedModel::capture(&a, &m1, prov()).to_toml().unwrap();
    let t2 = LearnedModel::capture(&a, &m2, prov()).to_toml().unwrap();
    assert_eq!(
        t1, t2,
        "two identical decompilations produced different artifacts \
         (non-determinism leaked into output)"
    );
    // The serialized form is non-trivial (not an empty/degenerate doc).
    assert!(t1.len() > 64 && t1.contains("[[state]]"));
}

#[test]
fn mining_is_deterministic_and_survives_a_serialize_reload() {
    let a = alpha();
    let mut w = waf();
    let mut eq = WMethodEq { extra_states: 2 };
    let learned = l_star(&mut w, &json_body, &a, &mut eq).unwrap().sfa;
    let needles: [&[u8]; 1] = [b"<sx"];
    let g = attack_grammar(&a, &needles);

    let r1 = mine_bypasses(&learned, &g, 16, 10);
    let r2 = mine_bypasses(&learned, &g, 16, 10);
    assert_eq!(r1, r2, "mine_bypasses is not deterministic");

    // Reload from the artifact ⇒ identical mining (no model drift
    // across serialization).
    let model = LearnedModel::capture(&a, &learned, prov());
    let reloaded = LearnedModel::from_toml(&model.to_toml().unwrap())
        .unwrap()
        .sfa()
        .unwrap();
    let r3 = mine_bypasses(&reloaded, &g, 16, 10);
    assert_eq!(
        r1, r3,
        "mining differs after serialize/reload — artifact is lossy"
    );
}

#[test]
fn the_two_learners_are_deterministic_across_repeated_runs() {
    // Repeating KV/L* on the same oracle yields the exact same machine
    // every time (10 repeats), and they agree with each other.
    use wafrift_wafmodel::kv_learn;
    let a = alpha();
    let baseline = {
        let mut w = waf();
        let mut e = WMethodEq { extra_states: 2 };
        l_star(&mut w, &json_body, &a, &mut e).unwrap().sfa
    };
    for _ in 0..10 {
        let mut w = waf();
        let mut e = WMethodEq { extra_states: 2 };
        let again = l_star(&mut w, &json_body, &a, &mut e).unwrap().sfa;
        assert!(again.equivalent(&baseline), "L* not run-to-run stable");

        let mut wk = waf();
        let mut ek = WMethodEq { extra_states: 2 };
        let kv = kv_learn(&mut wk, &json_body, &a, &mut ek).unwrap().sfa;
        assert!(kv.equivalent(&baseline), "KV diverged from L*");
    }
}
