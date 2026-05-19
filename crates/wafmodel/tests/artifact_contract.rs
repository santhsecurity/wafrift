//! Truth contract for the learned-model artifact: lossless round-trip
//! and *re-validated* import (a tampered artifact is rejected, never
//! trusted or panicked on).

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, LearnedModel, PacBound, Provenance, Rule, SimRegexWaf, WMethodEq, l_star,
};

fn json_body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
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
fn corpus(k: usize, max: usize) -> Vec<Vec<usize>> {
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

#[test]
fn artifact_round_trips_losslessly_and_preserves_provenance() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let pat = "<s[^>]*/";
    let mut w = waf(pat);
    let fp = w.fingerprint();
    let mut eq = WMethodEq { extra_states: 2 };
    let rep = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap();

    let prov = Provenance {
        oracle_id: "crs-core".into(),
        ruleset_fingerprint: Some(fp.clone()),
        membership_queries: rep.membership_queries,
        equivalence_rounds: rep.equivalence_rounds,
        pac: Some(PacBound::compute(5000, 0.01, 2)),
    };
    let model = LearnedModel::capture(&alpha, &rep.sfa, prov.clone());
    let toml = model.to_toml().unwrap();
    // TOML is human-inspectable: the fingerprint is literally in it.
    assert!(
        toml.contains(&fp),
        "provenance fingerprint must be in the artifact"
    );

    let back = LearnedModel::from_toml(&toml).unwrap();
    assert_eq!(back.provenance, prov, "provenance must round-trip exactly");

    let sfa2 = back.sfa().unwrap();
    let alpha2 = back.alphabet().unwrap();
    assert!(
        rep.sfa.equivalent(&sfa2),
        "deserialized automaton must recognise the identical language"
    );
    // And it still classifies the real corpus identically.
    for c in corpus(alpha.len(), 7) {
        assert_eq!(
            sfa2.accepts(&alpha2.concretize(&c)),
            rep.sfa.accepts(&alpha.concretize(&c))
        );
    }
}

#[test]
fn guarantee_certified_model_has_no_pac_field() {
    // W-method certifies by *guarantee*, not probability ⇒ pac = None
    // is the honest record (stronger than any ε). The test asserts we
    // don't fabricate a PAC number when we didn't sample.
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mut w = waf("<s");
    let mut eq = WMethodEq { extra_states: 2 };
    let rep = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap();
    let model = LearnedModel::capture(
        &alpha,
        &rep.sfa,
        Provenance {
            oracle_id: "crs".into(),
            ruleset_fingerprint: None,
            membership_queries: rep.membership_queries,
            equivalence_rounds: rep.equivalence_rounds,
            pac: None,
        },
    );
    let back = LearnedModel::from_toml(&model.to_toml().unwrap()).unwrap();
    assert!(back.provenance.pac.is_none());
}

#[test]
fn tampered_artifact_is_rejected_not_trusted() {
    let alpha = Alphabet::new(vec![b'<', b's'], b'A');
    let mut w = waf("<s");
    let mut eq = WMethodEq { extra_states: 2 };
    let rep = l_star(&mut w, &json_body, &alpha, &mut eq).unwrap();
    let toml = LearnedModel::capture(
        &alpha,
        &rep.sfa,
        Provenance {
            oracle_id: "crs".into(),
            ruleset_fingerprint: None,
            membership_queries: rep.membership_queries,
            equivalence_rounds: rep.equivalence_rounds,
            pac: None,
        },
    )
    .to_toml()
    .unwrap();

    // (a) Corrupt a predicate to all-zero ⇒ that state's guards no
    // longer cover the byte domain ⇒ import MUST error (not panic,
    // not silently accept an incomplete automaton).
    let zero = "0".repeat(64);
    let broken = {
        // Replace the FIRST pred hex value with all zeros.
        let i = toml.find("pred = \"").unwrap() + 8;
        let j = i + 64;
        format!("{}{}{}", &toml[..i], zero, &toml[j..])
    };
    let m = LearnedModel::from_toml(&broken).unwrap();
    let err = m.sfa().unwrap_err();
    assert!(
        err.to_string().contains("not total") || err.to_string().contains("overlapping"),
        "incomplete/contradictory automaton must be rejected, got: {err}"
    );

    // (b) Unknown schema version ⇒ from_toml errors.
    let bumped = toml.replacen("schema_version = 1", "schema_version = 999", 1);
    assert!(LearnedModel::from_toml(&bumped).is_err());

    // (c) Malformed predicate hex ⇒ error, not panic.
    let badhex = {
        let i = toml.find("pred = \"").unwrap() + 8;
        format!("{}{}{}", &toml[..i], "zz", &toml[i + 2..])
    };
    assert!(
        LearnedModel::from_toml(&badhex)
            .and_then(|m| m.sfa())
            .is_err()
    );
}
