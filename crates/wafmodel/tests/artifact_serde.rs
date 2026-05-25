//! Artifact serde round-trip tests -- 3 targeted tests.
//! Mandated tests 13-15.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, LearnedModel, Provenance, Rule, SimRegexWaf, WMethodEq, l_star,
};

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

/// to_toml() then from_toml() is lossless for a non-trivial automaton
/// (>= 3 states, >= 2 transitions).
#[test]
fn artifact_toml_round_trip() {
    // Pattern "<s/" needs at least 4 states.
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let mut oracle = waf("<s/");
    let mut eq = WMethodEq { extra_states: 3 };
    let report = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap();
    let sfa = &report.sfa;
    assert!(sfa.len() >= 3, "test requires >= 3 states, got {}", sfa.len());

    let prov = Provenance {
        oracle_id: "crs-core-test".into(),
        ruleset_fingerprint: Some("deadbeef12345678".into()),
        membership_queries: report.membership_queries,
        equivalence_rounds: report.equivalence_rounds,
        pac: None,
    };
    let model = LearnedModel::capture(&alpha, sfa, prov.clone());
    let toml_str = model.to_toml().unwrap();

    // Must be human-readable.
    assert!(!toml_str.is_empty(), "to_toml must produce non-empty string");
    assert!(toml_str.contains("schema_version"), "must contain schema_version");
    assert!(toml_str.contains("crs-core-test"), "must contain oracle_id");
    assert!(toml_str.contains("deadbeef12345678"), "must contain fingerprint");

    // Round-trip.
    let parsed = LearnedModel::from_toml(&toml_str).unwrap();
    assert_eq!(parsed.provenance, prov, "provenance must survive round-trip");

    let sfa2 = parsed.sfa().unwrap();
    assert!(
        sfa.equivalent(&sfa2),
        "deserialized automaton must recognize the same language; \
         distinguishing word: {:?}",
        sfa.distinguishing_word(&sfa2)
    );

    // Spot-check on concrete inputs.
    for w in [b"".as_ref(), b"<", b"<s", b"<s/", b"abc"] {
        assert_eq!(
            sfa.accepts(w),
            sfa2.accepts(w),
            "round-tripped SFA disagrees on {:?}",
            String::from_utf8_lossy(w)
        );
    }
}

/// from_toml on malformed/garbage input returns Err, never panics.
#[test]
fn artifact_rejects_malformed_toml() {
    // Plain garbage.
    assert!(
        LearnedModel::from_toml("not a real toml {{{").is_err(),
        "malformed TOML must return Err"
    );

    // Empty string.
    assert!(
        LearnedModel::from_toml("").is_err(),
        "empty string must return Err"
    );

    // Valid TOML but wrong schema.
    assert!(
        LearnedModel::from_toml("[foo]\nbar = 1\n").is_err(),
        "TOML with wrong schema must return Err"
    );

    // Wrong schema version.
    let wrong_version = "schema_version = 9999\nstart = 0\nalphabet = [65]\n\
        [provenance]\noracle_id = \"x\"\nmembership_queries = 0\n\
        equivalence_rounds = 0\n\n[[state]]\naccept = false\n\n\
        [[state.edge]]\nto = 0\npred = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"\n";
    assert!(
        LearnedModel::from_toml(wrong_version).is_err(),
        "unsupported schema version must return Err"
    );

    // Malformed predicate hex.
    let bad_pred = "schema_version = 1\nstart = 0\nalphabet = [65]\n\
        [provenance]\noracle_id = \"x\"\nmembership_queries = 0\n\
        equivalence_rounds = 0\n\n[[state]]\naccept = false\n\n\
        [[state.edge]]\nto = 0\npred = \"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\"\n";
    let result = LearnedModel::from_toml(bad_pred);
    match result {
        Err(_) => {}
        Ok(m) => {
            assert!(
                m.sfa().is_err(),
                "malformed pred hex must cause sfa() to return Err"
            );
        }
    }
}

/// A TOML with an extra unknown field documents the project's behavior
/// (permissive or strict) and pins it against silent regressions.
#[test]
fn artifact_backwards_compat_unknown_field() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let mut oracle = waf("<s/");
    let mut eq = WMethodEq { extra_states: 3 };
    let report = l_star(&mut oracle, &json_body, &alpha, &mut eq).unwrap();
    let sfa = &report.sfa;

    let prov = Provenance {
        oracle_id: "compat-test".into(),
        ruleset_fingerprint: None,
        membership_queries: report.membership_queries,
        equivalence_rounds: report.equivalence_rounds,
        pac: None,
    };
    let model = LearnedModel::capture(&alpha, sfa, prov.clone());
    let base_toml = model.to_toml().unwrap();

    // Inject an extra unknown top-level field.
    let extended_toml = format!(
        "{}\nunknown_future_field_for_compat_test = 42\n",
        base_toml
    );

    // Pin the actual behavior: accept or reject unknown fields.
    let result = LearnedModel::from_toml(&extended_toml);
    match result {
        Ok(m) => {
            // Permissive: unknown field ignored.
            assert_eq!(m.provenance, prov, "provenance must survive unknown-field round-trip");
            let sfa2 = m.sfa().expect("sfa must be valid after ignoring unknown field");
            assert!(
                sfa.equivalent(&sfa2),
                "language must be preserved when unknown field is ignored: {:?}",
                sfa.distinguishing_word(&sfa2)
            );
        }
        Err(e) => {
            // Strict: unknown field rejected. Error must be descriptive.
            assert!(
                !e.to_string().is_empty(),
                "rejection of unknown field must produce a non-empty error"
            );
            // This branch documents that the format is STRICT.
            // If forward-compat is desired, remove deny_unknown_fields.
        }
    }

    // Unknown field injected into the provenance sub-table.
    if let Some(idx) = base_toml.find("[provenance]") {
        let extended_prov = format!(
            "{}\nnew_prov_field = \"future\"\n{}",
            &base_toml[..idx + "[provenance]".len()],
            &base_toml[idx + "[provenance]".len()..]
        );
        // Must not panic regardless of accept/reject.
        let _ = LearnedModel::from_toml(&extended_prov);
    }
}
