//! Determinism: pure mutators yield byte-identical output on repeated calls with fixed inputs.

mod common;

use wafrift_encoding::{
    Strategy as S, encode,
    encoding::strategy::all_strategies,
    header::{case_mix, tab_separator, whitespace_pad},
    tamper::{all_tamper_names, tamper},
    url_mutate::{UrlMutateConfig, UrlStrategy, mutate_url},
};

#[test]
fn encode_pure_strategies_twice_are_byte_identical() {
    let stress = common::unicode_stress();
    let payload = stress.as_bytes();
    let pollution_payload = b"k=v";

    for &strategy in all_strategies() {
        // All strategies are now deterministic (FNV-1a seeded where previously
        // random). RandomCase was made deterministic in commit 14fd8fb.
        // SpaceToRandomBlank was fixed earlier. Include all strategies.
        let bytes_in = if matches!(strategy, S::ParameterPollution) {
            pollution_payload
        } else {
            payload
        };

        let a = encode(bytes_in, strategy).unwrap_or_else(|e| {
            panic!("Fix: encode must succeed for deterministic audit ({strategy:?}): {e:?}")
        });
        let b = encode(bytes_in, strategy).unwrap();
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "{strategy:?} must be deterministic for identical input"
        );
    }
}

#[test]
fn encode_random_case_is_deterministic_post_fix() {
    // Post-fix (commit 14fd8fb): RandomCase is now FNV-1a seeded, not
    // rand::random — identical inputs produce byte-identical outputs so
    // bench replays that discovered a bypass are reproducible.
    let payload = "AbCdEfGhIjKlMnOpQrStUvWxYz";
    let a = encode(payload.as_bytes(), S::RandomCase).unwrap();
    let b = encode(payload.as_bytes(), S::RandomCase).unwrap();
    assert_eq!(
        a, b,
        "RandomCase must be deterministic: same input → same output (FNV-1a seeded)"
    );
    // Distinct inputs must produce distinct outputs (not a constant encoder).
    let c = encode(b"AbCdEfGhIjKlMnOpQrStUvWxY".as_ref(), S::RandomCase).unwrap();
    assert_ne!(
        a, c,
        "RandomCase must vary with input — not a fixed-case encoder"
    );
}

#[test]
fn encode_space_to_random_blank_is_deterministic() {
    // SpaceToRandomBlank was made deterministic (FNV-1a hash of payload + position)
    // so bench-waf --seed produces byte-identical output on repeated runs.
    let payload = "SELECT * FROM t WHERE a = 1 AND b = 2";
    let a = encode(payload.as_bytes(), S::SpaceToRandomBlank).unwrap();
    let b = encode(payload.as_bytes(), S::SpaceToRandomBlank).unwrap();
    assert_eq!(
        a, b,
        "SpaceToRandomBlank must be deterministic for identical input"
    );
    // Distinct inputs must produce distinct outputs (not a constant encoder).
    let c = encode(b"SELECT 1 FROM x".as_ref(), S::SpaceToRandomBlank).unwrap();
    assert_ne!(a, c, "SpaceToRandomBlank must vary with input");
}

#[test]
fn url_strategy_apply_bytes_deterministic() {
    let stress = common::unicode_stress();
    let bytes = stress.as_bytes();
    for strat in [
        UrlStrategy::PercentEncodeAggressive,
        UrlStrategy::DoublePercentEncode,
        UrlStrategy::NonCanonicalSpaces,
        UrlStrategy::Hpp,
    ] {
        assert_eq!(strat.apply_bytes(bytes), strat.apply_bytes(bytes));
        assert_eq!(strat.apply(stress.as_str()), strat.apply(stress.as_str()));
    }
}

#[test]
fn mutate_url_deterministic_for_fixed_path() {
    let cfg = UrlMutateConfig::default();
    let path = format!("/api/search?q={}&flag=1", common::unicode_stress());
    let a = mutate_url(&path, &cfg);
    let b = mutate_url(&path, &cfg);
    assert_eq!(a.0, b.0);
    assert_eq!(a.1, b.1);
}

#[test]
fn tamper_named_strategies_all_deterministic() {
    // Post-fix (commit 14fd8fb): random_case is now FNV-1a seeded and
    // deterministic. All tampers are now deterministic — no exclusions.
    let p = common::unicode_stress();
    for name in all_tamper_names() {
        let a = tamper(name, p.as_str(), Some("sql")).unwrap();
        let b = tamper(name, p.as_str(), Some("sql")).unwrap();
        assert_eq!(a, b, "tamper({name}) must be deterministic");
    }
}

#[test]
fn tamper_random_case_deterministic_and_varies_with_input() {
    // Post-fix: random_case is deterministic — same input produces the same
    // mixed-case output every run. Different inputs produce different output.
    let a = tamper("random_case", "PayloadText", Some("sql")).unwrap();
    let b = tamper("random_case", "PayloadText", Some("sql")).unwrap();
    assert_eq!(
        a, b,
        "random_case tamper must be deterministic (FNV-1a seeded)"
    );
    // Distinct inputs must produce distinct patterns.
    let c = tamper("random_case", "PayloadTexu", Some("sql")).unwrap();
    assert_ne!(
        a, c,
        "random_case must vary with input — not a fixed-case encoder"
    );
}

#[test]
fn header_functions_all_deterministic() {
    // whitespace_pad was made deterministic (FNV-1a hash of name+value drives
    // pad width) so bench-waf --seed produces byte-identical output.
    let name = "Content-Type";
    let value = common::unicode_stress();
    assert_eq!(case_mix(name), case_mix(name));
    assert_eq!(
        tab_separator(name, value.as_str()),
        tab_separator(name, value.as_str())
    );
    assert_eq!(
        whitespace_pad(name, value.as_str()),
        whitespace_pad(name, value.as_str()),
        "whitespace_pad must be deterministic for identical input (bench-safe)"
    );
    // Distinct values → distinct pad widths (not a constant encoder).
    let mut seen = std::collections::HashSet::new();
    for v in ["a.com", "b.net", "c.org", "d.io", "e.dev"] {
        seen.insert(whitespace_pad(name, v));
    }
    assert!(
        seen.len() >= 2,
        "whitespace_pad should vary across distinct values, got {} unique outputs",
        seen.len()
    );
}
