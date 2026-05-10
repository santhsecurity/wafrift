//! Determinism: pure mutators yield byte-identical output on repeated calls with fixed inputs.

mod common;

use wafrift_encoding::{
    encode,
    encoding::strategy::all_strategies,
    header::{case_mix, tab_separator, whitespace_pad},
    tamper::{all_tamper_names, tamper},
    url_mutate::{UrlMutateConfig, UrlStrategy, mutate_url},
    Strategy as S,
};

#[test]
fn encode_pure_strategies_twice_are_byte_identical() {
    let stress = common::unicode_stress();
    let payload = stress.as_bytes();
    let pollution_payload = b"k=v";

    for &strategy in all_strategies() {
        if matches!(strategy, S::RandomCase | S::SpaceToRandomBlank) {
            continue;
        }

        let bytes_in = if matches!(strategy, S::ParameterPollution) {
            pollution_payload
        } else {
            payload
        };

        let a = encode(bytes_in, strategy).unwrap_or_else(|e| {
            panic!(
                "Fix: encode must succeed for deterministic audit ({strategy:?}): {e:?}"
            )
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
fn encode_random_case_negative_not_identical_across_calls() {
    let payload = "AbCdEfGhIjKlMnOpQrStUvWxYz";
    let a = encode(payload.as_bytes(), S::RandomCase).unwrap();
    let b = encode(payload.as_bytes(), S::RandomCase).unwrap();
    assert_ne!(
        a, b,
        "negative twin: RandomCase injects entropy and must not be byte-stable"
    );
}

#[test]
fn encode_space_to_random_blank_negative_not_stable() {
    let payload = "SELECT * FROM t WHERE a = 1 AND b = 2";
    let mut diff = 0_u32;
    for _ in 0..40 {
        let u = encode(payload.as_bytes(), S::SpaceToRandomBlank).unwrap();
        let v = encode(payload.as_bytes(), S::SpaceToRandomBlank).unwrap();
        if u != v {
            diff += 1;
        }
    }
    assert!(
        diff > 0,
        "negative twin: SpaceToRandomBlank must vary across repeated calls"
    );
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
fn tamper_named_strategies_deterministic_except_random_case() {
    let p = common::unicode_stress();
    for name in all_tamper_names() {
        if *name == "random_case" {
            continue;
        }
        let a = tamper(name, p.as_str(), Some("sql")).unwrap();
        let b = tamper(name, p.as_str(), Some("sql")).unwrap();
        assert_eq!(a, b, "tamper({name}) must be deterministic");
    }
}

#[test]
fn tamper_random_case_negative_unstable() {
    let a = tamper("random_case", "PayloadText", Some("sql")).unwrap();
    let b = tamper("random_case", "PayloadText", Some("sql")).unwrap();
    assert_ne!(a, b, "negative twin: random_case tamper must vary");
}

#[test]
fn header_functions_deterministic_except_whitespace_pad_rng() {
    let name = "Content-Type";
    let value = common::unicode_stress();
    assert_eq!(case_mix(name), case_mix(name));
    assert_eq!(
        tab_separator(name, value.as_str()),
        tab_separator(name, value.as_str())
    );

    let mut varied = false;
    for _ in 0..40 {
        let x = whitespace_pad(name, value.as_str());
        let y = whitespace_pad(name, value.as_str());
        if x != y {
            varied = true;
            break;
        }
    }
    assert!(
        varied,
        "negative twin: whitespace_pad must eventually diverge (RNG padding)"
    );
}
