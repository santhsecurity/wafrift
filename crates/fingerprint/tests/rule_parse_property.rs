//! Parser robustness: malformed community rules must error, never panic.

use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use wafrift_detect::{DetectRulesError, RuleEngine};

#[test]
fn malformed_toml_load_returns_err() {
    let mut engine = RuleEngine::default();
    let err = engine
        .load_from_str("[[waf]]\nname = ")
        .expect_err("Fix: truncated TOML must not parse successfully");
    assert!(
        matches!(err, DetectRulesError::Parse(_)),
        "Fix: expected Parse error, got {err:?}"
    );
}

#[test]
fn invalid_regex_in_rule_returns_err() {
    let bad = r#"
[[waf]]
name = "BadRegex"
vendor = "x"
confidence_threshold = 0.3
source = "wafrift:test"
[[waf.signature]]
body_regex = "("
weight = 1.0
"#;
    let mut engine = RuleEngine::default();
    let err = engine
        .load_from_str(bad)
        .expect_err("Fix: invalid regex must fail compile");
    assert!(
        matches!(err, DetectRulesError::Parse(_)),
        "Fix: expected Parse error, got {err:?}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn random_utf8_load_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=2048)) {
        let text = String::from_utf8_lossy(&bytes);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut engine = RuleEngine::default();
            let load = engine.load_from_str(&text);
            if load.is_ok() {
                let _ = engine.compile_body_regex_set();
            }
        }));
        assert!(
            outcome.is_ok(),
            "Fix: RuleEngine must not panic on arbitrary input (utf8 lossy len {})",
            text.len()
        );
    }
}
