//! Adversarial coverage for composition grammar + [`evade_mcts`] on small payloads.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wafrift_strategy::composition::{self, EvasionLayer};
use wafrift_strategy::strategy;
use wafrift_types::{EvasionConfig, Request};

#[cfg(test)]
mod helpers {
    use super::*;

    pub fn minimal_config() -> EvasionConfig {
        EvasionConfig {
            fingerprint_rotation: false,
            ..EvasionConfig::default()
        }
    }

    pub fn tiny_sqli_requests() -> Vec<Request> {
        vec![
            Request::get("https://target.example/search?q=1"),
            Request::post("https://target.example/api", b"id=1".to_vec()),
        ]
    }
}

use helpers::{minimal_config, tiny_sqli_requests};

#[test]
fn is_valid_sequence_rejects_encoding_before_grammar() {
    let bad = vec![EvasionLayer::Encoding, EvasionLayer::Grammar];
    assert!(!composition::is_valid_sequence(&bad));
}

#[test]
fn canonicalize_fixes_invalid_encoding_grammar_order() {
    let mut layers = vec![
        EvasionLayer::Encoding,
        EvasionLayer::Grammar,
        EvasionLayer::ContentType,
    ];
    composition::canonicalize(&mut layers);
    assert!(composition::is_valid_sequence(&layers));
    assert_eq!(layers[0], EvasionLayer::Grammar);
    assert_eq!(layers[1], EvasionLayer::Encoding);
}

#[test]
fn smuggling_without_content_type_is_invalid() {
    let seq = vec![EvasionLayer::Header, EvasionLayer::Smuggling];
    assert!(!composition::is_valid_sequence(&seq));
}

#[test]
fn body_padding_requires_prior_body_mutators() {
    let invalid = vec![
        EvasionLayer::Grammar,
        EvasionLayer::BodyPadding,
        EvasionLayer::ContentType,
    ];
    assert!(!composition::is_valid_sequence(&invalid));

    let mut fixable = vec![
        EvasionLayer::ContentType,
        EvasionLayer::Grammar,
        EvasionLayer::BodyPadding,
        EvasionLayer::Encoding,
    ];
    composition::canonicalize(&mut fixable);
    assert!(composition::is_valid_sequence(&fixable));
    assert_eq!(fixable.last(), Some(&EvasionLayer::BodyPadding));
}

#[test]
fn evade_mcts_small_payloads_never_panic() {
    let config = minimal_config();
    for req in tiny_sqli_requests() {
        let outcome = catch_unwind(AssertUnwindSafe(|| strategy::evade_mcts(&req, &config, 2)));
        assert!(
            outcome.is_ok(),
            "evade_mcts must not panic on small hostile-ish payloads"
        );
    }
}

#[test]
fn evade_mcts_depth_zero_returns_none_without_panic() {
    let req = Request::get("https://target.example/");
    let config = minimal_config();
    let result = strategy::evade_mcts(&req, &config, 0);
    assert!(result.is_none());
}
