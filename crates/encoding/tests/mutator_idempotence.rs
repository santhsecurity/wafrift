//! Property tests: double-application idempotence or bounded expansion (1k cases each).

mod common;

use proptest::prelude::*;
use wafrift_encoding::{
    encode,
    encoding::strategy::all_strategies,
    tamper::{all_tamper_names, tamper},
    url_mutate::{UrlMutateConfig, UrlStrategy, mutate_url},
    Strategy as S,
};

/// Encoders where `encode(encode(x)) == encode(x)` for valid UTF-8 payloads (fixed-point).
const IDEMPOTENT: &[S] = &[
    S::CaseAlternation,
    S::FullwidthEncode,
    S::HomoglyphEncode,
    S::WhitespaceInsertion,
    S::SqlCommentInsertion,
    S::SpaceToComment,
    S::SpaceToDash,
    S::SpaceToHash,
    S::SpaceToPlus,
];

/// Second pass may expand faster than 4× (encoding `%`, entities, etc.); still checked separately in panic audit.
fn second_pass_expansion_skipped(strategy: S) -> bool {
    matches!(
        strategy,
        S::RandomCase
            | S::SpaceToRandomBlank
            | S::UrlEncode
            | S::UrlEncodeLower
            | S::DoubleUrlEncode
            | S::TripleUrlEncode
            | S::UnicodeEncode
            | S::IisUnicodeEncode
            | S::JsonEncode
            | S::HtmlEntityEncode
            | S::HtmlEntityDecimalEncode
            | S::MysqlVersionedComment
            | S::PercentagePrefix
            | S::BetweenObfuscation
            | S::GzipEncode
            | S::DeflateEncode
    )
}

fn tamper_second_pass_cap(name: &str, once_len: usize) -> usize {
    match name {
        "url_encode" => common::max_encoded_output_bytes(S::UrlEncode, once_len),
        "double_url_encode" => common::max_encoded_output_bytes(S::DoubleUrlEncode, once_len),
        "unicode_escape" => common::max_encoded_output_bytes(S::UnicodeEncode, once_len),
        "html_entity" => common::max_encoded_output_bytes(S::HtmlEntityEncode, once_len),
        "case_alternation" => common::max_encoded_output_bytes(S::CaseAlternation, once_len),
        "whitespace_insertion" => common::max_encoded_output_bytes(S::WhitespaceInsertion, once_len),
        "sql_comment" => common::max_encoded_output_bytes(S::SqlCommentInsertion, once_len),
        "null_byte" => common::max_encoded_output_bytes(S::NullByte, once_len),
        "overlong_utf8" => common::max_encoded_output_bytes(S::OverlongUtf8, once_len),
        "base64" => common::max_encoded_output_bytes(S::Base64Encode, once_len),
        "hex_encode" => common::max_encoded_output_bytes(S::HexEncode, once_len),
        _ => once_len.saturating_mul(4).saturating_add(64),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_strategy_utf8_idempotence_and_second_pass_cap(
        payload in prop::collection::vec(any::<char>(), 0..512)
            .prop_map(|cs| cs.into_iter().collect::<String>())
    ) {
        let bytes = payload.as_bytes();

        for &strategy in IDEMPOTENT {
            let once = encode(bytes, strategy).expect("Fix: idempotent strategy must accept UTF-8 text");
            let twice = encode(once.as_bytes(), strategy).expect("Fix: second pass must succeed");
            prop_assert_eq!(
                once,
                twice,
                "idempotent strategy {:?} must stabilize",
                strategy
            );
        }

        for &strategy in all_strategies() {
            if IDEMPOTENT.contains(&strategy) {
                continue;
            }
            if matches!(strategy, S::RandomCase | S::SpaceToRandomBlank) {
                continue;
            }

            let Ok(once) = encode(bytes, strategy) else {
                continue;
            };
            let Ok(twice) = encode(once.as_bytes(), strategy) else {
                continue;
            };

            if second_pass_expansion_skipped(strategy) {
                prop_assert!(
                    twice.len() <= common::max_encoded_output_bytes(strategy, once.len()),
                    "second pass must stay within documented cap: {:?} once={} twice={}",
                    strategy,
                    once.len(),
                    twice.len()
                );
            } else {
                prop_assert!(
                    twice.len() <= once.len().saturating_mul(4),
                    "Fix: second pass expansion >4× for {:?}: once_len={} twice_len={}",
                    strategy,
                    once.len(),
                    twice.len()
                );
            }
        }
    }

    #[test]
    fn prop_tamper_second_pass_cap(payload in prop::collection::vec(any::<char>(), 0..256)
        .prop_map(|cs| cs.into_iter().collect::<String>()))
    {
        for name in all_tamper_names() {
            if *name == "random_case" {
                continue;
            }
            let once = tamper(name, &payload, Some("sql")).expect("tamper");
            let twice = tamper(name, &once, Some("sql")).expect("tamper second");
            let cap = tamper_second_pass_cap(name, once.len());
            prop_assert!(
                twice.len() <= cap,
                "tamper {name}: second pass growth once={} twice={} cap={}",
                once.len(),
                twice.len(),
                cap
            );
        }
    }

    #[test]
    fn prop_mutate_url_second_pass_cap(path in prop::collection::vec(any::<char>(), 0..128)
        .prop_map(|cs| format!("/p?q={}", cs.into_iter().collect::<String>())))
    {
        let cfg = UrlMutateConfig {
            mutate_query_values: true,
            mutate_last_path_segment: false,
            strategy: UrlStrategy::PercentEncodeAggressive,
        };
        let (once, _) = mutate_url(&path, &cfg);
        let (twice, _) = mutate_url(&once, &cfg);
        prop_assert!(
            twice.len() <= once.len().saturating_mul(4).saturating_add(256),
            "mutate_url second pass growth once={} twice={}",
            once.len(),
            twice.len()
        );
    }
}
