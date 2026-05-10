//! Shared fixtures and explicit output caps for mutator integration tests.

#![allow(dead_code)]

use wafrift_encoding::encoding::strategy::Strategy;

pub const ONE_MB: usize = 1024 * 1024;

/// Conservative worst-case output length (bytes) for [`Strategy`] given input byte length `n`.
#[must_use]
pub fn max_encoded_output_bytes(strategy: Strategy, input_len: usize) -> usize {
    match strategy {
        Strategy::UrlEncode | Strategy::UrlEncodeLower => input_len.saturating_mul(3).saturating_add(64),
        Strategy::DoubleUrlEncode => input_len.saturating_mul(6).saturating_add(64),
        Strategy::TripleUrlEncode => input_len.saturating_mul(9).saturating_add(128),
        Strategy::UnicodeEncode => input_len.saturating_mul(18).saturating_add(512),
        Strategy::IisUnicodeEncode => input_len.saturating_mul(10).saturating_add(512),
        Strategy::JsonEncode => input_len.saturating_mul(10).saturating_add(32),
        Strategy::HtmlEntityEncode => input_len.saturating_mul(22).saturating_add(512),
        Strategy::HtmlEntityDecimalEncode => input_len.saturating_mul(26).saturating_add(512),
        Strategy::CaseAlternation | Strategy::RandomCase => input_len.saturating_add(256),
        Strategy::WhitespaceInsertion => input_len.saturating_add(256),
        Strategy::SqlCommentInsertion => input_len.saturating_mul(6).saturating_add(256),
        Strategy::MysqlVersionedComment => input_len.saturating_mul(5).saturating_add(8192),
        Strategy::NullByte => input_len.saturating_add(128),
        Strategy::OverlongUtf8 => input_len.saturating_mul(12).saturating_add(256),
        Strategy::OverlongUtf8More => input_len.saturating_mul(18).saturating_add(256),
        Strategy::ChunkedSplit => {
            let chunks = input_len / 1024 + 4;
            input_len.saturating_add(chunks.saturating_mul(24)).saturating_add(256)
        }
        Strategy::ParameterPollution => input_len.saturating_add(64),
        Strategy::Base64Encode | Strategy::Base64UrlEncode => {
            input_len
                .saturating_add(3)
                .saturating_div(3)
                .saturating_mul(4)
                .saturating_add(64)
        }
        Strategy::HexEncode => input_len.saturating_mul(2).saturating_add(64),
        Strategy::Utf7Encode => input_len.saturating_mul(16).saturating_add(512),
        Strategy::GzipEncode | Strategy::DeflateEncode => input_len.saturating_mul(10).saturating_add(65536),
        Strategy::SpaceToComment => input_len.saturating_mul(6),
        Strategy::SpaceToDash => input_len.saturating_mul(6),
        Strategy::SpaceToHash => input_len.saturating_mul(3),
        Strategy::SpaceToPlus => input_len.saturating_mul(3),
        Strategy::SpaceToRandomBlank => input_len.saturating_add(256),
        Strategy::PercentagePrefix => input_len.saturating_mul(10).saturating_add(256),
        Strategy::BetweenObfuscation => input_len.saturating_mul(48).saturating_add(512),
        Strategy::UnmagicQuotes => input_len.saturating_mul(6),
        Strategy::FullwidthEncode => input_len.saturating_mul(5),
        Strategy::HomoglyphEncode => input_len.saturating_mul(5),
        #[allow(unreachable_patterns)]
        _ => input_len.saturating_mul(40).saturating_add(1_048_576),
    }
}

#[must_use]
pub fn mb_zeros() -> Vec<u8> {
    vec![0_u8; ONE_MB]
}

#[must_use]
pub fn mb_del() -> Vec<u8> {
    vec![0x7F_u8; ONE_MB]
}

/// Invalid UTF-8 byte sequences for negative-path coverage (mutators must not panic).
#[must_use]
pub fn invalid_utf8_fixtures() -> Vec<Vec<u8>> {
    vec![
        vec![0x80],
        vec![0xC0, 0xAF],
        vec![0xF0, 0x80, 0x80, 0x80],
        vec![0xED, 0xA0, 0x80],
        vec![0xFF, 0xFE, 0xFD],
    ]
}

/// Rich Unicode for UTF-8-capable mutators (emoji, RTL, combining).
#[must_use]
pub fn unicode_stress() -> String {
    let mut s = String::new();
    s.push_str("αβγ😀🏴‍☠️");
    s.push('\u{202E}');
    s.push_str("SELECT * FROM \"quotes\"");
    s
}
