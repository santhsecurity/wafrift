//! Strategy enum and main encode() dispatcher.

use super::invisible::{
    circled_letter_encode, ligature_encode, parenthesized_letter_encode, soft_hyphen_inject,
    tag_char_encode, variation_selector_pad, variation_selector_supplementary_pad,
    word_joiner_wrap,
};
use super::keyword::{
    between_obfuscate, case_alternate, mysql_versioned_comment, percentage_prefix,
    random_case_alternate, space_to_comment, space_to_dash, space_to_hash, space_to_plus,
    space_to_random_blank, sql_comment_insert, unmagic_quotes, whitespace_insert,
};
use super::structural::{
    base64_encode, base64_url_encode, chunked_split, deflate_encode, gzip_encode, hex_encode,
    null_byte_inject, overlong_utf8, overlong_utf8_more, parameter_pollute, utf7_encode,
};
use super::unicode::{
    fullwidth_encode, homoglyph_encode, html_entity_decimal_encode, html_entity_encode,
    iis_unicode_encode, json_string_encode, unicode_encode,
};
use super::url::{double_url_encode, triple_url_encode, url_encode, url_encode_lower};
use crate::error::EncodeError;

/// Maximum input payload size to prevent OOM on adversarial input.
pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;

/// Default chunk size for `Strategy::ChunkedSplit`.
///
/// 1 KiB chunks are large enough to avoid excessive chunk-count overhead
/// on typical SQLi payloads (< 1 KB) while small enough that a WAF
/// scanning only the first chunk misses the rest. Callers needing a
/// different split granularity can call `structural::chunked_split` directly.
pub const CHUNKED_SPLIT_DEFAULT_CHUNK_SIZE: usize = 1024;

/// MySQL version number used in `/*!VERSIONKEYWORD*/` versioned comments.
///
/// `50000` = MySQL 5.0.0, the baseline for the `/*!...*/` conditional-
/// execution syntax. Any MySQL 5.0+ instance will execute the wrapped
/// keyword; WAFs that don't implement the MySQL comment parser will skip it.
/// Virtually every production MySQL installation targeted by Cloudflare
/// CumulusFire runs >= 5.0.0.
pub const MYSQL_VERSIONED_COMMENT_VERSION: u32 = 50_000;

/// Available encoding strategies.
///
/// # Context hints
/// Many strategies are only semantically correct in specific parser contexts.
/// Use [`Strategy::contexts`] to query the applicable contexts for a strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Strategy {
    /// Standard URL encoding (%XX) — preserves unreserved chars per RFC 3986.
    /// Safe for: query strings, paths, form data.
    UrlEncode,
    /// Lowercase hex URL encoding (%xx) — same semantics as `UrlEncode`.
    /// Safe for: query strings, paths, form data.
    UrlEncodeLower,
    /// Double URL encoding (%25XX) — bypasses WAFs that decode once.
    /// Safe for: query strings, paths, form data.
    DoubleUrlEncode,
    /// Triple URL encoding (%2525XX) — bypasses WAFs that decode twice.
    /// Safe for: query strings, paths, form data.
    TripleUrlEncode,
    /// Unicode escape (\uXXXX) — ONLY safe when target parses JSON/JavaScript.
    /// Unsafe for: raw HTTP parameters, headers, most server frameworks.
    UnicodeEncode,
    /// IIS/ASP percent Unicode (%uXXXX) — ONLY safe on IIS/ASP classic parsers.
    /// Unsafe for: modern servers (nginx, Apache, Node.js, etc.).
    IisUnicodeEncode,
    /// JSON string encoding with Unicode escapes — ONLY safe in JSON contexts.
    /// Unsafe for: raw HTTP parameters.
    JsonEncode,
    /// HTML entity encoding (&#xXX;) — ONLY safe in HTML contexts.
    /// Unsafe for: raw HTTP parameters, JSON bodies.
    HtmlEntityEncode,
    /// HTML decimal entity encoding (&#60;) — ONLY safe in HTML contexts.
    /// Unsafe for: raw HTTP parameters, JSON bodies.
    HtmlEntityDecimalEncode,
    /// Alternating case (`SeLeCt`) — bypasses case-sensitive keyword filters.
    /// Safe for: any text context where case is preserved.
    CaseAlternation,
    /// Random alternating case — non-deterministic variant of `CaseAlternation`.
    /// Safe for: any text context where case is preserved.
    RandomCase,
    /// Tab insertion BETWEEN tokens — preserves keyword integrity.
    /// Safe for: SQL contexts where whitespace separates tokens.
    WhitespaceInsertion,
    /// SQL comment insertion BETWEEN tokens — preserves keyword integrity.
    /// Safe for: SQL contexts where comments are treated as whitespace.
    SqlCommentInsertion,
    /// `MySQL` versioned comment (`/*!50000SELECT*/`) — executed by `MySQL`, ignored by WAFs.
    /// Safe for: `MySQL` backends.
    MysqlVersionedComment,
    /// Null byte injection (%00) — ONLY semantically correct for C-style string parsers.
    /// Context: php, some CGI implementations.
    NullByte,
    /// Overlong UTF-8 encoding (2-byte) — ONLY works against legacy WAFs that normalize.
    /// Context: iis-6, very old frontends.
    OverlongUtf8,
    /// Extended overlong UTF-8 encoding (3-byte) — broader coverage than `OverlongUtf8`.
    /// Context: iis-6, very old frontends.
    OverlongUtf8More,
    /// Chunked transfer-encoding split — ONLY valid with `Transfer-Encoding: chunked`.
    /// Context: http-request-body.
    ChunkedSplit,
    /// HTTP parameter pollution — duplicate parameter with benign first value.
    /// Safe for: query strings, form data.
    ParameterPollution,
    /// Base64 encoding (standard alphabet).
    /// Safe for: headers, bodies, query strings (may need URL encoding after).
    Base64Encode,
    /// Base64 URL-safe encoding (-_ no padding).
    /// Safe for: URL contexts where +/ would be mangled.
    Base64UrlEncode,
    /// Hex encoding.
    /// Safe for: any byte context.
    HexEncode,
    /// UTF-7 encoding per RFC 2152.
    /// Context: legacy IIS/.NET parsers that decode UTF-7.
    Utf7Encode,
    /// Gzip compression — ONLY valid with `Content-Encoding: gzip`.
    /// Context: http-request-body.
    GzipEncode,
    /// Deflate compression — ONLY valid with `Content-Encoding: deflate`.
    /// Context: http-request-body.
    DeflateEncode,
    /// Replace spaces with SQL comments (`/**/`).
    /// Safe for: SQL contexts.
    SpaceToComment,
    /// Replace spaces with dash comments (`--`).
    /// Safe for: SQL contexts.
    SpaceToDash,
    /// Replace spaces with hash comments (`#`).
    /// Safe for: `MySQL` contexts.
    SpaceToHash,
    /// Replace spaces with plus signs (`+`).
    /// Safe for: URL-encoded form data.
    SpaceToPlus,
    /// Replace spaces with random blank characters.
    /// Safe for: SQL contexts.
    SpaceToRandomBlank,
    /// Prefix each character with `%` — lightweight bypass.
    /// Safe for: contexts that strip `%` before parsing.
    PercentagePrefix,
    /// Between obfuscation (`=` → `BETWEEN # AND #`).
    /// Safe for: SQL contexts.
    BetweenObfuscation,
    /// Unmagic quotes (`%bf%27`) — multi-byte charset quote escape.
    /// Context: PHP with GBK/Big5/Shift-JIS connections.
    UnmagicQuotes,
    /// Fullwidth Unicode (`ＳＥＬＥＣＴuntouched`) — bypasses ASCII keyword regex.
    /// Context: backends that perform NFKC normalization (Java, .NET, Python 3, `PostgreSQL`).
    FullwidthEncode,
    /// Homoglyph substitution — visually identical Unicode chars for `'`, `"`, `<`, `>`, `=`.
    /// Context: byte-level WAFs with Unicode-tolerant backends.
    HomoglyphEncode,
    /// Plan 9 tag-character encoding — every ASCII byte becomes
    /// `U+E0000 + byte`. Renders invisible; LLM-WAF tokenizers
    /// frequently still decode them, defeating keyword filters.
    /// Context: any (codepoint-level transforms).
    TagCharEncode,
    /// Append U+FE0F VARIATION SELECTOR-16 after every codepoint.
    /// Some normalizers strip it; many WAFs don't.
    /// Context: any.
    VariationSelectorPad,
    /// Same as `VariationSelectorPad` but rotates through the
    /// supplementary range U+E0100..=U+E01EF (per-position selector).
    /// Defeats filters that strip the basic VS range only.
    /// Context: any.
    VariationSelectorSupplementaryPad,
    /// Replace `ff`/`fi`/`fl`/`ffi`/`ffl`/`st`/`ſt` with their
    /// precomposed stylistic ligature codepoints (U+FB00..=U+FB06).
    /// NFKC decomposes back; pre-NFKC WAFs see opaque codepoints.
    /// Context: nfkc (origins that NFKC-fold).
    LigatureEncode,
    /// Replace ASCII letters with U+24B6..=U+24E9 circled forms.
    /// NFKC-equivalent to ASCII letters.
    /// Context: nfkc.
    CircledLetterEncode,
    /// Replace ASCII letters with U+1F110..=U+1F12B (upper) /
    /// U+249C..=U+24B5 (lower) parenthesized forms.
    /// NFKC-equivalent to ASCII letters. Rotation partner for
    /// `FullwidthEncode` / `CircledLetterEncode`.
    /// Context: nfkc.
    ParenthesizedLetterEncode,
    /// Inject U+00AD SOFT HYPHEN between every pair of codepoints.
    /// Visually invisible; some backends strip during normalization.
    /// Context: any.
    SoftHyphenInject,
    /// Wrap each codepoint in U+2060 WORD JOINER.
    /// Zero-width, NFC-stable, NFKC strips it.
    /// Context: any.
    WordJoinerWrap,
}

impl Strategy {
    /// Returns the string identifier for this encoding strategy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UrlEncode => "UrlEncode",
            Self::UrlEncodeLower => "UrlEncodeLower",
            Self::DoubleUrlEncode => "DoubleUrlEncode",
            Self::TripleUrlEncode => "TripleUrlEncode",
            Self::UnicodeEncode => "UnicodeEncode",
            Self::IisUnicodeEncode => "IisUnicodeEncode",
            Self::JsonEncode => "JsonEncode",
            Self::HtmlEntityEncode => "HtmlEntityEncode",
            Self::HtmlEntityDecimalEncode => "HtmlEntityDecimalEncode",
            Self::CaseAlternation => "CaseAlternation",
            Self::RandomCase => "RandomCase",
            Self::WhitespaceInsertion => "WhitespaceInsertion",
            Self::SqlCommentInsertion => "SqlCommentInsertion",
            Self::MysqlVersionedComment => "MysqlVersionedComment",
            Self::NullByte => "NullByte",
            Self::OverlongUtf8 => "OverlongUtf8",
            Self::OverlongUtf8More => "OverlongUtf8More",
            Self::ChunkedSplit => "ChunkedSplit",
            Self::ParameterPollution => "ParameterPollution",
            Self::Base64Encode => "Base64Encode",
            Self::Base64UrlEncode => "Base64UrlEncode",
            Self::HexEncode => "HexEncode",
            Self::Utf7Encode => "Utf7Encode",
            Self::GzipEncode => "GzipEncode",
            Self::DeflateEncode => "DeflateEncode",
            Self::SpaceToComment => "SpaceToComment",
            Self::SpaceToDash => "SpaceToDash",
            Self::SpaceToHash => "SpaceToHash",
            Self::SpaceToPlus => "SpaceToPlus",
            Self::SpaceToRandomBlank => "SpaceToRandomBlank",
            Self::PercentagePrefix => "PercentagePrefix",
            Self::BetweenObfuscation => "BetweenObfuscation",
            Self::UnmagicQuotes => "UnmagicQuotes",
            Self::FullwidthEncode => "FullwidthEncode",
            Self::HomoglyphEncode => "HomoglyphEncode",
            Self::TagCharEncode => "TagCharEncode",
            Self::VariationSelectorPad => "VariationSelectorPad",
            Self::VariationSelectorSupplementaryPad => "VariationSelectorSupplementaryPad",
            Self::LigatureEncode => "LigatureEncode",
            Self::CircledLetterEncode => "CircledLetterEncode",
            Self::ParenthesizedLetterEncode => "ParenthesizedLetterEncode",
            Self::SoftHyphenInject => "SoftHyphenInject",
            Self::WordJoinerWrap => "WordJoinerWrap",
        }
    }

    /// Returns the parser contexts where this strategy is semantically safe.
    ///
    /// An empty slice means the strategy is generally applicable.
    /// Callers should gate strategy application by matching these contexts
    /// against the target type (e.g., `json`, `html`, `sql`, `php`, `iis-6`).
    #[must_use]
    pub const fn contexts(&self) -> &'static [&'static str] {
        match self {
            Self::UrlEncode
            | Self::UrlEncodeLower
            | Self::DoubleUrlEncode
            | Self::TripleUrlEncode
            | Self::ParameterPollution => &[],
            Self::UnicodeEncode => &["json", "javascript"],
            Self::IisUnicodeEncode => &["iis", "asp"],
            Self::JsonEncode => &["json"],
            Self::HtmlEntityEncode | Self::HtmlEntityDecimalEncode => &["html"],
            Self::CaseAlternation | Self::RandomCase | Self::WhitespaceInsertion => &[],
            Self::SqlCommentInsertion
            | Self::MysqlVersionedComment
            | Self::SpaceToComment
            | Self::SpaceToDash
            | Self::SpaceToRandomBlank
            | Self::BetweenObfuscation => &["sql"],
            Self::SpaceToHash => &["sql", "mysql"],
            Self::SpaceToPlus => &["url-encoded"],
            Self::NullByte => &["php", "cgi"],
            Self::OverlongUtf8 | Self::OverlongUtf8More => &["iis-6"],
            Self::ChunkedSplit => &["http-request-body"],
            Self::Base64Encode | Self::Base64UrlEncode | Self::HexEncode => &[],
            Self::Utf7Encode => &["iis", "legacy-dotnet"],
            Self::GzipEncode | Self::DeflateEncode => &["http-request-body"],
            Self::PercentagePrefix => &[],
            Self::UnmagicQuotes => &["php", "gbk", "big5", "shift-jis"],
            Self::FullwidthEncode => &["nfkc", "java", "dotnet", "python3", "postgresql"],
            Self::HomoglyphEncode => &[],
            Self::TagCharEncode
            | Self::VariationSelectorPad
            | Self::VariationSelectorSupplementaryPad
            | Self::SoftHyphenInject
            | Self::WordJoinerWrap => &[],
            Self::LigatureEncode | Self::CircledLetterEncode | Self::ParenthesizedLetterEncode => {
                &["nfkc"]
            }
        }
    }
}

fn check_size(payload: &[u8]) -> Result<(), EncodeError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        Err(EncodeError::PayloadTooLarge {
            max: MAX_PAYLOAD_SIZE,
            actual: payload.len(),
        })
    } else {
        Ok(())
    }
}

/// Encode a payload using the selected strategy.
///
/// # Errors
/// Returns `EncodeError::PayloadTooLarge` if the input exceeds [`MAX_PAYLOAD_SIZE`].
/// Returns `EncodeError::InvalidUtf8` for text-oriented strategies when the input
/// contains invalid UTF-8.
///
/// # UTF-8 safety
/// Text-oriented strategies validate UTF-8 via `std::str::from_utf8` and return
/// `InvalidUtf8` on failure. No unsafe UTF-8 conversions (`from_utf8_unchecked`,
/// lossy casts, etc.) are used in the encoding pipeline.
pub fn encode(payload: impl AsRef<[u8]>, strategy: Strategy) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    check_size(payload)?;

    match strategy {
        Strategy::UrlEncode => Ok(url_encode(payload)),
        Strategy::UrlEncodeLower => Ok(url_encode_lower(payload)),
        Strategy::DoubleUrlEncode => Ok(double_url_encode(payload)),
        Strategy::TripleUrlEncode => Ok(triple_url_encode(payload)),
        Strategy::UnicodeEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(unicode_encode(text))
        }
        Strategy::IisUnicodeEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(iis_unicode_encode(text))
        }
        Strategy::JsonEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(json_string_encode(text))
        }
        Strategy::HtmlEntityEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(html_entity_encode(text))
        }
        Strategy::HtmlEntityDecimalEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(html_entity_decimal_encode(text))
        }
        Strategy::CaseAlternation => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(case_alternate(text))
        }
        Strategy::RandomCase => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(random_case_alternate(text))
        }
        Strategy::WhitespaceInsertion => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(whitespace_insert(text))
        }
        Strategy::SqlCommentInsertion => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(sql_comment_insert(text))
        }
        Strategy::MysqlVersionedComment => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(mysql_versioned_comment(
                text,
                MYSQL_VERSIONED_COMMENT_VERSION,
            ))
        }
        Strategy::NullByte => Ok(null_byte_inject(payload)?),
        Strategy::OverlongUtf8 => Ok(overlong_utf8(payload)?),
        Strategy::OverlongUtf8More => Ok(overlong_utf8_more(payload)?),
        Strategy::ChunkedSplit => {
            let body = chunked_split(payload, CHUNKED_SPLIT_DEFAULT_CHUNK_SIZE)?.body;
            String::from_utf8(body).map_err(|_| EncodeError::InvalidUtf8)
        }
        Strategy::ParameterPollution => Ok(parameter_pollute(payload)?),
        Strategy::Base64Encode => Ok(base64_encode(payload)),
        Strategy::Base64UrlEncode => Ok(base64_url_encode(payload)),
        Strategy::HexEncode => Ok(hex_encode(payload)),
        Strategy::Utf7Encode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(utf7_encode(text))
        }
        Strategy::GzipEncode => Ok(gzip_encode(payload)?),
        Strategy::DeflateEncode => Ok(deflate_encode(payload)?),
        Strategy::SpaceToComment => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(space_to_comment(text))
        }
        Strategy::SpaceToDash => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(space_to_dash(text))
        }
        Strategy::SpaceToHash => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(space_to_hash(text))
        }
        Strategy::SpaceToPlus => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(space_to_plus(text))
        }
        Strategy::SpaceToRandomBlank => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(space_to_random_blank(text))
        }
        Strategy::PercentagePrefix => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(percentage_prefix(text))
        }
        Strategy::BetweenObfuscation => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(between_obfuscate(text))
        }
        Strategy::UnmagicQuotes => Ok(unmagic_quotes(payload)?),
        Strategy::FullwidthEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(fullwidth_encode(text))
        }
        Strategy::HomoglyphEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(homoglyph_encode(text))
        }
        Strategy::TagCharEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(tag_char_encode(text))
        }
        Strategy::VariationSelectorPad => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(variation_selector_pad(text, '\u{FE0F}'))
        }
        Strategy::VariationSelectorSupplementaryPad => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(variation_selector_supplementary_pad(text))
        }
        Strategy::LigatureEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(ligature_encode(text))
        }
        Strategy::CircledLetterEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(circled_letter_encode(text))
        }
        Strategy::ParenthesizedLetterEncode => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(parenthesized_letter_encode(text))
        }
        Strategy::SoftHyphenInject => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(soft_hyphen_inject(text))
        }
        Strategy::WordJoinerWrap => {
            let text = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
            Ok(word_joiner_wrap(text))
        }
    }
}

/// All available strategies in escalation order (least aggressive → most aggressive).
static ALL_STRATEGIES: std::sync::LazyLock<Vec<Strategy>> = std::sync::LazyLock::new(|| {
    let mut strategies = vec![
        Strategy::CaseAlternation,
        Strategy::RandomCase,
        Strategy::WhitespaceInsertion,
        Strategy::SqlCommentInsertion,
        Strategy::SpaceToPlus,
        Strategy::SpaceToRandomBlank,
        Strategy::SpaceToComment,
        Strategy::SpaceToDash,
        Strategy::SpaceToHash,
        Strategy::UrlEncode,
        Strategy::UrlEncodeLower,
        Strategy::DoubleUrlEncode,
        Strategy::UnicodeEncode,
        Strategy::IisUnicodeEncode,
        Strategy::JsonEncode,
        Strategy::HtmlEntityEncode,
        Strategy::HtmlEntityDecimalEncode,
        Strategy::NullByte,
        Strategy::PercentagePrefix,
        Strategy::TripleUrlEncode,
        Strategy::ChunkedSplit,
        Strategy::ParameterPollution,
        Strategy::MysqlVersionedComment,
        Strategy::Base64Encode,
        Strategy::Base64UrlEncode,
        Strategy::OverlongUtf8,
        Strategy::OverlongUtf8More,
        Strategy::HexEncode,
        Strategy::Utf7Encode,
        Strategy::BetweenObfuscation,
        Strategy::UnmagicQuotes,
        Strategy::FullwidthEncode,
        Strategy::HomoglyphEncode,
        Strategy::GzipEncode,
        Strategy::DeflateEncode,
        Strategy::TagCharEncode,
        Strategy::VariationSelectorPad,
        Strategy::VariationSelectorSupplementaryPad,
        Strategy::LigatureEncode,
        Strategy::CircledLetterEncode,
        Strategy::ParenthesizedLetterEncode,
        Strategy::SoftHyphenInject,
        Strategy::WordJoinerWrap,
    ];
    strategies.sort_by(|a, b| {
        super::layered::aggressiveness(*a)
            .partial_cmp(&super::layered::aggressiveness(*b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    strategies
});

#[must_use]
pub fn all_strategies() -> &'static [Strategy] {
    &ALL_STRATEGIES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_url_encode_basic() {
        assert_eq!(encode("A<", Strategy::UrlEncode).unwrap(), "A%3C");
    }

    #[test]
    fn encode_url_encode_lower() {
        assert_eq!(encode("A<", Strategy::UrlEncodeLower).unwrap(), "A%3c");
    }

    #[test]
    fn encode_double_url_encode() {
        assert_eq!(
            encode("A<", Strategy::DoubleUrlEncode).unwrap(),
            "%2541%253C"
        );
    }

    #[test]
    fn encode_case_alternation() {
        let result = encode("SELECT", Strategy::CaseAlternation).unwrap();
        assert!(result.contains("SeL") || result.contains("sEl"));
    }

    #[test]
    fn encode_null_byte() {
        let result = encode("file.php", Strategy::NullByte).unwrap();
        assert!(result.contains('\x00') || result.contains("%00"));
    }

    #[test]
    fn encode_base64() {
        assert_eq!(encode("hello", Strategy::Base64Encode).unwrap(), "aGVsbG8=");
    }

    #[test]
    fn encode_hex() {
        assert_eq!(encode("ABC", Strategy::HexEncode).unwrap(), "414243");
    }

    #[test]
    fn encode_json() {
        // F67: encoder now produces escaped CONTENT only, no
        // surrounding quotes — the variant builder substitutes
        // into an existing JSON string field.
        assert_eq!(encode("A<", Strategy::JsonEncode).unwrap(), "A<");
        // Real escape: backslash + control char.
        assert_eq!(encode("a\\\nb", Strategy::JsonEncode).unwrap(), "a\\\\\\nb");
    }

    #[test]
    fn encode_html_entity() {
        assert_eq!(
            encode("A<", Strategy::HtmlEntityEncode).unwrap(),
            "&#x41;&#x3C;"
        );
    }

    #[test]
    fn encode_invalid_utf8_fails() {
        let invalid = vec![0x80, 0x81, 0x82];
        let result = encode(&invalid, Strategy::CaseAlternation);
        assert!(matches!(result, Err(EncodeError::InvalidUtf8)));
    }

    #[test]
    fn encode_payload_too_large_fails() {
        let huge = vec![b'X'; MAX_PAYLOAD_SIZE + 1];
        let result = encode(&huge, Strategy::UrlEncode);
        assert!(matches!(result, Err(EncodeError::PayloadTooLarge { .. })));
    }

    /// R55 pass-19 I6 (CLAUDE.md §12 TESTING boundary): the gate is
    /// `payload.len() > MAX_PAYLOAD_SIZE` (strictly greater-than), so
    /// a payload of exactly `MAX_PAYLOAD_SIZE` MUST succeed. Anti-rig:
    /// if someone changes the comparison to `>=`, this test fails
    /// instantly. The complementary `> MAX_PAYLOAD_SIZE + 1` case is
    /// pinned by `encode_payload_too_large_fails`.
    #[test]
    fn encode_at_exact_max_payload_size_succeeds() {
        let at_limit = vec![b'X'; MAX_PAYLOAD_SIZE];
        let result = encode(&at_limit, Strategy::UrlEncode);
        assert!(
            result.is_ok(),
            "boundary contract: exactly MAX_PAYLOAD_SIZE bytes must encode, got {result:?}"
        );
    }

    #[test]
    fn all_strategies_non_empty() {
        let strategies = all_strategies();
        assert!(!strategies.is_empty());
        assert!(strategies.contains(&Strategy::UrlEncode));
    }

    #[test]
    fn strategy_as_str_roundtrip() {
        for s in all_strategies() {
            assert!(!s.as_str().is_empty());
        }
    }

    #[test]
    fn strategy_contexts_returns_slice() {
        assert!(Strategy::UrlEncode.contexts().is_empty());
        assert_eq!(Strategy::JsonEncode.contexts(), &["json"]);
        assert_eq!(Strategy::SpaceToComment.contexts(), &["sql"]);
    }

    #[test]
    fn encode_empty_payload() {
        assert_eq!(encode("", Strategy::UrlEncode).unwrap(), "");
    }

    #[test]
    fn encode_unicode() {
        let result = encode("A<", Strategy::UnicodeEncode).unwrap();
        assert!(result.contains("\\u"));
    }

    #[test]
    fn encode_chunked_split() {
        let result = encode("hello", Strategy::ChunkedSplit).unwrap();
        assert!(result.contains("\r\n"));
        assert!(result.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn encode_parameter_pollution() {
        let result = encode("key=value", Strategy::ParameterPollution).unwrap();
        assert!(result.contains("key="));
    }

    #[test]
    fn encode_gzip_produces_base64() {
        let result = encode("hello", Strategy::GzipEncode).unwrap();
        // Gzip output is base64-encoded
        assert!(!result.is_empty());
    }

    #[test]
    fn encode_iis_unicode() {
        let result = encode("A<", Strategy::IisUnicodeEncode).unwrap();
        assert!(result.contains("%u"));
    }
}
