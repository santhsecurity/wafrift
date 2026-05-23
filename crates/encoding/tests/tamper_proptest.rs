//! Proptest fuzz coverage for every TamperStrategy builtin.
//!
//! Each strategy is exercised against arbitrary UTF-8 strings, ASCII-control
//! payloads, multi-byte chars, and empty inputs.  The suite asserts:
//!
//!  1. `tamper(s, ctx)` never panics for ANY string input.
//!  2. `aggressiveness()` ∈ [0.0, 1.0] and not NaN.
//!  3. For idempotent-class tampers (case_alternation, zero_width_inject):
//!     `tamper(tamper(s))` is reachable without panic.
//!  4. For the BellSeparatorTamper: output round-trips via replace.
//!  5. For ZeroWidthInjectTamper: stripping zero-width chars recovers input.
//!  6. Near-max-length blobs (via Vec<u8> → String) never panic.

use proptest::prelude::*;
use wafrift_encoding::tamper::{
    Base64Tamper, BellSeparatorTamper, BracketConfusableTamper, CaseAlternationTamper,
    DoubleUrlEncodeTamper, HexEncodeTamper, HexLiteralKeywordTamper, HtmlEntityTamper,
    HtmlEntityVariantsTamper, MathBoldTamper, MxssNamespaceWrapTamper,
    MysqlVersionedCommentWrapTamper, NullByteTamper, OverlongUtf8Tamper,
    PostgresDollarQuoteTamper, RandomCaseTamper, SqlCommentTamper, TamperStrategy,
    UnicodeEscapeTamper, UrlEncodeTamper, WhitespaceInsertionTamper, ZeroWidthInjectTamper,
};

// ── Helper: proptest strategy that generates adversarial strings ─────────────
/// Arbitrary UTF-8 strings including ASCII controls, multibyte chars, and
/// near-empty strings.  `proptest::string::string_regex` keeps things
/// interesting without slowing the suite down.
fn adversarial_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Plain ASCII payloads
        "[ -~]{0,256}",
        // ASCII control chars
        "[\\x00-\\x1f]{0,64}",
        // Multibyte: latin + Greek + CJK
        "[a-zA-Z0-9\\u00C0-\\u024F\\u0370-\\u03FF\\u4E00-\\u9FFF]{0,128}",
        // Mixed whitespace
        "[\\t\\n\\r ]{0,64}",
        // SQL keywords
        Just("SELECT * FROM users WHERE id=1".to_string()),
        Just("' OR '1'='1".to_string()),
        Just("UNION SELECT NULL,NULL,NULL--".to_string()),
        // XSS
        Just("<script>alert(1)</script>".to_string()),
        Just("<img src=x onerror=alert(1)>".to_string()),
        // Empty
        Just(String::new()),
        // Lone surrogate-safe: null byte
        Just("\0".to_string()),
        // Max-ish length
        prop::collection::vec(any::<u8>(), 0..4096)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
    ]
}

// ── Macro: generate never-panic + aggressiveness tests for each tamper ───────
macro_rules! never_panic_tests {
    ($($tamper:ident => $test_name:ident),* $(,)?) => {
        $(
            proptest! {
                #[test]
                fn $test_name(s in adversarial_string()) {
                    let t = $tamper;
                    let out = t.tamper(&s, None);
                    // Not empty when input is not empty (some tampers wrap; allow growth)
                    let _ = out; // panic-safety is the only assertion here
                    let a = t.aggressiveness();
                    prop_assert!(
                        (0.0..=1.0).contains(&a) && !a.is_nan(),
                        "aggressiveness {} out of [0,1] for {}",
                        a,
                        t.name()
                    );
                }
            }
        )*
    };
}

never_panic_tests! {
    UrlEncodeTamper            => prop_url_encode_never_panics,
    DoubleUrlEncodeTamper      => prop_double_url_encode_never_panics,
    UnicodeEscapeTamper        => prop_unicode_escape_never_panics,
    HtmlEntityTamper           => prop_html_entity_never_panics,
    HtmlEntityVariantsTamper   => prop_html_entity_variants_never_panics,
    MathBoldTamper             => prop_math_bold_never_panics,
    CaseAlternationTamper      => prop_case_alternation_never_panics,
    RandomCaseTamper           => prop_random_case_never_panics,
    WhitespaceInsertionTamper  => prop_whitespace_insertion_never_panics,
    SqlCommentTamper           => prop_sql_comment_never_panics,
    NullByteTamper             => prop_null_byte_never_panics,
    OverlongUtf8Tamper         => prop_overlong_utf8_never_panics,
    Base64Tamper               => prop_base64_never_panics,
    HexEncodeTamper            => prop_hex_encode_never_panics,
    ZeroWidthInjectTamper      => prop_zero_width_inject_never_panics,
    PostgresDollarQuoteTamper  => prop_postgres_dollar_quote_never_panics,
    MysqlVersionedCommentWrapTamper => prop_mysql_versioned_comment_never_panics,
    HexLiteralKeywordTamper    => prop_hex_literal_keyword_never_panics,
    BellSeparatorTamper        => prop_bell_separator_never_panics,
    BracketConfusableTamper    => prop_bracket_confusable_never_panics,
    MxssNamespaceWrapTamper    => prop_mxss_namespace_wrap_never_panics,
}

// ── Idempotent-class double-apply tests ──────────────────────────────────────

proptest! {
    /// case_alternation applied twice must not panic.
    #[test]
    fn prop_case_alternation_double_apply_no_panic(s in adversarial_string()) {
        let t = CaseAlternationTamper;
        let once = t.tamper(&s, None);
        let _ = t.tamper(&once, None);
    }

    /// zero_width_inject applied twice must not panic AND stripping ZW chars
    /// from the first result recovers the original string.
    #[test]
    fn prop_zero_width_inject_strip_recovers_original(s in "[ -~]{0,256}") {
        // Only test printable ASCII so the round-trip is well-defined;
        // the ZW chars are injected AFTER ASCII alpha, not replacing them.
        let t = ZeroWidthInjectTamper;
        let out = t.tamper(&s, None);
        let stripped: String = out
            .chars()
            .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .collect();
        prop_assert_eq!(
            stripped.as_str(),
            s.as_str(),
            "stripping ZW chars from zero_width_inject output did not recover input"
        );
        // Double-apply must not panic
        let _ = t.tamper(&out, None);
    }

    /// bell_separator round-trips: replace BEL back to space recovers input.
    #[test]
    fn prop_bell_separator_round_trips(s in "[ -~]{0,256}") {
        let t = BellSeparatorTamper;
        let out = t.tamper(&s, None);
        let restored = out.replace('\u{0007}', " ");
        prop_assert_eq!(
            restored.as_str(),
            s.as_str(),
            "bell_separator round-trip failed"
        );
    }

    /// bracket_confusable: the ASCII `<` / `>` disappear from output.
    #[test]
    fn prop_bracket_confusable_no_ascii_angle_brackets(s in "[ -~]{0,256}") {
        let t = BracketConfusableTamper;
        let out = t.tamper(&s, None);
        prop_assert!(
            !out.contains('<') && !out.contains('>'),
            "bracket_confusable left ASCII angle brackets in: {out:?}"
        );
    }

    /// mxss_namespace_wrap always starts with the MathML harness prefix.
    #[test]
    fn prop_mxss_namespace_wrap_always_starts_with_math(s in adversarial_string()) {
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper(&s, None);
        prop_assert!(
            out.starts_with("<math>"),
            "mxss_namespace_wrap output missing MathML root: {out:?}"
        );
    }

    /// postgres_dollar_quote: when the input has no single-quote, output equals input.
    #[test]
    fn prop_postgres_dollar_quote_passthrough_when_no_quote(
        s in "[a-zA-Z0-9 \\t\\n;=<>\\[\\]{}()*+-]{0,256}"
    ) {
        let t = PostgresDollarQuoteTamper;
        let out = t.tamper(&s, None);
        prop_assert_eq!(
            out.as_str(),
            s.as_str(),
            "postgres_dollar_quote mutated an input without single quotes"
        );
    }

    /// mysql_versioned_comment_wrap wraps everything in /*!50000 ... */
    #[test]
    fn prop_mysql_versioned_comment_wrap_structure(s in adversarial_string()) {
        let t = MysqlVersionedCommentWrapTamper;
        let out = t.tamper(&s, None);
        prop_assert!(
            out.starts_with("/*!50000 ") && out.ends_with(" */"),
            "mysql_versioned_comment_wrap produced malformed output: {out:?}"
        );
    }

    /// aggressiveness is in [0,1] for ALL tampers across all registry entries.
    #[test]
    fn prop_registry_aggressiveness_in_range(_s in Just(())) {
        let registry = wafrift_encoding::tamper::TamperRegistry::with_defaults();
        for name in registry.names() {
            let strat = registry.get(name).expect("just iterated this name");
            let a = strat.aggressiveness();
            prop_assert!(
                (0.0..=1.0).contains(&a) && !a.is_nan(),
                "registry tamper `{name}` aggressiveness {a} out of [0,1]"
            );
        }
    }
}

// ── Near-usize::MAX-length via Vec<u8> ────────────────────────────────────────
// We can't actually allocate usize::MAX bytes, but a 512 KB random blob covers
// the "unexpected multi-byte boundary" class of bugs without OOM risk.

#[test]
fn tamper_random_512k_blob_no_panic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Deterministic but non-trivial blob so the test is reproducible.
    let mut blob = Vec::with_capacity(512 * 1024);
    let mut h: u64 = 0xDEAD_BEEF_CAFE_BABE;
    while blob.len() < 512 * 1024 {
        let mut hasher = DefaultHasher::new();
        h.hash(&mut hasher);
        h = hasher.finish();
        blob.extend_from_slice(&h.to_le_bytes());
    }
    let s = String::from_utf8_lossy(&blob).into_owned();

    // Every tamper must survive this; panic = real bug.
    let tampers: &[&dyn TamperStrategy] = &[
        &UrlEncodeTamper,
        &CaseAlternationTamper,
        &RandomCaseTamper,
        &WhitespaceInsertionTamper,
        &SqlCommentTamper,
        &Base64Tamper,
        &HexEncodeTamper,
        &ZeroWidthInjectTamper,
        &BracketConfusableTamper,
        &BellSeparatorTamper,
        &MxssNamespaceWrapTamper,
    ];
    for t in tampers {
        let _ = t.tamper(&s, None);
    }
}

// ── UTF-8 boundary edge cases ──────────────────────────────────────────────────

#[test]
fn tamper_utf8_boundary_chars_no_panic() {
    // Characters at notable boundaries: U+007F (DEL), U+0080 (first 2-byte),
    // U+07FF (last 2-byte), U+0800 (first 3-byte), U+FFFD (replacement char),
    // U+10000 (first 4-byte), U+10FFFF (highest codepoint).
    let edge = "\u{007F}\u{0080}\u{07FF}\u{0800}\u{FFFD}\u{10000}\u{10FFFF}";
    let tampers: &[&dyn TamperStrategy] = &[
        &UrlEncodeTamper,
        &DoubleUrlEncodeTamper,
        &UnicodeEscapeTamper,
        &HtmlEntityTamper,
        &HtmlEntityVariantsTamper,
        &CaseAlternationTamper,
        &RandomCaseTamper,
        &Base64Tamper,
        &HexEncodeTamper,
        &ZeroWidthInjectTamper,
        &BellSeparatorTamper,
        &BracketConfusableTamper,
    ];
    for t in tampers {
        let _ = t.tamper(edge, None);
    }
}
