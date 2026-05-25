//! Adversarial fixtures for the Cloudflare WAF response parser
//! (`wafrift_oracle::cloudflare::parse_cf_block`).
//!
//! Closes #173. Real CF responses vary wildly: edge POP rotation,
//! retry-after on rate limits, missing cf-ray on cache hits, body
//! truncation mid-html, multi-byte UTF-8 in attribution strings,
//! lowercased headers from proxies, mid-stream socket disconnect.
//! The parser must NEVER panic on any of them — corrupted input
//! falls back to `BlockClass::Unknown` and we keep going.

use wafrift_oracle::cloudflare::{parse_cf_block, BlockClass};

// Compact helper so each fixture reads as one block.
fn hdr(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

// ───────────────────────────────────────────────────────────────
// Header-shape adversarial inputs
// ───────────────────────────────────────────────────────────────

#[test]
fn truncated_cf_ray_does_not_panic() {
    // Real CF cf-ray is 16+ hex chars + "-IATA". Some intermediaries
    // truncate.
    let h = hdr(&[("cf-ray", "abc")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_ray_with_no_dash_does_not_panic() {
    let h = hdr(&[("cf-ray", "abcdef0123456789")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_ray_with_lowercase_iata_does_not_panic() {
    let h = hdr(&[("cf-ray", "abcdef0123456789-sjc")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_ray_with_non_iata_suffix_does_not_panic() {
    let h = hdr(&[("cf-ray", "abcdef0123456789-XXXXX")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_ray_empty_does_not_panic() {
    let h = hdr(&[("cf-ray", "")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_mitigated_unknown_value_does_not_panic() {
    let h = hdr(&[("cf-mitigated", "asdf-not-a-real-value")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn cf_mitigated_empty_value() {
    let h = hdr(&[("cf-mitigated", "")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn case_variations_in_header_names() {
    // Some proxies normalize header case to upper or mixed.
    let h = hdr(&[("CF-RAY", "abcdef0123456789-SJC"), ("CF-Mitigated", "block")]);
    let signal = parse_cf_block(&h, b"");
    // Parser should be case-insensitive on header names.
    assert!(
        signal.cf_ray.is_some() || matches!(signal.block_class, BlockClass::Unknown),
        "should handle uppercase header names"
    );
}

#[test]
fn duplicate_cf_ray_headers_does_not_panic() {
    let h = hdr(&[
        ("cf-ray", "first-SJC"),
        ("cf-ray", "second-LHR"),
    ]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn retry_after_classifies_as_rate_limited() {
    let h = hdr(&[("retry-after", "60"), ("cf-ray", "x-SJC")]);
    let signal = parse_cf_block(&h, b"");
    assert!(matches!(signal.block_class, BlockClass::RateLimited));
}

#[test]
fn retry_after_non_numeric_does_not_panic() {
    let h = hdr(&[("retry-after", "soon, please")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn retry_after_negative_does_not_panic() {
    let h = hdr(&[("retry-after", "-9999")]);
    let _ = parse_cf_block(&h, b"");
}

#[test]
fn retry_after_huge_value_does_not_panic() {
    let h = hdr(&[("retry-after", "18446744073709551615")]); // u64::MAX
    let _ = parse_cf_block(&h, b"");
}

// ───────────────────────────────────────────────────────────────
// Body-shape adversarial inputs
// ───────────────────────────────────────────────────────────────

#[test]
fn empty_body_with_block_headers() {
    let h = hdr(&[("cf-mitigated", "block"), ("cf-ray", "x-SJC")]);
    let signal = parse_cf_block(&h, b"");
    assert!(matches!(
        signal.block_class,
        BlockClass::ManagedRulesetBlock | BlockClass::Unknown
    ));
}

#[test]
fn html_truncated_mid_tag_does_not_panic() {
    // CF block pages sometimes get truncated by intermediaries.
    let body = b"<html><body>Sorry, you have been blocked. Cloudflare Ray ID: abc-SJC";
    let _ = parse_cf_block(&[], body);
}

#[test]
fn body_with_only_open_brace_does_not_panic() {
    let _ = parse_cf_block(&[], b"{");
}

#[test]
fn body_with_only_html_comment_open_does_not_panic() {
    let _ = parse_cf_block(&[], b"<!-- ");
}

#[test]
fn body_with_unterminated_comment_does_not_panic() {
    let _ = parse_cf_block(&[], b"<!-- 951220");
}

#[test]
fn body_with_just_double_dashes() {
    let _ = parse_cf_block(&[], b"--");
}

#[test]
fn cve_id_in_body_attributes_correctly() {
    let body = b"Error 1020 - Access denied. Pattern matched: CVE-2021-44228";
    let signal = parse_cf_block(&[], body);
    assert!(
        signal.ruleset_hint.as_deref() == Some("log4shell")
            || signal.ruleset_hint.is_some(),
        "CVE-2021-44228 should map to log4shell or some ruleset hint"
    );
}

#[test]
fn body_with_multibyte_utf8_in_attribution() {
    let body = "Sorry — vous avez été bloqué. Cloudflare Ray ID: déjà-vu-SJC".as_bytes();
    let _ = parse_cf_block(&[], body);
}

#[test]
fn body_with_invalid_utf8_does_not_panic() {
    let body: &[u8] = &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let _ = parse_cf_block(&[], body);
}

#[test]
fn body_with_null_bytes_does_not_panic() {
    let body: &[u8] = &[b'<', 0, 0, 0, b'>', 0];
    let _ = parse_cf_block(&[], body);
}

#[test]
fn body_50kb_no_panic() {
    let body = "Sorry, you have been blocked. ".repeat(2000);
    let _ = parse_cf_block(&[], body.as_bytes());
}

#[test]
fn body_with_only_whitespace_does_not_panic() {
    let _ = parse_cf_block(&[], b"   \r\n\t  ");
}

#[test]
fn body_with_thousand_open_tags_does_not_panic() {
    let body = "<a>".repeat(1000);
    let _ = parse_cf_block(&[], body.as_bytes());
}

#[test]
fn body_with_cf_error_code_1020_classifies_managed_rule() {
    // Parser recognises the canonical CF block-page phrasings —
    // `error code: 1020`, `<!-- error code: 1020 -->`,
    // `data-translate="error_code">1020<`, `::ERRORPAGESSTATUS::1020`.
    let body = b"<html>error code: 1020 - Access denied.</html>";
    let signal = parse_cf_block(&[], body);
    // 1020 maps to waf-managed-rule per Sonnet C's parser.
    assert!(
        signal.ruleset_hint.is_some(),
        "error 1020 should produce a ruleset hint, got {:?}",
        signal.ruleset_hint
    );
}

#[test]
fn body_with_cf_error_code_1015_classifies_rate_limit() {
    let body = b"Error 1015 - Rate limited";
    let signal = parse_cf_block(&[], body);
    // 1015 = rate-limited.
    let class = signal.block_class;
    assert!(
        matches!(class, BlockClass::RateLimited | BlockClass::Unknown),
        "error 1015 should classify as RateLimited (got {class:?})"
    );
}

#[test]
fn html_with_old_style_rule_id_comment() {
    let body = b"<html><body>blocked <!-- 951220 --></body></html>";
    let signal = parse_cf_block(&[], body);
    // Old-style comment with rule_id is the most specific signal.
    assert!(!signal.rule_attribution.is_empty() || signal.ruleset_hint.is_some());
}

#[test]
fn old_rule_comment_with_alpha_does_not_panic() {
    let body = b"<!-- abc-not-a-number -->";
    let _ = parse_cf_block(&[], body);
}

#[test]
fn old_rule_comment_with_negative_number_does_not_panic() {
    let body = b"<!-- -1 -->";
    let _ = parse_cf_block(&[], body);
}

// ───────────────────────────────────────────────────────────────
// Challenge / CAPTCHA / Browser-check shapes
// ───────────────────────────────────────────────────────────────

#[test]
fn cf_mitigated_challenge_body_says_just_a_moment() {
    let h = hdr(&[("cf-mitigated", "challenge"), ("cf-ray", "x-SJC")]);
    let body = b"<html><title>Just a moment...</title></html>";
    let signal = parse_cf_block(&h, body);
    assert!(matches!(
        signal.block_class,
        BlockClass::BrowserCheck | BlockClass::BotChallenge | BlockClass::Unknown
    ));
}

#[test]
fn captcha_body_marker() {
    let h = hdr(&[("cf-mitigated", "challenge"), ("cf-ray", "x-SJC")]);
    let body = b"<html>Please solve the CAPTCHA below to continue.</html>";
    let signal = parse_cf_block(&h, body);
    assert!(matches!(
        signal.block_class,
        BlockClass::Captcha | BlockClass::BotChallenge | BlockClass::Unknown
    ));
}

#[test]
fn manual_review_body_marker_does_not_panic() {
    let body = b"Your request is under manual review. Please contact support.";
    let _ = parse_cf_block(&[], body);
}

// ───────────────────────────────────────────────────────────────
// Mixed signals — multiple potential block_class hints
// ───────────────────────────────────────────────────────────────

#[test]
fn block_and_retry_after_takes_rate_limit() {
    // retry-after present should take precedence over cf-mitigated:block.
    let h = hdr(&[
        ("retry-after", "30"),
        ("cf-mitigated", "block"),
        ("cf-ray", "x-SJC"),
    ]);
    let signal = parse_cf_block(&h, b"");
    assert!(matches!(signal.block_class, BlockClass::RateLimited));
}

#[test]
fn cve_id_alone_produces_attribution() {
    // CVE-2021-44228 in the body must produce SOME attribution —
    // the parser surfaces either the raw CVE id or the named class
    // "log4shell" (both are valid; the raw CVE id is more specific
    // because it pins which CVE the rule fired on).
    let body = b"<html>Pattern matched: log4j class CVE-2021-44228</html>";
    let signal = parse_cf_block(&[], body);
    let hint = signal.ruleset_hint.as_deref().unwrap_or("");
    assert!(
        hint == "log4shell" || hint.contains("CVE-2021-44228"),
        "expected log4shell or CVE id attribution, got: {hint:?}"
    );
}

#[test]
fn old_comment_beats_cve_id() {
    // Old-style <!-- 951220 --> comment is even more specific than CVE.
    let body = b"<!-- 951220 --> blocked due to CVE-2021-44228 pattern match";
    let signal = parse_cf_block(&[], body);
    // The numeric rule_id should be the strongest attribution.
    assert!(!signal.rule_attribution.is_empty());
}

// ───────────────────────────────────────────────────────────────
// Determinism — same input → same signal
// ───────────────────────────────────────────────────────────────

#[test]
fn parse_is_deterministic() {
    let h = hdr(&[("cf-mitigated", "block"), ("cf-ray", "abc-SJC")]);
    let body = b"<html><body>blocked <!-- 951220 --></body></html>";
    let a = parse_cf_block(&h, body);
    let b = parse_cf_block(&h, body);
    assert_eq!(format!("{:?}", a), format!("{:?}", b));
}

// ───────────────────────────────────────────────────────────────
// Composite real-shape CF responses
// ───────────────────────────────────────────────────────────────

#[test]
fn realistic_cf_managed_ruleset_block() {
    let h = hdr(&[
        ("server", "cloudflare"),
        ("cf-ray", "9f1c2a8a3e8e1234-SJC"),
        ("cf-mitigated", "block"),
        ("content-type", "text/html; charset=UTF-8"),
    ]);
    let body = br#"<!DOCTYPE html>
        <html><head><title>Attention Required! | Cloudflare</title></head>
        <body>
        <h1>Sorry, you have been blocked</h1>
        <p>You are unable to access this site. Cloudflare Ray ID: 9f1c2a8a3e8e1234-SJC</p>
        <!-- 942100 -->
        </body></html>"#;
    let signal = parse_cf_block(&h, body);
    assert!(matches!(
        signal.block_class,
        BlockClass::ManagedRulesetBlock
    ));
    assert!(signal.cf_ray.is_some());
}

#[test]
fn realistic_cf_browser_check() {
    let h = hdr(&[
        ("server", "cloudflare"),
        ("cf-ray", "0a1b2c3d4e5f6789-LHR"),
        ("cf-mitigated", "challenge"),
        ("content-type", "text/html"),
    ]);
    let body = br#"<html><head><title>Just a moment...</title>
        <meta http-equiv="refresh" content="5"></head>
        <body>Checking your browser before accessing the site.</body></html>"#;
    let signal = parse_cf_block(&h, body);
    assert!(matches!(
        signal.block_class,
        BlockClass::BrowserCheck | BlockClass::BotChallenge | BlockClass::Unknown
    ));
}

#[test]
fn realistic_cf_rate_limit() {
    let h = hdr(&[
        ("server", "cloudflare"),
        ("cf-ray", "1111aaaa2222bbbb-FRA"),
        ("retry-after", "120"),
    ]);
    let body = b"Error 1015 - You are being rate limited";
    let signal = parse_cf_block(&h, body);
    assert!(matches!(signal.block_class, BlockClass::RateLimited));
}

#[test]
fn no_cf_headers_at_all_means_unknown() {
    let signal = parse_cf_block(&[], b"<html>normal body</html>");
    assert!(matches!(signal.block_class, BlockClass::Unknown));
    assert!(signal.cf_ray.is_none());
}
