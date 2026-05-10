//! Regression coverage for the 2026-05-10 swarm-audit findings on
//! escape_for_context (encoding/contextual.rs):
//!   HIGH: XmlAttribute escaped `&"<>` but not `'`. A payload containing
//!     `'` would break out of an `<elem attr='...'>` form.
//!   HIGH: JsonString did not escape U+2028 / U+2029. Inlined into
//!     `<script>JSON</script>` or passed to eval(), an attacker-
//!     controlled value could close the JS string and inject script.
//!   HIGH: CookieValue percent-encoded only `; = \\r \\n \\0`. RFC 6265
//!     §4.1.1 cookie-octet excludes space, `,`, `"`, `\\` as well —
//!     Chrome / Firefox / curl truncate cookies at the offending byte,
//!     making bypass probes silently lie about the value sent.

use wafrift_encoding::contextual::escape_for_context;
use wafrift_types::injection_context::InjectionContext;

// ── XmlAttribute apostrophe escape ──────────────────────────────────

#[test]
fn xml_attribute_escapes_apostrophe() {
    let escaped = escape_for_context("don't", InjectionContext::XmlAttribute).unwrap();
    assert!(
        !escaped.contains('\''),
        "single-quote must be escaped to &apos;, got: {escaped}"
    );
    assert!(escaped.contains("&apos;"), "expected &apos; in {escaped}");
}

#[test]
fn xml_attribute_still_escapes_other_metas() {
    // Negative twin — make sure adding apos didn't regress the original
    // four escapes.
    let escaped =
        escape_for_context("a&b\"c<d>e", InjectionContext::XmlAttribute).unwrap();
    assert!(escaped.contains("&amp;"));
    assert!(escaped.contains("&quot;"));
    assert!(escaped.contains("&lt;"));
    assert!(escaped.contains("&gt;"));
}

// ── JsonString U+2028 / U+2029 escapes ──────────────────────────────

#[test]
fn json_string_escapes_line_separator_u2028() {
    // U+2028 must round-trip through any JS parser as the escape
    // sequence  , NOT the literal character.
    let payload = "a\u{2028}b";
    let escaped = escape_for_context(payload, InjectionContext::JsonString).unwrap();
    assert!(
        !escaped.contains('\u{2028}'),
        "U+2028 must be escaped, got: {escaped:?}"
    );
    assert!(escaped.contains("\\u2028"));
}

#[test]
fn json_string_escapes_paragraph_separator_u2029() {
    let payload = "a\u{2029}b";
    let escaped = escape_for_context(payload, InjectionContext::JsonString).unwrap();
    assert!(
        !escaped.contains('\u{2029}'),
        "U+2029 must be escaped, got: {escaped:?}"
    );
    assert!(escaped.contains("\\u2029"));
}

#[test]
fn json_string_existing_escapes_still_work() {
    let payload = "\"hello\\\nworld\t\x00";
    let escaped = escape_for_context(payload, InjectionContext::JsonString).unwrap();
    // Must contain escape forms, not raw chars.
    assert!(escaped.contains("\\\""));
    assert!(escaped.contains("\\\\"));
    assert!(escaped.contains("\\n"));
    assert!(escaped.contains("\\t"));
    assert!(escaped.contains("\\u0000"));
}

// ── CookieValue extended encoding ───────────────────────────────────

#[test]
fn cookie_value_encodes_space() {
    let escaped = escape_for_context("hello world", InjectionContext::CookieValue).unwrap();
    assert!(
        !escaped.contains(' '),
        "space must be percent-encoded in cookie value, got: {escaped}"
    );
    assert!(escaped.contains("%20"));
}

#[test]
fn cookie_value_encodes_comma() {
    let escaped =
        escape_for_context("a,b,c", InjectionContext::CookieValue).unwrap();
    assert!(!escaped.contains(','), "comma must be encoded, got: {escaped}");
    assert!(escaped.contains("%2C"));
}

#[test]
fn cookie_value_encodes_double_quote_and_backslash() {
    let escaped =
        escape_for_context("a\"b\\c", InjectionContext::CookieValue).unwrap();
    assert!(
        !escaped.contains('"'),
        "double-quote must be encoded, got: {escaped}"
    );
    assert!(
        !escaped.contains('\\'),
        "backslash must be encoded, got: {escaped}"
    );
    assert!(escaped.contains("%22"));
    assert!(escaped.contains("%5C"));
}

#[test]
fn cookie_value_still_encodes_pre_existing_set() {
    // Negative twin — make sure adding new chars didn't drop old ones.
    let escaped =
        escape_for_context("a;b=c\r\n\0d", InjectionContext::CookieValue).unwrap();
    assert!(escaped.contains("%3B"));
    assert!(escaped.contains("%3D"));
    assert!(escaped.contains("%0D"));
    assert!(escaped.contains("%0A"));
    assert!(escaped.contains("%00"));
}
