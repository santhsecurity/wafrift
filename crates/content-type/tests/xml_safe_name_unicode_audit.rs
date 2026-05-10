//! Regression coverage for the 2026-05-10 swarm-audit finding:
//!   HIGH | xml_safe_name used `is_ascii_alphabetic` /
//!     `is_ascii_alphanumeric`, which mangled valid Unicode XML names
//!     (e.g. `日本語`, `café`, `Ñame`) into all-underscores. XML 1.0
//!     §2.3 NameStartChar permits any Unicode letter; an operator
//!     submitting non-Latin parameter names would see their data
//!     silently corrupted.
//!
//! Pre-fix every "preserves Unicode" assertion below would have failed.

use wafrift_content_type::xml_safe_name;

#[test]
fn preserves_japanese_kanji() {
    let out = xml_safe_name("日本語");
    assert_eq!(out, "日本語", "kanji must round-trip, got: {out}");
}

#[test]
fn preserves_accented_latin() {
    let out = xml_safe_name("café");
    assert_eq!(out, "café");
    let out = xml_safe_name("Ñame");
    assert_eq!(out, "Ñame");
}

#[test]
fn preserves_cyrillic() {
    let out = xml_safe_name("параметр");
    assert_eq!(out, "параметр");
}

#[test]
fn replaces_disallowed_punctuation_with_underscore() {
    // Negative twin — the function must still reject XML-meta chars.
    let out = xml_safe_name("a<b>c");
    assert!(!out.contains('<'));
    assert!(!out.contains('>'));
    assert!(out.contains('_'));
}

#[test]
fn empty_name_becomes_underscore() {
    assert_eq!(xml_safe_name(""), "_");
}

#[test]
fn first_char_must_be_letter_or_underscore() {
    // A digit is not a valid NameStartChar; should be replaced.
    let out = xml_safe_name("1abc");
    assert_eq!(&out[..1], "_", "first char must not be a digit");
    assert!(out.contains("abc"));
}

#[test]
fn ascii_alphanumeric_still_works() {
    assert_eq!(xml_safe_name("foo-bar.baz_qux"), "foo-bar.baz_qux");
}
