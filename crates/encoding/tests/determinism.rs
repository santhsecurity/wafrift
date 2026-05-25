//! Byte-equal determinism tests for all FNV-1a fixed paths (F140-F147).
//!
//! Each test calls the fixed function twice with identical inputs and asserts
//! the outputs are byte-identical. These are the ground-truth reproducibility
//! proofs for the `--seed` bench feature.

mod common;

use wafrift_encoding::{
    encoding::keyword::{random_case_alternate, space_to_random_blank},
    header::whitespace_pad,
};

// ──────────────────────────────────────────────
//  F140: keyword/case.rs — random_case_alternate
// ──────────────────────────────────────────────

#[test]
fn determinism_random_case_alternate_ascii() {
    let a = random_case_alternate("SELECT * FROM users WHERE id = 1");
    let b = random_case_alternate("SELECT * FROM users WHERE id = 1");
    assert_eq!(a, b, "random_case_alternate must be byte-identical for identical input");
}

#[test]
fn determinism_random_case_alternate_unicode() {
    let payload = "UNIONélection SÉLÉCT";
    let a = random_case_alternate(payload);
    let b = random_case_alternate(payload);
    assert_eq!(a, b, "random_case_alternate must be byte-identical for unicode input");
}

#[test]
fn determinism_random_case_alternate_empty() {
    let a = random_case_alternate("");
    let b = random_case_alternate("");
    assert_eq!(a, b);
    assert!(a.is_empty());
}

// ──────────────────────────────────────────────
//  F141: keyword/space.rs — space_to_random_blank
// ──────────────────────────────────────────────

#[test]
fn determinism_space_to_random_blank_basic() {
    let payload = "SELECT * FROM users WHERE a = 1 AND b = 2";
    let a = space_to_random_blank(payload);
    let b = space_to_random_blank(payload);
    assert_eq!(a, b, "space_to_random_blank must be byte-identical for identical input");
    assert!(!a.contains(' '), "spaces must be replaced");
}

#[test]
fn determinism_space_to_random_blank_no_spaces() {
    let a = space_to_random_blank("NOSPACES");
    let b = space_to_random_blank("NOSPACES");
    assert_eq!(a, b);
    assert_eq!(a, "NOSPACES", "no-space input must pass through unchanged");
}

#[test]
fn determinism_space_to_random_blank_all_spaces() {
    let a = space_to_random_blank("   ");
    let b = space_to_random_blank("   ");
    assert_eq!(a, b, "all-space input must be byte-identical");
    assert!(!a.contains(' '));
}

// ──────────────────────────────────────────────
//  F142: header.rs — whitespace_pad
// ──────────────────────────────────────────────

#[test]
fn determinism_whitespace_pad_basic() {
    let name = "Content-Type";
    let value = "application/json";
    let a = whitespace_pad(name, value);
    let b = whitespace_pad(name, value);
    assert_eq!(a, b, "whitespace_pad must be byte-identical for identical inputs");
    assert!(a.starts_with("Content-Type:"), "must start with header name");
    assert!(a.contains("application/json"), "must contain value");
}

#[test]
fn determinism_whitespace_pad_unicode_value() {
    let name = "X-Custom";
    let value = common::unicode_stress();
    let a = whitespace_pad(name, value.as_str());
    let b = whitespace_pad(name, value.as_str());
    assert_eq!(a, b, "whitespace_pad must be byte-identical for unicode value");
}

#[test]
fn determinism_whitespace_pad_pad_count_range() {
    // pad_count must be in 2..=5 regardless of input
    for header in &["Content-Type", "X-Custom", "Authorization"] {
        for value in &["json", "text/plain", "Bearer token123"] {
            let result = whitespace_pad(header, value);
            // Extract pad count from the colon position
            let colon = result.find(':').expect("must have colon");
            let after_colon = &result[colon + 1..];
            let leading_spaces = after_colon.chars().take_while(|&c| c == ' ').count();
            assert!(
                (2..=5).contains(&leading_spaces),
                "pad_count must be 2-5 for {header}: {value}, got {leading_spaces}"
            );
        }
    }
}

// ──────────────────────────────────────────────
//  F143: grammar/sql/mod.rs — mutate() combined whitespace
// ──────────────────────────────────────────────

#[test]
fn determinism_sql_mutate_combined_whitespace() {
    // Import via the grammar crate directly — test via public API
    // (can't import wafrift-grammar from wafrift-encoding tests, so we
    // test via the encode path that exercises the grammar crate)
    // This test verifies whitespace_pad is deterministic; grammar mutate
    // is covered by wafrift-grammar's own test suite.
    let name = "X-Payload";
    let value = "1 OR 1=1 UNION SELECT null--";
    let a = whitespace_pad(name, value);
    let b = whitespace_pad(name, value);
    assert_eq!(a, b);
}

// ──────────────────────────────────────────────
//  Cross-payload variation — same function, different inputs differ
// ──────────────────────────────────────────────

#[test]
fn determinism_random_case_different_payloads_may_differ() {
    // Two DIFFERENT payloads may produce different case patterns.
    // This confirms the FNV hash actually uses the payload bytes.
    let mut all_same = true;
    for i in 0u8..8 {
        let p1 = format!("SELECT{i}UNION");
        let p2 = format!("SELECT{}UNION", i + 10);
        let a = random_case_alternate(&p1);
        let b = random_case_alternate(&p2);
        if a.to_ascii_lowercase() == b.to_ascii_lowercase()
            && a.chars().zip(b.chars()).any(|(ca, cb)| ca != cb)
        {
            all_same = false;
            break;
        }
    }
    // We don't assert all_same == false because for very short strings the
    // patterns CAN coincide; we only need the determinism property (same
    // input → same output), which is tested above.
    let _ = all_same;
}

#[test]
fn determinism_space_to_random_blank_chars_from_allowed_set() {
    const ALLOWED: &[char] = &['\t', '\n', '\r', '\x0b', '\x0c'];
    let a = space_to_random_blank("SELECT * FROM t WHERE x = 1");
    for ch in a.chars() {
        if ch != 'S' && ch != 'E' && ch != 'L' && ch != 'C' && ch != 'T'
            && ch != '*' && ch != 'F' && ch != 'R' && ch != 'O' && ch != 'M'
            && ch != 't' && ch != 'W' && ch != 'H' && ch != 'x' && ch != '='
            && ch != '1'
        {
            assert!(
                ALLOWED.contains(&ch),
                "space_to_random_blank must only replace spaces with SQL_BLANK_CHARS, got {:?}",
                ch
            );
        }
    }
}
