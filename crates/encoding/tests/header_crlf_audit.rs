//! Regression coverage for the 2026-05-10 swarm-audit CRITICAL:
//!   header.rs mutators embedded `value` verbatim in their output. A
//!   caller passing `value = "x\r\nEvil-Header: pwn"` produced response-
//!   splitting / request-smuggling on the wire — the exact threat the
//!   crate claims to be probing for, not exposing. Each public mutator
//!   now sanitises CR / LF / NUL via `sanitize_header_value()` before
//!   embedding, closing the gap without an API break.

use wafrift_encoding::header::{
    comma_join, duplicate_header, line_fold, multi_line_fold, tab_separator, trailing_space,
    whitespace_pad,
};

const CRLF_INJECTION: &str = "x\r\nEvil-Header: pwn";
const NUL_INJECTION: &str = "x\0Evil";

fn assert_no_smuggling_chars(out: &str, label: &str) {
    assert!(
        !out.contains('\r'),
        "{label} output must not contain CR — would smuggle a header. got: {out:?}"
    );
    assert!(
        !out.contains('\n'),
        "{label} output must not contain LF — would smuggle a header. got: {out:?}"
    );
    assert!(
        !out.contains('\0'),
        "{label} output must not contain NUL — many HTTP/1 stacks truncate at NUL. got: {out:?}"
    );
}

#[test]
fn tab_separator_strips_crlf_in_value() {
    assert_no_smuggling_chars(
        &tab_separator("X-Custom", CRLF_INJECTION),
        "tab_separator",
    );
}

#[test]
fn whitespace_pad_strips_crlf_in_value() {
    assert_no_smuggling_chars(
        &whitespace_pad("X-Custom", CRLF_INJECTION),
        "whitespace_pad",
    );
}

#[test]
fn line_fold_does_not_double_fold_pre_folded_value() {
    // Pre-fix, embedding a CR/LF would produce `\r\n  ...\r\n\t...`
    // — nested folding that no compliant server accepts. Now stripped.
    let out = line_fold("X-Custom", "before\r\nafter");
    // The ONLY \r\n permitted is the one line_fold inserts itself.
    let crlf_count = out.matches("\r\n").count();
    assert!(
        crlf_count <= 1,
        "line_fold must not double-fold a pre-folded value: {out:?}"
    );
}

#[test]
fn multi_line_fold_strips_crlf_in_value() {
    // multi_line_fold inserts \r\n itself; the value-controlled CR/LF
    // must not appear ON TOP of those.
    let out = multi_line_fold("X-Custom", "abc\r\ndef\r\nghi");
    // multi_line_fold inserts at most 2 of its own line breaks (3 chunks).
    let crlf_count = out.matches("\r\n").count();
    assert!(
        crlf_count <= 2,
        "multi_line_fold must not stack value CRLF on top of its own: {out:?}"
    );
}

#[test]
fn duplicate_header_strips_crlf_in_both_values() {
    let (b, r) = duplicate_header("X-Custom", CRLF_INJECTION, "benign\rvalue");
    assert_no_smuggling_chars(&b, "duplicate_header.benign");
    assert_no_smuggling_chars(&r, "duplicate_header.real");
}

#[test]
fn trailing_space_strips_crlf_in_value() {
    assert_no_smuggling_chars(&trailing_space("X-Custom", CRLF_INJECTION), "trailing_space");
}

#[test]
fn comma_join_strips_crlf_in_both_values() {
    assert_no_smuggling_chars(
        &comma_join("X-Custom", CRLF_INJECTION, "ok"),
        "comma_join.real",
    );
    assert_no_smuggling_chars(
        &comma_join("X-Custom", "ok", CRLF_INJECTION),
        "comma_join.benign",
    );
}

#[test]
fn null_byte_in_value_is_stripped() {
    // Many HTTP/1 stacks truncate header values at the first NUL,
    // turning a benign-looking header into a smuggled one downstream.
    assert_no_smuggling_chars(&tab_separator("X", NUL_INJECTION), "tab_separator NUL");
    assert_no_smuggling_chars(&whitespace_pad("X", NUL_INJECTION), "whitespace_pad NUL");
}

#[test]
fn clean_value_unchanged() {
    // Negative twin — sanitise must not eat normal characters.
    let out = tab_separator("X-Custom", "normal value with spaces");
    assert_eq!(out, "X-Custom:\tnormal value with spaces");
}
