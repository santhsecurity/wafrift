//! Regression coverage for the 2026-05-10 swarm-audit CRITICAL:
//!   non_canonical_spaces in url_mutate.rs passed through structural
//!   bytes (& = % # + ? ; \\0 + control chars). After the upstream
//!   percent_decode_bytes had already turned `%26c%3Devil` into the
//!   literal bytes `&c=evil`, this re-emitted them verbatim — the
//!   server then split the value at `&` and `=` into THREE pairs
//!   (HTTP parameter injection). The fix percent-encodes every byte
//!   that would be parsed as URL/form structure or ASCII control.
//!
//! Pre-fix every "no structural byte in output" assertion would fail.

use wafrift_encoding::url_mutate::{UrlMutateConfig, UrlStrategy, mutate_url};

/// Pre-fix the bug was: percent-encoded dangerous bytes in the URL
/// would be DECODED by the upstream `percent_decode_bytes` step, then
/// `non_canonical_spaces` would re-emit them verbatim (instead of
/// re-encoding). To reproduce, the test value MUST come in as a
/// percent-escape (e.g. `%26` for `&`) so the decode step turns it
/// into the raw structural byte that the strategy then handled.
fn run(percent_encoded_value: &str) -> String {
    let cfg = UrlMutateConfig {
        strategy: UrlStrategy::NonCanonicalSpaces,
        mutate_query_values: true,
        mutate_last_path_segment: false,
    };
    let url = format!("/?k={percent_encoded_value}");
    let (out, _techs) = mutate_url(&url, &cfg);
    out.trim_start_matches('/').trim_start_matches('?').to_string()
}

fn assert_no_structural_byte(qs: &str, byte: char) {
    // The query-string is `k=...` so the FIRST `=` and `&` in the
    // result are legitimate framing. We only need to check the value
    // portion (after the first `=`).
    let value_start = qs.find('=').map(|i| i + 1).unwrap_or(0);
    let value = &qs[value_start..];
    // For `&` we want to ensure NO additional `&` appears in the value
    // (the value is the only param, so any `&` would be injection).
    assert!(
        !value.contains(byte),
        "value portion of {qs:?} must not contain raw `{byte}` — would split into another pair"
    );
}

#[test]
fn percent_encoded_ampersand_does_not_inject_a_pair() {
    // Pre-fix: `?k=a%26b=evil` would decode to `a&b=evil`, then
    // non_canonical_spaces re-emitted `&` verbatim → query string
    // `?k=a&b=evil` with TWO pairs.
    let qs = run("a%26b=evil");
    assert_no_structural_byte(&qs, '&');
}

#[test]
fn percent_encoded_equals_does_not_create_a_subpair() {
    let qs = run("alpha%3Dbeta");
    let value_start = qs.find('=').map(|i| i + 1).unwrap_or(0);
    let value = &qs[value_start..];
    assert!(
        !value.contains('='),
        "value portion of {qs:?} must not contain raw `=`"
    );
}

#[test]
fn percent_encoded_percent_is_re_encoded() {
    // `%25` decodes to `%`. The strategy must re-emit it as `%25` so
    // the server doesn't treat it as the start of another escape.
    let qs = run("a%25b");
    let value_start = qs.find('=').map(|i| i + 1).unwrap_or(0);
    let value = &qs[value_start..];
    // Every `%` in the output must be the start of a valid `%XX` pair.
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%' {
            assert!(
                bytes.get(i + 1).map(|b| b.is_ascii_hexdigit()).unwrap_or(false)
                    && bytes.get(i + 2).map(|b| b.is_ascii_hexdigit()).unwrap_or(false),
                "value {value:?} has a `%` at index {i} not followed by 2 hex digits"
            );
        }
    }
}

#[test]
fn percent_encoded_hash_does_not_open_a_fragment() {
    let qs = run("foo%23bar");
    let value_start = qs.find('=').map(|i| i + 1).unwrap_or(0);
    let value = &qs[value_start..];
    assert!(
        !value.contains('#'),
        "raw `#` would split URL into a fragment and discard the rest of the query"
    );
}

#[test]
fn percent_encoded_null_byte_is_re_encoded() {
    let qs = run("safe%00evil");
    assert!(
        !qs.contains('\0'),
        "raw NUL would be rejected or truncated by upstream parsers, got: {qs:?}"
    );
}

#[test]
fn percent_encoded_question_mark_does_not_double_query() {
    let qs = run("a%3Fb=c");
    let value_start = qs.find('=').map(|i| i + 1).unwrap_or(0);
    let value = &qs[value_start..];
    assert!(
        !value.contains('?'),
        "raw `?` would create a second query-string in the URL"
    );
}

#[test]
fn safe_chars_still_pass_through_cosmetically() {
    // Negative twin: spaces (raw, not encoded) still become `+`,
    // slashes still %2F, etc.
    let qs = run("hello%20world%2Fpath");
    // After decode: "hello world/path". After non_canonical_spaces:
    // "hello+world%2Fpath".
    assert!(qs.contains('+'), "space must still become +, got: {qs:?}");
    assert!(qs.contains("%2F"), "slash must still be encoded as %2F, got: {qs:?}");
}
