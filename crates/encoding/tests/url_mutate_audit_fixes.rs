//! Regression coverage for the 2026-05-10 kimi audit findings on
//! `url_mutate.rs`. Each `#[test]` corresponds to one finding and
//! would have FAILED before the matching fix in the same commit.

use wafrift_encoding::url_mutate::{
    MAX_DOUBLE_ENCODE_INPUT, UrlMutateConfig, UrlStrategy, mutate_url,
};

// ── CRITICAL #1: fragment delimiter destroyed by query mutation ───

#[test]
fn fragment_delimiter_preserved_through_query_mutation() {
    let cfg = UrlMutateConfig {
        mutate_query_values: true,
        mutate_last_path_segment: false,
        strategy: UrlStrategy::PercentEncodeAggressive,
    };
    let (out, _) = mutate_url("/p?q=1#frag", &cfg);
    assert!(
        out.ends_with("#frag"),
        "fragment must survive verbatim; pre-fix '#' was encoded as %23 \
         and the entire fragment merged into the query value. got: {out}"
    );
    assert!(
        !out.contains("%23"),
        "fragment delimiter # must NOT be percent-encoded as %23; got: {out}"
    );
}

#[test]
fn fragment_with_special_chars_is_not_mutated() {
    let cfg = UrlMutateConfig {
        mutate_query_values: true,
        mutate_last_path_segment: false,
        strategy: UrlStrategy::PercentEncodeAggressive,
    };
    // The fragment contains chars (=, &, /) that the query mutator
    // would otherwise touch. Fragments are CLIENT-SIDE; the server
    // never sees them, so mutating them is wrong by construction.
    let (out, _) = mutate_url("/p?q=1#section=2&x=3/y", &cfg);
    assert!(
        out.contains("#section=2&x=3/y"),
        "fragment body must pass through unmodified; got: {out}"
    );
}

#[test]
fn no_fragment_no_change_to_query_behaviour() {
    // Negative twin — the fragment fix must not regress the
    // happy-path case where there's no fragment at all.
    let cfg = UrlMutateConfig {
        mutate_query_values: true,
        mutate_last_path_segment: false,
        strategy: UrlStrategy::PercentEncodeAggressive,
    };
    let (out, techniques) = mutate_url("/p?q=admin", &cfg);
    assert!(
        out.contains("?q=") && !out.contains('#'),
        "no fragment in input → no fragment in output; got: {out}"
    );
    assert!(
        techniques.iter().any(|t| t.starts_with("url:query_values")),
        "query mutation must still fire when fragment is absent"
    );
}

// ── HIGH #1: DoublePercentEncode unbounded allocation ─────────────

#[test]
fn double_percent_encode_caps_oversize_input() {
    // Hitting the cap should NOT produce 9× the input — the strategy
    // falls back to single-pass aggressive encoding (3× max) when
    // input exceeds MAX_DOUBLE_ENCODE_INPUT. This is the DoS guard.
    let huge = "%".repeat(MAX_DOUBLE_ENCODE_INPUT + 1);
    let s = UrlStrategy::DoublePercentEncode.apply(&huge);
    // Worst-case single-pass: each byte → "%XX" (3 bytes).
    let upper_bound = (MAX_DOUBLE_ENCODE_INPUT + 1) * 3;
    assert!(
        s.len() <= upper_bound,
        "DoublePercentEncode on oversize input must fall back to single \
         pass; got {} bytes, upper bound {}",
        s.len(),
        upper_bound
    );
}

#[test]
fn double_percent_encode_at_limit_still_double_encodes() {
    // Boundary: exactly at limit should still get the double pass.
    let val = "%".repeat(64);
    let s = UrlStrategy::DoublePercentEncode.apply(&val);
    // After two passes the literal % becomes %2525 (5 bytes per
    // input byte). Don't pin exact length — pin the marker.
    assert!(
        s.contains("%2525"),
        "small input must still get the full double-encode pass; got: {s}"
    );
}

// ── HIGH #2: path segment double-encoding (admin%2Ephp → admin%252Ephp)

#[test]
fn last_path_segment_decodes_before_re_encoding() {
    let cfg = UrlMutateConfig {
        mutate_query_values: false,
        mutate_last_path_segment: true,
        strategy: UrlStrategy::PercentEncodeAggressive,
    };
    let (out, _) = mutate_url("/admin%2Ephp", &cfg);
    // Pre-fix: tail `admin%2Ephp` was treated as literal bytes,
    // producing `admin%252Ephp` (the % → %25, the rest preserved
    // because they're alnum). Post-fix: tail is decoded to
    // `admin.php` first, then re-encoded so `.` becomes `%2E`.
    assert!(
        !out.contains("%252E"),
        "pre-existing %2E must not be double-encoded into %252E; got: {out}"
    );
    assert!(
        out.contains("%2E"),
        "the decoded `.` must be re-encoded as %2E by the strategy; got: {out}"
    );
}

#[test]
fn last_path_segment_without_pre_encoding_still_works() {
    // Negative twin — clean segments shouldn't change behaviour.
    let cfg = UrlMutateConfig {
        mutate_query_values: false,
        mutate_last_path_segment: true,
        strategy: UrlStrategy::PercentEncodeAggressive,
    };
    let (out, _) = mutate_url("/admin.php", &cfg);
    assert!(
        out.contains("%2E"),
        "clean `.php` must encode to %2E.php; got: {out}"
    );
}
