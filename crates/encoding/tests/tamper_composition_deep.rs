//! Composition tests: chaining tampers and verifying that the output
//! of one fed as input to another remains structurally sensible.
//!
//! The user-facing pattern is multi-strategy escalation in
//! `wafrift evade --max-strategies N` — once we ship N tampers,
//! C(N, k) combinations exist. We can't test all but we pin the
//! interesting ones plus property-style invariants.

use wafrift_encoding::tamper;

// ────────────────────────────────────────────────────────────────
// json_unicode_alnum compositions
// ────────────────────────────────────────────────────────────────

#[test]
fn json_unicode_alnum_then_url_encode_round_trip_ok() {
    let p = "UNION SELECT";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("url_encode", &a, None).unwrap();
    // The backslash and percent should be URL-encoded.
    assert!(b.contains("%5C") || b.contains("%5c"));
}

#[test]
fn json_unicode_alnum_then_double_url_encode_ok() {
    let p = "alert(1)";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("double_url_encode", &a, None).unwrap();
    assert!(b.contains("%25"));
}

#[test]
fn json_unicode_alnum_then_base64_ok() {
    let p = "UNION";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("base64", &a, None).unwrap();
    // Base64 output is a non-empty string.
    assert!(!b.is_empty());
}

#[test]
fn json_unicode_alnum_then_html_entity_ok() {
    let p = "<script>";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("html_entity", &a, None).unwrap();
    // HTML entity encoding wraps every char.
    assert!(b.contains("&#x"));
}

#[test]
fn url_encode_then_json_unicode_alnum() {
    let p = "UNION SELECT";
    let a = tamper("url_encode", p, None).unwrap();
    let b = tamper("json_unicode_alnum", &a, None).unwrap();
    // Hex digits in the URL-encoded form become \uXXXX escapes.
    assert!(b.contains("\\u"));
}

#[test]
fn case_alternation_then_json_unicode_alnum() {
    let p = "select union";
    let a = tamper("case_alternation", p, None).unwrap();
    let b = tamper("json_unicode_alnum", &a, None).unwrap();
    // Mixed case still all encoded.
    assert!(b.contains("\\u"));
    assert!(!b.contains("select"));
    assert!(!b.contains("SELECT"));
}

// ────────────────────────────────────────────────────────────────
// sql_adjacent_string_concat compositions
// ────────────────────────────────────────────────────────────────

#[test]
fn sql_adjacent_then_url_encode_ok() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("url_encode", &a, None).unwrap();
    // Single quotes URL-encoded to %27.
    assert!(b.contains("%27"));
}

#[test]
fn sql_adjacent_then_double_url_encode_ok() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("double_url_encode", &a, None).unwrap();
    assert!(b.contains("%2527"));
}

#[test]
fn sql_adjacent_then_html_entity_ok() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("html_entity", &a, None).unwrap();
    assert!(b.contains("&#x"));
}

#[test]
fn sql_concat_split_then_sql_adjacent_string_concat() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_concat_split", p, None).unwrap();
    let b = tamper("sql_adjacent_string_concat", &a, None).unwrap();
    // After both: literal sequence shattered to single chars (some passes
    // produce identical-form output, others compose).
    assert!(!b.is_empty());
}

#[test]
fn sql_adjacent_then_sql_char_decompose() {
    // After adjacent shatter, each single-char literal `'a'` becomes
    // CHAR(97). Compose check.
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("sql_char_decompose", &a, None).unwrap();
    // CHAR( appears for each shattered literal.
    assert!(b.contains("CHAR("));
}

#[test]
fn sql_adjacent_then_json_unicode_alnum() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("json_unicode_alnum", &a, None).unwrap();
    // Letters in identifiers get \uXXXX'd; quoted single chars stay quoted.
    assert!(b.contains("\\u"));
    assert!(b.contains('\''));
}

// ────────────────────────────────────────────────────────────────
// Both new tampers composed
// ────────────────────────────────────────────────────────────────

#[test]
fn json_unicode_alnum_then_sql_adjacent() {
    let p = "WHERE n='admin'";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("sql_adjacent_string_concat", &a, None).unwrap();
    // The 'admin' literal in the JSON-encoded form is still quoted —
    // sql_adjacent_string_concat should shatter it.
    assert!(b.contains("' '"));
}

#[test]
fn sql_adjacent_then_json_unicode_alnum_combined() {
    let p = "WHERE n='administrator'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("json_unicode_alnum", &a, None).unwrap();
    // Both transformations applied.
    assert!(b.contains("\\u")); // keyword chars encoded
    assert!(b.contains("' '")); // shattered literals still visible
}

#[test]
fn composition_does_not_panic_for_any_pair_of_new_tampers() {
    let payloads = [
        "UNION SELECT * FROM users",
        "WHERE n='admin'",
        "<script>alert(1)</script>",
        "${jndi:ldap://x/y}",
    ];
    let new_tampers = ["json_unicode_alnum", "sql_adjacent_string_concat"];
    for p in &payloads {
        for first in &new_tampers {
            for second in &new_tampers {
                let a = tamper(first, p, None).unwrap();
                let _ = tamper(second, &a, None).unwrap();
            }
        }
    }
}

#[test]
fn composition_with_all_default_tampers_does_not_panic() {
    use wafrift_encoding::all_tamper_names;
    let payload = "WHERE n='admin' AND k='secret'";
    for first in all_tamper_names() {
        let a = tamper(first, payload, None).unwrap();
        for second in all_tamper_names() {
            let _ = tamper(second, &a, None).unwrap_or_else(|_| panic!("{first} -> {second}"));
        }
    }
}

#[test]
fn three_way_composition_does_not_panic() {
    let payload = "WHERE n='admin'";
    let triples = [
        (
            "sql_adjacent_string_concat",
            "json_unicode_alnum",
            "url_encode",
        ),
        (
            "json_unicode_alnum",
            "sql_adjacent_string_concat",
            "html_entity",
        ),
        (
            "sql_concat_split",
            "sql_adjacent_string_concat",
            "json_unicode_alnum",
        ),
        ("case_alternation", "json_unicode_alnum", "url_encode"),
        ("html_entity_variants", "json_unicode_alnum", "url_encode"),
    ];
    for (a, b, c) in &triples {
        let s1 = tamper(a, payload, None).unwrap();
        let s2 = tamper(b, &s1, None).unwrap();
        let _ = tamper(c, &s2, None).unwrap();
    }
}

// ────────────────────────────────────────────────────────────────
// Order-sensitivity check (one direction yields different result
// than the reverse — useful for evidence that we're not silently
// no-op-ing)
// ────────────────────────────────────────────────────────────────

#[test]
fn json_unicode_alnum_url_encode_order_matters() {
    let p = "UNION";
    let ab = tamper(
        "url_encode",
        &tamper("json_unicode_alnum", p, None).unwrap(),
        None,
    )
    .unwrap();
    let ba = tamper(
        "json_unicode_alnum",
        &tamper("url_encode", p, None).unwrap(),
        None,
    )
    .unwrap();
    assert_ne!(ab, ba);
}

#[test]
fn sql_adjacent_then_url_encode_order_matters() {
    let p = "WHERE n='admin'";
    let ab = tamper(
        "url_encode",
        &tamper("sql_adjacent_string_concat", p, None).unwrap(),
        None,
    )
    .unwrap();
    let ba = tamper(
        "sql_adjacent_string_concat",
        &tamper("url_encode", p, None).unwrap(),
        None,
    )
    .unwrap();
    assert_ne!(ab, ba);
}

// ────────────────────────────────────────────────────────────────
// Length sanity in compositions
// ────────────────────────────────────────────────────────────────

#[test]
fn json_unicode_alnum_then_url_encode_within_24x_growth() {
    // \uXXXX is 6 chars; each becomes 3 url-encoded sequences max
    // (e.g., %5C%75XX...). Conservatively cap at 24x growth.
    let p = "UNION SELECT FROM users WHERE id=1 AND password=secret";
    let a = tamper("json_unicode_alnum", p, None).unwrap();
    let b = tamper("url_encode", &a, None).unwrap();
    assert!(b.len() <= p.len() * 24);
}

#[test]
fn sql_adjacent_then_html_entity_within_30x_growth() {
    let p = "WHERE n='admin'";
    let a = tamper("sql_adjacent_string_concat", p, None).unwrap();
    let b = tamper("html_entity", &a, None).unwrap();
    assert!(b.len() <= p.len() * 30);
}

// ────────────────────────────────────────────────────────────────
// UTF-8 preservation across composition
// ────────────────────────────────────────────────────────────────

#[test]
fn composition_preserves_utf8_validity_unicode_input() {
    let p = "WHERE n='café' AND city='日本'";
    let pairs = [
        ("sql_adjacent_string_concat", "json_unicode_alnum"),
        ("json_unicode_alnum", "url_encode"),
        ("sql_adjacent_string_concat", "html_entity"),
        ("html_entity_variants", "sql_adjacent_string_concat"),
    ];
    for (a, b) in &pairs {
        let s1 = tamper(a, p, None).unwrap();
        let s2 = tamper(b, &s1, None).unwrap();
        let _ = std::str::from_utf8(s2.as_bytes())
            .unwrap_or_else(|_| panic!("invalid UTF-8 from composition {a} -> {b}"));
    }
}

#[test]
fn composition_preserves_utf8_for_all_pairs_simple_payload() {
    use wafrift_encoding::all_tamper_names;
    let p = "WHERE n='admin'";
    for first in all_tamper_names() {
        let a = tamper(first, p, None).unwrap();
        for second in all_tamper_names() {
            let b = tamper(second, &a, None).unwrap();
            let _ = std::str::from_utf8(b.as_bytes())
                .unwrap_or_else(|_| panic!("invalid UTF-8 from {first} -> {second}"));
        }
    }
}
