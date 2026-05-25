use super::{
    blind::order_by_probes,
    common::{and_alternatives, equality_alternatives, extract_quoted_string, or_alternatives},
    mutate,
    operators::{replace_comment_terminator, replace_equality, replace_logical_operator},
    strings::{hex_literal, no_space_wrap, split_string_concat},
};

#[test]
fn tautology_mutation_produces_variants() {
    let mutations = mutate("' OR 1=1--", 20);
    assert!(
        !mutations.is_empty(),
        "should produce at least one mutation"
    );
    let has_like = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("LIKE"));
    let has_between = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("BETWEEN"));
    assert!(
        has_like || has_between,
        "should have semantic tautology variants"
    );
}

#[test]
fn comment_terminator_rotation() {
    let mutations = mutate("' OR 1=1--", 200);
    let has_hash = mutations
        .iter()
        .any(|mutation| mutation.payload.ends_with('#'));
    let has_plus = mutations
        .iter()
        .any(|mutation| mutation.payload.ends_with("--+"));
    assert!(has_hash || has_plus, "should rotate comment terminators");
}

#[test]
fn whitespace_alternatives_applied() {
    let mutations = mutate("' OR 1=1--", 200);
    let has_tab = mutations
        .iter()
        .any(|mutation| mutation.payload.contains('\t'));
    let has_comment = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("/**/"));
    assert!(has_tab || has_comment, "should replace whitespace");
}

#[test]
fn union_select_mutation() {
    let mutations = mutate("' UNION SELECT username FROM users--", 20);
    assert!(!mutations.is_empty());
}

#[test]
fn equality_operator_swap() {
    let mutations = mutate("' OR 1=1--", 50);
    let has_like = mutations
        .iter()
        .any(|mutation| mutation.payload.contains(" LIKE "));
    assert!(has_like, "should swap = for LIKE");
}

#[test]
fn string_splitting() {
    let mutations = mutate("' OR username='admin'--", 200);
    let has_concat = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("CONCAT("));
    let has_pipe = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("||"));
    assert!(has_concat || has_pipe, "should split string literals");
}

#[test]
fn no_mutations_for_empty() {
    let mutations = mutate("", 10);
    assert!(mutations.is_empty());
}

#[test]
fn mutations_are_different_from_original() {
    let original = "' OR 1=1--";
    let mutations = mutate(original, 20);
    for mutation in &mutations {
        assert_ne!(
            mutation.payload, original,
            "mutation should differ from original"
        );
    }
}

#[test]
fn max_mutations_respected() {
    let mutations = mutate("' OR 1=1--", 3);
    assert!(mutations.len() <= 3);
}

#[test]
fn combined_mutations_exist() {
    let mutations = mutate("' OR 1=1--", 50);
    let has_combined = mutations
        .iter()
        .any(|mutation| mutation.rules_applied.len() > 1);
    assert!(has_combined, "should produce combined mutations");
}

#[test]
fn case_when_tautology() {
    let mutations = mutate("' OR 1=1--", 50);
    let has_case = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("CASE WHEN"));
    assert!(has_case, "should produce CASE WHEN tautology variant");
}

#[test]
fn hex_literal_encoding() {
    let mutations = mutate("' OR username='admin'--", 300);
    let has_hex = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("0x"));
    assert!(has_hex, "should encode strings as hex literals");
}

#[test]
fn hex_literal_produces_correct_encoding() {
    assert_eq!(hex_literal("admin"), "0x61646d696e");
    assert_eq!(hex_literal("A"), "0x41");
}

#[test]
fn conditional_expression_tautologies() {
    let mutations = mutate("' OR 1=1--", 50);
    let has_if = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("IF("));
    let has_iif_cond = mutations
        .iter()
        .any(|mutation| mutation.payload.contains("IIF("));
    assert!(
        has_if || has_iif_cond,
        "should produce IF/IIF conditional tautologies"
    );
}

#[test]
fn dialect_aware_string_constructors() {
    let splits = split_string_concat("admin");
    let has_chr = splits.iter().any(|split| split.contains("CHR("));
    let has_nchar = splits.iter().any(|split| split.contains("NCHAR("));
    let has_hex = splits.iter().any(|split| split.starts_with("0x"));
    assert!(has_chr, "should produce PostgreSQL CHR() variant");
    assert!(has_nchar, "should produce MSSQL NCHAR() variant");
    assert!(has_hex, "should produce MySQL hex literal");
}

#[test]
fn order_by_probes_generated() {
    let probes = order_by_probes(5);
    assert_eq!(probes.len(), 5);
    assert!(probes[0].contains("ORDER BY 1"));
    assert!(probes[4].contains("ORDER BY 5"));
}

// ── common.rs tests ──

#[test]
fn extract_quoted_string_basic() {
    assert_eq!(extract_quoted_string("'admin'"), Some("admin".to_string()));
}

#[test]
fn extract_quoted_string_ignores_escaped_quotes() {
    // The value between the outer quotes should be "It\'s", but
    // extract_quoted_string returns the raw content including the
    // backslash.  The key point is that the escaped quote does NOT
    // terminate the string prematurely.
    assert_eq!(
        extract_quoted_string("'It\\'s a test'"),
        Some("It\\'s a test".to_string())
    );
}

#[test]
fn extract_quoted_string_too_long_returns_none() {
    let long = "'".to_string() + &"a".repeat(21) + "'";
    assert_eq!(extract_quoted_string(&long), None);
}

#[test]
fn extract_quoted_string_no_quotes_returns_none() {
    assert_eq!(extract_quoted_string("admin"), None);
}

#[test]
fn extract_quoted_string_empty_returns_none() {
    assert_eq!(extract_quoted_string("''"), None);
}

#[test]
fn or_alternatives_not_empty() {
    assert!(!or_alternatives().is_empty());
}

#[test]
fn and_alternatives_not_empty() {
    assert!(!and_alternatives().is_empty());
}

#[test]
fn equality_alternatives_not_empty() {
    assert!(!equality_alternatives().is_empty());
}

// ── operators.rs tests ──

#[test]
fn replace_comment_terminator_hash_to_dash() {
    assert_eq!(
        replace_comment_terminator("' OR 1=1#", "--"),
        Some("' OR 1=1--".to_string())
    );
}

#[test]
fn replace_comment_terminator_longest_first() {
    // "-- -" must match before "--" so we don't leave a trailing space.
    assert_eq!(
        replace_comment_terminator("' OR 1=1-- -", "#"),
        Some("' OR 1=1#".to_string())
    );
}

#[test]
fn replace_comment_terminator_no_match() {
    assert_eq!(replace_comment_terminator("' OR 1=1", "#"), None);
}

// ── strings.rs tests ──

#[test]
fn no_space_wrap_replaces_select() {
    assert_eq!(
        no_space_wrap("' UNION select username FROM users--"),
        Some("' UNION(SELECT(username FROM users--".to_string())
    );
}

#[test]
fn no_space_wrap_no_select_returns_none() {
    assert_eq!(no_space_wrap("' OR 1=1--"), None);
}

#[test]
fn split_string_concat_short_input() {
    let r = split_string_concat("ab");
    assert!(
        r.iter().any(|s| s.contains("'a'||'b'")),
        "should include concatenation variant: {r:?}"
    );
    assert!(
        r.iter().any(|s| s.starts_with("0x")),
        "should include hex variant: {r:?}"
    );
}

#[test]
fn split_string_concat_decimal_for_short() {
    // Values <= 8 chars get a CONV(base36) variant.
    let r = split_string_concat("test");
    assert!(
        r.iter().any(|s| s.contains("CONV(")),
        "should include CONV variant for short string: {r:?}"
    );
}

#[test]
fn split_string_concat_no_decimal_for_long() {
    // Values > 8 chars do NOT get a CONV variant.
    let r = split_string_concat("verylongstringindeed");
    assert!(
        !r.iter().any(|s| s.contains("CONV(")),
        "should NOT include CONV variant for long string: {r:?}"
    );
}

// ── operators.rs direct tests ──

#[test]
fn replace_logical_operator_or_basic() {
    let alts = vec!["||".to_string()];
    let result = replace_logical_operator("' OR 1=1", &alts, "or");
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(result.contains("||"), "expected || replacement: {result}");
}

#[test]
fn replace_logical_operator_and_basic() {
    let alts = vec!["&&".to_string()];
    let result = replace_logical_operator("' AND 1=1", &alts, "and");
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(result.contains("&&"), "expected && replacement: {result}");
}

#[test]
fn replace_logical_operator_skips_inside_single_quotes() {
    let alts = vec!["||".to_string()];
    // The OR is inside single quotes — must NOT be replaced.
    let result = replace_logical_operator("'hello or world' OR 1=1", &alts, "or");
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(
        result.contains("'hello or world'"),
        "quoted OR must be preserved: {result}"
    );
    assert!(
        result.contains("||"),
        "unquoted OR must still be replaced: {result}"
    );
}

#[test]
fn replace_logical_operator_skips_inside_double_quotes() {
    let alts = vec!["&&".to_string()];
    let result = replace_logical_operator("\"foo and bar\" AND 1=1", &alts, "and");
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(
        result.contains("\"foo and bar\""),
        "quoted AND must be preserved: {result}"
    );
}

#[test]
fn replace_logical_operator_no_match() {
    let alts = vec!["||".to_string()];
    assert_eq!(replace_logical_operator("' = 1", &alts, "or"), None);
}

#[test]
fn replace_equality_basic() {
    assert_eq!(
        replace_equality("' OR 1=1", " LIKE "),
        Some("' OR 1 LIKE 1".to_string())
    );
}

#[test]
fn replace_equality_skips_inside_quotes() {
    let result = replace_equality("'a=b' OR 1=1", " LIKE ");
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(
        result.contains("'a=b'"),
        "quoted = must be preserved: {result}"
    );
    assert!(
        result.contains(" LIKE "),
        "unquoted = must be replaced: {result}"
    );
}

#[test]
fn replace_equality_skips_compound_operators() {
    // !=, <=, >=, and == should NOT match standalone = replacement.
    assert_eq!(replace_equality("' OR 1!=1", " LIKE "), None);
    assert_eq!(replace_equality("' OR 1<=1", " LIKE "), None);
    assert_eq!(replace_equality("' OR 1>=1", " LIKE "), None);
    assert_eq!(replace_equality("' OR 1==1", " LIKE "), None);
}

#[test]
fn replace_equality_no_equals() {
    assert_eq!(replace_equality("' OR 1 AND 1", " LIKE "), None);
}

#[test]
fn replace_equality_first_equals_only() {
    // Should replace only the first unquoted =.
    let result = replace_equality("a=b=c", " LIKE ").unwrap();
    assert_eq!(result, "a LIKE b=c");
}

#[test]
fn mutate_is_deterministic_across_calls() {
    // F143 regression: pre-fix the combined-whitespace pass picked
    // both base index and whitespace variant via rand::thread_rng(),
    // so the same payload produced different mutation lists across
    // calls. Gene-bank replay needs identical output for identical
    // input. Same hazard as F114/F136/F140/F142.
    let a = mutate("' OR 1=1--", 30);
    let b = mutate("' OR 1=1--", 30);
    assert_eq!(a.len(), b.len(), "mutation count must be stable");
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        assert_eq!(x.payload, y.payload, "mutation {i} payload diverged: {} vs {}", x.payload, y.payload);
    }
}
