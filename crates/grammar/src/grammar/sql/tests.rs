use super::{
    blind::order_by_probes,
    mutate,
    strings::{hex_literal, split_string_concat},
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
    let mutations = mutate("' OR 1=1--", 50);
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
    let mutations = mutate("' OR 1=1--", 60);
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
    let mutations = mutate("' OR username='admin'--", 30);
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
    let mutations = mutate("' OR username='admin'--", 100);
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
