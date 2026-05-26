//! Property + adversarial tests for the GraphQL evasion payload library.
//!
//! Three invariants the public surface MUST hold across all input
//! domains:
//!
//! 1. **No panics on any input.** Generator fns take `usize` depth /
//!    batch / alias counts. The hunt loop and MCTS routinely sweep
//!    these up to large values; a single panic would break the
//!    bench run mid-flight.
//! 2. **JSON-valid output.** Every emitted body must parse with
//!    `serde_json`. WAFs and origin GraphQL servers reject malformed
//!    JSON immediately, so any non-JSON output is a zero-bypass-rate
//!    waste of a probe.
//! 3. **GraphQL parser shape — balanced braces.** A depth-N or
//!    fragment-N body that doesn't balance braces gets a parse error
//!    at the origin and the WAF rule never fires. We don't run a
//!    full parser here, but balanced `{` / `}` is the cheapest
//!    necessary condition.

use proptest::prelude::*;
use wafrift_graphql::{
    INTROSPECTION_QUERY, SIMPLE_INTROSPECTION_QUERY, TEST_BATCH_SIZES, TEST_DEPTHS,
    TYPE_INTROSPECTION_QUERY, alias_flood_payload, all_evasion_payloads,
    generate_batch, generate_deep_query, generate_fragment_query,
    introspection_whitespace_split_payloads, op_name_mismatch_payloads,
};

// ───────────────────────────────────────────────────────────────
// 1. No-panic invariants across the full input domain
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn deep_query_no_panic(depth in 0usize..=500) {
        let _ = generate_deep_query(depth);
    }

    #[test]
    fn fragment_query_no_panic(depth in 0usize..=500) {
        let _ = generate_fragment_query(depth);
    }

    #[test]
    fn batch_no_panic(size in 0usize..=500) {
        let _ = generate_batch(size);
    }

    #[test]
    fn alias_flood_no_panic(n in 0usize..=2000) {
        let _ = alias_flood_payload(n);
    }
}

// ───────────────────────────────────────────────────────────────
// 2. JSON-valid invariants
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn batch_payloads_are_valid_json_array(size in 0usize..=200) {
        let b = generate_batch(size);
        let s = serde_json::to_string(&b).expect("batch serializes");
        let v: serde_json::Value = serde_json::from_str(&s).expect("round-trips");
        prop_assert!(v.is_array(), "batch must be a JSON array, got {v:?}");
        prop_assert_eq!(v.as_array().unwrap().len(), size);
    }

    #[test]
    fn alias_flood_is_valid_json_object(n in 1usize..=500) {
        let p = alias_flood_payload(n);
        let v: serde_json::Value = serde_json::from_str(&p).expect("alias flood JSON-valid");
        prop_assert!(v.is_object());
        prop_assert!(v.get("query").is_some());
        prop_assert!(v["query"].is_string());
    }
}

#[test]
fn alias_flood_zero_is_empty_query_but_valid_json() {
    // n=0 is a degenerate but valid input — must produce a parseable
    // empty-aliases query, not a panic or malformed string.
    let p = alias_flood_payload(0);
    let v: serde_json::Value = serde_json::from_str(&p).unwrap();
    assert!(v["query"].is_string());
}

// ───────────────────────────────────────────────────────────────
// 3. Brace-balance invariant — required for parser acceptance.
// ───────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn deep_query_braces_always_balance(depth in 0usize..=500) {
        let q = generate_deep_query(depth);
        let opens = q.matches('{').count();
        let closes = q.matches('}').count();
        prop_assert_eq!(opens, closes, "{}", format!("imbalanced at depth {depth}"));
    }

    #[test]
    fn fragment_query_braces_always_balance(depth in 0usize..=500) {
        let q = generate_fragment_query(depth);
        let opens = q.matches('{').count();
        let closes = q.matches('}').count();
        prop_assert_eq!(opens, closes, "{}", format!("fragment imbalanced at depth {depth}"));
    }

    #[test]
    fn alias_flood_inner_braces_balance(n in 0usize..=500) {
        let p = alias_flood_payload(n);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let q = v["query"].as_str().unwrap();
        prop_assert_eq!(
            q.matches('{').count(),
            q.matches('}').count(),
            "alias-flood query braces unbalanced"
        );
    }
}

// ───────────────────────────────────────────────────────────────
// Vendored constants — sanity-pin the gqlprobe contract.
// ───────────────────────────────────────────────────────────────

#[test]
fn introspection_query_contains_schema_keyword() {
    assert!(INTROSPECTION_QUERY.contains("__schema"));
    assert!(INTROSPECTION_QUERY.contains("queryType"));
    assert!(INTROSPECTION_QUERY.contains("types"));
}

#[test]
fn simple_introspection_is_shorter_than_full() {
    assert!(SIMPLE_INTROSPECTION_QUERY.len() < INTROSPECTION_QUERY.len());
    assert!(SIMPLE_INTROSPECTION_QUERY.contains("__schema"));
}

#[test]
fn type_introspection_takes_a_variable() {
    assert!(TYPE_INTROSPECTION_QUERY.contains("$name: String!"));
    assert!(TYPE_INTROSPECTION_QUERY.contains("__type"));
}

#[test]
fn test_depths_are_strictly_increasing() {
    let depths: Vec<usize> = TEST_DEPTHS.to_vec();
    let mut sorted = depths.clone();
    sorted.sort_unstable();
    assert_eq!(
        depths, sorted,
        "TEST_DEPTHS not sorted ascending — sweep order is wrong"
    );
}

#[test]
fn test_batch_sizes_are_strictly_increasing() {
    let sizes: Vec<usize> = TEST_BATCH_SIZES.to_vec();
    let mut sorted = sizes.clone();
    sorted.sort_unstable();
    assert_eq!(sizes, sorted);
}

#[test]
fn test_depths_include_dos_range() {
    // The depths array MUST include at least one ≥100 entry — that's
    // the depth where most unprotected GraphQL servers actually choke.
    assert!(TEST_DEPTHS.iter().any(|&d| d >= 100));
}

// ───────────────────────────────────────────────────────────────
// Generator semantic tests — depth/size actually scales.
// ───────────────────────────────────────────────────────────────

#[test]
fn deep_query_scales_with_depth() {
    let q5 = generate_deep_query(5);
    let q50 = generate_deep_query(50);
    let q500 = generate_deep_query(500);
    assert!(q5.len() < q50.len());
    assert!(q50.len() < q500.len());
    // Each level adds "friends{" (8 chars) + "}" (1 char) = 9 chars.
    // q500 vs q5: 495 extra levels = ~4455 chars minimum.
    assert!(q500.len() >= q5.len() + 4000);
}

#[test]
fn batch_scales_linearly_with_size() {
    let b10 = generate_batch(10);
    let b100 = generate_batch(100);
    assert_eq!(b10.len(), 10);
    assert_eq!(b100.len(), 100);
}

#[test]
fn alias_flood_scales_with_n() {
    let p10 = alias_flood_payload(10);
    let p1000 = alias_flood_payload(1000);
    assert!(p1000.len() > p10.len() * 50);
}

// ───────────────────────────────────────────────────────────────
// Wafrift-specific additions — invariant-pin them.
// ───────────────────────────────────────────────────────────────

#[test]
fn op_name_mismatch_payloads_at_least_three_variants() {
    assert!(op_name_mismatch_payloads().len() >= 3);
}

#[test]
fn op_name_mismatch_is_actual_mismatch() {
    // Each payload's operationName MUST NOT appear as a substring of
    // its `query` field — that's the entire bypass technique.
    for p in op_name_mismatch_payloads() {
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let op_name = v["operationName"].as_str().unwrap();
        let query = v["query"].as_str().unwrap();
        assert!(
            !query.contains(op_name),
            "op name {op_name} found in query body {query} — not a mismatch"
        );
    }
}

#[test]
fn whitespace_split_payloads_at_least_five_variants() {
    // We claim 5 distinct whitespace-encoding strategies; that's the
    // minimum contract for a "battery".
    assert!(introspection_whitespace_split_payloads().len() >= 5);
}

#[test]
fn whitespace_split_payloads_are_all_distinct() {
    let payloads = introspection_whitespace_split_payloads();
    let unique: std::collections::BTreeSet<&String> = payloads.iter().collect();
    assert_eq!(
        unique.len(),
        payloads.len(),
        "whitespace battery contains duplicate strings"
    );
}

#[test]
fn whitespace_split_at_least_one_uses_zero_width_codepoint() {
    // The ZWSP / variation-selector approach is novel relative to
    // pure-whitespace; verify the battery still exercises it.
    let payloads = introspection_whitespace_split_payloads();
    let has_zw = payloads
        .iter()
        .any(|p| p.chars().any(|c| matches!(c, '\u{200B}'..='\u{200F}')));
    assert!(has_zw, "battery lacks zero-width-class encoding variant");
}

#[test]
fn whitespace_split_at_least_one_uses_comment() {
    // GraphQL `#comment` is a parser whitespace; signature-matching
    // regex on `__schema{` doesn't tolerate the comment. Confirm the
    // battery includes this strategy.
    let payloads = introspection_whitespace_split_payloads();
    let has_comment = payloads
        .iter()
        .any(|p| p.contains("__schema") && p.contains('#'));
    assert!(has_comment, "battery lacks #comment whitespace variant");
}

// ───────────────────────────────────────────────────────────────
// Unified battery — all_evasion_payloads.
// ───────────────────────────────────────────────────────────────

#[test]
fn all_evasion_payloads_no_duplicates() {
    let v = all_evasion_payloads();
    let unique: std::collections::BTreeSet<&String> = v.iter().collect();
    assert_eq!(
        unique.len(),
        v.len(),
        "all_evasion_payloads has {} duplicates of {} total",
        v.len() - unique.len(),
        v.len()
    );
}

#[test]
fn all_evasion_payloads_all_valid_json() {
    for p in all_evasion_payloads() {
        let parsed: serde_json::Value = serde_json::from_str(&p).unwrap_or_else(|e| {
            panic!("all_evasion_payloads emitted non-JSON: {p:?} — {e}")
        });
        // Either an object with "query", or an array (the batch ones).
        assert!(
            parsed.is_object() || parsed.is_array(),
            "non-object/array payload: {p:?}"
        );
    }
}

#[test]
fn all_evasion_payloads_size_threshold() {
    // Below this and we've regressed our battery — bump if you
    // intentionally add. Catches accidental deletions.
    let v = all_evasion_payloads();
    assert!(v.len() >= 30, "evasion battery shrunk to {}", v.len());
}

#[test]
fn all_evasion_payloads_covers_introspection_class() {
    let v = all_evasion_payloads();
    let has_schema = v.iter().any(|p| p.contains("__schema"));
    assert!(has_schema, "battery missing __schema introspection");
}

#[test]
fn all_evasion_payloads_covers_alias_flood_class() {
    let v = all_evasion_payloads();
    // alias flood always emits `a0:` followed by `__typename`.
    let has_alias_flood = v.iter().any(|p| p.contains("a0:__typename"));
    assert!(has_alias_flood, "battery missing alias flood class");
}

#[test]
fn all_evasion_payloads_covers_depth_bomb_class() {
    let v = all_evasion_payloads();
    // Depth bomb always starts with `{\"query\":\"query DeepTest...`.
    let has_depth = v.iter().any(|p| p.contains("DeepTest"));
    assert!(has_depth, "battery missing depth-bomb class");
}
