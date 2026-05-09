//! Out-of-band confirmation tests.

use uuid::Uuid;
use wafrift_oracle::oob::embed::embed_canary;
use wafrift_types::oob::OobCanary;

fn make_canary() -> OobCanary {
    OobCanary {
        id: Uuid::new_v4(),
        expected_dns: "abc123.oast.fun".into(),
        expected_http_path: "/wafrift-oob/abc123".into(),
        created_at: None,
    }
}

// ── embed_canary ───────────────────────────────────────────────────────────

#[test]
fn embed_sql_load_file() {
    let canary = make_canary();
    let out = embed_canary("' UNION SELECT 1", &canary, "Sql");
    assert!(out.contains("LOAD_FILE"));
    assert!(out.contains(&canary.expected_dns));
}

#[test]
fn embed_cmd_nslookup() {
    let canary = make_canary();
    let out = embed_canary("; whoami", &canary, "CommandInjection");
    assert!(out.contains("nslookup"));
    assert!(out.contains(&canary.expected_dns));
    assert!(out.contains("; whoami"));
}

#[test]
fn embed_ssrf_http() {
    let canary = make_canary();
    let out = embed_canary("http://127.0.0.1", &canary, "Ssrf");
    assert!(out.contains("http://"));
    assert!(out.contains(&canary.expected_dns));
    assert!(out.contains(&canary.expected_http_path));
}

#[test]
fn embed_xss_img_tag() {
    let canary = make_canary();
    let out = embed_canary("<script>alert(1)</script>", &canary, "Xss");
    assert!(out.contains("<img"));
    assert!(out.contains(&canary.expected_dns));
    assert!(out.contains(&canary.expected_http_path));
}

#[test]
fn embed_unknown_returns_original() {
    let canary = make_canary();
    let original = "hello world";
    let out = embed_canary(original, &canary, "Unknown");
    assert_eq!(out, original);
}

#[test]
fn embed_nosql_returns_original() {
    let canary = make_canary();
    let original = r#"{"$ne": null}"#;
    let out = embed_canary(original, &canary, "NoSql");
    assert_eq!(out, original);
}

#[test]
fn embed_path_traversal_returns_original() {
    let canary = make_canary();
    let original = "../../../etc/passwd";
    let out = embed_canary(original, &canary, "PathTraversal");
    assert_eq!(out, original);
}

#[test]
fn embed_template_returns_original() {
    let canary = make_canary();
    let original = "{{7*7}}";
    let out = embed_canary(original, &canary, "TemplateInjection");
    assert_eq!(out, original);
}

#[test]
fn embed_preserves_original_payload_prefix() {
    let canary = make_canary();
    let out = embed_canary("PREFIX", &canary, "Sql");
    assert!(out.starts_with("PREFIX"));
}

#[test]
fn embed_canary_id_in_dns() {
    let canary = make_canary();
    let out = embed_canary("x", &canary, "Ssrf");
    // The canary DNS should appear in the output
    assert!(out.contains(&canary.expected_dns));
}

// ── OobCanary uniqueness ───────────────────────────────────────────────────

#[test]
fn canary_ids_are_unique() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..100 {
        let canary = make_canary();
        assert!(ids.insert(canary.id), "duplicate UUID generated");
    }
}
