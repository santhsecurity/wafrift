//! End-to-end tests for `wafrift audit` and `wafrift harden`.
//!
//! Both commands are fully offline — no HTTP, no mock server.
//! They operate on the embedded CRS ruleset (default) and accept
//! `--format json` for machine-parseable output.
//!
//! Tests verify:
//! 1. `audit --help` exits 0 and documents key flags.
//! 2. `audit` appears in top-level help.
//! 3. `audit` exits 0 with the embedded ruleset.
//! 4. `audit --format json` emits valid JSON with required fields.
//! 5. `audit --class xss` exits 0 and reports at least one hole.
//! 6. `audit --class sqli` exits 0.
//! 7. `audit` with a non-existent ruleset file exits non-zero.
//! 8. `harden --help` exits 0.
//! 9. `harden` exits 0 (closure proven) on embedded ruleset.
//! 10. `harden --format json` emits valid JSON with `all_proven`.
//! 11. `harden --class xss` exits 0.
//! 12. `harden --class sqli` exits 0.
//! 13. `harden` with non-existent ruleset exits non-zero.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn audit_help_documents_flags() {
    let (code, stdout, _) = wafrift(&["audit", "--help"]);
    assert_eq!(code, 0, "audit --help must exit 0");
    assert!(
        stdout.contains("--format"),
        "must document --format: {stdout}"
    );
    assert!(
        stdout.contains("--class"),
        "must document --class: {stdout}"
    );
    assert!(
        stdout.contains("--ruleset"),
        "must document --ruleset: {stdout}"
    );
}

#[test]
fn audit_and_harden_appear_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("audit"),
        "audit must appear in top-level help: {stdout}"
    );
    assert!(
        stdout.contains("harden"),
        "harden must appear in top-level help: {stdout}"
    );
}

#[test]
fn harden_help_documents_flags() {
    let (code, stdout, _) = wafrift(&["harden", "--help"]);
    assert_eq!(code, 0, "harden --help must exit 0");
    assert!(
        stdout.contains("--format"),
        "must document --format: {stdout}"
    );
    assert!(
        stdout.contains("--class"),
        "must document --class: {stdout}"
    );
}

// ── `audit` ───────────────────────────────────────────────────────────────

#[test]
fn audit_exits_0_with_embedded_ruleset() {
    let (code, _stdout, stderr) = wafrift(&["audit"]);
    assert_eq!(
        code, 0,
        "audit must exit 0 on embedded ruleset; stderr: {stderr}"
    );
}

#[test]
fn audit_json_format_emits_valid_json_with_required_fields() {
    let (code, stdout, stderr) = wafrift(&["audit", "--format", "json"]);
    assert_eq!(code, 0, "audit --format json must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("audit --format json must emit valid JSON");

    assert!(
        v["audited_class"].is_string(),
        "audited_class must be a string: {v}"
    );
    assert!(
        v["rules_loaded"].as_u64().unwrap_or(0) > 0,
        "rules_loaded must be > 0: {v}"
    );
    assert!(
        v["total_holes"].is_number(),
        "total_holes must be a number: {v}"
    );
    assert!(v["holes"].is_array(), "holes must be an array: {v}");
    assert!(
        v["ruleset_fingerprint"].is_string(),
        "ruleset_fingerprint must be a string: {v}"
    );
    assert!(
        v["inbound_threshold"].is_number(),
        "inbound_threshold must be a number: {v}"
    );
}

#[test]
fn audit_json_holes_array_has_required_fields() {
    let (code, stdout, stderr) = wafrift(&["audit", "--format", "json"]);
    assert_eq!(code, 0, "audit must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let holes = v["holes"].as_array().expect("holes must be an array");
    // At least one hole must exist (double-URL encoding bypasses the embedded CRS).
    assert!(!holes.is_empty(), "audit must find at least one hole: {v}");
    for hole in holes {
        assert!(
            hole["class"].is_string(),
            "hole.class must be string: {hole}"
        );
        assert!(
            hole["label"].is_string(),
            "hole.label must be string: {hole}"
        );
        assert!(
            hole["attack"].is_string(),
            "hole.attack must be string: {hole}"
        );
        assert!(
            hole["delivered_as"].is_string(),
            "hole.delivered_as must be string: {hole}"
        );
    }
}

#[test]
fn audit_class_xss_exits_0_and_finds_holes() {
    let (code, stdout, stderr) = wafrift(&["audit", "--class", "xss", "--format", "json"]);
    assert_eq!(code, 0, "audit --class xss must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["audited_class"].as_str().unwrap_or(""), "xss");
    let holes = v["holes"].as_array().unwrap();
    assert!(!holes.is_empty(), "xss audit must find at least one hole");
    // Every hole must be xss class.
    for hole in holes {
        assert_eq!(
            hole["class"].as_str().unwrap_or(""),
            "xss",
            "all holes must be class=xss: {hole}"
        );
    }
}

#[test]
fn audit_class_sqli_exits_0() {
    let (code, _stdout, stderr) = wafrift(&["audit", "--class", "sqli"]);
    assert_eq!(code, 0, "audit --class sqli must exit 0; stderr: {stderr}");
}

#[test]
fn audit_nonexistent_ruleset_exits_nonzero() {
    let (code, _stdout, stderr) =
        wafrift(&["audit", "--ruleset", "/nonexistent/path/ruleset.toml"]);
    assert_ne!(
        code, 0,
        "nonexistent ruleset must exit non-zero; stderr: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "nonexistent ruleset must emit error message"
    );
}

// ── `harden` ──────────────────────────────────────────────────────────────

#[test]
fn harden_exits_0_closure_proven_on_embedded_ruleset() {
    let (code, _stdout, stderr) = wafrift(&["harden"]);
    assert_eq!(
        code, 0,
        "harden must exit 0 (closure proven) on embedded ruleset; stderr: {stderr}"
    );
}

#[test]
fn harden_json_format_emits_valid_json_with_all_proven() {
    let (code, stdout, stderr) = wafrift(&["harden", "--format", "json"]);
    assert_eq!(
        code, 0,
        "harden --format json must exit 0; stderr: {stderr}"
    );

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("harden --format json must emit valid JSON");

    assert!(
        v["all_proven"].as_bool().unwrap_or(false),
        "all_proven must be true on embedded ruleset: {v}"
    );
    assert!(v["classes"].is_array(), "classes must be an array: {v}");
    assert!(
        v["audited_class"].is_string(),
        "audited_class must be a string: {v}"
    );
}

#[test]
fn harden_json_classes_have_required_fields_and_added_rules() {
    let (code, stdout, stderr) = wafrift(&["harden", "--format", "json"]);
    assert_eq!(code, 0, "harden must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let classes = v["classes"].as_array().expect("classes must be an array");
    assert!(!classes.is_empty(), "classes array must not be empty: {v}");

    for class in classes {
        assert!(
            class["class"].is_string(),
            "class.class must be string: {class}"
        );
        assert!(
            class["holes_before"].is_number(),
            "holes_before must be number: {class}"
        );
        assert!(
            class["holes_after"].is_number(),
            "holes_after must be number: {class}"
        );
        assert!(
            class["benign_false_positives"].is_number(),
            "benign_false_positives must be number: {class}"
        );
        assert!(
            class["proven_closed"].as_bool().is_some(),
            "proven_closed must be boolean: {class}"
        );
        let rules = class["added_rules"]
            .as_array()
            .expect("added_rules must be array");
        assert!(
            !rules.is_empty(),
            "harden must add rules for class: {class}"
        );

        // Each rule must have transforms as an ARRAY (not a string —
        // this was the pre-fix bug).
        for rule in rules {
            assert!(rule["id"].is_string(), "rule.id must be string: {rule}");
            assert!(
                rule["transforms"].is_array(),
                "rule.transforms must be an array (not string): {rule}"
            );
            assert!(
                !rule["transforms"].as_array().unwrap().is_empty(),
                "rule.transforms must not be empty: {rule}"
            );
            assert!(
                rule["pattern"].is_string(),
                "rule.pattern must be string: {rule}"
            );
            assert!(
                rule["score"].is_number(),
                "rule.score must be number: {rule}"
            );
        }
    }
}

#[test]
fn harden_double_decode_rules_have_urldecodeuni_twice() {
    let (code, stdout, stderr) = wafrift(&["harden", "--format", "json"]);
    assert_eq!(code, 0, "harden must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let classes = v["classes"].as_array().unwrap();

    // At least one rule across all classes must have UrlDecodeUni appearing
    // twice (the double-decode variant for closing double-encoded bypass holes).
    let has_double_decode = classes.iter().any(|class| {
        class["added_rules"].as_array().unwrap().iter().any(|rule| {
            rule["transforms"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|t| t.as_str() == Some("UrlDecodeUni"))
                .count()
                >= 2
        })
    });
    assert!(
        has_double_decode,
        "harden must emit at least one double-UrlDecodeUni rule: {v}"
    );
}

#[test]
fn harden_class_xss_exits_0() {
    let (code, _stdout, stderr) = wafrift(&["harden", "--class", "xss"]);
    assert_eq!(code, 0, "harden --class xss must exit 0; stderr: {stderr}");
}

#[test]
fn harden_class_sqli_exits_0() {
    let (code, _stdout, stderr) = wafrift(&["harden", "--class", "sqli"]);
    assert_eq!(code, 0, "harden --class sqli must exit 0; stderr: {stderr}");
}

#[test]
fn harden_nonexistent_ruleset_exits_nonzero() {
    let (code, _stdout, stderr) =
        wafrift(&["harden", "--ruleset", "/nonexistent/path/ruleset.toml"]);
    assert_ne!(
        code, 0,
        "nonexistent ruleset must exit non-zero; stderr: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "nonexistent ruleset must emit error message"
    );
}
