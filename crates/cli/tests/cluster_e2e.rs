//! End-to-end tests for `wafrift cluster`.
//!
//! All tests are purely offline — no HTTP, no mock server. The command
//! reads a bench-waf JSON blob from a file / stdin and groups bypasses
//! by rule_id × payload class × edit-distance similarity.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. cluster appears in top-level help.
//! 3. Valid bench JSON with bypasses produces a cluster report.
//! 4. JSON format emits a structured cluster blob with schema_version.
//! 5. Empty bypasses produces an empty cluster report (exit 0).
//! 6. Missing/malformed input exits non-zero with an error message.

use std::io::Write;
use std::process::{Command, Stdio};

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn wafrift_stdin(args: &[&str], stdin_data: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wafrift");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait wafrift");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Minimal bench-waf JSON with two bypasses — one SQL, one XSS.
fn bench_json_with_bypasses() -> &'static str {
    r#"{
  "results": [
    {
      "id": "sql_001",
      "class": "sql",
      "rule_id": "942100",
      "evaded": {
        "variants_bypassed": 2,
        "variants_total": 5,
        "bypass_techniques": [
          "encoding/url/double",
          "tamper/comment_strip"
        ]
      }
    },
    {
      "id": "xss_001",
      "class": "xss",
      "rule_id": "941100",
      "evaded": {
        "variants_bypassed": 1,
        "variants_total": 3,
        "bypass_techniques": [
          "encoding/html/entity"
        ]
      }
    }
  ]
}"#
}

/// Bench JSON with no bypasses — all variants_bypassed = 0.
fn bench_json_no_bypasses() -> &'static str {
    r#"{"results":[{"id":"sql_001","class":"sql","evaded":{"variants_bypassed":0,"variants_total":5,"bypass_techniques":[]}}]}"#
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn cluster_help_documents_options() {
    let (code, stdout, _) = wafrift(&["cluster", "--help"]);
    assert_eq!(code, 0, "cluster --help must exit 0");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
    assert!(stdout.contains("--edit-threshold"), "stdout: {stdout}");
}

#[test]
fn cluster_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("cluster"),
        "cluster must appear in top-level help: {stdout}"
    );
}

#[test]
fn cluster_json_format_emits_schema_version_and_clusters() {
    let (code, stdout, stderr) =
        wafrift_stdin(&["cluster", "-", "--format", "json"], bench_json_with_bypasses());
    assert_eq!(code, 0, "cluster must exit 0; stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json must be valid JSON");
    assert_eq!(
        v["schema_version"].as_u64().unwrap_or(0),
        1,
        "schema_version must be 1: {v}"
    );
    assert!(
        v["total_bypasses"].as_u64().unwrap_or(0) > 0,
        "total_bypasses must be > 0: {v}"
    );
    let clusters = v["clusters"].as_array().expect("clusters array");
    assert!(
        !clusters.is_empty(),
        "clusters must be non-empty for input with bypasses: {v}"
    );
    // Each cluster must have required fields.
    for c in clusters {
        assert!(c["rule_id"].is_string(), "cluster.rule_id must be string: {c}");
        assert!(c["member_count"].is_number(), "cluster.member_count must be number: {c}");
    }
}

#[test]
fn cluster_empty_bypasses_produces_empty_cluster_report() {
    let (code, stdout, stderr) =
        wafrift_stdin(&["cluster", "-", "--format", "json"], bench_json_no_bypasses());
    assert_eq!(code, 0, "cluster with no bypasses must still exit 0; stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("json must be valid JSON");
    assert_eq!(
        v["total_bypasses"].as_u64().unwrap_or(1),
        0,
        "total_bypasses must be 0 when no variants bypassed: {v}"
    );
    let clusters = v["clusters"].as_array().expect("clusters array");
    assert!(clusters.is_empty(), "clusters must be empty with no bypasses: {v}");
}

#[test]
fn cluster_rejects_malformed_json_with_nonzero_exit() {
    let (code, _stdout, stderr) = wafrift_stdin(
        &["cluster", "-", "--format", "json"],
        "NOT VALID JSON AT ALL",
    );
    assert_ne!(code, 0, "malformed JSON must exit non-zero; stderr: {stderr}");
}

#[test]
fn cluster_rejects_missing_results_array() {
    let (code, _stdout, stderr) = wafrift_stdin(
        &["cluster", "-", "--format", "json"],
        r#"{"no_results_key": []}"#,
    );
    assert_ne!(code, 0, "JSON without 'results' must exit non-zero; stderr: {stderr}");
}

#[test]
fn cluster_text_format_emits_human_readable_output() {
    let (code, stdout, stderr) =
        wafrift_stdin(&["cluster", "-", "--format", "text"], bench_json_with_bypasses());
    assert_eq!(code, 0, "cluster text format must exit 0; stderr: {stderr}");
    // Text format: not a JSON object.
    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err()
            || stdout.trim().is_empty(),
        "text format must not be a JSON object on stdout: {stdout}"
    );
}
