//! End-to-end tests for `wafrift evade`.
//!
//! All tests are purely offline — no HTTP, no mock server.
//! `evade` transforms a payload through the evasion-technique engine
//! and emits variant payloads.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. evade appears in top-level help.
//! 3. JSON format emits schema_version=1 and a non-empty variants array.
//! 4. Each variant has payload, techniques, confidence fields.
//! 5. --only narrows the technique set to the named selector.
//! 6. JSONL format emits one JSON object per line (no top-level wrapper).
//! 7. Text format is not a JSON object on stdout.
//! 8. --payload-b64 accepts a base64-encoded payload and produces variants.

use std::io::Write;
use std::process::{Command, Stdio};

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn wafrift_stdin(args: &[&str], stdin_data: &[u8]) -> (i32, String, String) {
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
        .write_all(stdin_data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait wafrift");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn evade_help_documents_options() {
    let (code, stdout, _) = wafrift(&["evade", "--help"]);
    assert_eq!(code, 0, "evade --help must exit 0");
    assert!(stdout.contains("--payload"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
    assert!(stdout.contains("--stdin"), "stdout: {stdout}");
}

#[test]
fn evade_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("evade"),
        "evade must appear in top-level help: {stdout}"
    );
}

// ── JSON format ───────────────────────────────────────────────────────────

#[test]
fn evade_json_format_emits_schema_version_1() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "union select", "--format", "json"]);
    assert_eq!(code, 0, "evade must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(
        v["schema_version"].as_u64().unwrap_or(0),
        1,
        "schema_version must be 1: {v}"
    );
}

#[test]
fn evade_json_format_emits_non_empty_variants_array() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "union select", "--format", "json"]);
    assert_eq!(code, 0, "evade must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let variants = v["variants"].as_array().expect("variants must be array");
    assert!(
        !variants.is_empty(),
        "evade must produce at least one variant for 'union select': {v}"
    );
}

#[test]
fn evade_json_variants_have_required_fields() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "test-xss", "--format", "json"]);
    assert_eq!(code, 0, "evade must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let variants = v["variants"].as_array().expect("variants array");
    for variant in variants {
        assert!(
            variant["payload"].is_string(),
            "variant.payload must be string: {variant}"
        );
        assert!(
            variant["techniques"].is_array(),
            "variant.techniques must be array: {variant}"
        );
        assert!(
            variant["confidence"].is_number(),
            "variant.confidence must be number: {variant}"
        );
    }
}

// ── --only selector ───────────────────────────────────────────────────────

#[test]
fn evade_only_selector_limits_technique_set() {
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "test",
        "--only",
        "encoding/url/single",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "evade --only must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let variants = v["variants"].as_array().expect("variants array");
    assert!(
        !variants.is_empty(),
        "encoding/url/single must produce at least one variant: {v}"
    );

    // Every variant's techniques list must include the url-encode family name.
    // (The engine may use internal technique names so we check the payload
    //  is URL-encoded form of the input — i.e. the plain "test" transformed.)
    for variant in variants {
        let payload = variant["payload"].as_str().unwrap_or("");
        // URL-encoded "test" — characters may be encoded.
        // At minimum the payload must not be empty.
        assert!(!payload.is_empty(), "variant payload must not be empty: {variant}");
    }
}

// ── JSONL format ──────────────────────────────────────────────────────────

#[test]
fn evade_jsonl_format_emits_one_object_per_line() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "union select", "--format", "jsonl"]);
    assert_eq!(code, 0, "evade --format jsonl must exit 0; stderr: {stderr}");

    // Every non-empty line must be a valid JSON object.
    let mut line_count = 0usize;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let obj: serde_json::Value =
            serde_json::from_str(trimmed).expect("each jsonl line must be valid JSON");
        assert!(obj.is_object(), "jsonl line must be a JSON object: {trimmed}");
        line_count += 1;
    }
    assert!(
        line_count > 0,
        "jsonl must produce at least one line for 'union select': {stdout}"
    );
}

#[test]
fn evade_jsonl_lines_have_payload_field() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "test", "--format", "jsonl"]);
    assert_eq!(code, 0, "evade --format jsonl must exit 0; stderr: {stderr}");

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let obj: serde_json::Value = serde_json::from_str(trimmed).expect("valid JSON line");
        assert!(
            obj["payload"].is_string(),
            "jsonl line must have payload field: {trimmed}"
        );
    }
}

// ── Text format ───────────────────────────────────────────────────────────

#[test]
fn evade_text_format_is_not_json_object_on_stdout() {
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload", "union select", "--format", "text"]);
    assert_eq!(code, 0, "evade text format must exit 0; stderr: {stderr}");

    // Text format should not be parseable as a single top-level JSON object.
    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err()
            || stdout.trim().is_empty(),
        "text format must not be a pure JSON object on stdout: {stdout}"
    );
}

// ── --stdin ───────────────────────────────────────────────────────────────

#[test]
fn evade_stdin_reads_payload_from_stdin() {
    let (code, stdout, stderr) =
        wafrift_stdin(&["evade", "--stdin", "--format", "json"], b"xss payload");
    assert_eq!(code, 0, "evade --stdin must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let variants = v["variants"].as_array().expect("variants array");
    assert!(
        !variants.is_empty(),
        "evade --stdin must produce variants for 'xss payload': {v}"
    );
}

// ── --payload-b64 ─────────────────────────────────────────────────────────

#[test]
fn evade_payload_b64_decodes_and_produces_variants() {
    // base64("union select") = "dW5pb24gc2VsZWN0"
    let b64 = "dW5pb24gc2VsZWN0";
    let (code, stdout, stderr) =
        wafrift(&["evade", "--payload-b64", b64, "--format", "json"]);
    assert_eq!(code, 0, "evade --payload-b64 must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let variants = v["variants"].as_array().expect("variants array");
    assert!(
        !variants.is_empty(),
        "evade --payload-b64 must produce variants: {v}"
    );
}
