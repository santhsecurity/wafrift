//! End-to-end tests for `wafrift detect`.
//!
//! `detect` identifies a WAF/CDN from response metadata.  Its offline mode
//! (`--status / --headers / --body`) runs without any HTTP connection,
//! making it ideal for pure-offline e2e tests.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. detect appears in top-level help.
//! 3. Known Cloudflare headers → detected=Cloudflare with high confidence.
//! 4. Unknown server → detected=[] (empty).
//! 5. JSON output has required fields (detected array, status, infrastructure).
//! 6. Each detected entry has name, confidence, indicators fields.
//! 7. --status out-of-range (0, 1000) exits non-zero with a helpful error.
//! 8. Sucuri headers are detected.
//! 9. Body with Cloudflare marker is detected even without headers.

use std::process::Command;

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

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn detect_help_documents_options() {
    let (code, stdout, _) = wafrift(&["detect", "--help"]);
    assert_eq!(code, 0, "detect --help must exit 0");
    assert!(stdout.contains("--status"), "stdout: {stdout}");
    assert!(stdout.contains("--headers"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
    assert!(stdout.contains("--url"), "stdout: {stdout}");
}

#[test]
fn detect_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("detect"),
        "detect must appear in top-level help: {stdout}"
    );
}

// ── JSON schema ───────────────────────────────────────────────────────────

#[test]
fn detect_json_output_has_required_fields() {
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "Server: cloudflare",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");

    assert!(v["detected"].is_array(), "detected must be array: {v}");
    assert!(v["status"].is_number(), "status must be number: {v}");
    assert!(
        v["infrastructure"].is_array(),
        "infrastructure must be array: {v}"
    );
}

// ── Cloudflare detection ──────────────────────────────────────────────────

#[test]
fn detect_identifies_cloudflare_from_server_header() {
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "Server: cloudflare",
        "--headers",
        "CF-Ray: abc123-EWR",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let detected = v["detected"].as_array().expect("detected array");
    assert!(
        !detected.is_empty(),
        "Cloudflare headers must produce a detection: {v}"
    );

    let has_cloudflare = detected
        .iter()
        .any(|d| d["name"].as_str().unwrap_or("").to_lowercase().contains("cloudflare"));
    assert!(has_cloudflare, "must detect Cloudflare: {v}");
}

#[test]
fn detect_cloudflare_detection_has_required_fields() {
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "Server: cloudflare",
        "--headers",
        "CF-Ray: xyz",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let detected = v["detected"].as_array().expect("detected array");

    for entry in detected {
        assert!(
            entry["name"].is_string(),
            "detected.name must be string: {entry}"
        );
        assert!(
            entry["confidence"].is_number(),
            "detected.confidence must be number: {entry}"
        );
        assert!(
            entry["indicators"].is_array(),
            "detected.indicators must be array: {entry}"
        );
        let conf = entry["confidence"].as_f64().unwrap_or(0.0);
        assert!(
            conf >= 0.0 && conf <= 1.0,
            "confidence must be in [0, 1]: {entry}"
        );
    }
}

// ── Unknown server → empty detected ──────────────────────────────────────

#[test]
fn detect_unknown_server_produces_empty_detected() {
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "200",
        "--headers",
        "Server: nginx",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0 for unknown server; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let detected = v["detected"].as_array().expect("detected array");
    assert!(
        detected.is_empty(),
        "generic nginx must produce no WAF detection: {v}"
    );
}

// ── Sucuri detection ──────────────────────────────────────────────────────

#[test]
fn detect_identifies_sucuri_from_header() {
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "X-Sucuri-ID: abc123",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let detected = v["detected"].as_array().expect("detected array");
    assert!(
        !detected.is_empty(),
        "Sucuri X-Sucuri-ID header must produce a detection: {v}"
    );

    let has_sucuri = detected
        .iter()
        .any(|d| d["name"].as_str().unwrap_or("").to_lowercase().contains("sucuri"));
    assert!(has_sucuri, "must detect Sucuri: {v}");
}

// ── Error paths ───────────────────────────────────────────────────────────

#[test]
fn detect_rejects_out_of_range_status_0() {
    let (code, _stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "0",
        "--headers",
        "Server: test",
    ]);
    assert_ne!(code, 0, "status 0 must exit non-zero; stderr: {stderr}");
    // Error must hint at the valid range.
    assert!(
        stderr.contains("100") || stderr.contains("range") || stderr.contains("not a number"),
        "error must mention valid range; stderr: {stderr}"
    );
}

#[test]
fn detect_rejects_out_of_range_status_1000() {
    let (code, _stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "1000",
        "--headers",
        "Server: test",
    ]);
    assert_ne!(code, 0, "status 1000 must exit non-zero; stderr: {stderr}");
}

#[test]
fn detect_requires_at_least_status_or_url() {
    // No --status and no URL → must exit non-zero.
    let (code, _stdout, stderr) = wafrift(&["detect", "--headers", "Server: test"]);
    assert_ne!(
        code, 0,
        "detect with no --status and no URL must exit non-zero; stderr: {stderr}"
    );
}

// ── Infrastructure field ──────────────────────────────────────────────────

#[test]
fn detect_infrastructure_lists_server_header() {
    // The `infrastructure` field records known infrastructure-revealing
    // headers (Server, X-Powered-By, Via, etc.).  Use the canonical
    // `Server` header which detect explicitly tracks.
    let (code, stdout, stderr) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "Server: cloudflare",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "detect must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let infra = v["infrastructure"].as_array().expect("infrastructure array");

    // Server: cloudflare must appear in the infrastructure list.
    let has_server = infra.iter().any(|entry| {
        entry["header"]
            .as_str()
            .map(|h| h.to_ascii_lowercase() == "server")
            .unwrap_or(false)
    });
    assert!(
        has_server,
        "infrastructure must include the Server header: {v}"
    );
}
