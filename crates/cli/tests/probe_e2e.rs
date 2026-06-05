//! End-to-end tests for `wafrift probe`.
//!
//! All tests are purely offline — no HTTP, no mock server.
//! `probe` generates differential-analysis probe payloads (NDJSON by default).
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. probe appears in top-level help.
//! 3. Default output: NDJSON, one JSON object per line.
//! 4. Each probe line has payload, description, expected_blocked, tests fields.
//! 5. A baseline probe is always present (expected_blocked=false).
//! 6. --quick produces fewer probes than the full set.
//! 7. Every probe's expected_blocked is a boolean.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn probe_help_documents_options() {
    let (code, stdout, _) = wafrift(&["probe", "--help"]);
    assert_eq!(code, 0, "probe --help must exit 0");
    assert!(stdout.contains("--quick"), "stdout: {stdout}");
}

#[test]
fn probe_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("probe"),
        "probe must appear in top-level help: {stdout}"
    );
}

// ── Default output (NDJSON) ───────────────────────────────────────────────

#[test]
fn probe_emits_ndjson_one_object_per_line() {
    let (code, stdout, stderr) = wafrift(&["probe"]);
    assert_eq!(code, 0, "probe must exit 0; stderr: {stderr}");

    let mut line_count = 0usize;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let obj: serde_json::Value =
            serde_json::from_str(trimmed).expect("each probe line must be valid JSON");
        assert!(
            obj.is_object(),
            "probe line must be a JSON object: {trimmed}"
        );
        line_count += 1;
    }
    assert!(
        line_count > 0,
        "probe must emit at least one line: {stdout}"
    );
}

#[test]
fn probe_lines_have_required_fields() {
    let (code, stdout, stderr) = wafrift(&["probe"]);
    assert_eq!(code, 0, "probe must exit 0; stderr: {stderr}");

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let obj: serde_json::Value = serde_json::from_str(trimmed).expect("valid JSON");
        assert!(
            obj["payload"].is_string(),
            "probe.payload must be string: {trimmed}"
        );
        assert!(
            obj["description"].is_string(),
            "probe.description must be string: {trimmed}"
        );
        assert!(
            obj["expected_blocked"].is_boolean(),
            "probe.expected_blocked must be boolean: {trimmed}"
        );
        assert!(
            obj["tests"].is_string(),
            "probe.tests must be string: {trimmed}"
        );
    }
}

#[test]
fn probe_includes_baseline_probe_with_expected_blocked_false() {
    let (code, stdout, stderr) = wafrift(&["probe"]);
    assert_eq!(code, 0, "probe must exit 0; stderr: {stderr}");

    let has_baseline = stdout.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map(|obj| obj["expected_blocked"].as_bool() == Some(false))
            .unwrap_or(false)
    });
    assert!(
        has_baseline,
        "probe must include at least one baseline entry (expected_blocked=false): {stdout}"
    );
}

// ── --quick flag ──────────────────────────────────────────────────────────

#[test]
fn probe_quick_produces_fewer_lines_than_full_set() {
    let (code_full, out_full, _) = wafrift(&["probe"]);
    let (code_quick, out_quick, _) = wafrift(&["probe", "--quick"]);

    assert_eq!(code_full, 0, "probe must exit 0");
    assert_eq!(code_quick, 0, "probe --quick must exit 0");

    let count_full = out_full.lines().filter(|l| !l.trim().is_empty()).count();
    let count_quick = out_quick.lines().filter(|l| !l.trim().is_empty()).count();

    assert!(
        count_quick < count_full,
        "--quick must produce fewer probes ({count_quick}) than full ({count_full})"
    );
}

#[test]
fn probe_quick_still_emits_valid_json_lines() {
    let (code, stdout, stderr) = wafrift(&["probe", "--quick"]);
    assert_eq!(code, 0, "probe --quick must exit 0; stderr: {stderr}");

    let mut count = 0usize;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _: serde_json::Value = serde_json::from_str(trimmed)
            .unwrap_or_else(|e| panic!("--quick line must be valid JSON: {e}\nline: {trimmed}"));
        count += 1;
    }
    assert!(count > 0, "--quick must emit at least one line: {stdout}");
}
