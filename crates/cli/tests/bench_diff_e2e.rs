//! End-to-end tests for `wafrift bench-diff`.
//!
//! `bench-diff` is fully offline — compares two bench-waf JSON blobs
//! written to temp files. No HTTP, no mock server.
//!
//! Tests verify:
//! 1. `bench-diff --help` exits 0 and documents required flags.
//! 2. `bench-diff` appears in top-level help.
//! 3. No-regression scenario exits 0.
//! 4. Regression scenario exits 3.
//! 5. Missing baseline file exits 1.
//! 6. Non-JSON input file exits 1.
//! 7. `--bypass-drop-pp` custom threshold is honoured.
//! 8. raw-block-rate below floor exits 0 (stack-mismatch, not regression).

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

/// Write a bench-waf–shaped JSON fixture to a temp file and return the path.
fn write_fixture(suffix: &str, bypass_rate: f64, raw_block_rate: f64) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_bench_diff_e2e_{suffix}.json"));
    let body = serde_json::json!({
        "raw_block_rate": raw_block_rate,
        "evade_mode": true,
        "evaded_summary": {
            "overall_bypass_rate": bypass_rate
        }
    });
    std::fs::write(&p, serde_json::to_string(&body).unwrap()).expect("write fixture");
    p.to_str().unwrap().to_string()
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn bench_diff_help_documents_required_flags() {
    let (code, stdout, _) = wafrift(&["bench-diff", "--help"]);
    assert_eq!(code, 0, "bench-diff --help must exit 0");
    assert!(stdout.contains("--current"), "must document --current: {stdout}");
    assert!(stdout.contains("--baseline"), "must document --baseline: {stdout}");
    assert!(
        stdout.contains("--bypass-drop-pp"),
        "must document --bypass-drop-pp: {stdout}"
    );
}

#[test]
fn bench_diff_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("bench-diff"),
        "bench-diff must appear in top-level help: {stdout}"
    );
}

// ── Regression gate ───────────────────────────────────────────────────────

#[test]
fn bench_diff_exits_0_when_no_regression() {
    let base = write_fixture("no_regress_base", 0.50, 1.0);
    let cur = write_fixture("no_regress_cur", 0.50, 1.0);
    let (code, stdout, stderr) = wafrift(&[
        "bench-diff",
        "--baseline",
        &base,
        "--current",
        &cur,
    ]);
    assert_eq!(code, 0, "no-regression diff must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("OK") || stdout.contains("bypass"),
        "no-regression must report OK: {stdout}"
    );
}

#[test]
fn bench_diff_exits_3_on_regression() {
    // baseline 50%, current 40% → 10pp drop → regression (> 2pp threshold).
    let base = write_fixture("regress_base", 0.50, 1.0);
    let cur = write_fixture("regress_cur", 0.40, 1.0);
    let (code, _stdout, stderr) = wafrift(&[
        "bench-diff",
        "--baseline",
        &base,
        "--current",
        &cur,
    ]);
    assert_eq!(
        code, 3,
        "10pp regression must exit 3; stderr: {stderr}"
    );
    assert!(
        stderr.to_uppercase().contains("REGRESSION"),
        "regression must be reported in stderr: {stderr}"
    );
}

#[test]
fn bench_diff_custom_threshold_gates_regression() {
    // baseline 50%, current 47% → 3pp drop.
    // Default threshold (2pp) → regression. Custom (5pp) → no regression.
    let base = write_fixture("thresh_base", 0.50, 1.0);
    let cur = write_fixture("thresh_cur", 0.47, 1.0);

    let (code_default, _, _) = wafrift(&[
        "bench-diff",
        "--baseline",
        &base,
        "--current",
        &cur,
    ]);
    assert_eq!(
        code_default, 3,
        "3pp drop must be a regression at default 2pp threshold"
    );

    let (code_custom, _, _) = wafrift(&[
        "bench-diff",
        "--baseline",
        &base,
        "--current",
        &cur,
        "--bypass-drop-pp",
        "5",
    ]);
    assert_eq!(
        code_custom, 0,
        "3pp drop must NOT be a regression at 5pp threshold"
    );
}

#[test]
fn bench_diff_raw_block_floor_does_not_cause_exit_3() {
    // Raw block rate below floor = "stack changed", not a wafrift regression.
    // bypass rate unchanged → must still exit 0.
    let base = write_fixture("floor_base", 0.50, 1.0);
    let cur = write_fixture("floor_cur", 0.50, 0.80); // raw-block dropped
    let (code, _stdout, _stderr) = wafrift(&[
        "bench-diff",
        "--baseline",
        &base,
        "--current",
        &cur,
    ]);
    assert_eq!(
        code, 0,
        "stack-mismatch (raw-block below floor) must exit 0, not 3"
    );
}

// ── Error paths ───────────────────────────────────────────────────────────

#[test]
fn bench_diff_missing_baseline_exits_1() {
    let cur = write_fixture("missing_base_cur", 0.50, 1.0);
    let mut missing = std::env::temp_dir();
    missing.push("wafrift_bench_diff_e2e_completely_missing.json");
    let _ = std::fs::remove_file(&missing);
    let (code, _stdout, stderr) = wafrift(&[
        "bench-diff",
        "--baseline",
        missing.to_str().unwrap(),
        "--current",
        &cur,
    ]);
    assert_eq!(code, 1, "missing baseline file must exit 1; stderr: {stderr}");
    assert!(!stderr.is_empty(), "missing file must emit error message");
}

#[test]
fn bench_diff_malformed_baseline_exits_1() {
    let mut bad = std::env::temp_dir();
    bad.push("wafrift_bench_diff_e2e_malformed.json");
    std::fs::write(&bad, "this is not json").unwrap();
    let cur = write_fixture("malformed_cur", 0.50, 1.0);
    let (code, _stdout, stderr) = wafrift(&[
        "bench-diff",
        "--baseline",
        bad.to_str().unwrap(),
        "--current",
        &cur,
    ]);
    assert_eq!(code, 1, "malformed baseline must exit 1; stderr: {stderr}");
    let _ = std::fs::remove_file(&bad);
}
