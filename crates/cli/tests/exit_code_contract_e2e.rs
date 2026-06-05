//! Exit-code contract tests — §12 anti-rig.
//!
//! Every input-error path that should exit 2 (operator-supplied value wrong:
//! missing/unreadable file, malformed content, empty required arg, unknown
//! selector) gets its own test here. All tests are offline — no HTTP, no
//! mock server, no disk writes to shared paths.
//!
//! Exit-code contract (from `main.rs`):
//!   0  success
//!   1  runtime / IO error (TLS, network, internal)
//!   2  argument / input error (missing file, malformed value, unknown selector)
//!
//! Tests deliberately check `== 2` (not just `!= 0`) to pin the contract:
//! a silent regression that changes exit 2 → exit 1 is as breaking as
//! a crash for CI scripts that inspect the code numerically.

mod common;
use common::wafrift;
use std::io::Write;
use std::process::{Command, Stdio};

// ── helpers ───────────────────────────────────────────────────────────────────

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

/// Path that is guaranteed not to exist during the test run.
fn nonexistent_path() -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "wafrift_exit2_test_nonexistent_{}.json",
        std::process::id()
    ));
    // Ensure it really doesn't exist.
    let _ = std::fs::remove_file(&p);
    p.to_str().unwrap().to_string()
}

// ── scan: empty --payload → exit 2 ───────────────────────────────────────────

#[test]
fn scan_empty_payload_exits_2() {
    // An empty --payload is an operator input error; the contract says exit 2.
    // We use an unreachable address so no network I/O occurs and the check
    // fires before any HTTP attempt.
    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        "http://127.0.0.1:1",
        "--payload",
        "",
        // light level to avoid variant-generation cost
    ]);
    assert_eq!(
        code, 2,
        "scan with empty --payload must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

// ── scan --corpus missing path → exit 2 ──────────────────────────────────────

#[test]
fn scan_corpus_missing_path_exits_2() {
    let missing = nonexistent_path();
    // --corpus with a non-existent path and a target: triggers the bench
    // delegation path in main.rs. bench-waf will fail to load the corpus
    // (exit 1 from the bench engine for IO failure) — but the `--corpus`
    // MISSING-TARGET check is what we're pinning here.
    //
    // No target → input_error() → exit 2.
    let (code, _stdout, stderr) = wafrift(&[
        "scan", "--corpus",
        &missing,
        // Deliberately omit target so the "needs a target URL" branch fires.
    ]);
    assert_eq!(
        code, 2,
        "scan --corpus without target must exit 2 (input error); got {code}; stderr: {stderr}"
    );
}

// ── sarif /missing → exit 2 ──────────────────────────────────────────────────

#[test]
fn sarif_missing_file_exits_2() {
    let missing = nonexistent_path();
    let (code, _stdout, stderr) = wafrift(&["sarif", &missing]);
    assert_eq!(
        code, 2,
        "sarif <missing-file> must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

#[test]
fn sarif_malformed_json_stdin_exits_2() {
    let (code, _stdout, stderr) = wafrift_stdin(&["sarif", "-"], "NOT_VALID_JSON");
    assert_eq!(
        code, 2,
        "sarif with malformed JSON must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

// ── cluster /missing → exit 2 ────────────────────────────────────────────────

#[test]
fn cluster_missing_file_exits_2() {
    let missing = nonexistent_path();
    let (code, _stdout, stderr) = wafrift(&["cluster", &missing]);
    assert_eq!(
        code, 2,
        "cluster <missing-file> must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

#[test]
fn cluster_malformed_json_stdin_exits_2() {
    let (code, _stdout, stderr) = wafrift_stdin(&["cluster", "-"], "NOT_VALID_JSON");
    assert_eq!(
        code, 2,
        "cluster with malformed JSON stdin must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

#[test]
fn cluster_json_without_results_key_exits_2() {
    // JSON that is valid but has no 'results' array is a malformed input.
    let (code, _stdout, stderr) = wafrift_stdin(&["cluster", "-"], r#"{"no_results": []}"#);
    assert_eq!(
        code, 2,
        "cluster with JSON missing 'results' must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

// ── --payload-class: invalid value → exit 2 (clap) ───────────────────────────

#[test]
fn scan_invalid_payload_class_exits_2() {
    // clap's value_parser rejects unknown values with exit 2 automatically.
    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        "http://127.0.0.1:1",
        "--payload",
        "test",
        "--payload-class",
        "definitely_not_a_class",
    ]);
    assert_eq!(
        code, 2,
        "scan with invalid --payload-class must exit 2 (input error); got {code}; stderr: {stderr}"
    );
}

#[test]
fn scan_valid_payload_class_accepted() {
    // All 10 documented values must be accepted by the parser.
    // We run with an unreachable target: we just need the parse to succeed.
    // The scan will fail at the network layer (exit 1) — NOT at parse (exit 2).
    for cls in &[
        "sql",
        "xss",
        "cmdi",
        "ssti",
        "path",
        "ldap",
        "xxe",
        "ssrf",
        "nosql",
        "log4shell",
    ] {
        let (code, _stdout, stderr) = wafrift(&[
            "scan",
            "http://127.0.0.1:1",
            "--payload",
            "test",
            "--payload-class",
            cls,
            "--dry-run",
        ]);
        // dry-run skips network; exits 0 after printing the budget.
        // On any platform where port 1 is bindable (shouldn't happen but guard anyway)
        // exit could be 0 or 1 — what matters is it is NOT 2.
        assert_ne!(
            code, 2,
            "--payload-class={cls} is a valid value and must not exit 2; got {code}; stderr: {stderr}"
        );
    }
}

// ── report --scan-json /missing → exit 2 ─────────────────────────────────────

#[test]
fn report_missing_scan_json_exits_2() {
    let missing = nonexistent_path();
    let (code, _stdout, stderr) = wafrift(&["report", "--scan-json", &missing]);
    assert_eq!(
        code, 2,
        "report --scan-json <missing> must exit 2 (input error); got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

#[test]
fn report_malformed_scan_json_stdin_exits_2() {
    let (code, _stdout, stderr) = wafrift_stdin(&["report", "--scan-stdin"], "NOT_VALID_JSON");
    assert_eq!(
        code, 2,
        "report --scan-stdin with malformed JSON must exit 2; got {code}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr must contain 'error:': {stderr}"
    );
}

// ── Exit-1 sites deliberately left at exit 1 (anti-rig: pin them too) ────────

#[test]
fn sarif_schema_mismatch_exits_2_not_1() {
    // When the sarif input is valid JSON but has no recognised bypass key
    // (`results` or `bypasses`), the command already correctly exits 2
    // (documented overload, pre-existing, not changed). Pin it.
    let (code, _stdout, stderr) = wafrift_stdin(&["sarif", "-"], r#"{"unrecognised_key": []}"#);
    assert_eq!(
        code, 2,
        "sarif with unrecognised schema must exit 2 (pre-existing anti-rig); got {code}; stderr: {stderr}"
    );
}

// ── LM-A01: prove the production `unreachable!()` arms are truly unreachable ──
//
// Four production `unreachable!()` sites are guarded by clap argument
// invariants (`required_unless_present*` / `conflicts_with*`). The contract
// (CLAUDE.md "no stubs / prove unreachable") requires proving the guard fires
// BEFORE the run_* fn — i.e. clap rejects the triggering input with exit 2 so
// the panic can never be hit. Each test below drives the real binary with the
// exact input that would otherwise reach the panic and asserts clap's exit 2.

#[test]
fn bench_diff_missing_current_exits_2() {
    // bench_diff.rs:67 `unreachable!("clap guarantees one of current /
    // current_positional")`. With neither form supplied, clap rejects
    // (`--current` is required_unless_present="current_positional").
    let (code, _o, stderr) = wafrift(&["bench-diff"]);
    assert_eq!(
        code, 2,
        "bench-diff with no current/baseline must exit 2 (clap usage); got {code}; stderr: {stderr}"
    );
}

#[test]
fn bench_diff_missing_baseline_exits_2() {
    // bench_diff.rs:71 `unreachable!(... baseline ...)`. Supply current
    // positionally (clap then sees current present) but omit baseline → clap
    // rejects on the baseline requirement, before run_bench_diff loads files.
    let (code, _o, stderr) = wafrift(&["bench-diff", "some_current.json"]);
    assert_eq!(
        code, 2,
        "bench-diff with current but no baseline must exit 2 (clap usage); got {code}; stderr: {stderr}"
    );
}

#[test]
fn detect_no_url_no_status_exits_2() {
    // detect_cmd.rs:536 `unreachable!("clap requires --status unless --url is
    // present")`. With no URL (positional or --url) and no --status, clap's
    // `required_unless_present_any = ["url","url_positional"]` rejects.
    let (code, _o, stderr) = wafrift(&["detect"]);
    assert_eq!(
        code, 2,
        "detect with no url and no --status must exit 2 (clap usage); got {code}; stderr: {stderr}"
    );
}

#[test]
fn import_curl_conflicting_sources_exits_2() {
    // import_curl.rs:349 `unreachable!("clap conflicts_with prevents this")`.
    // `--curl-file` conflicts_with `--from-stdin`; supplying both is rejected
    // by clap before run_import_curl resolves the (curl, file, stdin) tuple.
    let (code, _o, stderr) = wafrift(&[
        "import-curl",
        "--curl-file",
        "some_capture.txt",
        "--from-stdin",
    ]);
    assert_eq!(
        code, 2,
        "import-curl with both --curl-file and --from-stdin must exit 2 (clap conflict); got {code}; stderr: {stderr}"
    );
}
