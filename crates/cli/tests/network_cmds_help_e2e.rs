//! Help-surface and argument-validation e2e tests for network-dependent
//! wafrift subcommands.
//!
//! These commands perform HTTP/DNS/TCP in their core logic, so we only
//! test the offline portions:
//!   - `import-curl`   — flag parsing and mutual-exclusion validation
//!   - `legendary`     — help and argument validation
//!   - `origin-hints`  — help and missing-host error
//!
//! No mocks, no external connections — all tests exit before any I/O.

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

// ─────────────────────────────────────────────────────────────────────────────
// import-curl
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn import_curl_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("import-curl"),
        "import-curl must appear in top-level help: {stdout}"
    );
}

#[test]
fn import_curl_help_exits_0_and_documents_flags() {
    let (code, stdout, _) = wafrift(&["import-curl", "--help"]);
    assert_eq!(code, 0, "import-curl --help must exit 0");
    assert!(stdout.contains("--curl-file"), "must document --curl-file: {stdout}");
    assert!(stdout.contains("--from-stdin"), "must document --from-stdin: {stdout}");
    assert!(stdout.contains("--payload"), "must document --payload: {stdout}");
    assert!(stdout.contains("--format"), "must document --format: {stdout}");
}

#[test]
fn import_curl_from_stdin_and_curl_file_are_mutually_exclusive() {
    // Providing both flags must exit 2 (clap argument conflict).
    let fake_file = {
        let mut p = std::env::temp_dir();
        p.push("wafrift_import_curl_e2e_dummy.txt");
        std::fs::write(&p, "curl https://example.com/").unwrap_or(());
        p.to_str().unwrap().to_string()
    };
    let (code, _stdout, stderr) = wafrift(&[
        "import-curl",
        "--from-stdin",
        "--curl-file",
        &fake_file,
    ]);
    assert_eq!(
        code, 2,
        "--from-stdin and --curl-file must be mutually exclusive (exit 2); stderr: {stderr}"
    );
}

#[test]
fn import_curl_positional_and_from_stdin_are_mutually_exclusive() {
    let (code, _stdout, _stderr) = wafrift(&[
        "import-curl",
        "curl https://example.com/",
        "--from-stdin",
    ]);
    assert_eq!(
        code, 2,
        "positional curl arg and --from-stdin must be mutually exclusive (exit 2)"
    );
}

#[test]
fn import_curl_nonexistent_curl_file_exits_nonzero() {
    let mut p = std::env::temp_dir();
    p.push("wafrift_import_curl_e2e_nonexistent.txt");
    let _ = std::fs::remove_file(&p);
    let (code, _stdout, stderr) = wafrift(&["import-curl", "--curl-file", p.to_str().unwrap()]);
    assert_ne!(code, 0, "nonexistent --curl-file must exit non-zero; stderr: {stderr}");
    assert!(!stderr.is_empty(), "missing curl file must emit error message");
}

#[test]
fn import_curl_invalid_level_exits_nonzero() {
    let (code, _stdout, _stderr) = wafrift(&[
        "import-curl",
        "curl https://example.com/",
        "--level",
        "ultra-supreme",
    ]);
    assert_ne!(code, 0, "--level with invalid value must exit non-zero");
}

// ─────────────────────────────────────────────────────────────────────────────
// legendary
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn legendary_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("legendary"),
        "legendary must appear in top-level help: {stdout}"
    );
}

#[test]
fn legendary_help_exits_0_and_documents_target() {
    let (code, stdout, _) = wafrift(&["legendary", "--help"]);
    assert_eq!(code, 0, "legendary --help must exit 0");
    // The TARGET positional argument must be documented.
    assert!(
        stdout.to_lowercase().contains("target"),
        "legendary --help must document the target argument: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// origin-hints
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn origin_hints_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("origin-hints"),
        "origin-hints must appear in top-level help: {stdout}"
    );
}

#[test]
fn origin_hints_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["origin-hints", "--help"]);
    assert_eq!(code, 0, "origin-hints --help must exit 0");
}

#[test]
fn origin_hints_invalid_format_exits_nonzero() {
    // Clap value_parser rejects invalid format strings.
    let (code, _stdout, _stderr) =
        wafrift(&["origin-hints", "example.com", "--format", "toml"]);
    assert_ne!(code, 0, "--format toml must exit non-zero (invalid value)");
}
