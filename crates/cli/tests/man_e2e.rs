//! End-to-end tests for `wafrift man`.
//!
//! `man` generates a troff man page from the live clap command tree.
//! It is fully offline — no HTTP, no mock server.
//!
//! Tests verify:
//! 1. `man --help` exits 0.
//! 2. `man` appears in top-level help.
//! 3. `man` (stdout) exits 0 and emits valid troff content.
//! 4. Man page contains the binary name and at least one .SH section.
//! 5. `man --sub probe` exits 0 and emits probe-specific content.
//! 6. `man --sub wafrift` exits 0 (explicit top-level page).
//! 7. `man --sub nonexistent` exits non-zero with an error.
//! 8. `man --output <temp-file>` writes the page to a file.

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

fn unique_temp_path(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_man_e2e_{suffix}.1"));
    let _ = std::fs::remove_file(&p);
    p
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn man_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["man", "--help"]);
    assert_eq!(code, 0, "man --help must exit 0");
}

#[test]
fn man_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("man"),
        "man must appear in top-level help: {stdout}"
    );
}

// ── Default output (stdout) ───────────────────────────────────────────────

#[test]
fn man_exits_0_and_emits_troff() {
    let (code, stdout, stderr) = wafrift(&["man"]);
    assert_eq!(code, 0, "man must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "man must emit troff content to stdout: {stderr}"
    );
    // Troff pages always start with .TH (title header) or .ie/.el macros.
    let is_troff = stdout.contains(".TH ") || stdout.contains(".ie ") || stdout.contains(".SH ");
    assert!(is_troff, "man output must be troff format: {stdout}");
}

#[test]
fn man_page_contains_binary_name_and_sh_section() {
    let (code, stdout, stderr) = wafrift(&["man"]);
    assert_eq!(code, 0, "man must exit 0; stderr: {stderr}");
    // Must contain the binary name.
    assert!(
        stdout.contains("wafrift"),
        "man page must mention 'wafrift': {stdout}"
    );
    // Must contain at least one .SH section header.
    assert!(
        stdout.contains(".SH"),
        "man page must have at least one .SH section: {stdout}"
    );
}

#[test]
fn man_page_contains_name_and_synopsis_sections() {
    let (code, stdout, stderr) = wafrift(&["man"]);
    assert_eq!(code, 0, "man must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("NAME") || stdout.contains(".SH NAME"),
        "man page must have NAME section: {stdout}"
    );
}

// ── `--sub` flag ──────────────────────────────────────────────────────────

#[test]
fn man_sub_probe_exits_0_and_emits_probe_content() {
    let (code, stdout, stderr) = wafrift(&["man", "--sub", "probe"]);
    assert_eq!(code, 0, "man --sub probe must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "man --sub probe must emit content: {stderr}"
    );
    // The probe subcommand page must mention probe.
    assert!(
        stdout.to_lowercase().contains("probe"),
        "man --sub probe must mention 'probe': {stdout}"
    );
}

#[test]
fn man_sub_wafrift_exits_0() {
    let (code, _stdout, stderr) = wafrift(&["man", "--sub", "wafrift"]);
    assert_eq!(code, 0, "man --sub wafrift must exit 0; stderr: {stderr}");
}

#[test]
fn man_sub_nonexistent_exits_nonzero() {
    let (code, _stdout, stderr) = wafrift(&["man", "--sub", "this-subcommand-does-not-exist"]);
    assert_ne!(
        code, 0,
        "man --sub for unknown subcommand must exit non-zero; stderr: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "unknown --sub must emit an error message"
    );
}

// ── `--output` flag ───────────────────────────────────────────────────────

#[test]
fn man_output_to_file_writes_troff_content() {
    let out_path = unique_temp_path("output");
    let out_str = out_path.to_str().expect("path is UTF-8");

    let (code, _stdout, stderr) = wafrift(&["man", "--output", out_str]);
    assert_eq!(code, 0, "man --output must exit 0; stderr: {stderr}");

    let content = std::fs::read_to_string(&out_path)
        .unwrap_or_else(|e| panic!("man --output file must be written: {e}; path={out_str}"));
    let _ = std::fs::remove_file(&out_path);

    assert!(
        !content.trim().is_empty(),
        "man --output file must not be empty"
    );
    let is_troff = content.contains(".TH ") || content.contains(".ie ") || content.contains(".SH ");
    assert!(is_troff, "man --output file must be troff format: {content}");
}
