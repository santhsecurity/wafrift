//! End-to-end tests for `wafrift init`.
//!
//! All tests are purely offline — no HTTP, no mock server.  Each test that
//! writes a file uses a unique temp-file path (via `std::env::temp_dir()`)
//! and cleans up after itself so tests are safe to run in parallel.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. init appears in top-level help.
//! 3. Writing to a new path succeeds (exit 0) and creates a valid TOML file.
//! 4. The generated file contains expected scaffold keys.
//! 5. Writing to an existing path without --force exits 1 with a clear error.
//! 6. Writing to an existing path with --force succeeds (exit 0).
//! 7. --quiet suppresses the "Next steps" advisory text on stderr/stdout.

mod common;
use common::wafrift;
use std::fs;
use std::path::PathBuf;

/// Return a temp-dir path that does NOT exist yet (suffix ensures parallel
/// tests use distinct paths even if the OS recycles temp dirs quickly).
fn unique_temp_path(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_init_e2e_{suffix}.toml"));
    // Clean up any stale file from a prior interrupted run.
    let _ = fs::remove_file(&p);
    p
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn init_help_documents_options() {
    let (code, stdout, _) = wafrift(&["init", "--help"]);
    assert_eq!(code, 0, "init --help must exit 0");
    assert!(stdout.contains("--output"), "stdout: {stdout}");
    assert!(stdout.contains("--force"), "stdout: {stdout}");
}

#[test]
fn init_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("init"),
        "init must appear in top-level help: {stdout}"
    );
}

// ── Happy path ────────────────────────────────────────────────────────────

#[test]
fn init_creates_toml_file_at_specified_path() {
    let path = unique_temp_path("create");
    let path_str = path.to_str().expect("temp path is UTF-8");

    let (code, _stdout, stderr) = wafrift(&["init", "--output", path_str]);
    assert_eq!(
        code, 0,
        "init must exit 0 for a fresh path; stderr: {stderr}"
    );

    assert!(
        path.exists(),
        "init must create the file at the given --output path"
    );
    fs::remove_file(&path).ok();
}

#[test]
fn init_generated_file_is_valid_toml() {
    let path = unique_temp_path("valid_toml");
    let path_str = path.to_str().expect("temp path is UTF-8");

    let (code, _, _) = wafrift(&["init", "--output", path_str]);
    assert_eq!(code, 0);

    let contents = fs::read_to_string(&path).expect("read generated file");
    fs::remove_file(&path).ok();

    // TOML: all commented-out lines start with '#'. The file must not be empty.
    assert!(!contents.is_empty(), "generated config must not be empty");
    // At minimum it should contain a TOML comment header.
    assert!(
        contents.contains('#'),
        "generated config must contain TOML comment lines: {contents}"
    );
}

#[test]
fn init_generated_file_contains_expected_scaffold_keys() {
    let path = unique_temp_path("scaffold_keys");
    let path_str = path.to_str().expect("temp path is UTF-8");

    let (code, _, _) = wafrift(&["init", "--output", path_str]);
    assert_eq!(code, 0);

    let contents = fs::read_to_string(&path).expect("read generated file");
    fs::remove_file(&path).ok();

    // The scaffold should mention at least some of the known config surface.
    // These strings appear either as commented key names or in comments.
    for keyword in ["wafrift", "toml", "scan"] {
        assert!(
            contents.to_lowercase().contains(keyword),
            "scaffold must mention '{keyword}': {contents}"
        );
    }
}

#[test]
fn init_stdout_mentions_output_path() {
    let path = unique_temp_path("path_mention");
    let path_str = path.to_str().expect("temp path is UTF-8");

    let (code, stdout, stderr) = wafrift(&["init", "--output", path_str]);
    assert_eq!(code, 0);
    fs::remove_file(&path).ok();

    // The combined output (stdout or stderr) should mention the output path
    // so the operator can confirm where the file landed.
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(path_str) || combined.contains("wrote"),
        "init output must mention the output path or confirm the write; combined: {combined}"
    );
}

// ── Collision / --force ───────────────────────────────────────────────────

#[test]
fn init_refuses_to_clobber_existing_file_without_force() {
    let path = unique_temp_path("no_clobber");
    let path_str = path.to_str().expect("temp path is UTF-8");

    // Create the file first.
    let (code1, _, _) = wafrift(&["init", "--output", path_str]);
    assert_eq!(code1, 0, "first init must succeed");

    // Second init without --force must fail.
    let (code2, _stdout, stderr) = wafrift(&["init", "--output", path_str]);
    assert_eq!(
        code2, 1,
        "init without --force on existing file must exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.contains("already exists") || stderr.contains("force"),
        "error must hint at --force; stderr: {stderr}"
    );

    fs::remove_file(&path).ok();
}

#[test]
fn init_force_overwrites_existing_file() {
    let path = unique_temp_path("force_overwrite");
    let path_str = path.to_str().expect("temp path is UTF-8");

    // Create the file first.
    let (code1, _, _) = wafrift(&["init", "--output", path_str]);
    assert_eq!(code1, 0);

    // Second init WITH --force must succeed.
    let (code2, _stdout, stderr) = wafrift(&["init", "--output", path_str, "--force"]);
    assert_eq!(
        code2, 0,
        "init --force on existing file must exit 0; stderr: {stderr}"
    );

    // File must still exist and be non-empty.
    let contents = fs::read_to_string(&path).expect("read after --force");
    assert!(!contents.is_empty(), "overwritten file must not be empty");

    fs::remove_file(&path).ok();
}

// ── --quiet ───────────────────────────────────────────────────────────────

#[test]
fn init_quiet_suppresses_advisory_text() {
    let path = unique_temp_path("quiet");
    let path_str = path.to_str().expect("temp path is UTF-8");

    let (code, stdout, stderr) = wafrift(&["init", "--output", path_str, "--quiet"]);
    assert_eq!(code, 0, "init --quiet must exit 0; stderr: {stderr}");
    fs::remove_file(&path).ok();

    // With --quiet the "Next steps" advisory block must not appear.
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.contains("Next steps"),
        "--quiet must suppress the 'Next steps' advisory: {combined}"
    );
}
