//! End-to-end tests for `wafrift bank`.
//!
//! Tests the pure-offline subcommands: `list`, `gen-key`, `export`.
//! Network subcommands (`pull`, `submit`) are not tested here.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. bank appears in top-level help.
//! 3. `bank list` exits 0 (even with an empty local bank).
//! 4. `bank gen-key` exits 0 and emits a public key hex string.
//! 5. `bank gen-key` produces a different key on each invocation.
//! 6. `bank export` exits 0 and emits a JSON envelope.
//! 7. `bank list --help` exits 0.
//! 8. `bank gen-key --help` exits 0.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn bank_help_documents_subcommands() {
    let (code, stdout, _) = wafrift(&["bank", "--help"]);
    assert_eq!(code, 0, "bank --help must exit 0");
    assert!(stdout.contains("list"), "stdout: {stdout}");
    assert!(stdout.contains("export"), "stdout: {stdout}");
    assert!(stdout.contains("import"), "stdout: {stdout}");
    assert!(stdout.contains("gen-key"), "stdout: {stdout}");
}

#[test]
fn bank_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("bank"),
        "bank must appear in top-level help: {stdout}"
    );
}

#[test]
fn bank_list_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["bank", "list", "--help"]);
    assert_eq!(code, 0, "bank list --help must exit 0");
}

#[test]
fn bank_gen_key_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["bank", "gen-key", "--help"]);
    assert_eq!(code, 0, "bank gen-key --help must exit 0");
}

// ── `bank list` ───────────────────────────────────────────────────────────

#[test]
fn bank_list_exits_0() {
    let (code, _stdout, stderr) = wafrift(&["bank", "list"]);
    assert_eq!(code, 0, "bank list must exit 0; stderr: {stderr}");
}

#[test]
fn bank_list_produces_non_empty_output() {
    let (code, stdout, stderr) = wafrift(&["bank", "list"]);
    assert_eq!(code, 0, "bank list must exit 0; stderr: {stderr}");
    // Even with an empty gene bank, the output must describe the bank state.
    assert!(
        !stdout.trim().is_empty(),
        "bank list must produce output: {stderr}"
    );
}

// ── `bank gen-key` ────────────────────────────────────────────────────────

/// Return a temp path that does NOT exist yet.
fn unique_temp_key_path(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_bank_e2e_key_{suffix}.hex"));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn bank_gen_key_emits_public_key_hex() {
    let key_path = unique_temp_key_path("emit");
    let key_str = key_path.to_str().expect("path is UTF-8");

    let (code, stdout, stderr) = wafrift(&["bank", "gen-key", "--output", key_str]);
    let _ = std::fs::remove_file(&key_path);
    assert_eq!(code, 0, "bank gen-key must exit 0; stderr: {stderr}");

    // Output contains a public_key_hex = <64 hex chars> line.
    assert!(
        stdout.contains("public_key_hex"),
        "bank gen-key must emit public_key_hex: {stdout}"
    );

    // Extract the hex value and verify it's a valid 64-char hex string.
    let hex_line = stdout
        .lines()
        .find(|l| l.contains("public_key_hex"))
        .unwrap_or("");
    let hex_val = hex_line.split('=').nth(1).unwrap_or("").trim();
    assert_eq!(
        hex_val.len(),
        64,
        "public_key_hex must be 64 hex chars: '{hex_val}'"
    );
    assert!(
        hex_val.chars().all(|c| c.is_ascii_hexdigit()),
        "public_key_hex must be hex digits only: '{hex_val}'"
    );
}

#[test]
fn bank_gen_key_produces_unique_keys() {
    let p1 = unique_temp_key_path("unique1");
    let p2 = unique_temp_key_path("unique2");

    let (_, stdout1, _) = wafrift(&["bank", "gen-key", "--output", p1.to_str().unwrap()]);
    let (_, stdout2, _) = wafrift(&["bank", "gen-key", "--output", p2.to_str().unwrap()]);

    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);

    let key1 = stdout1
        .lines()
        .find(|l| l.contains("public_key_hex"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let key2 = stdout2
        .lines()
        .find(|l| l.contains("public_key_hex"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    assert!(
        !key1.is_empty() && !key2.is_empty(),
        "both gen-key invocations must produce a key"
    );
    assert_ne!(
        key1, key2,
        "two consecutive gen-key invocations must produce different keys"
    );
}

// ── `bank export` ─────────────────────────────────────────────────────────

#[test]
fn bank_export_to_stdout_exits_0_and_emits_json_envelope() {
    // Export to stdout via `--output -` must emit a valid JSON object.
    // The envelope may be empty (no bypasses recorded yet) but must be
    // valid JSON with at least the schema-level structure.
    let (code, stdout, stderr) = wafrift(&["bank", "export", "--output", "-"]);
    assert_eq!(
        code, 0,
        "bank export --output - must exit 0; stderr: {stderr}"
    );

    // The output must be parseable as JSON.
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("bank export must emit valid JSON");
}
