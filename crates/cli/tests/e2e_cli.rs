//! End-to-end CLI integration tests.
//!
//! These drive the real `wafrift` binary via `std::process::Command`, parse its
//! stdout/stderr, and verify exit codes.  This is the product-level test layer
//! — it catches regressions that unit tests miss (broken clap args, missing
//! subcommands, serialization issues, etc.).

use std::process::Command;

/// Helper: run wafrift with args and return (exit_code, stdout, stderr).
fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("failed to execute wafrift binary");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// ── Version & help ─────────────────────────────────────────────────────

#[test]
fn help_exits_0() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0, "wafrift --help should exit 0");
    assert!(
        stdout.contains("Usage:"),
        "help output should contain 'Usage:': {stdout}"
    );
}

#[test]
fn version_exits_0() {
    let (code, stdout, _) = wafrift(&["--version"]);
    assert_eq!(code, 0, "wafrift --version should exit 0");
    assert!(
        stdout.contains("wafrift"),
        "version output should mention 'wafrift': {stdout}"
    );
}

#[test]
fn no_args_exits_cleanly() {
    // Running without args enters interactive mode which exits 1 on non-TTY
    let (code, _stdout, _stderr) = wafrift(&[]);
    // Interactive mode exits 0 on TTY, 1 on non-TTY — both are correct
    assert!(
        code == 0 || code == 1,
        "wafrift with no args should exit cleanly, got {code}"
    );
}

// ── Subcommand help ────────────────────────────────────────────────────

#[test]
fn evade_help() {
    let (code, stdout, _) = wafrift(&["evade", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--payload"));
    assert!(stdout.contains("--level"));
}

#[test]
fn detect_help() {
    let (code, stdout, _) = wafrift(&["detect", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--status"));
    assert!(stdout.contains("--headers"));
}

#[test]
fn scan_help() {
    let (code, stdout, _) = wafrift(&["scan", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--payload"));
    assert!(stdout.contains("--target"));
}

#[test]
fn probe_help() {
    let (code, _stdout, _) = wafrift(&["probe", "--help"]);
    assert_eq!(code, 0);
}

#[test]
fn completion_help() {
    let (code, stdout, _) = wafrift(&["completion", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("bash") || stdout.contains("zsh") || stdout.contains("fish"));
}

// ── Evade subcommand ───────────────────────────────────────────────────

#[test]
fn evade_sql_injection() {
    let (code, stdout, _) = wafrift(&[
        "evade",
        "--payload", "' OR 1=1--",
        "--level", "light",
    ]);
    assert_eq!(code, 0, "evade should succeed");
    assert!(
        stdout.contains("SQL") || stdout.contains("sql"),
        "should classify as SQL injection: {stdout}"
    );
}

#[test]
fn evade_xss() {
    let (code, stdout, _) = wafrift(&[
        "evade",
        "--payload", "<script>alert(1)</script>",
        "--level", "light",
    ]);
    assert_eq!(code, 0, "evade should succeed");
    assert!(
        stdout.contains("XSS") || stdout.contains("xss") || stdout.contains("Xss"),
        "should classify as XSS: {stdout}"
    );
}

#[test]
fn evade_encoding_only() {
    let (code, stdout, _) = wafrift(&[
        "evade",
        "--payload", "test_payload",
        "--encoding-only",
    ]);
    assert_eq!(code, 0, "evade --encoding-only should succeed");
    // Should produce some output
    assert!(!stdout.is_empty(), "should produce output");
}

#[test]
fn evade_all_levels() {
    for level in &["light", "medium", "heavy"] {
        let (code, _stdout, stderr) = wafrift(&[
            "evade",
            "--payload", "1=1",
            "--level", level,
        ]);
        assert_eq!(code, 0, "evade --level {level} should succeed: stderr={stderr}");
    }
}

// ── Detect subcommand ──────────────────────────────────────────────────

#[test]
fn detect_cloudflare() {
    let (code, stdout, _) = wafrift(&[
        "detect",
        "--status", "403",
        "--headers", "server: cloudflare",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.to_lowercase().contains("cloudflare"),
        "should detect Cloudflare: {stdout}"
    );
}

#[test]
fn detect_modsecurity() {
    let (code, stdout, _) = wafrift(&[
        "detect",
        "--status", "403",
        "--headers", "server: Apache",
        "--body", "ModSecurity Action",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.to_lowercase().contains("modsecurity") || stdout.to_lowercase().contains("mod"),
        "should detect ModSecurity from body: {stdout}"
    );
}

#[test]
fn detect_unknown_waf() {
    let (code, stdout, _) = wafrift(&[
        "detect",
        "--status", "200",
        "--headers", "server: nginx",
    ]);
    assert_eq!(code, 0);
    // Should handle gracefully even with no WAF detected
    // Output can be "No WAF detected" or empty — just shouldn't crash
    let _ = stdout;
}

// ── Scan subcommand validation ─────────────────────────────────────────

#[test]
fn scan_missing_required_args() {
    // scan requires --target and --payload
    let (code, _stdout, stderr) = wafrift(&["scan"]);
    assert_ne!(code, 0, "scan without args should fail");
    assert!(
        stderr.contains("required") || stderr.contains("error"),
        "should mention missing required arg: {stderr}"
    );
}

// ── Shell completion generation ────────────────────────────────────────

#[test]
fn completion_bash() {
    let (code, stdout, _) = wafrift(&["completion", "bash"]);
    assert_eq!(code, 0, "bash completion should succeed");
    assert!(
        stdout.contains("complete") || stdout.contains("wafrift") || stdout.contains("_wafrift"),
        "should produce bash completion script: {}", &stdout[..stdout.len().min(200)]
    );
}

#[test]
fn completion_zsh() {
    let (code, stdout, _) = wafrift(&["completion", "zsh"]);
    assert_eq!(code, 0, "zsh completion should succeed");
    assert!(!stdout.is_empty(), "should produce zsh completion script");
}

// ── Error handling ─────────────────────────────────────────────────────

#[test]
fn unknown_subcommand_fails() {
    let (code, _stdout, stderr) = wafrift(&["nonexistent"]);
    assert_ne!(code, 0, "unknown subcommand should fail");
    assert!(
        stderr.contains("error") || stderr.contains("unrecognized"),
        "should report error for unknown subcommand: {stderr}"
    );
}

#[test]
fn invalid_level_fails() {
    let (code, _stdout, stderr) = wafrift(&[
        "evade",
        "--payload", "test",
        "--level", "nonexistent_level",
    ]);
    assert_ne!(code, 0, "invalid level should fail");
    assert!(
        stderr.contains("error") || stderr.contains("invalid"),
        "should report error for invalid level: {stderr}"
    );
}
