//! Regression test: every wafrift binary must respond to `--version`.
//!
//! Pre-fix at v0.2.12: `wafrift-proxy --version` errored with
//! `unexpected argument '--version' found`. Pentesters routinely
//! check `--version` to verify which build they're running for
//! their report — a missing `--version` flag fails the first
//! `tool --version` smoke test that any audit checklist runs.

use std::process::Command;

#[test]
fn wafrift_version_flag_prints_version() {
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .arg("--version")
        .output()
        .expect("invoke wafrift --version");
    assert!(
        output.status.success(),
        "wafrift --version exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("wafrift "),
        "version output must start with binary name: got {stdout:?}"
    );
    // The version part must be a parseable semver-ish triple
    // matching the workspace `version` (and the published crate).
    let version = stdout.trim().strip_prefix("wafrift ").unwrap_or("");
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "expected MAJOR.MINOR.PATCH version, got {version:?}"
    );
    for p in &parts {
        assert!(
            p.chars().all(|c| c.is_ascii_digit()),
            "version part {p:?} must be all digits"
        );
    }
}
