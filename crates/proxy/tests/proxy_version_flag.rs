//! Regression test: `wafrift-proxy --version` must print the build
//! version. Pre-fix at v0.2.12 the proxy lacked `version` in its
//! clap derive and errored with `unexpected argument '--version'
//! found`. This test locks the contract.

use std::process::Command;

#[test]
fn wafrift_proxy_version_flag_prints_version() {
    let bin = env!("CARGO_BIN_EXE_wafrift-proxy");
    let output = Command::new(bin)
        .arg("--version")
        .output()
        .expect("invoke wafrift-proxy --version");
    assert!(
        output.status.success(),
        "wafrift-proxy --version exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("wafrift-proxy "),
        "version output must start with binary name: got {stdout:?}"
    );
    // MAJOR.MINOR.PATCH check, all digits.
    let version = stdout.trim().strip_prefix("wafrift-proxy ").unwrap_or("");
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
