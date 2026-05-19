//! End-to-end CLI contract for `wafrift audit` / `wafrift harden`,
//! driven through the REAL built binary (CLAUDE.md test-type #10):
//! parse stdout, assert exit code, assert the product claims.

use std::process::Command;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("binary runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn audit_reports_real_holes_zero_config() {
    // No flags, no network, no files: must work out of the box.
    let (stdout, _e, code) = run(&["audit"]);
    assert_eq!(code, 0, "audit must succeed zero-config");
    assert!(stdout.contains("WAF decompilation report"));
    assert!(stdout.contains("ruleset fingerprint :"));
    // The shipped CRS core is brittle against decode-mismatch + case
    // delivery, so the X-ray must surface concrete holes (not a
    // vacuous clean bill).
    assert!(stdout.contains("HOLE ["), "audit must find real holes");
    assert!(
        stdout.contains("hole(s) found."),
        "audit must report a hole count"
    );
}

#[test]
fn audit_class_filter_scopes_the_report() {
    let (stdout, _e, code) = run(&["audit", "--class", "sqli"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("class: sqli"));
    assert!(
        !stdout.contains("== class: xss =="),
        "--class sqli must not audit xss"
    );
}

#[test]
fn harden_reduces_holes_and_is_honest_about_residuals() {
    let (stdout, stderr, code) = run(&["harden", "--class", "xss"]);
    assert!(stdout.contains("synthesized closing rules"));
    assert!(
        stdout.contains("[[rule]]"),
        "must emit deployable CRS rules"
    );
    // The closure ledger must be present and parseable.
    let before: usize = grab(&stdout, "holes before : ");
    let after: usize = grab(&stdout, "holes after  : ");
    assert!(before > 0, "shipped CRS has decode-mismatch xss holes");
    assert!(
        after < before,
        "the synthesized single+double-decode rules MUST reduce holes ({before} -> {after})"
    );
    // Exit code is a truthful CI gate, consistent with the ledger.
    if after == 0 {
        assert_eq!(code, 0);
        assert!(stdout.contains("closure      : PROVEN"));
    } else {
        assert_eq!(code, 1, "residual holes ⇒ non-zero gate");
        assert!(stderr.contains("closure NOT proven"));
        // Residuals are disclosed structurally, never hidden.
        assert!(
            stdout.contains("residual     :") && stdout.contains("REQUEST_BODY_PROCESSOR=JSON"),
            "the JSON-unescape residual must be honestly attributed, not silently dropped"
        );
    }
}

fn grab(s: &str, key: &str) -> usize {
    s.lines()
        .find_map(|l| l.trim().strip_prefix(key))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("ledger line {key:?} not found in:\n{s}"))
}

#[test]
fn audit_help_is_discoverable() {
    let (stdout, _e, code) = run(&["audit", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--ruleset"));
    assert!(stdout.contains("--class"));
}
