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

// ── harden --format json ──────────────────────────────────────────────────

#[test]
fn harden_json_format_produces_valid_json() {
    let (stdout, _e, _code) = run(&["harden", "--class", "xss", "--format", "json"]);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("harden --format json must emit valid JSON");
    assert!(
        v.get("all_proven").is_some(),
        "JSON must have 'all_proven' key"
    );
    assert!(v.get("classes").is_some(), "JSON must have 'classes' key");
    assert!(v["classes"].is_array(), "'classes' must be a JSON array");
}

#[test]
fn harden_json_added_rules_have_correct_transform_array() {
    let (stdout, _e, _code) = run(&["harden", "--class", "xss", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("must be valid JSON");
    let classes = v["classes"].as_array().expect("classes is array");
    for class in classes {
        let rules = class["added_rules"]
            .as_array()
            .expect("added_rules is array");
        for rule in rules {
            let tf = rule["transforms"]
                .as_array()
                .expect("transforms must be an array");
            assert!(
                !tf.is_empty(),
                "every added rule must have a non-empty transforms array"
            );
            // Double-decode rules have id ending in "-dbl" and must contain
            // "UrlDecodeUni" twice.
            let id = rule["id"].as_str().unwrap_or("");
            if id.ends_with("-dbl") {
                let url_decode_count = tf
                    .iter()
                    .filter(|t| t.as_str() == Some("UrlDecodeUni"))
                    .count();
                assert_eq!(
                    url_decode_count, 2,
                    "double-decode rule {id} must have UrlDecodeUni twice, got: {tf:?}"
                );
            }
        }
    }
}

#[test]
fn harden_human_output_double_decode_toml_has_two_urldecodings() {
    // The pre-fix bug: human TOML output hardcoded a single-decode transform
    // list for ALL rules, even double-decode variants. After the fix, the
    // TOML snippet for a "-dbl" rule must contain UrlDecodeUni twice.
    let (stdout, _e, _code) = run(&["harden", "--class", "xss"]);
    // Find blocks starting with [[rule]] and ending at the next blank line.
    let mut in_dbl_rule = false;
    let mut dbl_rule_transforms = String::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed == "[[rule]]" {
            in_dbl_rule = false;
            dbl_rule_transforms.clear();
        }
        if trimmed.starts_with("id = ") && trimmed.contains("-dbl") {
            in_dbl_rule = true;
        }
        if in_dbl_rule && trimmed.starts_with("transforms = ") {
            dbl_rule_transforms = trimmed.to_string();
        }
    }
    assert!(
        !dbl_rule_transforms.is_empty(),
        "must find at least one -dbl rule in harden xss output"
    );
    let count = dbl_rule_transforms.matches("UrlDecodeUni").count();
    assert_eq!(
        count, 2,
        "double-decode rule TOML must list UrlDecodeUni twice; got: {dbl_rule_transforms}"
    );
}

#[test]
fn harden_help_shows_format_flag() {
    let (stdout, _e, code) = run(&["harden", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--format"),
        "harden --help must document --format flag"
    );
}

#[test]
fn audit_json_format_produces_valid_json() {
    let (stdout, _e, code) = run(&["audit", "--class", "xss", "--format", "json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("audit --format json must emit valid JSON");
    assert!(v.get("total_holes").is_some(), "must have 'total_holes'");
    assert!(v.get("holes").is_some(), "must have 'holes' array");
    assert!(v.get("rules_loaded").is_some(), "must have 'rules_loaded'");
}
