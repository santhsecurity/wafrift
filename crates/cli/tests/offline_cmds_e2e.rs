//! End-to-end tests for purely-offline wafrift subcommands that didn't yet
//! have dedicated e2e test suites:
//!
//! - `egress-example` — print JSON egress preset snippets
//! - `completion`     — generate shell completions
//! - `report`         — generate markdown/JSON findings report (empty bank)
//! - `seed`           — pre-load gene-bank with techniques (--dry-run only)
//!
//! No HTTP, no mock server, no disk writes to shared paths.
//!
//! Tests verify:
//!  1. Each command appears in top-level help.
//!  2. `--help` exits 0.
//!  3. Core happy-path exits 0 and emits expected content.
//!  4. Invalid inputs exit non-zero with an error.

mod common;
use common::wafrift;

// ─────────────────────────────────────────────────────────────────────────────
// egress-example
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn egress_example_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("egress-example"),
        "egress-example must appear in top-level help: {stdout}"
    );
}

#[test]
fn egress_example_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["egress-example", "--help"]);
    assert_eq!(code, 0, "egress-example --help must exit 0");
}

#[test]
fn egress_example_default_emits_valid_json() {
    let (code, stdout, stderr) = wafrift(&["egress-example"]);
    assert_eq!(code, 0, "egress-example must exit 0; stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("egress-example must emit valid JSON");
    assert!(
        v.is_object(),
        "egress-example output must be a JSON object: {v}"
    );
    assert!(
        v["proxies"].is_array(),
        "egress-example output must have a proxies array: {v}"
    );
    let proxies = v["proxies"].as_array().unwrap();
    assert!(!proxies.is_empty(), "proxies array must not be empty: {v}");
}

#[test]
fn egress_example_tor_preset_contains_socks5_url() {
    let (code, stdout, stderr) = wafrift(&["egress-example", "--preset", "tor"]);
    assert_eq!(
        code, 0,
        "egress-example --preset tor must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let proxies = v["proxies"].as_array().unwrap();
    let has_socks5 = proxies.iter().any(|p| {
        p.as_str()
            .map(|s| s.starts_with("socks5") && s.contains("127.0.0.1"))
            .unwrap_or(false)
    });
    assert!(
        has_socks5,
        "tor preset must include a socks5h://127.0.0.1:... proxy: {v}"
    );
}

#[test]
fn egress_example_unknown_preset_exits_nonzero() {
    let (code, _stdout, _stderr) = wafrift(&["egress-example", "--preset", "this-is-not-a-preset"]);
    assert_ne!(code, 0, "unknown --preset must exit non-zero");
}

// ─────────────────────────────────────────────────────────────────────────────
// completion
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn completion_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("completion"),
        "completion must appear in top-level help: {stdout}"
    );
}

#[test]
fn completion_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["completion", "--help"]);
    assert_eq!(code, 0, "completion --help must exit 0");
}

#[test]
fn completion_bash_emits_shell_script() {
    let (code, stdout, stderr) = wafrift(&["completion", "bash"]);
    assert_eq!(code, 0, "completion bash must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "completion bash must emit content: {stderr}"
    );
    // Bash completions always define a `_wafrift` function.
    assert!(
        stdout.contains("_wafrift") || stdout.contains("wafrift"),
        "bash completion must reference 'wafrift': {stdout}"
    );
}

#[test]
fn completion_zsh_emits_content() {
    let (code, stdout, stderr) = wafrift(&["completion", "zsh"]);
    assert_eq!(code, 0, "completion zsh must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "completion zsh must emit content: {stderr}"
    );
}

#[test]
fn completion_powershell_emits_content() {
    let (code, stdout, stderr) = wafrift(&["completion", "powershell"]);
    assert_eq!(
        code, 0,
        "completion powershell must exit 0; stderr: {stderr}"
    );
    assert!(
        !stdout.trim().is_empty(),
        "completion powershell must emit content: {stderr}"
    );
    // PowerShell completions reference Register-ArgumentCompleter or similar.
    assert!(
        stdout.contains("wafrift") || stdout.contains("Register"),
        "powershell completion must reference wafrift or Register: {stdout}"
    );
}

#[test]
fn completion_fish_emits_content() {
    let (code, stdout, stderr) = wafrift(&["completion", "fish"]);
    assert_eq!(code, 0, "completion fish must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "completion fish must emit content: {stderr}"
    );
}

#[test]
fn completion_unknown_shell_exits_nonzero() {
    let (code, _stdout, _stderr) = wafrift(&["completion", "notashell"]);
    assert_ne!(code, 0, "completion with unknown shell must exit non-zero");
}

// ─────────────────────────────────────────────────────────────────────────────
// report
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn report_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("report"),
        "report must appear in top-level help: {stdout}"
    );
}

#[test]
fn report_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["report", "--help"]);
    assert_eq!(code, 0, "report --help must exit 0");
}

#[test]
fn report_empty_bank_exits_0_and_emits_markdown() {
    // With no proxy gene bank present, report falls back to an empty bank
    // and emits a "No bypasses recorded yet" markdown page.
    let (code, stdout, stderr) = wafrift(&["report"]);
    assert_eq!(
        code, 0,
        "report must exit 0 on empty bank; stderr: {stderr}"
    );
    assert!(
        !stdout.trim().is_empty(),
        "report must emit markdown content: {stderr}"
    );
    // Markdown reports always have a heading.
    assert!(
        stdout.contains("wafrift") || stdout.contains("findings") || stdout.contains("#"),
        "report must emit a markdown heading: {stdout}"
    );
}

#[test]
fn report_json_format_emits_valid_json_with_schema_version() {
    let (code, stdout, stderr) = wafrift(&["report", "--format", "json"]);
    assert_eq!(
        code, 0,
        "report --format json must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("report --format json must emit valid JSON");

    assert!(
        v["schema_version"].is_number(),
        "schema_version must be a number: {v}"
    );
    assert!(
        v["wafrift_version"].is_string(),
        "wafrift_version must be a string: {v}"
    );
    assert!(
        v["total_hosts"].is_number(),
        "total_hosts must be a number: {v}"
    );
    assert!(
        v["hosts_with_bypasses"].is_number(),
        "hosts_with_bypasses must be a number: {v}"
    );
    assert!(v["findings"].is_array(), "findings must be an array: {v}");
}

#[test]
fn report_json_empty_bank_has_zero_findings() {
    let (code, stdout, stderr) = wafrift(&["report", "--format", "json"]);
    assert_eq!(
        code, 0,
        "report --format json must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let findings = v["findings"].as_array().unwrap();
    // With an empty bank, there should be zero findings.
    assert_eq!(
        findings.len(),
        0,
        "empty bank must produce zero findings: {v}"
    );
}

#[test]
fn report_nonexistent_explicit_proxy_bank_exits_nonzero() {
    // When an explicit --proxy-bank path is given but the file doesn't exist,
    // report exits 1 with an actionable error (not a silent empty fallback).
    // This is intentional: the default bank auto-creates; an explicit path
    // that's missing signals operator error.
    let bank_path = {
        let mut p = std::env::temp_dir();
        p.push("wafrift_offline_cmds_e2e_nonexistent_bank.json");
        let _ = std::fs::remove_file(&p);
        p.to_str().unwrap().to_string()
    };
    let (code, _stdout, stderr) = wafrift(&["report", "--proxy-bank", &bank_path]);
    assert_ne!(
        code, 0,
        "report with nonexistent explicit proxy-bank must exit non-zero; stderr: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "report with missing bank path must emit an actionable error message"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// seed
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn seed_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("seed"),
        "seed must appear in top-level help: {stdout}"
    );
}

#[test]
fn seed_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["seed", "--help"]);
    assert_eq!(code, 0, "seed --help must exit 0");
}

#[test]
fn seed_dry_run_waf_exits_0_and_reports_technique() {
    // R56 pass-21 §10 COHERENCE: old camelCase ID "EncodingDoubleUrl" was
    // renamed to path-style "encoding/url/double". Updated to match the
    // canonical technique ID emitted by `wafrift techniques list`.
    let (code, stdout, stderr) = wafrift(&[
        "seed",
        "--technique",
        "encoding/url/double",
        "--waf",
        "cloudflare",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "seed --dry-run must exit 0; stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.to_lowercase().contains("dry run") || combined.to_lowercase().contains("would"),
        "seed --dry-run must mention dry run: combined={combined}"
    );
    assert!(
        combined.contains("encoding/url/double"),
        "seed --dry-run must echo the technique name: combined={combined}"
    );
    assert!(
        combined.to_lowercase().contains("cloudflare"),
        "seed --dry-run must echo the WAF name: combined={combined}"
    );
}

#[test]
fn seed_dry_run_multiple_techniques() {
    // R56 pass-21 §10 COHERENCE: old camelCase IDs updated to path-style.
    // EncodingDoubleUrl → encoding/url/double
    // EncodingUrlUnicode → encoding/unicode/iis-percent (IIS %-encoding)
    let (code, stdout, stderr) = wafrift(&[
        "seed",
        "--technique",
        "encoding/url/double,encoding/unicode/iis-percent",
        "--waf",
        "akamai",
        "--dry-run",
    ]);
    assert_eq!(
        code, 0,
        "seed --dry-run with multiple techniques must exit 0; stderr: {stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("encoding/url/double"),
        "seed --dry-run must mention encoding/url/double: combined={combined}"
    );
}

#[test]
fn seed_missing_waf_and_host_exits_nonzero() {
    // `seed` requires either --waf or --host; neither → exits 1.
    let (code, _stdout, stderr) =
        wafrift(&["seed", "--technique", "encoding/url/double", "--dry-run"]);
    assert_ne!(
        code, 0,
        "seed without --waf or --host must exit non-zero; stderr: {stderr}"
    );
    assert!(
        !stderr.is_empty(),
        "seed without destination must emit an error message"
    );
}

#[test]
fn seed_missing_technique_exits_nonzero() {
    // `--technique` is required — clap rejects the invocation.
    let (code, _stdout, _stderr) = wafrift(&["seed", "--waf", "cloudflare", "--dry-run"]);
    assert_ne!(code, 0, "seed without --technique must exit non-zero");
}
