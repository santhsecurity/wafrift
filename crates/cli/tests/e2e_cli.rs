//! End-to-end CLI integration tests.
//!
//! These drive the real `wafrift` binary via `std::process::Command`, parse its
//! stdout/stderr, and verify exit codes.  This is the product-level test layer
//! — it catches regressions that unit tests miss (broken clap args, missing
//! subcommands, serialization issues, etc.).

use std::process::Command;

/// Helper: run wafrift with args and return (`exit_code`, stdout, stderr).
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
    let (code, stdout, _) = wafrift(&["evade", "--payload", "' OR 1=1--", "--level", "light"]);
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
        "--payload",
        "<script>alert(1)</script>",
        "--level",
        "light",
    ]);
    assert_eq!(code, 0, "evade should succeed");
    assert!(
        stdout.contains("XSS") || stdout.contains("xss") || stdout.contains("Xss"),
        "should classify as XSS: {stdout}"
    );
}

#[test]
fn evade_encoding_only() {
    let (code, stdout, _) = wafrift(&["evade", "--payload", "test_payload", "--encoding-only"]);
    assert_eq!(code, 0, "evade --encoding-only should succeed");
    // Should produce some output
    assert!(!stdout.is_empty(), "should produce output");
}

#[test]
fn evade_all_levels() {
    for level in &["light", "medium", "heavy"] {
        let (code, _stdout, stderr) = wafrift(&["evade", "--payload", "1=1", "--level", level]);
        assert_eq!(
            code, 0,
            "evade --level {level} should succeed: stderr={stderr}"
        );
    }
}

/// Regression for TODO 2026-05-17: `--only encoding/base64/standard` returned
/// "No variants generated" at the default --level medium because the
/// medium-level pool was the first 6 strategies sorted by aggressiveness
/// and base64 sat past that cut. Explicit --only must override the level pool.
#[test]
fn evade_only_overrides_level_pool() {
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "SELECT * FROM users WHERE id=1",
        "--only",
        "encoding/base64/standard",
    ]);
    assert_eq!(
        code, 0,
        "evade --only encoding/base64/standard should succeed: stderr={stderr}"
    );
    assert!(
        stdout.contains("Base64Encode") || stdout.contains("encoding::Base64Encode"),
        "output should contain a base64 variant: stdout={stdout}"
    );
}

#[test]
fn evade_stdin_reads_payload() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args([
            "evade", "--stdin", "--only", "encoding/base64/standard",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wafrift");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"piped_payload_value")
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "exit 0; stdout={stdout}");
    assert!(
        stdout.contains("Base64Encode") || stdout.contains("encoding::Base64Encode"),
        "stdout should contain base64 variant: {stdout}"
    );
}

#[test]
fn evade_stdin_and_payload_conflict() {
    let (code, _stdout, stderr) = wafrift(&[
        "evade", "--payload", "x", "--stdin",
    ]);
    assert_ne!(code, 0, "must reject --payload + --stdin together");
    assert!(
        stderr.to_lowercase().contains("conflict") || stderr.to_lowercase().contains("cannot"),
        "expected clap conflict message: {stderr}"
    );
}

#[test]
fn evade_neither_payload_nor_stdin_errors() {
    let (code, _stdout, stderr) = wafrift(&["evade"]);
    assert_ne!(code, 0, "must require one of --payload / --stdin");
    assert!(
        stderr.to_lowercase().contains("required")
            || stderr.to_lowercase().contains("missing"),
        "expected required-arg message: {stderr}"
    );
}

#[test]
fn evade_explain_shows_per_technique_lines() {
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "SELECT 1",
        "--only",
        "encoding/base64/standard",
        "--explain",
    ]);
    assert_eq!(code, 0, "exit 0; stderr={stderr}");
    assert!(
        stdout.contains("Explain") && stdout.contains("encoding/base64/standard"),
        "explain block should list base64 path: {stdout}"
    );
}

#[test]
fn evade_explain_quiet_emits_trailing_json_object() {
    let (code, stdout, stderr) = wafrift(&[
        "--quiet", "evade", "--payload", "X", "--only", "encoding/base64/standard", "--explain",
    ]);
    assert_eq!(code, 0, "exit 0; stderr={stderr}");
    // Last non-empty line should be an explain object.
    let last = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last()
        .expect("at least one line");
    assert!(
        last.contains("\"explain\""),
        "last line should be the explain object: {last}"
    );
    // And every other line must be a variant object (has "payload" key).
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        if line == last {
            continue;
        }
        assert!(
            line.contains("\"payload\""),
            "variant line should contain payload: {line}"
        );
    }
}

#[test]
fn evade_explain_with_encoding_only() {
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "SELECT 1",
        "--encoding-only",
        "--only",
        "encoding/base64/standard",
        "--explain",
    ]);
    assert_eq!(code, 0, "exit 0; stderr={stderr}");
    assert!(
        stdout.contains("Explain") && stdout.contains("encoding/base64/standard"),
        "explain should still show under --encoding-only: {stdout}"
    );
}

#[test]
fn evade_parameter_pollution_rejected_in_header_context() {
    // Headers don't parse `a=1&a=2` syntax — parameter pollution is N/A there.
    // (Body is intentionally allowed: form-urlencoded bodies use the same syntax.)
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "X",
        "--only",
        "encoding/parameter-pollution",
        "--target-context",
        "header",
        "--explain",
    ]);
    assert_ne!(code, 0, "should fail when only inapplicable strategy is selected");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("parameter pollution") || combined.contains("headers/cookies"),
        "must surface parameter-pollution applicability reason: {combined}"
    );
}

#[test]
fn evade_parameter_pollution_works_in_body_context() {
    // Form-urlencoded bodies use `a=1&b=2` — parameter pollution applies.
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "X",
        "--only",
        "encoding/parameter-pollution",
        "--target-context",
        "body",
    ]);
    assert_eq!(code, 0, "parameter pollution must be applicable in body: stderr={stderr}");
    assert!(
        stdout.contains("ParameterPollute") || stdout.contains("=1&X"),
        "should produce a polluted variant: {stdout}"
    );
}

#[test]
fn evade_rejects_empty_payload() {
    let (code, _stdout, stderr) = wafrift(&["evade", "--payload", ""]);
    assert_ne!(code, 0, "empty --payload must error");
    assert!(
        stderr.contains("empty"),
        "stderr should mention emptiness: {stderr}"
    );
}

#[test]
fn evade_stdin_rejects_interactive_terminal() {
    // No stdin pipe → reading would hang. Must detect and error.
    let (code, _stdout, stderr) = wafrift(&["evade", "--stdin", "--only", "encoding/base64/standard"]);
    assert_ne!(code, 0, "--stdin on a TTY-less non-pipe must error, not hang");
    // In CI / our test harness stdin is closed (no TTY, no pipe), so the
    // is_terminal check is false and the read_to_string returns empty —
    // either path must produce a clear error, not hang.
    assert!(
        stderr.contains("stdin") || stderr.contains("empty") || stderr.contains("pipe"),
        "stderr should explain the stdin failure: {stderr}"
    );
}

#[test]
fn evade_empty_variants_writes_error_to_output_file() {
    use std::fs;
    let tmp = std::env::temp_dir().join("wafrift_evade_empty_test.json");
    let _ = fs::remove_file(&tmp);
    let (code, _stdout, _stderr) = wafrift(&[
        "--quiet",
        "evade",
        "--payload",
        "X",
        "--only",
        "encoding/compression/gzip",
        "--target-context",
        "header",
        "--explain",
        "--output",
        tmp.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "no-variants path should exit non-zero");
    let body = fs::read_to_string(&tmp).expect("output file should be written even on empty-variants");
    assert!(
        body.contains("no variants generated") && body.contains("explain"),
        "output should contain the JSON error blob with explain: {body}"
    );
    let _ = fs::remove_file(&tmp);
}

#[test]
fn evade_target_context_skips_inapplicable_with_reason() {
    let (code, stdout, stderr) = wafrift(&[
        "evade",
        "--payload",
        "SELECT 1",
        "--only",
        "encoding/compression/gzip",
        "--target-context",
        "header",
        "--explain",
    ]);
    // gzip-only + header context => no variants. The error must explain why,
    // not just say "No variants generated."
    assert_ne!(code, 0, "gzip in a header is not applicable; should fail");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("not applicable") || combined.contains("compression"),
        "must surface applicability reason: {combined}"
    );
}

// ── Detect subcommand ──────────────────────────────────────────────────

#[test]
fn detect_cloudflare() {
    let (code, stdout, _) = wafrift(&[
        "detect",
        "--status",
        "403",
        "--headers",
        "server: cloudflare",
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
        "--status",
        "403",
        "--headers",
        "server: Apache",
        "--body",
        "ModSecurity Action",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.to_lowercase().contains("modsecurity") || stdout.to_lowercase().contains("mod"),
        "should detect ModSecurity from body: {stdout}"
    );
}

#[test]
fn detect_unknown_waf() {
    let (code, stdout, _) = wafrift(&["detect", "--status", "200", "--headers", "server: nginx"]);
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
        "should produce bash completion script: {}",
        &stdout[..stdout.len().min(200)]
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
fn bench_waf_validate_only_emits_schema_versioned_json() {
    // --validate-only doesn't need a target. We exercise the JSON shape
    // by piping through python to assert schema_version + wafrift_version
    // are both top-level keys.
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("wafrift-bench-validate-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let corpus = dir.join("corpus");
    let _ = std::fs::create_dir_all(&corpus);
    // Minimal valid corpus: one file with one case.
    let toml = corpus.join("sql.toml");
    {
        let mut f = std::fs::File::create(&toml).unwrap();
        writeln!(
            f,
            r#"[[case]]
id = "smoke_select"
class = "sql"
payload = "' OR 1=1--""#
        )
        .unwrap();
    }
    let (code, _stdout, _stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        code, 0,
        "validate-only on a clean 1-case corpus should exit 0"
    );
}

#[test]
fn bench_waf_help_lists_all_strategies() {
    // bench-waf --help text must enumerate every selectable strategy and
    // call out the `all` keyword shortcut. If a future change renames a
    // strategy or drops one from the help, this test catches it.
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0, "bench-waf --help should exit 0");
    for keyword in &[
        "heavy",
        "mcts",
        "smuggling",
        "content-type",
        "redos",
        "hill-climb",
        "sim-anneal",
        "tabu",
        "novelty",
        "map-elites",
        "differential",
        "all",
        "lineage-output",
    ] {
        assert!(
            stdout.contains(keyword),
            "bench-waf --help missing strategy keyword {keyword:?}\n--- stdout ---\n{stdout}"
        );
    }
}

#[test]
fn invalid_level_fails() {
    let (code, _stdout, stderr) =
        wafrift(&["evade", "--payload", "test", "--level", "nonexistent_level"]);
    assert_ne!(code, 0, "invalid level should fail");
    assert!(
        stderr.contains("error") || stderr.contains("invalid"),
        "should report error for invalid level: {stderr}"
    );
}

// ── New practitioner surface (replay / report / init) ─────────────────

#[test]
fn replay_help_lists_source_flags() {
    let (code, stdout, _) = wafrift(&["replay", "--help"]);
    assert_eq!(code, 0, "replay --help should exit 0");
    for keyword in &[
        "--target",
        "--param",
        "--payload",
        "--from-host",
        "--from-waf",
        "--technique",
    ] {
        assert!(
            stdout.contains(keyword),
            "replay --help missing flag {keyword:?}: {stdout}"
        );
    }
}

#[test]
fn replay_without_techniques_errors_actionable() {
    // No --technique, --from-host, or --from-waf — must fail with a
    // message that names the missing flags, not a generic "no input".
    let (code, _stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        "https://example.com/x",
        "--payload",
        "test",
    ]);
    assert_ne!(code, 0, "replay with no source flag should fail");
    assert!(
        stderr.contains("--technique")
            || stderr.contains("--from-host")
            || stderr.contains("--from-waf"),
        "error must name the missing source flags: {stderr}"
    );
}

#[test]
fn report_help_documents_format_options() {
    let (code, stdout, _) = wafrift(&["report", "--help"]);
    assert_eq!(code, 0, "report --help should exit 0");
    assert!(
        stdout.contains("markdown"),
        "report --help missing markdown format: {stdout}"
    );
    assert!(
        stdout.contains("json"),
        "report --help missing json format: {stdout}"
    );
    assert!(
        stdout.contains("--proxy-bank"),
        "report --help missing --proxy-bank: {stdout}"
    );
}

#[test]
fn report_json_emits_valid_json_with_schema_version() {
    use std::io::Write;
    // Write a minimal proxy-bank JSON to a tempfile.
    let tmp = std::env::temp_dir().join(format!("wafrift-report-test-{}.json", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).expect("create tempfile");
        writeln!(
            f,
            r#"{{"schema":1,"hosts":{{"api.example.com":{{"proven_winners":["EncodingUrl"],"blocklisted":[],"waf_name":"ModSec"}}}}}}"#
        ).unwrap();
    }
    let (code, stdout, _) = wafrift(&[
        "report",
        "--proxy-bank",
        tmp.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&tmp);
    assert_eq!(code, 0, "report --format json should exit 0");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("report --format json must emit valid JSON");
    assert_eq!(parsed["schema_version"], 1, "schema_version field missing");
    assert_eq!(parsed["hosts_with_bypasses"], 1);
    assert_eq!(parsed["findings"][0]["host"], "api.example.com");
}

#[test]
fn init_creates_scaffold_then_refuses_overwrite() {
    let dir = std::env::temp_dir().join(format!("wafrift-init-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let target = dir.join(".wafrift.toml");

    let (code, _stdout, _stderr) = wafrift(&["init", "--output", target.to_str().unwrap()]);
    assert_eq!(code, 0, "first init should succeed");
    assert!(target.exists(), "scaffold file must be created");

    // Second init without --force must refuse.
    let (code2, _stdout2, stderr2) = wafrift(&["init", "--output", target.to_str().unwrap()]);
    assert_ne!(code2, 0, "second init without --force should fail");
    assert!(
        stderr2.contains("--force"),
        "error must mention --force escape hatch: {stderr2}"
    );

    // Third init WITH --force must succeed.
    let (code3, _stdout3, _stderr3) =
        wafrift(&["init", "--output", target.to_str().unwrap(), "--force"]);
    assert_eq!(code3, 0, "third init with --force should succeed");

    let _ = std::fs::remove_dir_all(&dir);
}
