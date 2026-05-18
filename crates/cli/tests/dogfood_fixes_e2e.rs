//! End-to-end proving + adversarial tests for the dogfooding-found
//! defects. Every test drives the real `wafrift` binary and asserts the
//! exact behaviour the fix promises, with a negative twin so the
//! assertion can't pass on a stub. Network-touching cases point at
//! `127.0.0.1:1` (nothing listens) so they fail *fast and locally* with
//! a connection error — which still proves the argument plumbing is
//! correct (the bug was "rejected at parse time", not "couldn't
//! connect").

use std::io::Write;
use std::process::{Command, Stdio};

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn wafrift_stdin(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wafrift");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait wafrift");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ───────────────────────── detect: status range ─────────────────────────

#[test]
fn detect_rejects_out_of_range_status() {
    // Numeric-but-out-of-range: must give the helpful 100–599 message
    // (these reach our value-parser).
    for bad in ["999", "0", "99", "1000", "notanum"] {
        let (code, _o, e) = wafrift(&["detect", "--status", bad, "--headers", "server: nginx"]);
        assert_ne!(code, 0, "detect --status {bad} must be rejected, not scored");
        assert!(
            e.contains("100") && (e.to_lowercase().contains("range") || e.contains("not a number")),
            "status {bad}: error should explain the 100-599 rule, got: {e}"
        );
    }
    // Flag-shaped value `-1` is rejected earlier by clap itself; the
    // contract is only "invalid status never silently scored".
    let (code, _o, _e) = wafrift(&["detect", "--status", "-1", "--headers", "server: nginx"]);
    assert_ne!(code, 0, "detect --status -1 must be rejected");
}

#[test]
fn detect_accepts_valid_status_twin() {
    let (code, out, _e) = wafrift(&["detect", "--status", "403", "--headers", "server: nginx"]);
    assert_eq!(code, 0, "a valid status must still work");
    assert!(
        out.to_lowercase().contains("waf") || out.to_lowercase().contains("detect"),
        "valid detect should produce a verdict: {out}"
    );
}

// ───────────────────────── detect: CloudFront edge headers ───────────────

#[test]
fn detect_finds_cloudfront_via_edge_headers() {
    // The exact discourse.org shape that previously reported "No WAF".
    let (code, out, _e) = wafrift(&[
        "detect",
        "--status",
        "200",
        "--headers",
        "via: 1.1 b7f67574068333a51eb10f999105d790.cloudfront.net (CloudFront)",
        "--headers",
        "x-cache: Hit from cloudfront",
        "--headers",
        "x-amz-cf-pop: IAD89-P3",
        "--headers",
        "x-amz-cf-id: abcdefghijklmnopqrstuvwxyz",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.to_lowercase().contains("cloudfront"),
        "CloudFront edge headers must be detected, got: {out}"
    );
}

#[test]
fn detect_cloudfront_each_marker_independently() {
    // Each strong marker on its own must be enough (weights ≥ 0.5 > 0.3).
    for hdr in [
        "via: 1.1 x.cloudfront.net (CloudFront)",
        "x-amz-cf-id: opaqueid",
        "x-amz-cf-pop: SFO5-C1",
    ] {
        let (code, out, _e) =
            wafrift(&["detect", "--status", "200", "--headers", hdr, "--headers", "server: nginx"]);
        assert_eq!(code, 0);
        assert!(
            out.to_lowercase().contains("cloudfront"),
            "marker {hdr:?} alone should detect CloudFront, got: {out}"
        );
    }
}

#[test]
fn detect_no_waf_still_reports_infrastructure_twin() {
    // meta.discourse.org shape: plain nginx, no WAF, no CDN markers.
    // Must NOT falsely claim CloudFront, but MUST surface the server.
    let (code, out, _e) = wafrift(&[
        "detect",
        "--status",
        "200",
        "--headers",
        "server: nginx",
        "--headers",
        "x-frame-options: SAMEORIGIN",
    ]);
    assert_eq!(code, 0);
    assert!(
        !out.to_lowercase().contains("cloudfront"),
        "must not hallucinate CloudFront on a plain nginx host: {out}"
    );
    assert!(
        out.to_lowercase().contains("nginx") || out.to_lowercase().contains("no waf"),
        "should still surface the origin server / an honest no-WAF verdict: {out}"
    );
}

// ───────────────────────── detect --url plumbing ─────────────────────────

#[test]
fn detect_url_flag_is_accepted_and_probes() {
    // Nothing listens on :1 → must fail with a *probe/connection* error,
    // proving --url is wired (the bug was "unexpected argument '--url'").
    let (code, _o, e) = wafrift(&["detect", "--url", "http://127.0.0.1:1"]);
    assert_ne!(code, 0);
    assert!(
        !e.contains("unexpected argument"),
        "--url must be a real flag, not an arg-parse error: {e}"
    );
    assert!(
        e.to_lowercase().contains("probe") || e.to_lowercase().contains("request") || e.to_lowercase().contains("failed"),
        "should fail at the network probe, not parsing: {e}"
    );
}

#[test]
fn detect_url_conflicts_with_manual_status_headers() {
    let (code, _o, e) = wafrift(&[
        "detect",
        "--url",
        "http://127.0.0.1:1",
        "--status",
        "403",
        "--headers",
        "server: x",
    ]);
    assert_ne!(code, 0);
    assert!(
        e.contains("cannot be used with") || e.contains("conflict"),
        "--url and --status/--headers must be mutually exclusive: {e}"
    );
}

// ───────────────────────── evade: --format / b64 / NUL ───────────────────

#[test]
fn evade_format_json_emits_ndjson() {
    let (code, out, _e) = wafrift(&["evade", "--payload", "' OR 1=1 -- ", "--format", "json"]);
    assert_eq!(code, 0, "evade --format json must be accepted (was rejected)");
    let first = out.lines().next().unwrap_or("");
    let v: serde_json::Value =
        serde_json::from_str(first).expect("--format json must emit parseable JSON per line");
    assert!(v.get("payload").is_some(), "json variant needs a payload field: {first}");
}

#[test]
fn evade_text_mode_is_not_json_twin() {
    let (code, out, _e) = wafrift(&["evade", "--payload", "abc", "--format", "text"]);
    assert_eq!(code, 0);
    assert!(
        serde_json::from_str::<serde_json::Value>(out.lines().next().unwrap_or("x")).is_err(),
        "text mode must not emit JSON: {out}"
    );
}

#[test]
fn evade_payload_b64_carries_binary_safely() {
    // base64 of bytes 0x00 0x01 'A' — impossible to pass via argv.
    let (code, out, _e) = wafrift(&["evade", "--payload-b64", "AAFB", "--format", "json"]);
    assert_eq!(code, 0, "--payload-b64 must decode and run");
    assert!(!out.is_empty(), "should still produce variants for a control-byte payload");
}

#[test]
fn evade_empty_payload_explains_nul_truncation() {
    // The dogfood case: `$'\x00..'` arrives as "" after argv truncation.
    let (code, _o, e) = wafrift(&["evade", "--payload", ""]);
    assert_ne!(code, 0);
    assert!(
        e.contains("NUL") && (e.contains("--stdin") || e.contains("--payload-b64")),
        "empty-payload error must explain NUL truncation + the binary-safe path: {e}"
    );
}

#[test]
fn evade_stdin_is_binary_safe() {
    let (code, out, _e) = wafrift_stdin(&["evade", "--stdin", "--format", "json"], &[0x00, 0x01, b'<', b's', b'>']);
    assert_eq!(code, 0, "stdin must accept non-UTF8/binary bytes (lossy), not hard-error");
    assert!(!out.is_empty());
}

#[test]
fn evade_requires_a_payload_source() {
    let (code, _o, e) = wafrift(&["evade"]);
    assert_ne!(code, 0);
    assert!(
        e.contains("payload") || e.contains("stdin") || e.contains("required"),
        "missing payload source must be a clear error: {e}"
    );
}

// ───────────────────────── seed: --technique required ────────────────────

#[test]
fn seed_technique_is_required_and_marked() {
    let (code, _o, e) = wafrift(&["seed", "--waf", "cloudflare", "--dry-run"]);
    assert_ne!(code, 0, "seed without --technique must fail");
    assert!(
        e.to_lowercase().contains("technique") && e.to_lowercase().contains("requir"),
        "clap must enforce --technique as required: {e}"
    );
    let (hc, help, _e) = wafrift(&["seed", "--help"]);
    assert_eq!(hc, 0);
    assert!(
        help.contains("--technique"),
        "help must document --technique: {help}"
    );
}

#[test]
fn seed_with_technique_dry_run_twin() {
    let (code, out, err) = wafrift(&[
        "seed", "--waf", "cloudflare", "--technique", "EncodingDoubleUrl", "--dry-run",
    ]);
    assert_eq!(code, 0, "valid seed --dry-run should succeed: {err}");
    assert!(
        format!("{out}{err}").to_uppercase().contains("DRY RUN"),
        "dry-run should announce itself: {out} / {err}"
    );
}

// ───────────────────────── import-curl ───────────────────────────────────

#[test]
fn import_curl_takes_positional_and_no_payload_runs_detection() {
    let (code, _o, e) = wafrift(&["import-curl", "curl -s http://127.0.0.1:1/login"]);
    // No payload → detection path; connection fails fast, but the point
    // is it parsed the positional curl and did NOT demand --param/--payload.
    assert!(
        !e.contains("required") && !e.contains("unexpected argument"),
        "positional curl + no payload must NOT be an arg error: {e}"
    );
    assert!(
        e.to_lowercase().contains("detection")
            || e.to_lowercase().contains("parsed")
            || e.to_lowercase().contains("probe")
            || e.to_lowercase().contains("request"),
        "should attempt the parsed-target detection path: {e} (code {code})"
    );
}

#[test]
fn import_curl_rejects_non_curl_adversarial() {
    let (code, _o, e) = wafrift(&["import-curl", "wget http://x/"]);
    assert_ne!(code, 0);
    assert!(
        e.contains("curl"),
        "a non-curl invocation must be rejected with a clear message: {e}"
    );
}

// ───────────────────────── bench-waf corpus resolution ───────────────────

#[test]
fn bench_waf_explicit_missing_corpus_errors_not_silently_substituted() {
    // An explicit --corpus that doesn't exist must FAIL with a clear
    // message naming the path — never silently fall back to some other
    // corpus discovered via exe-relative walking (that would benchmark
    // a corpus the operator never chose).
    let (code, out, e) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        "/definitely/not/here/corpus",
    ]);
    assert_ne!(code, 0, "explicit missing --corpus must not exit 0: {out}");
    assert!(
        e.contains("/definitely/not/here/corpus") && e.to_lowercase().contains("does not exist"),
        "error must name the missing explicit path, not silently substitute: {e}"
    );
}

// ───────────────────────── report ← scan JSON ────────────────────────────

#[test]
fn report_ingests_scan_json_via_stdin() {
    let scan_json = r#"{
        "scan_schema_version": 1,
        "target": "https://api.example.com/search",
        "waf": "Cloudflare",
        "bypassed": 2,
        "bypass_variants": [
            {"variant": 1, "payload": "x", "techniques": ["encoding::DoubleUrlEncode"], "confidence": 0.9},
            {"variant": 2, "payload": "y", "techniques": ["grammar::tautology"], "confidence": 0.8}
        ]
    }"#;
    let (code, out, err) =
        wafrift_stdin(&["report", "--scan-stdin"], scan_json.as_bytes());
    assert_eq!(code, 0, "report --scan-stdin must succeed: {err}");
    assert!(
        out.contains("api.example.com"),
        "report must include the scanned host: {out}"
    );
    assert!(
        out.contains("DoubleUrlEncode") || out.contains("tautology"),
        "report must surface the proven techniques from scan JSON: {out}"
    );
    assert!(
        !out.contains("No bypasses recorded yet") && !err.contains("gene bank not found"),
        "scan → report must compose without the proxy gene bank: {out} / {err}"
    );
}

#[test]
fn report_rejects_non_scan_json_adversarial() {
    let (code, _o, e) = wafrift_stdin(&["report", "--scan-stdin"], b"{\"unrelated\": true}");
    assert_ne!(code, 0);
    assert!(
        e.to_lowercase().contains("target") || e.to_lowercase().contains("scan json"),
        "a non-scan JSON blob must produce a clear error: {e}"
    );
}
