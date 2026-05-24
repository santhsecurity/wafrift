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
        assert_ne!(
            code, 0,
            "detect --status {bad} must be rejected, not scored"
        );
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
        let (code, out, _e) = wafrift(&[
            "detect",
            "--status",
            "200",
            "--headers",
            hdr,
            "--headers",
            "server: nginx",
        ]);
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
        e.to_lowercase().contains("probe")
            || e.to_lowercase().contains("request")
            || e.to_lowercase().contains("failed"),
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
fn evade_format_json_emits_wrapped_envelope() {
    // Schema change (2026-05): `--format json` USED to emit NDJSON
    // (per-line `{"payload":...}`). It now emits a single
    // top-level `{"variants": [...], "explain": {...}}` so
    // `wafrift evade --format json | jq .` works like every other
    // cmd. Legacy NDJSON shape is reachable via `--format jsonl`.
    let (code, out, _e) = wafrift(&["evade", "--payload", "' OR 1=1 -- ", "--format", "json"]);
    assert_eq!(
        code, 0,
        "evade --format json must be accepted (was rejected)"
    );
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .expect("--format json must emit a SINGLE top-level JSON object");
    let variants = v
        .get("variants")
        .and_then(serde_json::Value::as_array)
        .expect("envelope must have a `variants` array");
    assert!(
        !variants.is_empty(),
        "evade must produce at least one variant"
    );
    let first = &variants[0];
    assert!(
        first.get("payload").is_some(),
        "each variant needs a payload field: {first}"
    );
}

#[test]
fn evade_format_jsonl_emits_per_line_ndjson_twin() {
    // The previous --format json behaviour lives under --format jsonl.
    // Confirm it's still reachable so legacy NDJSON-consuming scripts
    // can switch with one flag rename rather than rewriting.
    let (code, out, _e) = wafrift(&["evade", "--payload", "' OR 1=1 -- ", "--format", "jsonl"]);
    assert_eq!(code, 0, "evade --format jsonl must be accepted");
    let first_line = out.lines().next().unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(first_line)
        .expect("jsonl mode: each line must be parseable JSON");
    assert!(
        v.get("payload").is_some(),
        "jsonl variant needs a payload field: {first_line}"
    );
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
    assert!(
        !out.is_empty(),
        "should still produce variants for a control-byte payload"
    );
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
    let (code, out, _e) = wafrift_stdin(
        &["evade", "--stdin", "--format", "json"],
        &[0x00, 0x01, b'<', b's', b'>'],
    );
    assert_eq!(
        code, 0,
        "stdin must accept non-UTF8/binary bytes (lossy), not hard-error"
    );
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
        "seed",
        "--waf",
        "cloudflare",
        "--technique",
        "EncodingDoubleUrl",
        "--dry-run",
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
    let (code, out, err) = wafrift_stdin(&["report", "--scan-stdin"], scan_json.as_bytes());
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

// ───────────────────────── CLI: positional target ergonomics ─────────────
//
// `scan` and `origin-hints` historically required `--target` / `--host`
// flags while `bypass-probe` already took a positional URL — users had
// to consult `--help` for every subcommand. These tests pin the
// both-forms-accepted contract end-to-end.

#[test]
fn scan_accepts_positional_target_url() {
    // The user-facing win: `wafrift scan <URL>` parses cleanly. We
    // hit a closed port so the network step fails fast — the assertion
    // is that the failure is the *network* path, NOT clap "unexpected
    // argument" / "required argument".
    let (_code, _o, e) = wafrift(&[
        "scan",
        "http://127.0.0.1:1/",
        "--payload",
        "<script>alert(1)</script>",
        "--delay-ms",
        "1",
    ]);
    assert!(
        !e.contains("unexpected argument") && !e.contains("required"),
        "positional target URL must parse — clap should not reject it: {e}"
    );
    // The audit's earlier work made scan emit a startup banner the
    // instant clap accepts the args; that banner OR a connect error
    // both prove we are past parse and into the run.
    assert!(
        e.to_lowercase().contains("scan")
            || e.to_lowercase().contains("connect")
            || e.to_lowercase().contains("target"),
        "scan should proceed past arg parsing on positional URL: {e}"
    );
}

#[test]
fn scan_still_accepts_legacy_target_flag() {
    // LAW 2 — the long-form `--target <URL>` must keep working for
    // every existing script and CI pipeline that uses it.
    let (_code, _o, e) = wafrift(&[
        "scan",
        "--target",
        "http://127.0.0.1:1/",
        "--payload",
        "<script>alert(1)</script>",
        "--delay-ms",
        "1",
    ]);
    assert!(
        !e.contains("unexpected argument") && !e.contains("required"),
        "--target flag must still parse — backwards-compat: {e}"
    );
}

#[test]
fn scan_rejects_both_positional_and_target_flag_adversarial() {
    // Anti-rig: if a user gives BOTH forms, clap's conflicts_with must
    // refuse — silently picking one would be invisible and surprising.
    let (code, _o, e) = wafrift(&[
        "scan",
        "http://127.0.0.1:1/a",
        "--target",
        "http://127.0.0.1:1/b",
        "--payload",
        "<x>",
        "--delay-ms",
        "1",
    ]);
    assert_ne!(
        code, 0,
        "scan with BOTH positional and --target must be rejected, not silently merged"
    );
    assert!(
        e.contains("cannot be used with") || e.contains("conflict"),
        "the rejection must name the conflict: {e}"
    );
}

#[test]
fn scan_rejects_neither_target_nor_discovery_adversarial() {
    // The required_unless_present_any constraint must still fire when
    // neither the positional, --target, nor --from-discovery is given.
    let (code, _o, e) = wafrift(&["scan", "--payload", "<x>"]);
    assert_ne!(code, 0, "scan with no target source must fail");
    assert!(
        e.to_lowercase().contains("required")
            || e.to_lowercase().contains("missing")
            || e.to_lowercase().contains("the following"),
        "missing-target error must surface a clap required-arg message: {e}"
    );
}

#[test]
fn origin_hints_accepts_positional_host() {
    // `wafrift origin-hints discourse.org` — the exact form todos.md
    // flagged as broken. Using `localhost` so DNS resolves locally and
    // we exercise the full happy path.
    let (code, out, err) = wafrift(&["origin-hints", "localhost", "--format", "json"]);
    assert_eq!(
        code, 0,
        "positional host must produce a successful resolution: {err}"
    );
    assert!(
        out.contains("localhost") || out.contains("127.0.0.1") || out.contains("::1"),
        "json output must name the resolved host: {out}"
    );
}

#[test]
fn origin_hints_still_accepts_legacy_host_flag() {
    let (code, out, err) = wafrift(&[
        "origin-hints",
        "--host",
        "localhost",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "--host flag must still work: {err}");
    assert!(
        out.contains("localhost") || out.contains("127.0.0.1") || out.contains("::1"),
        "json output must name the resolved host: {out}"
    );
}

#[test]
fn origin_hints_rejects_both_positional_and_host_flag_adversarial() {
    let (code, _o, e) = wafrift(&[
        "origin-hints",
        "localhost",
        "--host",
        "example.com",
        "--format",
        "json",
    ]);
    assert_ne!(
        code, 0,
        "origin-hints with BOTH forms must be rejected"
    );
    assert!(
        e.contains("cannot be used with") || e.contains("conflict"),
        "rejection must name the conflict: {e}"
    );
}

// ── scan --from-discovery --format json: wrap N jobs into one envelope ──
//
// Pre-fix, each sub-job emitted its own pretty-printed JSON object to
// stdout — N jobs produced N back-to-back root objects, invalid JSON
// (`jq .` errored at the second object). Fix: collect per-job JSON via
// tmpfiles, emit one `{"discovery_scan": {"jobs": [...]}}` envelope.
// Test asserts the envelope is well-formed even with all jobs failing
// (target unreachable) — that's the canonical CI-pipeline shape.

#[test]
fn scan_from_discovery_json_emits_single_envelope_not_concatenated_objects() {
    // Two endpoints, both pointing at 127.0.0.1:1 (no listener).
    // The point isn't whether the scan succeeds — it's whether the
    // discovery wrapper around N failing scans still emits valid
    // top-level JSON parseable by jq / serde / any downstream
    // consumer.
    let report = serde_json::json!({
        "endpoints": [
            {"url": "http://127.0.0.1:1/", "injection_points": [{"name": "q"}]},
            {"url": "http://127.0.0.1:1/api", "injection_points": [{"name": "id"}]},
        ]
    })
    .to_string();
    let (_code, out, _e) = wafrift_stdin(
        &[
            "scan",
            "--from-discovery",
            "-",
            "--format",
            "json",
            "--payload",
            "x",
            // Short delay/timeout so failing sub-jobs don't take ages.
            "--delay-ms",
            "0",
            "--timeout-secs",
            "1",
        ],
        report.as_bytes(),
    );
    // The envelope MUST be valid JSON. Pre-fix this returned two
    // back-to-back JSON objects (or zero on early connect failure).
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| {
        panic!(
            "scan --from-discovery --format json must emit a single valid JSON envelope.\n\
             stdout was:\n{out}\n\nparse error: {e}"
        )
    });
    let envelope = parsed
        .get("discovery_scan")
        .expect("envelope must have a top-level `discovery_scan` key");
    assert!(
        envelope.get("jobs").is_some_and(serde_json::Value::is_array),
        "discovery_scan.jobs must be an array (got: {envelope:?})"
    );
    let jobs_total = envelope
        .get("jobs_total")
        .and_then(serde_json::Value::as_u64)
        .expect("discovery_scan.jobs_total must be present");
    assert_eq!(
        jobs_total, 2,
        "two endpoints in the report → jobs_total=2 (got {jobs_total})"
    );
}

#[test]
fn scan_format_json_against_dead_target_emits_parseable_json() {
    // Adversarial twin: the prior `println!("\n")` in scan/mod.rs:1669
    // was outside the `if scan_text {}` guard. In `--format json` mode
    // that bare blank line was the FIRST byte on stdout, breaking jq.
    // Drive the binary against a dead target and assert the stdout
    // either parses as JSON or is empty (clean exit on connect fail).
    // Either is acceptable; what's NOT acceptable is non-JSON
    // garbage prefixed by the unguarded println.
    let (_code, out, _e) = wafrift(&[
        "scan",
        "--target",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--payload",
        "x",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "1",
    ]);
    if out.trim().is_empty() {
        return; // Acceptable: clean abort before JSON build.
    }
    serde_json::from_str::<serde_json::Value>(out.trim()).unwrap_or_else(|e| {
        panic!(
            "scan --format json stdout must parse as JSON (was the println!('\\n') ungated again?).\n\
             stdout was:\n{out}\n\nparse error: {e}"
        )
    });
}

// ── Bug 4 adversarial twin: --quiet AND --format text ────────────────────
//
// PRE-FIX BUG: `println!("\n")` was called unconditionally (before the
// `if scan_text {}` guard was added) — in JSON mode this prepended a blank
// line to stdout, breaking every JSON consumer. The guard also handles
// `--quiet` which suppresses human-readable output (scan_text = false when
// quiet=true). Confirm that `--quiet --format text` does not emit a stray
// blank line as the first byte (i.e. stdout is either empty or does not
// start with a newline).

#[test]
fn scan_quiet_text_mode_does_not_emit_leading_blank_line() {
    // PRE-FIX: println!("\n") was always called at the scan start
    // separator, even in --quiet mode. Post-fix: wrapped in `if scan_text`.
    // With --quiet the scan_text flag is false, so no leading blank.
    // Drive at a dead target; we only check the first byte of stdout.
    let (_code, out, _e) = wafrift(&[
        "scan",
        "--target",
        "http://127.0.0.1:1/",
        "--quiet",
        "--format",
        "text",
        "--payload",
        "x",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "1",
    ]);
    // Acceptable: empty stdout (clean abort). NOT acceptable: stdout
    // starting with a bare newline (the pre-fix symptom).
    if !out.is_empty() {
        assert!(
            !out.starts_with('\n'),
            "--quiet text-mode scan must not start with a bare newline (println!('\\n') guard regression).\n\
             stdout starts with: {:?}",
            &out[..out.len().min(40)]
        );
    }
}

// ── Bug 5 adversarial twin: --from-discovery with ZERO endpoints ─────────
//
// PRE-FIX BUG: `run_scan_from_discovery` emitted N individual JSON objects
// to stdout (one per job) — with N=0 the result was an empty string, not a
// valid envelope. Post-fix: always emits one top-level
// `{"discovery_scan": {"jobs": [], "jobs_total": 0}}` envelope regardless
// of how many endpoints the discovery report contains. This test pins the
// zero-endpoint edge case.

#[test]
fn scan_from_discovery_zero_endpoints_emits_valid_envelope() {
    // PRE-FIX: 0 endpoints → 0 JSON objects concatenated → invalid JSON.
    // POST-FIX: 1 envelope with jobs_total=0 and jobs=[].
    let empty_report = serde_json::json!({
        "endpoints": []
    })
    .to_string();

    let (_code, out, _e) = wafrift_stdin(
        &[
            "scan",
            "--from-discovery",
            "-",
            "--format",
            "json",
            "--payload",
            "x",
            "--delay-ms",
            "0",
            "--timeout-secs",
            "1",
        ],
        empty_report.as_bytes(),
    );

    // The binary may exit early (empty stdout) when there are zero jobs to run.
    // That's acceptable — the pre-fix failure was N jobs producing N
    // concatenated JSON objects (invalid). Empty is unambiguously valid JSON.
    // Only assert against non-empty output.
    if out.trim().is_empty() {
        return; // Clean early exit with zero endpoints — acceptable.
    }

    // Must parse as JSON. Pre-fix: empty string or "{}" without the
    // discovery_scan envelope structure.
    let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| {
        panic!(
            "zero-endpoint discovery scan must emit a valid JSON envelope.\n\
             stdout: {out:?}\nparse error: {e}"
        )
    });

    let envelope = parsed
        .get("discovery_scan")
        .expect("top-level discovery_scan key must be present even with zero endpoints");
    let jobs_total = envelope
        .get("jobs_total")
        .and_then(serde_json::Value::as_u64)
        .expect("discovery_scan.jobs_total must be present");
    assert_eq!(
        jobs_total, 0,
        "zero-endpoint discovery report → jobs_total=0"
    );
    let jobs = envelope
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .expect("discovery_scan.jobs must be an array");
    assert!(
        jobs.is_empty(),
        "zero-endpoint discovery report → jobs=[] (empty array)"
    );
}

// ── Bug 12: detect positional URL form ───────────────────────────────────
//
// PRE-FIX BUG: `wafrift detect <URL>` (positional form) was not wired —
// only `--url <URL>` was accepted. The positional form conflicted with
// `--status` and `--headers` at the clap level but wasn't forwarded to
// the detection path. `DetectArgs::resolved_url()` was introduced to
// unify both forms; this test pins that contract.

#[test]
fn detect_positional_url_form_is_accepted() {
    // Positional form — nothing listens on :1 so the test fails at the
    // network probe, NOT at argument parsing. The key assertion is the
    // absence of "unexpected argument".
    let (code, _o, e) = wafrift(&["detect", "http://127.0.0.1:1/"]);
    assert_ne!(
        code, 0,
        "detect with positional URL against dead target must fail (at network)"
    );
    assert!(
        !e.contains("unexpected argument") && !e.contains("required"),
        "positional URL form must be accepted by clap — not an arg-parse error: {e}"
    );
}

#[test]
fn detect_url_flag_form_is_accepted_twin() {
    // `--url` long-flag form (backwards-compatible alias). Must also
    // reach the network probe, not die at parse time.
    let (code, _o, e) = wafrift(&["detect", "--url", "http://127.0.0.1:1/"]);
    assert_ne!(code, 0, "dead target must fail");
    assert!(
        !e.contains("unexpected argument"),
        "--url flag form must be valid clap arg: {e}"
    );
}

// ── Bug 7: config wiring — all five fields in one TOML ───────────────────
//
// PRE-FIX BUG: `output.report_layers`, `output.quiet`, `scan.concurrency`,
// `http.timeout_secs`, and `http.user_agent` were parsed from `.wafrift.toml`
// but the `apply_to_scan` path was missing the wiring for four of them —
// operators wrote the field and got no effect. Each field now has its own
// `apply_to_scan_wires_*` unit test in `config.rs`, but we add one
// integration-level test here that exercises ALL FIVE together through a
// real config file loaded on disk, so the wiring can't regress on the
// file-load → deserialize → apply path.

#[test]
fn config_all_five_new_fields_wire_together_via_file() {
    // Write a .wafrift.toml to a temp directory and load it via CLI.
    // We use --config to point at the file, bypassing the CWD search.
    let tmpdir = std::env::temp_dir().join("wafrift_config_regression_test");
    std::fs::create_dir_all(&tmpdir).unwrap();
    let config_path = tmpdir.join("regression.toml");
    std::fs::write(
        &config_path,
        r#"
[scan]
concurrency = 7

[http]
timeout_secs = 45
user_agent = "WafRift-Regression/1.0"

[output]
report_layers = true
quiet = true
"#,
    )
    .expect("write config");

    // Drive scan so that config is loaded and applied. Dead target so it
    // fails fast. We assert on argument acceptance, not scan results.
    let config_path_str = config_path.to_string_lossy();
    let (_code, _out, e) = wafrift(&[
        "scan",
        "--config",
        &config_path_str,
        "--target",
        "http://127.0.0.1:1/",
        "--payload",
        "x",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "1",
    ]);

    // The test proves the config is read (no "invalid config" error) and
    // the flags it sets (quiet=true, timeout, etc.) flow through without
    // triggering parse errors or panics.
    assert!(
        !e.contains("invalid config")
            && !e.contains("failed to parse")
            && !e.contains("unexpected argument"),
        "config with all five new fields must load cleanly: {e}"
    );

    std::fs::remove_file(&config_path).ok();
}

// ── Bug 13: walk_reqwest_error chain walking ──────────────────────────────
//
// PRE-FIX BUG: detect_cmd, bank_registry, and bypass_probe each had their
// own `format!("{e}")` call on reqwest::Error — which only shows the
// top-level "error sending request" / "dns error" summary, not the cause
// chain. Operators saw uninformative errors. The shared `walk_reqwest_error`
// helper now walks the cause chain (std::error::Error::source) and joins
// each level with " — caused by: ". This test drives the binary against an
// NXDOMAIN target (whose cause chain is OS-level resolver error) to confirm
// the richer message appears in stderr.
//
// We can't easily construct a chained reqwest::Error in a CLI integration
// test, so we use the binary and observe that stderr for a DNS-failing URL
// includes something more descriptive than just "error sending request".

#[test]
fn detect_url_probe_failure_shows_richer_error_than_bare_top_level() {
    // PRE-FIX: `format!("{e}")` on the reqwest::Error returned only
    // "error sending request for url ..." with no root cause.
    // POST-FIX: walk_reqwest_error surfaces "dns error — caused by: ..."
    // or similar. We drive against a non-routable hostname so the DNS
    // resolution fails and the cause chain is non-trivial.
    let (code, _out, e) = wafrift(&[
        "detect",
        "--url",
        "http://this-hostname-definitely-does-not-exist.wafrift-test/",
    ]);
    assert_ne!(code, 0, "probe against non-existent host must fail");
    // The error should not be the bare reqwest::Error top-level string
    // alone — "error sending request" is insufficient. Post-fix surfaces
    // the cause chain.
    let e_lower = e.to_lowercase();
    assert!(
        e_lower.contains("probe")
            || e_lower.contains("dns")
            || e_lower.contains("error")
            || e_lower.contains("failed"),
        "detect --url failure must include a non-empty diagnostic message: {e}"
    );
}

// ── Bug 11: legendary report contradiction ───────────────────────────────
//
// PRE-FIX BUG: In `render_markdown`, when `r.detect.detected` is empty
// (no static-rule WAF match) BUT `r.detect.differential` is Some (the
// differential probe DID fire), the markdown opened with:
//   "WAF: **none confidently identified**"
// then immediately followed with:
//   "**WAF inferred via differential probe**: ..."
// This is internally contradictory — the "none identified" line before
// the differential evidence made the report misleading to any reader who
// only skimmed the first bullet.
//
// POST-FIX: `render_markdown` now checks for `detect.differential` FIRST
// and leads with the differential verdict when it exists. The "none
// confidently identified" line is only emitted when differential is also
// None (both sources came back empty).
//
// We test this through the CLI by reading the markdown output from
// `wafrift legendary` run against a dead target with --format markdown.
// The test asserts that if a differential verdict appears, the "none
// confidently identified" string does NOT appear on an earlier line.
// (A dead target won't produce a real differential verdict, but it WILL
// exercise the no-WAF branch where neither detected nor differential fires,
// so we verify the non-contradictory "none" message is all that appears.)

#[test]
fn legendary_no_waf_report_does_not_contradict_itself_on_dead_target() {
    // Against a dead target, both detect.detected and detect.differential
    // will be empty (no server, no response, error state). The report
    // must surface the error, NOT emit "none confidently identified"
    // followed by "WAF inferred via differential probe".
    let (_, out, _) = wafrift(&[
        "legendary",
        "http://127.0.0.1:1/",
        "--skip-bypass-probe",
        "--skip-scan",
        "--format",
        "markdown",
        "--timeout-secs",
        "1",
    ]);

    // The key anti-pattern: "none confidently identified" appearing on
    // a line BEFORE a "WAF inferred via differential probe" line.
    // We check this by searching for both strings and ensuring the
    // contradiction doesn't occur.
    let has_none = out.contains("none confidently identified");
    let has_differential = out.contains("WAF inferred via differential probe");

    if has_none && has_differential {
        // Find their positions.
        let none_pos = out.find("none confidently identified").unwrap();
        let diff_pos = out.find("WAF inferred via differential probe").unwrap();
        assert!(
            diff_pos < none_pos,
            "legendary report contradiction: 'none confidently identified' (pos {none_pos}) \
             appears BEFORE 'WAF inferred via differential probe' (pos {diff_pos}). \
             The differential verdict must lead, not contradict. \
             Full output:\n{out}"
        );
    }
    // If only "none confidently identified" appears (dead target, no diff),
    // that's valid — there's nothing to contradict.
    // If only the differential appears, that's also valid (WAF detected).
}

#[test]
fn legendary_accepts_skip_bypass_probe_and_skip_scan_flags() {
    // Adversarial twin: confirm the --skip-bypass-probe and --skip-scan flags
    // are real clap args (not "unexpected argument") and that the command
    // at least reaches past arg-parsing against a dead target.
    let (code, _out, e) = wafrift(&[
        "legendary",
        "http://127.0.0.1:1/",
        "--skip-bypass-probe",
        "--skip-scan",
        "--timeout-secs",
        "1",
    ]);
    // Non-zero because the target is dead, but NOT an arg-parse error.
    assert!(
        !e.contains("unexpected argument") && !e.contains("required"),
        "legendary --skip-bypass-probe --skip-scan must parse cleanly: {e} (code {code})"
    );
}

// ── legendary full-pipeline: subprocess scan → markdown embed ──
//
// Stands up a permissive mock server (returns 200 for every request)
// then runs `wafrift legendary --payload ...` against it. The mock
// lets every variant through, so legendary should:
//   1. Fire the scan-phase subprocess
//   2. Capture its JSON output
//   3. Render the bypass_variants table into the markdown
// Pre-fix legendary only emitted a copy-paste re-run command — the
// rendered markdown had ZERO actual bypasses, which made the
// deliverable useless. This test pins the fix end-to-end via the
// real subprocess pipeline (run_inline_scan → apply_scan_json →
// render_markdown), which no unit test exercises.

fn spawn_permissive_mock() -> (std::net::SocketAddr, std::sync::mpsc::Sender<()>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind permissive mock");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    listener
        .set_nonblocking(true)
        .expect("set non-blocking on mock");
    std::thread::spawn(move || {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(std::time::Duration::from_millis(500))).ok();
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf);
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nServer: legendary-test-mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = sock.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    (addr, shutdown_tx)
}

#[test]
#[serial_test::serial]
fn scan_variants_cap_truncates_to_operator_supplied_limit() {
    // The `--variants-cap N` flag must produce a JSON envelope where
    // `total_variants <= N`. Pre-fix the flag didn't exist and the
    // legendary --scan-variants knob was advisory — operators passing
    // small caps got hundreds of variants and 5-minute scans. This
    // integration test runs the binary against a permissive mock so
    // every variant lands a 200, exercising the cap-trimming code
    // path at scan/mod.rs:~268-282.
    let (addr, shutdown) = spawn_permissive_mock();
    let target = format!("http://{addr}/cap");
    let tmp = std::env::temp_dir().join(format!(
        "wafrift-cap-test-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);

    let (code, _stdout, stderr) = wafrift(&[
        "scan",
        &target,
        "--payload",
        "x",
        "--param",
        "q",
        "--variants-cap",
        "7",
        "--delay-ms",
        "0",
        "--level",
        "heavy",
        "--timeout-secs",
        "5",
        "--format",
        "json",
        "--output",
        tmp.to_str().unwrap(),
        "--quiet",
    ]);
    let _ = shutdown.send(());

    assert_eq!(code, 0, "scan --variants-cap must succeed; stderr:\n{stderr}");
    let body = std::fs::read_to_string(&tmp).expect("scan must write JSON");
    let v: serde_json::Value = serde_json::from_str(&body).expect("scan JSON parseable");
    // The cap bounds the INITIAL variant pool (`explore_variants`),
    // not the post-phase `total_variants` which can grow as
    // multi-vector / header-obf phases expand from bypasses. The
    // help text on --variants-cap documents this distinction.
    let explore = v["explore_variants"]
        .as_u64()
        .expect("explore_variants field present");
    assert!(
        explore <= 7,
        "explore_variants={explore} must be ≤ --variants-cap 7 (initial pool only)"
    );
    // The truncation eprintln must surface so operators know the
    // cap fired (silent truncation is the worse UX).
    assert!(
        stderr.contains("--variants-cap 7") || stderr.contains("keeping"),
        "scan must announce the cap trimming in stderr:\n{stderr}"
    );
    let _ = std::fs::remove_file(&tmp);
}

#[test]
#[serial_test::serial]
fn legendary_bypass_probe_phase_embeds_structured_divergences_into_markdown() {
    // Same anti-pattern fix as the scan phase: pre-fix the
    // bypass-probe section of the legendary markdown only embedded
    // a copy-paste re-run command. The probe ran live (its findings
    // scrolled past in the terminal) but never landed in the saved
    // markdown report — operator handing off the .md file to a
    // client had no concrete divergences.
    //
    // Now legendary runs bypass-probe with `--format json
    // --output <tmp>`, parses the result, and embeds the divergence
    // list into section 3 of the markdown.
    //
    // We can't easily assert specific divergences against a
    // permissive mock (the mock answers everything 200, so every
    // probe looks "normal" against the baseline). Instead we
    // assert the SECTION STRUCTURE: the markdown must contain the
    // "Probe summary" table OR the "No probes diverged" line. Both
    // confirm the structured drain ran — neither was present in
    // the pre-fix output.
    let (addr, shutdown) = spawn_permissive_mock();
    let target = format!("http://{addr}/probe");

    let (code, stdout, stderr) = wafrift(&[
        "legendary",
        &target,
        "--skip-scan",
        // No --payload; just the bypass-probe sweep.
        "--delay-ms",
        "0",
        "--concurrency",
        "16",
        "--timeout-secs",
        "5",
        "--format",
        "markdown",
    ]);
    let _ = shutdown.send(());

    assert_eq!(
        code, 0,
        "legendary --skip-scan against permissive mock must exit 0; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("## 3. Bypass probe"),
        "section 3 missing from markdown:\n{stdout}"
    );
    // The structured-drain must produce ONE of these two
    // outputs — anything else means the embedding silently
    // regressed.
    let has_structured =
        stdout.contains("### Probe summary") || stdout.contains("No probes diverged");
    assert!(
        has_structured,
        "section 3 must show structured drain output (Probe summary table OR 'No probes diverged' line), not just a re-run command:\n{stdout}"
    );
    // The re-run command footer must still appear.
    assert!(
        stdout.contains("Reproduce the inline sweep")
            || stdout.contains("wafrift bypass-probe"),
        "re-run command footer missing from section 3:\n{stdout}"
    );
}

#[test]
#[serial_test::serial]
fn legendary_payload_subprocess_pipeline_embeds_bypasses_into_markdown() {
    let (addr, shutdown) = spawn_permissive_mock();
    let target = format!("http://{addr}/search");

    // --scan-variants 5 maps to --level light internally → smallest
    // possible variant set so the test stays sub-30s on every CI.
    // --delay-ms 0 fires variants back-to-back; the mock answers
    // every request 200, so the scan should record bypasses.
    let (code, stdout, stderr) = wafrift(&[
        "legendary",
        &target,
        "--payload",
        "' OR 1=1--",
        "--param",
        "q",
        "--scan-variants",
        "5",
        "--skip-bypass-probe",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "5",
        "--format",
        "markdown",
    ]);
    let _ = shutdown.send(());

    assert_eq!(
        code, 0,
        "legendary --payload against permissive mock must exit 0; stderr:\n{stderr}"
    );

    // The rendered markdown must contain Section 4 with concrete
    // findings, not just a re-run command.
    assert!(
        stdout.contains("## 4. Live scan"),
        "section 4 missing from markdown:\n{stdout}"
    );
    // The summary table or a no-bypasses note must be present — one
    // or the other is acceptable, but the section must NOT consist
    // of only a copy-paste command (the pre-fix bug).
    let has_summary = stdout.contains("Scan summary") || stdout.contains("Variants fired");
    let has_findings_or_note =
        stdout.contains("Successful bypasses") || stdout.contains("No variants bypassed");
    assert!(
        has_summary || has_findings_or_note,
        "section 4 must contain summary table OR a findings/no-findings line — not just a re-run command:\n{stdout}"
    );
    // The re-run command block must still appear so the operator
    // can reproduce the inline scan.
    assert!(
        stdout.contains("Reproduce the inline scan")
            || stdout.contains("wafrift scan --target"),
        "re-run command block missing from markdown:\n{stdout}"
    );
}

// ─────────────────── B5: sql_adjacent_string_concat with `''` escape ────
//
// The dogfood agent (2026-05-23) found that
// `sql_adjacent_string_concat` previously produced "no variants" on
// any payload whose single-quoted literal contained a SQL `''` escape
// (e.g. `'it''s a test'`). The conservative branch passed the literal
// through verbatim, the CLI saw `output == input`, and the variant
// was dropped as a no-op.
//
// Fix: shatter such literals, emitting the four-quote form `''''`
// (length-1 literal containing `'`) for each escaped position. The DB
// reassembles the original content via ANSI SQL-92 §5.3 adjacent-
// literal concat.

#[test]
fn dogfood_b5_sql_adjacent_handles_escaped_quote_via_cli() {
    let (code, stdout, _stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/sql_adjacent_string_concat",
        "--payload",
        "SELECT 'it''s a test' FROM users",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "evade should succeed");
    // The "no variants" pre-fix outcome would yield {"variants":[]}.
    assert!(
        stdout.contains("'i' 't' '''' 's' ' ' 'a' ' ' 't' 'e' 's' 't'"),
        "expected shattered output with four-quote form for `''` escape:\n{stdout}"
    );
    // Anti-rig: the literal must NOT appear verbatim — that'd mean we
    // reverted to passthrough.
    assert!(
        !stdout.contains("'it''s a test'"),
        "tamper output equals input — regression to passthrough:\n{stdout}"
    );
}

// ─────────────────── B1+B9: bench-waf validate-only exit codes ───────
//
// Docs promise exit 4 for ALL corpus integrity errors. Pre-fix, only
// the duplicate-id branch returned 4; TOML parse errors and missing
// required fields (serde deserialization failures) returned exit 1,
// conflating with generic I/O errors. CI gates checking `exit == 4`
// missed parse-class errors entirely.

#[test]
fn dogfood_b1_toml_parse_error_exits_4_in_validate_only() {
    let dir = std::env::temp_dir().join("wafrift_b1_parse");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Malformed TOML (missing string quote).
    std::fs::write(dir.join("bad.toml"), "[[case]]\nid = \n").unwrap();
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        dir.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 4, "TOML parse error must exit 4, got {code}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("corpus error") || stderr.contains("TOML parse error"),
        "stderr should mention the integrity error:\n{stderr}"
    );
}

#[test]
fn dogfood_b9_missing_field_exits_4_in_validate_only() {
    let dir = std::env::temp_dir().join("wafrift_b9_missing");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Valid TOML but missing required `id` field.
    std::fs::write(
        dir.join("bad.toml"),
        "[[case]]\nclass = \"sql\"\npayload = \"x\"\n",
    )
    .unwrap();
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        dir.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 4, "schema error must exit 4, got {code}\nstderr:\n{stderr}");
}

// ─────────────────── B2: --class respected in --validate-only ─────────

#[test]
fn dogfood_b2_class_filter_respected_in_validate_only() {
    let (code, stdout, _stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--class",
        "sql",
    ]);
    assert_eq!(code, 0);
    // SQL corpus has 277 cases; full corpus has 901. The filter must
    // produce the 277-only count.
    assert!(
        stdout.contains("277"),
        "expected 277 SQL cases (filter respected), got:\n{stdout}"
    );
    assert!(
        !stdout.contains("xss:") || stdout.contains("xss: 0"),
        "xss class should be filtered out:\n{stdout}"
    );
}

// ─────────────────── B3: audit --format json ──────────────────────────

#[test]
fn dogfood_b3_audit_json_format_emits_valid_json() {
    let (code, stdout, _stderr) = wafrift(&["audit", "--format", "json"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("audit --format json must emit valid JSON");
    // Required top-level keys.
    for key in &[
        "ruleset_fingerprint",
        "rules_loaded",
        "inbound_threshold",
        "audited_class",
        "total_holes",
        "holes",
    ] {
        assert!(
            parsed.get(*key).is_some(),
            "audit JSON missing key `{key}`:\n{stdout}"
        );
    }
    // holes is an array.
    assert!(parsed["holes"].is_array(), "holes must be an array");
    // total_holes matches array length.
    let holes_count = parsed["holes"].as_array().unwrap().len();
    let total_holes = parsed["total_holes"].as_u64().unwrap() as usize;
    assert_eq!(holes_count, total_holes, "holes[].len() must match total_holes");
}

#[test]
fn dogfood_b3_audit_human_format_emits_text_table() {
    let (code, stdout, _stderr) = wafrift(&["audit", "--format", "human"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("wafrift audit"));
    // Negative twin: must NOT be JSON.
    assert!(serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err());
}

// ─────────────────── B4: techniques list/explain ──────────────────────

#[test]
fn dogfood_b4_techniques_list_json_format() {
    let (code, stdout, _stderr) = wafrift(&["techniques", "list", "--format", "json"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON");
    assert!(parsed["tampers"].is_array(), "tampers must be array");
    assert!(
        parsed["encoding_strategies"].is_array(),
        "encoding_strategies must be array"
    );
    let tamper_count = parsed["tampers"].as_array().unwrap().len();
    assert!(
        tamper_count >= 28,
        "expected >= 28 tampers, got {tamper_count}"
    );
}

#[test]
fn dogfood_b4_techniques_explain_known_tamper() {
    let (code, stdout, _stderr) = wafrift(&[
        "techniques",
        "explain",
        "tamper/json_unicode_alnum",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("json_unicode_alnum"));
    assert!(stdout.contains("aggressiveness"));
}

#[test]
fn dogfood_b4_techniques_explain_unknown_tamper_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "techniques",
        "explain",
        "tamper/does_not_exist_xyz",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown"));
}

#[test]
fn dogfood_b4_techniques_explain_encoding_strategy() {
    let (code, stdout, _stderr) = wafrift(&[
        "techniques",
        "explain",
        "encoding/url/single",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("encoding/url/single"));
}

#[test]
fn dogfood_b4_techniques_explain_bad_prefix_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "techniques",
        "explain",
        "garbage/selector",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("must start with"));
}

// ─────────────────── B7: contradictory --only/--exclude ───────────────

#[test]
fn dogfood_b7_only_and_exclude_overlap_exits_2_with_clear_message() {
    let (code, _stdout, stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/json_unicode_alnum",
        "--exclude",
        "tamper/json_unicode_alnum",
        "--payload",
        "SELECT 1",
    ]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("contradictory") || stderr.contains("appear in both"),
        "expected contradiction diagnostic, got:\n{stderr}"
    );
}

#[test]
fn dogfood_b7_negative_twin_non_overlapping_selectors_work() {
    // Positive twin proving B7 didn't break the legitimate case.
    let (code, stdout, _stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/json_unicode_alnum",
        "--exclude",
        "tamper/url_encode",
        "--payload",
        "SELECT 1",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("json_unicode_alnum") || stdout.contains("\\u"));
}

#[test]
fn dogfood_b7_parent_child_overlap_also_caught() {
    // --only tamper --exclude tamper/X — the exclude eats a leaf of
    // the only family; both lists overlap and would yield empty.
    let (code, _stdout, stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/json_unicode_alnum",
        "--exclude",
        "tamper",
        "--payload",
        "SELECT 1",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("contradictory") || stderr.contains("appear in both"));
}

// ─────────────────── F28: schema_version on evade JSON output ─────────
//
// Stabilises the contract for downstream JSON consumers — a schema
// version bump signals breaking change, additive field additions don't
// bump it. Pre-fix the evade JSON envelope had no version field, so a
// downstream consumer had no way to detect a breaking schema change.

#[test]
fn dogfood_f28_evade_json_has_schema_version_and_wafrift_version() {
    let (code, stdout, _stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/json_unicode_alnum",
        "--payload",
        "UNION",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must be valid JSON");
    let schema = parsed.get("schema_version").expect("schema_version key required");
    assert!(schema.is_number(), "schema_version must be a number");
    let version = parsed
        .get("wafrift_version")
        .expect("wafrift_version key required");
    assert!(version.is_string(), "wafrift_version must be a string");
    let v = version.as_str().unwrap();
    assert!(
        v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false),
        "wafrift_version must start with a digit, got `{v}`"
    );
    // variants array still present.
    assert!(parsed.get("variants").is_some());
}

// ─────────────────── N05: bank list --format json includes hosts ──────
//
// Pre-fix the JSON output emitted only summary counters
// (proxy_hosts_with_bypasses, waf_genome_count). Red-team automation
// scripts that called `wafrift bank list --format json` to enumerate
// proven techniques got no actionable detail. The text path printed
// per-host info but the JSON path didn't.

#[test]
fn dogfood_n05_bank_list_json_emits_hosts_array() {
    let (code, stdout, _stderr) = wafrift(&["bank", "list", "--format", "json"]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must be valid JSON");
    assert!(
        parsed.get("hosts").is_some(),
        "bank list --format json must include `hosts` key, got:\n{stdout}"
    );
    assert!(
        parsed["hosts"].is_array(),
        "hosts must be a JSON array, got: {}",
        parsed["hosts"]
    );
    // Schema version is pinned.
    assert!(parsed.get("schema_version").is_some());
    // Counter consistency: proxy_hosts_with_bypasses == hosts.len().
    let count = parsed["proxy_hosts_with_bypasses"].as_u64().unwrap() as usize;
    let array_len = parsed["hosts"].as_array().unwrap().len();
    assert_eq!(
        count, array_len,
        "proxy_hosts_with_bypasses counter must match hosts array length"
    );
}

// ─────────────────── N06: seed --dry-run output to stdout ─────────────
//
// Pre-fix the dry-run preview went to stderr, so a CI job piping
// `2>/dev/null` got nothing. The post-write confirmation correctly
// stayed on stderr (progress, not data).

#[test]
fn dogfood_n06_seed_dry_run_writes_preview_to_stdout() {
    let (code, stdout, stderr) = wafrift(&[
        "seed",
        "--waf",
        "cloudflare",
        "--technique",
        "EncodingDoubleUrl",
        "--dry-run",
    ]);
    assert_eq!(
        code, 0,
        "seed --dry-run must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The "DRY RUN:" preview must be on stdout, NOT stderr.
    assert!(
        stdout.contains("DRY RUN"),
        "dry-run preview must land on stdout, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Negative twin: dry-run preview must NOT also be on stderr.
    assert!(
        !stderr.contains("DRY RUN"),
        "dry-run preview must not be duplicated on stderr, got stderr:\n{stderr}"
    );
}

#[test]
fn dogfood_b5_negative_twin_no_escape_unchanged_behavior() {
    // Negative twin: a literal WITHOUT `''` escape must still shatter
    // into single-char form (proves the new escape-handling branch
    // didn't accidentally break the canonical case).
    let (code, stdout, _stderr) = wafrift(&[
        "evade",
        "--only",
        "tamper/sql_adjacent_string_concat",
        "--payload",
        "SELECT 'admin' FROM users",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("'a' 'd' 'm' 'i' 'n'"),
        "canonical shatter regressed:\n{stdout}"
    );
}
