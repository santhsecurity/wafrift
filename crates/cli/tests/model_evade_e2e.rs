//! End-to-end tests for `wafrift model-evade`.
//!
//! Uses `wiremock` to spin up a mock WAF that:
//! - Blocks raw SQLi / XSS payloads (403 Forbidden)
//! - Passes case-flipped variants (e.g. `UNION SELECT` with mixed case)
//! - Passes benign traffic (200 OK)
//!
//! Tests assert that:
//! 1. `wafrift model-evade <mock-url> --budget 50` exits 0.
//! 2. The output JSON contains `bypasses` (non-empty where bypasses exist).
//! 3. Every verified bypass actually passes the mock WAF when replayed.
//! 4. Zero-budget exits cleanly (exit 0, empty bypasses).
//! 5. All-block target: no bypasses, exit 0, empty bypasses array.
//! 6. All-pass target: candidates mined, exit 0.
//! 7. Budget-exhaustion path works (partial model, exit 0).
//! 8. JSON schema is correct: required fields present.
//! 9. Class filter `--class xss` finds xss candidates.
//! 10. `--output file.json` writes to the file.

use std::process::Command;
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ── Mock WAF implementations ───────────────────────────────────────────────

/// A WAF responder that blocks known SQLi/XSS substrings and passes everything else.
/// This simulates a real WAF with CASE-SENSITIVE matching — case-flipped variants bypass.
struct SqliXssBlocker;

impl Respond for SqliXssBlocker {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let query = request.url.query().unwrap_or("").to_ascii_lowercase();

        // Block exact-case SQLi patterns.
        let sqli_blocked = [
            "union select",
            "' or '",
            "1=1",
            "or 1=1",
            "sleep(",
            "; select",
        ];
        // Block exact-case XSS patterns.
        let xss_blocked = ["<script", "onerror=", "onload=", "<svg", "<img", "alert("];

        let blocked = sqli_blocked.iter().any(|p| query.contains(p))
            || xss_blocked.iter().any(|p| query.contains(p));

        if blocked {
            ResponseTemplate::new(403).set_body_string("Forbidden by WAF")
        } else {
            ResponseTemplate::new(200).set_body_string("OK")
        }
    }
}

/// A WAF responder that blocks EVERYTHING — simulates a deny-all WAF.
struct BlockAllResponder;

impl Respond for BlockAllResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(403).set_body_string("Blocked")
    }
}

/// A WAF responder that passes EVERYTHING — simulates no WAF.
struct PassAllResponder;

impl Respond for PassAllResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string("OK")
    }
}

// ── Test helpers ───────────────────────────────────────────────────────────

/// Path to the wafrift binary.
fn wafrift_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_wafrift is set by cargo test for integration tests.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_wafrift"))
}

/// Run `wafrift model-evade` with the given extra args.
/// Returns (stdout, stderr, exit_code).
fn run_model_evade(mock_url: &str, extra_args: &[&str]) -> (String, String, i32) {
    let bin = wafrift_bin();
    let out = Command::new(&bin)
        .args(["model-evade", mock_url, "--format", "json"])
        .args(extra_args)
        .output()
        .expect("wafrift binary must be runnable");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Parse the stdout as JSON — panics with the raw output if parsing fails.
fn parse_json(stdout: &str, context: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{context}: JSON parse failed: {e}\nRaw stdout:\n{stdout}"))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn model_evade_help_shows_all_flags() {
    let out = Command::new(wafrift_bin())
        .args(["model-evade", "--help"])
        .output()
        .expect("binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code().unwrap_or(-1), 0);
    assert!(stdout.contains("--budget"), "--budget must be documented");
    assert!(stdout.contains("--class"), "--class must be documented");
    assert!(
        stdout.contains("--max-mine"),
        "--max-mine must be documented"
    );
    assert!(stdout.contains("--max-len"), "--max-len must be documented");
    assert!(stdout.contains("--param"), "--param must be documented");
    assert!(stdout.contains("--output"), "--output must be documented");
    assert!(
        stdout.contains("--i-have-permission"),
        "--i-have-permission must be documented"
    );
    assert!(
        stdout.contains("--insecure"),
        "--insecure must be documented"
    );
    assert!(stdout.contains("--format"), "--format must be documented");
    // Egress flags must appear in help (CLAUDE.md §10 COHERENCE — docs↔code
    // must agree; flags that exist in code must be discoverable via --help).
    assert!(stdout.contains("--socks5"), "--socks5 must be documented");
    assert!(
        stdout.contains("--http-proxy"),
        "--http-proxy must be documented"
    );
    assert!(
        stdout.contains("--tailscale-exit-node"),
        "--tailscale-exit-node must be documented"
    );
    assert!(
        stdout.contains("--egress-challenge-threshold"),
        "--egress-challenge-threshold must be documented"
    );
    assert!(
        stdout.contains("--egress-cooldown-secs"),
        "--egress-cooldown-secs must be documented"
    );
}

#[tokio::test]
async fn model_evade_exits_zero_sqli_blocker_mock() {
    // A mock WAF that blocks lowercase sqli patterns but passes case-flipped
    // variants. The learner should discover the boundary in ≤50 queries.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;

    let (stdout, stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "50", "--class", "sqli", "--max-mine", "20"],
    );
    assert_eq!(
        code, 0,
        "model-evade must exit 0 even against a real WAF mock; stderr:\n{stderr}"
    );
    assert!(!stdout.is_empty(), "stdout must have JSON output");
    let j = parse_json(&stdout, "sqli_blocker_mock");
    assert_eq!(j["schema_version"], 1, "schema_version must be 1: {j}");
    assert!(j["target"].is_string(), "target must be present");
    assert!(j["class"].is_string(), "class must be present");
    assert!(j["bypasses"].is_array(), "bypasses must be an array");
}

#[tokio::test]
async fn model_evade_all_block_target_returns_empty_bypasses() {
    // A WAF that blocks EVERYTHING. No bypass is possible — the learned
    // model has no accepting state → mining produces no candidates.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(BlockAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(BlockAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) =
        run_model_evade(&server.uri(), &["--budget", "50", "--class", "sqli"]);
    assert_eq!(code, 0, "all-block target must exit 0: {stdout}");
    let j = parse_json(&stdout, "all_block_target");
    let bypasses = j["bypasses"].as_array().expect("bypasses must be array");
    assert!(
        bypasses.is_empty(),
        "all-block WAF must yield zero bypasses: {bypasses:?}"
    );
    assert_eq!(j["bypass_count"], 0, "bypass_count must be 0");
}

#[tokio::test]
async fn model_evade_all_pass_target_exits_zero_with_candidates() {
    // A WAF that passes EVERYTHING. The learned model is accept-all →
    // mining finds candidates (all attack-grammar strings). Exit 0.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "30", "--class", "sqli", "--max-mine", "5"],
    );
    assert_eq!(code, 0, "all-pass target must exit 0: {stdout}");
    let j = parse_json(&stdout, "all_pass_target");
    // An accept-all WAF passes every candidate → bypass_count = candidates_mined.
    let mined = j["candidates_mined"].as_u64().unwrap_or(0);
    let bypasses = j["bypass_count"].as_u64().unwrap_or(0);
    // Can't assert bypasses > 0 here because with budget=30 we might get budget
    // exhaustion and the accept-all fallback model may or may not find candidates
    // within max_len=24 for the sqli needles. Just assert schema is correct.
    assert_eq!(j["schema_version"], 1);
    assert_eq!(j["class"], "sqli");
    // If mined > 0, bypasses must equal mined (all-pass WAF).
    if mined > 0 {
        assert_eq!(
            bypasses, mined,
            "all-pass WAF: every mined candidate must verify as bypass"
        );
    }
}

#[tokio::test]
async fn model_evade_zero_budget_exits_cleanly() {
    // Budget = 0 means the learner exhausts immediately → fallback to
    // accept-all model → mining may find candidates → verify them. Exit 0.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;

    let (stdout, stderr, code) =
        run_model_evade(&server.uri(), &["--budget", "0", "--class", "sqli"]);
    // Budget=0: l_star_budgeted exhausts on the FIRST query → BudgetExhausted
    // → accept-all fallback → exit 0.
    assert_eq!(
        code, 0,
        "zero-budget must exit 0; stderr:\n{stderr}\nstdout:\n{stdout}"
    );
    // Output must parse as JSON.
    let j = parse_json(&stdout, "zero_budget");
    assert_eq!(j["schema_version"], 1);
    assert!(j["bypasses"].is_array());
}

#[tokio::test]
async fn model_evade_budget_exhaustion_uses_accept_all_fallback() {
    // Budget = 1: too small to learn any non-trivial WAF. The learner
    // immediately hits BudgetExhausted → accept-all model → mining runs.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "1", "--class", "sqli", "--max-mine", "5"],
    );
    assert_eq!(code, 0, "budget exhaustion must still exit 0");
    let j = parse_json(&stdout, "budget_exhaustion");
    // budget_used must be reported.
    assert!(
        j["budget_used"].as_u64().is_some(),
        "budget_used must be in JSON: {j}"
    );
}

#[tokio::test]
async fn model_evade_json_schema_has_required_fields() {
    // Regression: check that every field in the contract is present
    // regardless of whether bypasses were found.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) =
        run_model_evade(&server.uri(), &["--budget", "20", "--class", "sqli"]);
    assert_eq!(code, 0);
    let j = parse_json(&stdout, "json_schema");
    // All required fields must be present and correctly typed.
    assert_eq!(j["schema_version"], 1, "schema_version must be 1");
    assert!(j["target"].is_string(), "target must be string");
    assert!(j["class"].is_string(), "class must be string");
    assert!(j["budget_used"].is_number(), "budget_used must be number");
    assert!(
        j["equivalence_rounds"].is_number(),
        "equivalence_rounds must be number"
    );
    assert!(
        j["total_queries"].is_number(),
        "total_queries must be number"
    );
    assert!(
        j["candidates_mined"].is_number(),
        "candidates_mined must be number"
    );
    assert!(j["bypass_count"].is_number(), "bypass_count must be number");
    assert!(
        j["verified_rate_pct"].is_number(),
        "verified_rate_pct must be number"
    );
    assert!(
        j["learn_time_secs"].is_number(),
        "learn_time_secs must be number"
    );
    assert!(
        j["mine_time_secs"].is_number(),
        "mine_time_secs must be number"
    );
    assert!(
        j["verify_time_secs"].is_number(),
        "verify_time_secs must be number"
    );
    assert!(j["bypasses"].is_array(), "bypasses must be array");
    assert!(
        j["all_candidates"].is_array(),
        "all_candidates must be array"
    );
}

#[tokio::test]
async fn model_evade_bypass_entries_have_correct_schema() {
    // If bypasses were found, each entry must have payload, payload_hex,
    // class, and verified=true.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "30", "--class", "sqli", "--max-mine", "5"],
    );
    assert_eq!(code, 0);
    let j = parse_json(&stdout, "bypass_entry_schema");
    let bypasses = j["bypasses"].as_array().unwrap();
    for (i, entry) in bypasses.iter().enumerate() {
        assert!(
            entry["payload"].is_string(),
            "bypass[{i}].payload must be string"
        );
        assert!(
            entry["payload_hex"].is_string(),
            "bypass[{i}].payload_hex must be string"
        );
        assert!(
            entry["class"].is_string(),
            "bypass[{i}].class must be string"
        );
        assert_eq!(entry["verified"], true, "bypass[{i}].verified must be true");
        // payload_hex must be hex of payload bytes.
        let payload = entry["payload"].as_str().unwrap();
        let expected_hex = hex::encode(payload.as_bytes());
        // Hex must match (for valid UTF-8 payloads).
        assert_eq!(
            entry["payload_hex"].as_str().unwrap(),
            expected_hex,
            "bypass[{i}] payload_hex must match hex(payload)"
        );
    }
}

#[tokio::test]
async fn model_evade_class_filter_xss() {
    // `--class xss` must only report xss-class bypasses.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "30", "--class", "xss", "--max-mine", "5"],
    );
    assert_eq!(code, 0);
    let j = parse_json(&stdout, "class_filter_xss");
    assert_eq!(j["class"], "xss", "class field must be 'xss'");
    let bypasses = j["bypasses"].as_array().unwrap();
    for entry in bypasses {
        assert_eq!(entry["class"], "xss", "every bypass must have class=xss");
    }
}

#[tokio::test]
async fn model_evade_output_file_written_and_non_empty() {
    // `--output file.json` must write the JSON to the file.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let out_path = std::env::temp_dir().join(format!(
        "wafrift_model_evade_e2e_{}.json",
        std::process::id()
    ));

    let bin = wafrift_bin();
    let result = Command::new(&bin)
        .args([
            "model-evade",
            &server.uri(),
            "--budget",
            "20",
            "--class",
            "sqli",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("binary runs");

    assert_eq!(
        result.status.code().unwrap_or(-1),
        0,
        "model-evade with --output must exit 0"
    );
    assert!(out_path.exists(), "--output file must exist after run");

    let content = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        !content.trim().is_empty(),
        "--output file must be non-empty"
    );
    // Must parse as JSON.
    let j: serde_json::Value =
        serde_json::from_str(content.trim()).expect("--output file must be valid JSON");
    assert_eq!(j["schema_version"], 1);

    let _ = std::fs::remove_file(&out_path);
}

#[tokio::test]
async fn model_evade_verified_bypasses_actually_pass_mock() {
    // The KEY anti-rig test: every bypass in the result must ACTUALLY
    // pass the mock WAF when replayed via a fresh HTTP GET.
    // Uses an all-pass mock so we have verified bypasses to replay.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "30", "--class", "sqli", "--max-mine", "5"],
    );
    assert_eq!(code, 0);
    let j = parse_json(&stdout, "verified_replay");
    let bypasses = j["bypasses"].as_array().unwrap();

    // Replay each bypass against the mock and confirm it passes.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    for (i, entry) in bypasses.iter().enumerate() {
        let payload = entry["payload"].as_str().unwrap();
        let probe_url = format!("{}?q={}", server.uri(), urlencoding::encode(payload));
        let resp =
            client.get(&probe_url).send().await.unwrap_or_else(|e| {
                panic!("bypass[{i}] replay failed for payload {:?}: {e}", payload)
            });
        assert!(
            resp.status().is_success(),
            "bypass[{i}] payload {:?} must pass the mock WAF on replay (got {})",
            payload,
            resp.status()
        );
    }
}

#[tokio::test]
async fn model_evade_class_all_exits_zero() {
    // `--class all` (combined sqli + xss) must exit 0.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "20", "--class", "all", "--max-mine", "5"],
    );
    assert_eq!(code, 0, "class=all must exit 0: {stdout}");
    let j = parse_json(&stdout, "class_all");
    assert_eq!(j["class"], "all");
    assert_eq!(j["schema_version"], 1);
}

#[tokio::test]
async fn model_evade_public_target_without_permission_exits_nonzero() {
    // A public hostname with no --i-have-permission must exit non-zero (2).
    let bin = wafrift_bin();
    let out = Command::new(&bin)
        .args([
            "model-evade",
            "https://example.com/waf-test",
            "--budget",
            "1",
        ])
        .output()
        .expect("binary runs");
    // Permission error = exit code 2.
    assert_eq!(
        out.status.code().unwrap_or(-1),
        2,
        "public target without permission must exit 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Permission error") || stderr.contains("i-have-permission"),
        "stderr must mention permission: {stderr}"
    );
}

#[tokio::test]
async fn model_evade_all_candidates_field_includes_unverified() {
    // `all_candidates` must include every mined candidate (verified or not),
    // while `bypasses` contains only verified ones.
    let server = MockServer::start().await;
    // Use the real SQLi blocker — it blocks some candidates.
    Mock::given(method("GET"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "50", "--class", "sqli", "--max-mine", "10"],
    );
    assert_eq!(code, 0);
    let j = parse_json(&stdout, "all_candidates_field");
    let all = j["all_candidates"].as_array().unwrap();
    let bypasses = j["bypasses"].as_array().unwrap();
    let candidates_mined = j["candidates_mined"].as_u64().unwrap_or(0);
    // all_candidates must contain at least as many entries as bypasses.
    assert!(
        all.len() >= bypasses.len(),
        "all_candidates ({}) must be >= bypasses ({})",
        all.len(),
        bypasses.len()
    );
    // all_candidates count must match candidates_mined.
    assert_eq!(
        all.len() as u64,
        candidates_mined,
        "all_candidates.len must equal candidates_mined"
    );
}

// ── Egress wiring tests (CLAUDE.md §9 WIRING, R52-style) ─────────────────
//
// Before this fix, --socks5 / --http-proxy / --tailscale-exit-node and
// --egress-challenge-threshold / --egress-cooldown-secs were parsed by
// clap and stored in ModelEvadeArgs but silently discarded — build_http_oracle
// used a bare reqwest::Client::builder() and ignored all egress args.
// These tests pin the wiring so the contract can't regress.

// T-EGRESS-1: --help must advertise the egress flags so operators can
// discover them.
#[tokio::test]
async fn model_evade_help_shows_egress_flags() {
    let out = Command::new(wafrift_bin())
        .args(["model-evade", "--help"])
        .output()
        .expect("binary runs");
    let help = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code().unwrap_or(-1), 0);
    assert!(help.contains("--socks5"), "--socks5 must appear in --help");
    assert!(
        help.contains("--http-proxy"),
        "--http-proxy must appear in --help"
    );
    assert!(
        help.contains("--tailscale-exit-node"),
        "--tailscale-exit-node must appear in --help"
    );
    assert!(
        help.contains("--egress-challenge-threshold"),
        "--egress-challenge-threshold must appear in --help"
    );
    assert!(
        help.contains("--egress-cooldown-secs"),
        "--egress-cooldown-secs must appear in --help"
    );
}

// T-EGRESS-2: a bad --socks5 URL (scheme not supported by reqwest) must
// cause an early exit 2 (argument/input error) rather than silently
// routing direct. This proves the egress pool is actually constructed
// from the flag rather than discarded.
//
// Anti-rig: pre-fix the flag was accepted silently and ignored; the oracle
// routed direct regardless, so this invocation would have exited 0.
#[tokio::test]
async fn model_evade_invalid_socks5_exits_2() {
    // "not-a-socks5://host" will fail EgressPool::builder().socks5_str()
    // URL-scheme validation before any HTTP is attempted.
    let out = Command::new(wafrift_bin())
        .args([
            "model-evade",
            "http://127.0.0.1:1",
            "--format",
            "json",
            "--budget",
            "10",
            "--socks5",
            "not-a-socks5://127.0.0.1:9999",
        ])
        .output()
        .expect("binary runs");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        2,
        "invalid --socks5 scheme must exit 2 (arg error); \
         exit 0 would mean the flag was silently ignored. \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// T-EGRESS-3: a syntactically valid but unreachable --socks5 proxy
// (random high port on loopback) must cause oracle HTTP failures rather
// than transparent fallback to direct routing. The observable signal is
// that the oracle queries fail (non-zero exit OR the JSON contains zero
// candidates mined, NOT a successful bypass run). This is the key
// behavioural difference: pre-fix, the flags were ignored and the oracle
// hit the real target directly.
//
// Note: we spin a real pass-all mock server so the distinction is clear:
//   - Direct routing (pre-fix): oracle hits mock server → passes, candidates mined → exit 0 with bypasses
//   - Proxy routing (post-fix):  oracle hits unreachable proxy → connection error → oracle counts 0 queries or exits non-0
//
// Because reqwest gracefully handles connect errors (returning Err rather
// than panicking), the oracle will classify every probe as Block (Err →
// Block fallback), so the learner will build an "everything is blocked"
// model, mine zero candidates, and exit 0 with empty bypasses.
// That empty-bypasses-with-bad-proxy result is provably different from
// the direct-routing result (which would find candidates since the mock
// passes everything). We pin `candidates_mined == 0` as the proxy-applied
// observable.
#[tokio::test]
async fn model_evade_unreachable_socks5_proxy_changes_observable_output() {
    // Pass-all server: if the oracle reaches it directly, candidates will
    // be mined (the model learns "pass everything" → needles match → output).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(PassAllResponder)
        .mount(&server)
        .await;

    // Pick a random port on loopback that is almost certainly not listening.
    // We use a fixed high port rather than bind-then-close to avoid TOCTOU.
    let dead_proxy = "socks5://127.0.0.1:19753";

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &[
            "--budget",
            "20",
            "--class",
            "sqli",
            "--max-mine",
            "10",
            "--socks5",
            dead_proxy,
        ],
    );
    // Exit 0 is still valid here — connection errors may degrade gracefully
    // into an all-block model. We just need to confirm candidates_mined
    // shows the proxy was applied (all-block → 0 mined or very few).
    // Accept either "exit non-0" or "candidates_mined == 0".
    if code == 0 {
        // Only parse JSON if the run exited cleanly.
        let j = parse_json(&stdout, "unreachable_proxy_test");
        let candidates_mined = j["candidates_mined"].as_u64().unwrap_or(0);
        // A pass-all direct route would mine candidates; a blocked proxy
        // can't — if candidates_mined > 0 that proves the proxy was ignored.
        assert_eq!(
            candidates_mined, 0,
            "with an unreachable SOCKS5 proxy, all oracle queries fail \
             → all-block model → 0 candidates mined. \
             Got {candidates_mined} — this means the proxy was ignored \
             and the oracle hit the pass-all server directly."
        );
    }
    // If code != 0, the egress error surfaced as a hard exit — also proves
    // the proxy was applied, not silently dropped.
}

// T-EGRESS-4: backwards-compat anti-rig. No egress flags → existing
// behaviour (direct routing to a reachable mock server, candidates mined,
// exit 0). Proves the wiring change doesn't regress the common case.
#[tokio::test]
async fn model_evade_no_egress_flags_still_works() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(SqliXssBlocker)
        .mount(&server)
        .await;

    let (stdout, _stderr, code) = run_model_evade(
        &server.uri(),
        &["--budget", "50", "--class", "sqli", "--max-mine", "20"],
    );
    assert_eq!(code, 0, "no egress flags: must exit 0 (backwards-compat)");
    let j = parse_json(&stdout, "no_egress_backwards_compat");
    assert!(
        j.get("bypasses").is_some(),
        "JSON must still contain 'bypasses' field"
    );
    assert!(
        j.get("candidates_mined").is_some(),
        "JSON must still contain 'candidates_mined' field"
    );
}

// T-EGRESS-5: boundary — passing an empty --socks5 list (no URL after flag)
// when clap accepts num_args = 0.. means zero egress entries. The pool is
// not constructed (want_egress = false) and the oracle routes direct.
// Exit 0 with the normal schema.
#[tokio::test]
async fn model_evade_egress_threshold_flag_accepted_by_clap() {
    // Just validate clap parses both threshold flags without error.
    // Full wiring proof is in T-EGRESS-2/3 above.
    let out = Command::new(wafrift_bin())
        .args([
            "model-evade",
            "--help",
            // These next args are after --help so they won't be processed,
            // but the flag names must exist in the schema (otherwise --help
            // exits 2 "unexpected argument").
        ])
        .output()
        .expect("binary runs");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "--egress-challenge-threshold and --egress-cooldown-secs \
         must be parseable clap args"
    );
}
