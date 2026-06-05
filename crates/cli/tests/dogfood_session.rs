//! Endless dogfood harness — spins up a realistic mock that
//! simulates WAF + cache + parser quirks, then drives EVERY new
//! subcommand (`distill`, `header-diff`, `body-diff`, `query-diff`,
//! `cache-diff`, `attack`, `scan -r`, `scan --auto-distill`) against
//! it via the real `wafrift` binary. Each subcommand must:
//!
//! 1. Exit 0.
//! 2. Emit valid JSON on `--format json`.
//! 3. Carry the shared-shape contract for its family (probes /
//!    bypass_variants / divergences keys, curl reproducer per row).
//!
//! This is the integration-level "use the tool end-to-end" proof —
//! if a subcommand passes its unit tests but fails here, the wire
//! between clap → run_* → JSON emission has a hole.

use std::io::Write;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

/// Realistic mock: combines header-aware dispatch, body-aware
/// reflection, query-aware reflection, and cache-style headers.
/// Returns the bound address.
async fn spawn_realistic_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();

                // Header-aware dispatch — X-Real-IP localhost yields
                // an internal-grant body.
                let internal_via_header = req.lines().any(|l| {
                    let lo = l.to_ascii_lowercase();
                    lo.starts_with("x-real-ip:") && lo.contains("127.0.0.1")
                });
                // Body / query reflection — any request containing
                // the canonical attack token gets the leaked body.
                let leaked = req.contains("WAFRIFT_ATTACK_TOKEN") || req.contains("PWN");
                // "Block" simulation for scan: anything containing
                // BLOCKED gets 403.
                let blocked = req.contains("BLOCKED");

                let (status, body) = if blocked {
                    (
                        "403 Forbidden",
                        "<html>blocked by mock WAF</html>".to_string(),
                    )
                } else if internal_via_header || leaked {
                    (
                        "200 OK",
                        "<html>internal / leaked — long body for delta detection</html>"
                            .to_string(),
                    )
                } else {
                    ("200 OK", "<html>baseline</html>".to_string())
                };
                // Cache-style headers on every response (lets
                // cache-diff probes detect cache_signals_match).
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\
                     Server: nginx/1.25\r\nCF-Cache-Status: HIT\r\nAge: 42\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    // Probe-until-ready using the stdlib (synchronous) TCP connect so this
    // loop works even if the tokio reactor is saturated. The listener is
    // bound at the OS level the moment TcpListener::bind returns; the
    // blocking connect goes through the kernel's SYN-ACK path and succeeds
    // immediately without needing the application's accept() to have run.
    {
        common::wait_for_server(addr);
    }
    addr
}

/// Helper: parse stdout as JSON; on failure include both stdout
/// AND stderr in the panic message (the actual bug-finding info).
fn parse_or_explain(stdout: &str, stderr: &str, ctx: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{ctx}: JSON parse failed ({e}). stdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

/// One target — every subcommand fires against this URL.
struct Target {
    base_url: String,
}

impl Target {
    fn spawn() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_realistic_mock());
        // Leak the runtime — keeps the mock alive for the entire
        // test, which suits the use-once nature of dogfood.
        std::mem::forget(rt);
        Self {
            base_url: format!("http://{addr}/"),
        }
    }
}

// ── distill ──────────────────────────────────────────────────

#[test]
fn dogfood_distill_reduces_bypass_to_minimum_form() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "distill",
        &t.base_url,
        "--payload",
        "/**/admin'/**/UNION/**/SELECT/**/1--",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "distill exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "distill");
    let orig_len = p["original"]["length"].as_u64().unwrap_or(0);
    let min_len = p["minimal"]["length"].as_u64().unwrap_or(u64::MAX);
    assert!(orig_len > 0, "original length > 0");
    assert!(
        min_len < orig_len,
        "min must be < original: orig={orig_len} min={min_len}"
    );
}

// ── header-diff ──────────────────────────────────────────────

#[test]
fn dogfood_header_diff_finds_xri_localhost_via_real_binary() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "header-diff",
        &t.base_url,
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "header-diff exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "header-diff");
    let results = p["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "must have results");
    // The realistic mock grants internal-body on X-Real-IP=127.0.0.1
    // → the x-real-ip-localhost probe MUST diverge.
    let xri = results
        .iter()
        .find(|r| r["kind"] == "x-real-ip-localhost")
        .expect("x-real-ip-localhost probe present");
    let sev = xri["severity"].as_str().unwrap_or("");
    assert!(
        sev == "medium" || sev == "high",
        "x-real-ip-localhost must diverge: severity={sev}"
    );
}

// ── body-diff ────────────────────────────────────────────────

#[test]
fn dogfood_body_diff_finds_token_leak_via_real_binary() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "body-diff",
        &t.base_url,
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "body-diff exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "body-diff");
    let total_div = p["divergences"]["high"].as_u64().unwrap_or(0)
        + p["divergences"]["medium"].as_u64().unwrap_or(0);
    assert!(
        total_div > 0,
        "realistic mock reflects WAFRIFT_ATTACK_TOKEN → must yield ≥1 divergence: {p}"
    );
}

// ── query-diff ───────────────────────────────────────────────

#[test]
fn dogfood_query_diff_finds_token_leak_via_real_binary() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "query-diff",
        &t.base_url,
        "--param",
        "q",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "query-diff exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "query-diff");
    let total_div = p["divergences"]["high"].as_u64().unwrap_or(0)
        + p["divergences"]["medium"].as_u64().unwrap_or(0);
    assert!(total_div > 0, "must yield ≥1 divergence");
}

// ── cache-diff ───────────────────────────────────────────────

#[test]
fn dogfood_cache_diff_flags_collisions_on_aggressive_cache_mock() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "cache-diff",
        &t.base_url,
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "cache-diff exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "cache-diff");
    let high = p["divergences"]["high"].as_u64().unwrap_or(0);
    assert!(
        high > 0,
        "aggressive-cache mock returns identical bodies → must yield ≥1 strong collision: {p}"
    );
}

// ── attack orchestrator ──────────────────────────────────────

#[test]
fn dogfood_attack_runs_all_seven_subprobes_concurrently_via_real_binary() {
    let t = Target::spawn();
    let (code, stdout, stderr) = wafrift(&[
        "attack",
        &t.base_url,
        "--param",
        "q",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--concurrency",
        "4",
        "--timeout-secs",
        "30",
        "--probe-timeout-secs",
        "120",
    ]);
    assert_eq!(code, 0, "attack exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "attack");
    let probes = p["probes"].as_object().expect("probes object");
    // All seven sub-probe families present.
    for family in [
        "url_path", "headers", "body", "query", "cache", "h2", "method",
    ] {
        assert!(
            probes.contains_key(family),
            "missing sub-probe family `{family}`"
        );
    }
    // Cross-family totals must be consistent.
    let total = p["divergences"]["total"].as_u64().unwrap_or(0);
    let h = p["divergences"]["high"].as_u64().unwrap_or(0);
    let m = p["divergences"]["medium"].as_u64().unwrap_or(0);
    assert_eq!(total, h + m, "totals must equal high + medium");
}

// ── scan -r raw-request mode + --auto-distill ────────────────

#[test]
fn dogfood_scan_raw_request_with_auto_distill_via_real_binary() {
    let t = Target::spawn();
    let port = t.base_url.split(':').nth(2).unwrap().trim_end_matches('/');
    let path = std::env::temp_dir().join(format!(
        "wafrift-dogfood-raw-{}-{port}.req",
        std::process::id()
    ));
    let body =
        format!("GET /search?q=§§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: */*\r\n\r\n");
    let mut f = std::fs::File::create(&path).expect("create fixture");
    f.write_all(body.as_bytes()).unwrap();
    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "-r",
        path.to_str().unwrap(),
        "--payload",
        "SAFEPAYLOAD",
        "--level",
        "light",
        "--encoding-only",
        "--auto-distill",
        "--auto-distill-max-fires",
        "30",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "scan -r exit 0 — stderr:\n{stderr}");
    let p = parse_or_explain(&stdout, &stderr, "scan -r");
    assert_eq!(p["mode"], "raw-request");
    assert_eq!(p["auto_distill_enabled"], true);
    let bypasses = p["bypass_variants"].as_array().expect("bypass_variants");
    assert!(
        !bypasses.is_empty(),
        "must have bypasses on safe-token mock"
    );
    // Every bypass has BOTH a repro_curl AND a minimal_payload + minimal_repro_curl.
    for b in bypasses {
        assert!(b["repro_curl"].is_string(), "repro_curl missing: {b}");
        assert!(
            b["minimal_payload"].is_string(),
            "minimal_payload missing: {b}"
        );
        assert!(
            b["minimal_repro_curl"].is_string(),
            "minimal_repro_curl missing: {b}"
        );
    }
}

// ── attack consistency: same target, multiple back-to-back runs
//    produce deterministic structure ──────────────────────────

#[test]
fn dogfood_attack_repeats_produce_same_shape_three_runs() {
    let t = Target::spawn();
    for i in 0..3 {
        let (code, stdout, stderr) = wafrift(&[
            "attack",
            &t.base_url,
            "--format",
            "json",
            "--quiet",
            "--delay-ms",
            "0",
            "--probe-timeout-secs",
            "30",
        ]);
        assert_eq!(code, 0, "attack run {i} exit 0 — stderr:\n{stderr}");
        let p = parse_or_explain(&stdout, &stderr, &format!("attack-run-{i}"));
        // Stable structure: all 7 families present every time.
        let probes = p["probes"].as_object().expect("probes object");
        assert_eq!(
            probes.len(),
            7,
            "run {i}: must have exactly 7 sub-probe families"
        );
    }
}

// ── attack error-resilience: one sub-probe failing doesn't kill the
//    others (point a sub-probe at a separate dead port) ─────

#[test]
fn dogfood_attack_subprobe_failures_are_isolated() {
    // Point at unreachable target — every sub-probe's baseline
    // probe should fail. Since R44-I3: when ≥4 sub-probes error at
    // the transport level the orchestrator exits 1 (not 0) so CI can
    // detect "nothing landed" rather than interpreting "0 divergences"
    // as a clean run. The JSON report is still emitted.
    let (code, stdout, stderr) = wafrift(&[
        "attack",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--probe-timeout-secs",
        "5",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(
        code, 1,
        "attack must exit 1 when all sub-probes fail (transport unreachable) — stderr:\n{stderr}"
    );
    let p = parse_or_explain(&stdout, &stderr, "attack-isolated-failure");
    let probes = p["probes"].as_object().expect("probes");
    // Every family records SOME failure signal. The h2-diff sub-probe
    // uses `h2_errors` (count of per-probe transport failures) rather
    // than a top-level `error` or `errors` field — check all three.
    for (family, body) in probes {
        let has_err = body.get("error").is_some();
        let has_errors = body
            .get("errors")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n > 0)
            .unwrap_or(false);
        // h2-diff records transport failures in `h2_errors`.
        let has_h2_errors = body
            .get("h2_errors")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n > 0)
            .unwrap_or(false);
        assert!(
            has_err || has_errors || has_h2_errors,
            "family `{family}` must record failure: {body}"
        );
    }
}

// ── scan URL-query mode + --auto-distill ─────────────────────

#[test]
fn dogfood_scan_url_query_no_waf_verdict_does_not_fabricate_distill() {
    let t = Target::spawn();
    // The realistic mock only 403s the literal `BLOCKED`; it lets real attack
    // canaries through, so it does NOT behave like a WAF. scan's surface probe
    // therefore honestly classifies it `param_live_no_waf` and the bypass
    // verdict is `WafNotInPlay` (exit 6) — you cannot "confirm a bypass" against
    // a target with no detectable WAF. This test pins that honesty contract:
    // even with --auto-distill set, scan must NOT manufacture bypasses or burn
    // ddmin fires when there is nothing to bypass. (The real auto-distill /
    // minimal_payload path against a *detected* WAF is covered by
    // raw_request_e2e::raw_request_auto_distill_populates_minimal_payload_per_bypass.)
    let (code, stdout, stderr) = wafrift(&[
        "scan",
        "--target",
        &t.base_url,
        "--payload",
        "SAFEPAYLOAD",
        "--param",
        "q",
        "--level",
        "light",
        "--encoding-only",
        "--auto-distill",
        "--auto-distill-max-fires",
        "20",
        "--format",
        "json",
    ]);
    // WafNotInPlay → exit 6 per scan::waf_bypass_verdict::exit_code_for_verdict.
    assert_eq!(
        code, 6,
        "no-WAF target must yield the WafNotInPlay verdict (exit 6); stderr:\n{stderr}"
    );
    let p = parse_or_explain(&stdout, &stderr, "scan url-query auto-distill");
    // The flag is still wired (operator asked for distillation)…
    assert_eq!(
        p["auto_distill_enabled"], true,
        "auto_distill_enabled must reflect the flag even when no WAF is in play"
    );
    // …but the verdict is honest: no WAF, no bypasses, no fabricated fires.
    assert_eq!(
        p["waf_bypass"]["verdict"], "waf_not_in_play",
        "verdict must be waf_not_in_play against a non-WAF mock: {p}"
    );
    assert_eq!(
        p["waf_bypass"]["waf_in_play"], false,
        "waf_in_play must be false against a non-WAF mock: {p}"
    );
    let bypasses = p["bypass_variants"]
        .as_array()
        .expect("bypass_variants array");
    assert!(
        bypasses.is_empty(),
        "no WAF in play ⇒ zero confirmed bypasses, not fabricated ones: {p}"
    );
    assert_eq!(
        p["auto_distill_fires_total"].as_u64().unwrap_or(u64::MAX),
        0,
        "scan must not burn ddmin fires when there is nothing to distill: {p}"
    );
}

// ── version: every command --help exits 0 and documents its key flags ──

#[test]
fn dogfood_every_new_subcommand_help_is_well_formed() {
    for cmd in [
        "distill",
        "header-diff",
        "body-diff",
        "query-diff",
        "cache-diff",
        "attack",
    ] {
        let (code, stdout, stderr) = wafrift(&[cmd, "--help"]);
        assert_eq!(code, 0, "{cmd} --help exit 0 — stderr:\n{stderr}");
        assert!(
            stdout.contains("--format"),
            "{cmd} --help must document --format: {stdout}"
        );
    }
}
