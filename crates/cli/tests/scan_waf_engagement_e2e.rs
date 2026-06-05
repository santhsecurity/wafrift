//! E2E tests for WAF engagement assessment (`scan` honesty layer).
//!
//! These mocks prove the contract:
//! - Identical benign/attack responses → `unguarded`, zero meaningful bypasses,
//!   explore phase skipped (low fire count).
//! - Always-403 WAF → `active`, meaningful bypass rate is honest.
//! - Selective blocks on differential probes → `selective`.
//! - Different bodies, no blocks → `param_live_no_waf`.
//! - `--full-scan-unguarded` restores heavy firing on unguarded targets.

use serial_test::serial;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

const STATIC_SHELL: &[u8] = b"STATIC_WAF_ENGAGEMENT_SHELL_v1";

/// Mock that returns the same 200 body for every request (upld.me-style unguarded param).
async fn spawn_identical_shell_mock() -> std::net::SocketAddr {
    spawn_handler_mock(|_req| (200, STATIC_SHELL.to_vec())).await
}

/// Mock that always returns 403 with a WAF block page (active WAF).
async fn spawn_always_block_mock() -> std::net::SocketAddr {
    let body = b"<html>Blocked by ModSecurity</html>";
    spawn_handler_mock(move |_req| (403, body.to_vec())).await
}

/// Mock: 403 when query looks like differential SqlKeyword / XssTag probes; else static shell.
async fn spawn_selective_block_mock() -> std::net::SocketAddr {
    spawn_handler_mock(|req| {
        let req = String::from_utf8_lossy(req);
        let block = req.contains("SqlKeyword")
            || req.contains("XssTag")
            || req.contains("XssEvent")
            || req.contains("SqlTautology");
        if block {
            (403, b"blocked by waf".to_vec())
        } else {
            (200, STATIC_SHELL.to_vec())
        }
    })
    .await
}

/// Mock: parameter changes body but never blocks (reflection without WAF).
async fn spawn_param_live_mock() -> std::net::SocketAddr {
    spawn_handler_mock(|req| {
        let req = String::from_utf8_lossy(req);
        if req.contains("wafrift_benign_probe0") {
            (200, b"BENIGN_BODY_v1".to_vec())
        } else if req.contains('q') || req.contains('Q') {
            (200, b"ATTACK_REFLECTED_BODY_v2".to_vec())
        } else {
            (200, b"ROOT".to_vec())
        }
    })
    .await
}

type MockHandler = Arc<dyn Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync>;

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

async fn spawn_handler_mock<F>(handler: F) -> std::net::SocketAddr
where
    F: Fn(&[u8]) -> (u16, Vec<u8>) + Send + Sync + 'static,
{
    let handler: MockHandler = Arc::new(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let (status, body) = handler(&buf[..n]);
                let resp = format!(
                    "{}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    status_line(status),
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    common::wait_for_server(addr);
    addr
}

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap()
}

fn parse_scan_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).expect("scan must emit valid JSON")
}

fn run_scan_on(addr: std::net::SocketAddr, extra_args: &[&str]) -> (i32, String, String) {
    let url = format!("http://{addr}/");
    let mut args = vec![
        "scan",
        url.as_str(),
        "--payload",
        "' OR 1=1--",
        "--param",
        "q",
        "--payload-class",
        "sql",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--max-fires",
        "200",
        "--no-auto-escalate",
        "--no-probe-surfaces",
    ];
    args.extend_from_slice(extra_args);
    wafrift(&args)
}

// ── Schema / flag documentation ───────────────────────────────────────────

#[test]
fn scan_help_documents_waf_engagement_flags() {
    let (code, stdout, _) = wafrift(&["scan", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--full-scan-unguarded"),
        "must document --full-scan-unguarded: {stdout}"
    );
    assert!(
        stdout.contains("--probe-surfaces"),
        "must document --probe-surfaces: {stdout}"
    );
    assert!(
        stdout.contains("--auto-escalate"),
        "must document --auto-escalate: {stdout}"
    );
}

// ── Unguarded (identical shell) ───────────────────────────────────────────

#[test]
#[serial]
fn scan_unguarded_mock_reports_zero_meaningful_bypass_and_skips_explore() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_identical_shell_mock());

    let (code, stdout, stderr) = run_scan_on(addr, &[]);
    assert_eq!(
        code, 6,
        "unguarded + zero meaningful bypass → exit 6; stderr: {stderr}"
    );
    let v = parse_scan_json(&stdout);

    assert_eq!(
        v["waf_engagement"]["level"].as_str().unwrap(),
        "unguarded",
        "identical shell must classify unguarded: {v}"
    );
    assert_eq!(
        v["meaningful_bypassed"].as_u64().unwrap(),
        0,
        "must not count pass-through as meaningful bypass: {v}"
    );
    assert!(
        (v["meaningful_bypass_rate_pct"].as_f64().unwrap() - 0.0).abs() < f64::EPSILON,
        "meaningful bypass rate must be 0: {v}"
    );
    let fired = v["total_requests_fired"].as_u64().unwrap();
    assert!(
        fired < 50,
        "unguarded scan must skip evasion phases (got {fired} fires): {v}"
    );
    assert!(
        v["bypass_variants"].as_array().unwrap().is_empty(),
        "unguarded must not emit bypass_variants: {v}"
    );
    assert!(
        v["unguarded_pass"].as_u64().unwrap() <= v["bypassed"].as_u64().unwrap(),
        "unguarded_pass must not exceed bypassed: {v}"
    );
}

#[test]
#[serial]
fn scan_unguarded_full_scan_flag_fires_more_than_default() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_identical_shell_mock());

    let (_, stdout_default, _) = run_scan_on(addr, &[]);
    let v_default = parse_scan_json(&stdout_default);
    let fired_default = v_default["total_requests_fired"].as_u64().unwrap();

    let (_, stdout_full, _) = run_scan_on(addr, &["--full-scan-unguarded"]);
    let v_full = parse_scan_json(&stdout_full);
    let fired_full = v_full["total_requests_fired"].as_u64().unwrap();

    assert!(
        fired_full > fired_default,
        "full-scan-unguarded must fire more requests (default={fired_default}, full={fired_full})"
    );
    assert_eq!(
        v_full["waf_engagement"]["level"].as_str().unwrap(),
        "unguarded"
    );
}

// ── Active WAF ────────────────────────────────────────────────────────────

#[test]
#[serial]
fn scan_active_waf_mock_reports_active_engagement() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_always_block_mock());

    let (code, stdout, stderr) = run_scan_on(addr, &[]);
    assert_eq!(
        code, 4,
        "active WAF with no bypass → exit 4; stderr: {stderr}"
    );
    let v = parse_scan_json(&stdout);
    assert_eq!(
        v["waf_bypass"]["verdict"].as_str().unwrap(),
        "waf_active_no_bypass"
    );
    assert!(v["waf_bypass"]["waf_in_play"].as_bool().unwrap());

    assert_eq!(
        v["waf_engagement"]["level"].as_str().unwrap(),
        "active",
        "403 block page must classify active: {v}"
    );
    assert!(
        v["waf_engagement"]["reason"]
            .as_str()
            .unwrap()
            .contains("blocked"),
        "reason must mention block: {v}"
    );
    // Baseline blocked — explore may still run but meaningful count is honest.
    assert!(
        v["meaningful_bypassed"].as_u64().unwrap() <= v["bypassed"].as_u64().unwrap(),
        "meaningful must be subset of bypassed: {v}"
    );
}

// ── Selective WAF ───────────────────────────────────────────────────────────

#[test]
#[serial]
fn scan_selective_mock_reports_selective_engagement() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_selective_block_mock());

    let (code, stdout, stderr) = run_scan_on(addr, &[]);
    let v = parse_scan_json(&stdout);
    assert!(
        code == 0 || code == 4,
        "selective: exit 0 if bypass found else 4; got {code} stderr: {stderr}"
    );
    assert!(v["waf_bypass"]["waf_in_play"].as_bool().unwrap());

    assert_eq!(
        v["waf_engagement"]["level"].as_str().unwrap(),
        "selective",
        "partial blocks must classify selective: {v}"
    );
    assert!(
        v["waf_engagement"]["differential_blocked"]
            .as_u64()
            .unwrap()
            > 0,
        "must record differential blocks: {v}"
    );
    // Selective surfaces allow meaningful bypass counting when variants slip through.
    assert!(
        v["waf_engagement"]["reason"]
            .as_str()
            .unwrap()
            .contains("differential")
    );
}

// ── Param live, no WAF ────────────────────────────────────────────────────

#[test]
#[serial]
fn scan_param_live_mock_reports_param_live_no_waf() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_param_live_mock());

    let (code, stdout, stderr) = run_scan_on(addr, &[]);
    assert_eq!(
        code, 6,
        "param_live_no_waf + zero meaningful → exit 6; stderr: {stderr}"
    );
    let v = parse_scan_json(&stdout);

    assert_eq!(
        v["waf_engagement"]["level"].as_str().unwrap(),
        "param_live_no_waf",
        "different bodies without blocks: {v}"
    );
    assert_eq!(v["meaningful_bypassed"].as_u64().unwrap(), 0);
}

// ── Contract: meaningful never exceeds bypassed ───────────────────────────

#[test]
#[serial]
fn scan_meaningful_bypassed_never_exceeds_bypassed_on_all_mocks() {
    let rt = test_runtime();

    for (name, addr) in [
        ("identical", rt.block_on(spawn_identical_shell_mock())),
        ("active", rt.block_on(spawn_always_block_mock())),
        ("selective", rt.block_on(spawn_selective_block_mock())),
        ("param_live", rt.block_on(spawn_param_live_mock())),
    ] {
        let (_, stdout, stderr) = run_scan_on(addr, &[]);
        let v = parse_scan_json(&stdout);
        let meaningful = v["meaningful_bypassed"].as_u64().unwrap_or(0);
        let bypassed = v["bypassed"].as_u64().unwrap_or(0);
        assert!(
            meaningful <= bypassed,
            "{name}: meaningful_bypassed ({meaningful}) > bypassed ({bypassed}); stderr={stderr}"
        );
    }
}

// ── Layer report envelope ─────────────────────────────────────────────────

#[test]
#[serial]
fn scan_report_layers_includes_waf_engagement_in_envelope() {
    let rt = test_runtime();
    let addr = rt.block_on(spawn_identical_shell_mock());
    let url = format!("http://{addr}/");

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        url.as_str(),
        "--payload",
        "test",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--report-layers",
        "--no-auto-escalate",
        "--no-probe-surfaces",
    ]);
    assert_eq!(code, 6, "unguarded layer report → exit 6; stderr: {stderr}");
    let v = parse_scan_json(&stdout);
    assert!(v["scan"].is_object(), "must wrap scan body: {v}");
    assert!(
        v["layer_report"]["baseline_probe"]["transport_ok"]
            .as_bool()
            .unwrap(),
        "baseline transport must be ok: {v}"
    );
    assert_eq!(
        v["scan"]["waf_engagement"]["level"].as_str().unwrap(),
        "unguarded"
    );
}
