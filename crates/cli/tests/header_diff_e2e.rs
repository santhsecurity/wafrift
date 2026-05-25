//! End-to-end test for `wafrift header-diff`.
//!
//! Spins up a mock origin that's "header-aware" — it returns
//! different bodies depending on whether `X-Real-IP: 127.0.0.1` is
//! present (simulating a backend that trusts the header for
//! "internal" gating). Drives `wafrift header-diff --format json`
//! against the running binary; verifies the JSON output reports the
//! divergence (probe body length differs from baseline) and emits a
//! curl reproducer.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_header_aware_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Simulate "X-Real-IP: 127.0.0.1 grants extra body."
                let internal = req.lines().any(|l| {
                    let lo = l.to_ascii_lowercase();
                    lo.starts_with("x-real-ip:") && lo.contains("127.0.0.1")
                });
                let body: String = if internal {
                    "<html>internal admin panel — secret content (long body)</html>".into()
                } else {
                    "<html>public</html>".into()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn header_diff_finds_xff_localhost_divergence_via_real_binary() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_header_aware_mock());

    let (code, stdout, stderr) = wafrift(&[
        "header-diff",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "header-diff should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse — stdout:\n{stdout}");
    assert_eq!(parsed["baseline_status"], 200);
    assert!(
        parsed["baseline_body_len"].as_u64().unwrap_or(0) > 0,
        "baseline_body_len must be > 0"
    );

    let results = parsed["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "results must be non-empty");

    // Find the x-real-ip-localhost probe. It MUST diverge on this
    // mock (body length differs), so severity should be medium or
    // high.
    let xri = results
        .iter()
        .find(|r| r["kind"] == "x-real-ip-localhost")
        .expect("x-real-ip-localhost probe in results");
    let sev = xri["severity"].as_str().unwrap_or("");
    assert!(
        sev == "medium" || sev == "high",
        "x-real-ip-localhost should diverge against header-aware mock: severity={sev}, full={xri}"
    );

    // The probe's curl reproducer must be a single-line `curl -i …`
    // invocation with the X-Real-IP header included.
    let curl = xri["curl_cmd"].as_str().expect("curl_cmd string");
    assert!(curl.starts_with("curl -i "), "got: {curl}");
    assert!(curl.contains("X-Real-IP"), "got: {curl}");
    assert!(curl.contains("127.0.0.1"), "got: {curl}");
}

#[test]
fn header_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "header-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(
        code, 1,
        "unreachable target must exit 1 — stderr:\n{stderr}"
    );
}

#[test]
fn header_diff_help_documents_all_options() {
    let (code, stdout, _) = wafrift(&["header-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
    assert!(stdout.contains("--proxy"), "stdout:\n{stdout}");
    assert!(stdout.contains("--header"), "stdout:\n{stdout}");
    assert!(stdout.contains("--concurrency"), "stdout:\n{stdout}");
}

#[test]
fn header_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("header-diff"),
        "header-diff must appear in top-level help: {stdout}"
    );
}

#[test]
fn header_diff_text_format_emits_summary_when_not_quiet() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_header_aware_mock());

    let (code, _stdout, stderr) = wafrift(&[
        "header-diff",
        &format!("http://{addr}/"),
        "--format",
        "text",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    // text format announces the probe + summary on stderr.
    assert!(
        stderr.contains("header-diff") || stderr.contains("divergence"),
        "stderr summary missing: {stderr}"
    );
}

#[test]
fn header_diff_concurrency_and_delay_options_accepted() {
    // Smoke: pass aggressive concurrency + delay flags — should
    // parse without erroring, even if the target is unreachable
    // (we don't care about completion, just option parsing).
    let (code, _stdout, _stderr) = wafrift(&[
        "header-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--concurrency",
        "16",
        "--delay-ms",
        "10",
        "--timeout-secs",
        "1",
    ]);
    // 1 = transport error (expected); 2+ = arg parse error (would
    // be a bug). We accept 0 too in case the system happens to
    // have something listening on :1 (unlikely).
    assert!(
        code == 0 || code == 1,
        "header-diff should exit 0 or 1, got {code}"
    );
}
