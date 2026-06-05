//! End-to-end test for `wafrift body-diff`.
//!
//! Spins up a mock origin that's "body-aware" — returns a longer
//! response when the request body contains the literal attack token
//! WAFRIFT_ATTACK_TOKEN (the canonical interpolation point). Drives
//! `wafrift body-diff --format json` against the running binary;
//! verifies divergent probes are reported with curl reproducers.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

async fn spawn_body_aware_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Read full body, not just first chunk — body-diff
                // sends bodies up to a few hundred bytes.
                let mut buf = vec![0u8; 64 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let leaked = req.contains("WAFRIFT_ATTACK_TOKEN")
                    || req.contains("+ADw-WAFRIFT_ATTACK_TOKEN+AD4-");
                let body: String = if leaked {
                    "<html>parsed attack token — origin saw it (long body)</html>".into()
                } else {
                    "<html>baseline</html>".into()
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
    // R66 pass-21 §7 DEDUP: route through `common::wait_for_server`
    // instead of the open-coded poll loop that lived in 19 e2e files.
    common::wait_for_server(addr);
    addr
}

#[test]
fn body_diff_finds_divergences_against_body_aware_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_body_aware_mock());

    let (code, stdout, stderr) = wafrift(&[
        "body-diff",
        &format!("http://{addr}/"),
        "--baseline-body",
        r#"{"q":"safe"}"#,
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "15",
    ]);
    assert_eq!(code, 0, "body-diff should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse — stdout:\n{stdout}");
    assert_eq!(parsed["baseline_status"], 200);

    let results = parsed["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "must have at least one probe result");

    // The token-carrying probes should diverge from baseline.
    let any_diverged = results.iter().any(|r| {
        r["severity"].as_str() == Some("medium") || r["severity"].as_str() == Some("high")
    });
    assert!(
        any_diverged,
        "at least one probe must diverge against a body-aware mock: {parsed}"
    );

    // Every probe must carry a curl reproducer of shape `curl -i -X POST …`.
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd string");
        assert!(curl.starts_with("curl -i -X POST "), "got: {curl}");
        assert!(curl.contains("Content-Type"), "got: {curl}");
        assert!(curl.contains("--data-binary"), "got: {curl}");
    }
}

#[test]
fn body_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "body-diff",
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
fn body_diff_help_documents_baseline_body_flag() {
    let (code, stdout, _) = wafrift(&["body-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--baseline-body"), "stdout:\n{stdout}");
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
}

#[test]
// body-diff consolidated under `wafrift diff body` (2026-05). LAW 2: flat
// alias must keep working forever.
fn body_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "body", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff body --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["body-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift body-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}

#[test]
fn body_diff_json_results_carry_content_type_field_per_probe() {
    // The JSON output should expose `content_type` so report tooling
    // can group / filter probes by parser surface.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_body_aware_mock());

    let (code, stdout, _) = wafrift(&[
        "body-diff",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "15",
    ]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let results = parsed["results"].as_array().unwrap();
    for r in results {
        assert!(
            r["content_type"].is_string(),
            "every probe must carry content_type: {r}"
        );
    }
    // At least one probe must be multipart, at least one json, at least one form-urlencoded.
    let cts: Vec<String> = results
        .iter()
        .filter_map(|r| r["content_type"].as_str().map(str::to_string))
        .collect();
    assert!(
        cts.iter().any(|c| c.contains("multipart")),
        "multipart probe missing: {cts:?}"
    );
    assert!(
        cts.iter().any(|c| c.contains("json")),
        "json probe missing: {cts:?}"
    );
    assert!(
        cts.iter().any(|c| c.contains("urlencoded")),
        "form-urlencoded probe missing: {cts:?}"
    );
}
