//! End-to-end test for `wafrift query-diff`.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_query_aware_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let leaked = req.contains("WAFRIFT_ATTACK_TOKEN");
                let body: String = if leaked {
                    "<html>attack token seen in query — long response body</html>".into()
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
    tokio::time::sleep(Duration::from_millis(40)).await;
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
fn query_diff_finds_divergences_against_query_aware_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_query_aware_mock());

    let (code, stdout, stderr) = wafrift(&[
        "query-diff",
        &format!("http://{addr}/"),
        "--param",
        "q",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "query-diff should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse");
    assert_eq!(parsed["baseline_status"], 200);
    let results = parsed["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "results must be non-empty");

    // At least one probe must diverge (the token-carrying ones).
    let any_diverged = results.iter().any(|r| {
        let sev = r["severity"].as_str().unwrap_or("");
        sev == "medium" || sev == "high"
    });
    assert!(any_diverged, "at least one probe must diverge: {parsed}");

    // Every probe has a single-line curl reproducer.
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd string");
        assert!(curl.starts_with("curl -i "), "got: {curl}");
    }
}

#[test]
fn query_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "query-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(code, 1, "unreachable target must exit 1 — stderr:\n{stderr}");
}

#[test]
fn query_diff_help_documents_param_flag() {
    let (code, stdout, _) = wafrift(&["query-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--param"), "stdout:\n{stdout}");
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
}

#[test]
fn query_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("query-diff"),
        "query-diff must appear in top-level help"
    );
}
