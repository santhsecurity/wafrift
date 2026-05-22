//! End-to-end test for `wafrift h2-diff`.
//!
//! Mock only speaks HTTP/1.1; H2 negotiation will fail on every
//! probe. h2-diff should exit 0 with per-probe `h2_error` populated
//! — informational, not a build failure.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_h1_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = "<html>ok</html>";
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
fn h2_diff_against_h1_only_mock_records_h2_errors_per_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_h1_mock());
    let (code, stdout, stderr) = wafrift(&[
        "h2-diff",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "3",
    ]);
    assert_eq!(code, 0, "h2-diff exit 0 even on H1-only target — stderr:\n{stderr}");
    let p: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse");
    let results = p["results"].as_array().expect("results");
    assert!(!results.is_empty(), "must have probe results");
    // Mock is H1-only → every probe should record an h2_error.
    let h2_errs = p["h2_errors"].as_u64().unwrap_or(0);
    assert!(
        h2_errs > 0,
        "H1-only mock must produce h2_errors > 0: {p}"
    );
    // Every probe row has BOTH H1 and H2 curl reproducers.
    for r in results {
        let h1c = r["h1_curl_cmd"].as_str().expect("h1_curl_cmd");
        let h2c = r["h2_curl_cmd"].as_str().expect("h2_curl_cmd");
        assert!(h1c.contains("--http1.1"), "got: {h1c}");
        assert!(h2c.contains("--http2"), "got: {h2c}");
    }
}

#[test]
fn h2_diff_against_unreachable_target_still_exits_cleanly() {
    let (code, _stdout, _stderr) = wafrift(&[
        "h2-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "1",
    ]);
    // Informational tool — exits 0 even when both H1 and H2 fail.
    assert_eq!(code, 0, "h2-diff is informational; should exit 0 even on transport failure");
}

#[test]
fn h2_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["h2-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
    assert!(stdout.contains("--payload"), "stdout:\n{stdout}");
}

#[test]
fn h2_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("h2-diff"),
        "h2-diff must appear in top-level help"
    );
}
