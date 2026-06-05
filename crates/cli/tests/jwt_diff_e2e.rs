//! End-to-end test for `wafrift jwt-diff`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

async fn spawn_jwt_mock() -> std::net::SocketAddr {
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
                // VULNERABLE mock: accepts any well-shaped bearer
                // token, returns extra body for tokens whose decoded
                // header contains "none" (a permissive-validator
                // simulation).
                let auth = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or("");
                // crude check: token after "Bearer " has three .-segments
                let well_shaped = auth.contains("Bearer ") && auth.matches('.').count() >= 2;
                let body = if well_shaped {
                    r#"{"data":"served"}"#
                } else {
                    r#"{"data":"reject"}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    common::wait_for_server(addr);
    addr
}

// HS256 baseline JWT (header.payload.fakesig) — well-formed enough
// for the runner to accept and mutate.
const BASELINE_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTkwMDAwMDAwMH0.fake-signature";

#[test]
#[serial_test::serial]
fn jwt_diff_against_permissive_mock_succeeds_and_emits_results() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_jwt_mock());
    let (code, stdout, stderr) = wafrift(&[
        "jwt-diff",
        &format!("http://{addr}/api/me"),
        "--token",
        BASELINE_JWT,
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "jwt-diff exit 0 — stderr:\n{stderr}");
    let p: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let results = p["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "must have probe results");
    // Each probe should carry a curl reproducer with Bearer header.
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd");
        assert!(curl.contains("Authorization: Bearer"), "got: {curl}");
    }
}

#[test]
fn jwt_diff_rejects_non_jwt_token_with_exit_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "jwt-diff",
        "http://127.0.0.1:65500/",
        "--token",
        "not-a-jwt",
        "--format",
        "json",
    ]);
    assert_eq!(code, 2, "non-jwt token must exit 2 — stderr:\n{stderr}");
}

#[test]
fn jwt_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, _stderr) = wafrift(&[
        "jwt-diff",
        "http://127.0.0.1:1/",
        "--token",
        BASELINE_JWT,
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn jwt_diff_help_documents_token_flag() {
    let (code, stdout, _) = wafrift(&["jwt-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--token"), "stdout:\n{stdout}");
}

#[test]
// jwt-diff consolidated under `wafrift diff jwt` (2026-05). LAW 2: flat
// alias must keep working forever.
fn jwt_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "jwt", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff jwt --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["jwt-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift jwt-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}
