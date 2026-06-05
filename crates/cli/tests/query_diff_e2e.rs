//! End-to-end test for `wafrift query-diff`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

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
    // R66 pass-21 §7 DEDUP: shared poll-until-ready helper.
    common::wait_for_server(addr);
    addr
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

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
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
    assert_eq!(
        code, 1,
        "unreachable target must exit 1 — stderr:\n{stderr}"
    );
}

#[test]
fn query_diff_help_documents_param_flag() {
    let (code, stdout, _) = wafrift(&["query-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--param"), "stdout:\n{stdout}");
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
}

#[test]
// query-diff consolidated under `wafrift diff query` (2026-05). LAW 2: flat
// alias must keep working forever.
fn query_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "query", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff query --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["query-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift query-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}
