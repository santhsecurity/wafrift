//! End-to-end test for `wafrift cors-diff`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

async fn spawn_cors_mock() -> std::net::SocketAddr {
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
                let origin = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("origin:"))
                    .and_then(|l| l.split_once(':').map(|x| x.1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let extra = if origin.is_empty() {
                    String::new()
                } else {
                    format!(
                        "Access-Control-Allow-Origin: {origin}\r\n\
                         Access-Control-Allow-Credentials: true\r\n"
                    )
                };
                let body = "{}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
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
fn cors_diff_finds_high_severity_on_reflective_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_cors_mock());
    let (code, stdout, stderr) = wafrift(&[
        "cors-diff",
        &format!("http://{addr}/api/me"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "30",
    ]);
    assert_eq!(code, 0, "cors-diff exit 0 — stderr:\n{stderr}");
    let p: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let high = p["divergences"]["high"].as_u64().unwrap_or(0);
    assert!(
        high > 0,
        "reflective+credentials mock must yield ≥1 high-severity CORS issue: {p}"
    );
}

#[test]
fn cors_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["cors-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"));
}

#[test]
// cors-diff consolidated under `wafrift diff cors` (2026-05). LAW 2: flat
// alias must keep working forever.
fn cors_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "cors", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff cors --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["cors-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift cors-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}
