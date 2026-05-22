//! End-to-end test for `wafrift method-diff`.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_method_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // PROPFIND returns a much longer body (mod_dav style).
                // Everything else returns the short baseline.
                let propfind = req.starts_with("PROPFIND ");
                let body = if propfind {
                    "<html>WebDAV property listing — long response distinguishable from GET baseline</html>"
                } else {
                    "<html>ok</html>"
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
fn method_diff_finds_propfind_divergence_on_mod_dav_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_method_mock());
    let (code, stdout, stderr) = wafrift(&[
        "method-diff",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "method-diff exit 0 — stderr:\n{stderr}");
    let p: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse");
    let total_div = p["divergences"]["high"].as_u64().unwrap_or(0)
        + p["divergences"]["medium"].as_u64().unwrap_or(0);
    assert!(total_div > 0, "PROPFIND must diverge against mod_dav mock: {p}");

    let results = p["results"].as_array().expect("results array");
    // Each probe carries curl_cmd with the variant method.
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd");
        assert!(curl.starts_with("curl -i -X "), "got: {curl}");
    }
}

#[test]
fn method_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, _stderr) = wafrift(&[
        "method-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(code, 1, "unreachable target must exit 1");
}

#[test]
fn method_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["method-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
    assert!(stdout.contains("--concurrency"), "stdout:\n{stdout}");
}

#[test]
fn method_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("method-diff"),
        "method-diff must appear in top-level help"
    );
}
