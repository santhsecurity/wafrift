//! End-to-end test for `wafrift cache-diff`.
//!
//! Spawns a mock with a Cloudflare-style cache (returns identical
//! body + CF-Cache-Status: HIT for every request) and verifies the
//! scanner correctly flags the cache-key collisions.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_cache_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8 * 1024];
                let _ = sock.read(&mut buf).await;
                // Identical body + identical cache signal on EVERY
                // request — simulates an aggressive cache where many
                // variants map to one key.
                let body = "<html>cached static asset</html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\
                     CF-Cache-Status: HIT\r\nAge: 42\r\n\r\n{body}",
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
fn cache_diff_flags_cache_key_collisions_on_aggressive_cache_mock() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_cache_mock());

    let (code, stdout, stderr) = wafrift(&[
        "cache-diff",
        &format!("http://{addr}/path"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "cache-diff should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse");
    assert_eq!(parsed["baseline_status"], 200);
    // Cache signal should be picked up — mock emits CF-Cache-Status + Age.
    let sig = parsed["baseline_cache_signal"]
        .as_str()
        .expect("baseline_cache_signal string");
    assert!(sig.contains("cf-cache-status=HIT"), "got: {sig}");
    assert!(sig.contains("age=42"), "got: {sig}");

    let results = parsed["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "must have probe results");

    // Mock returns IDENTICAL body for every request → every probe
    // should body-hash-match baseline → severity = high.
    let high_count = parsed["divergences"]["high"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        high_count > 0,
        "aggressive-cache mock must yield ≥1 high-severity collision: {parsed}"
    );

    // Every probe row carries a curl reproducer.
    for r in results {
        let curl = r["curl_cmd"].as_str().expect("curl_cmd string");
        assert!(curl.starts_with("curl -i"), "got: {curl}");
    }
}

#[test]
fn cache_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "cache-diff",
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
fn cache_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["cache-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--param"), "stdout:\n{stdout}");
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
}

#[test]
fn cache_diff_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("cache-diff"),
        "cache-diff must appear in top-level help"
    );
}
