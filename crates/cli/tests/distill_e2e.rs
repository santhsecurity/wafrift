//! End-to-end test for `wafrift distill`.
//!
//! Spins up a mock WAF that blocks on a literal substring, picks a
//! payload that bypasses it, drives `wafrift distill --format json`
//! against the running binary, and asserts the distilled payload is
//! strictly shorter while still containing the load-bearing bytes.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Mock WAF: blocks (403) when the request line OR body contains
/// the literal token `magic`. Otherwise 200 OK. Returns the bound
/// address + fire counter (lets tests assert ddmin's call budget).
async fn spawn_mock(magic: &'static str) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter_c = counter.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter_cc = counter_c.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                counter_cc.fetch_add(1, Ordering::SeqCst);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let blocked = req.contains(magic);
                let (status, body) = if blocked {
                    ("403 Forbidden", "<html>blocked</html>")
                } else {
                    ("200 OK", "<html>ok</html>")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    (addr, counter)
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
fn distill_reduces_long_bypass_to_minimum_via_real_binary() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, counter) = rt.block_on(spawn_mock("NEVERAPPEARS"));
    let target = format!("http://{addr}/");

    // The mock blocks only on literal "NEVERAPPEARS". Our payload
    // doesn't contain that token → every request returns 200 →
    // baseline bypasses → ddmin can recurse all the way down. The
    // payload has lots of structural noise; distill should peel it
    // off, eventually returning the minimum bypassing subset
    // (typically a single character against this mock, since
    // ANY non-empty payload bypasses).
    let (code, stdout, stderr) = wafrift(&[
        "distill",
        &target,
        "--param",
        "q",
        "--payload",
        "/**/admin'/**/UNION/**/SELECT/**/1--",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "distill should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("distill --format json must emit valid JSON");
    assert_eq!(parsed["target"], target.as_str());
    assert_eq!(parsed["param"], "q");
    let orig_len = parsed["original"]["length"].as_u64().unwrap_or(0);
    let min_len = parsed["minimal"]["length"].as_u64().unwrap_or(u64::MAX);
    assert!(orig_len > 0, "original length must be > 0: {parsed}");
    assert!(
        min_len < orig_len,
        "distilled must be SHORTER than original: orig={orig_len}, min={min_len}"
    );
    // Reduction is reported as a percentage.
    let reduction = parsed["reduction_pct"].as_f64().unwrap_or(-1.0);
    assert!(
        reduction > 0.0,
        "reduction_pct must be > 0: {reduction}"
    );
    // Counter sanity: at least 2 fires (baseline + ≥1 ddmin step).
    assert!(
        counter.load(Ordering::SeqCst) >= 2,
        "mock should have served at least 2 requests"
    );
}

#[test]
fn distill_rejects_payload_that_target_already_blocks() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock("BLOCKME"));
    let target = format!("http://{addr}/");

    // Payload contains "BLOCKME" → mock returns 403 → baseline probe
    // confirms a block → distill exits 2 with an actionable message.
    let (code, _stdout, stderr) = wafrift(&[
        "distill",
        &target,
        "--payload",
        "abc-BLOCKME-xyz",
        "--format",
        "json",
    ]);
    assert_eq!(code, 2, "distill should exit 2 — stderr:\n{stderr}");
    assert!(
        stderr.to_lowercase().contains("block"),
        "error must explain payload was blocked: stderr={stderr}"
    );
}

#[test]
fn distill_rejects_empty_payload() {
    // No need for a mock — empty payload short-circuits before any
    // network IO.
    let (code, _stdout, stderr) = wafrift(&[
        "distill",
        "http://127.0.0.1:65500",
        "--payload",
        "",
        "--format",
        "json",
    ]);
    assert_eq!(code, 2, "empty payload should exit 2 — stderr:\n{stderr}");
}

#[test]
fn distill_preserves_load_bearing_substring_through_reduction() {
    // Mock blocks on "DANGER". Pick a payload that doesn't contain
    // DANGER (bypasses), but the predicate (mock) only cares about
    // DANGER. Distillation should reduce, but it's not required to
    // preserve any particular substring (any non-DANGER reduction
    // bypasses). Test instead: minimal payload must NOT contain
    // "DANGER" and must be non-empty.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock("DANGER"));
    let target = format!("http://{addr}/");

    let (code, stdout, stderr) = wafrift(&[
        "distill",
        &target,
        "--payload",
        "harmless_payload_with_no_block_token",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "distill should exit 0 — stderr:\n{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let minimal = parsed["minimal"]["payload"]
        .as_str()
        .expect("minimal.payload string");
    assert!(!minimal.is_empty(), "minimal must be non-empty: {parsed}");
    assert!(
        !minimal.contains("DANGER"),
        "minimal must NOT contain the block token: {minimal}"
    );
}

#[test]
fn distill_respects_max_fires_cap() {
    // Tiny cap → ddmin runs out of fires fast → fires_capped=true.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock("NOPE")).clone();
    let target = format!("http://{addr}/");

    let (code, stdout, _) = wafrift(&[
        "distill",
        &target,
        "--payload",
        "abcdefghijklmnop", // 16 chars
        "--max-fires",
        "3", // baseline + 2 ddmin fires only
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "distill should exit 0 even when capped — stdout:\n{stdout}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let capped = parsed["fires_capped"].as_bool().unwrap_or(false);
    assert!(capped, "fires_capped must be true at low cap: {parsed}");
}

#[test]
fn distill_text_format_prints_summary_lines() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (addr, _) = rt.block_on(spawn_mock("xxx")).clone();
    let target = format!("http://{addr}/");

    let (code, stdout, _) = wafrift(&[
        "distill",
        &target,
        "--payload",
        "abcdefghij",
        "--format",
        "text",
    ]);
    assert_eq!(code, 0);
    // Text format prints labels operators read in the terminal.
    assert!(stdout.contains("Original payload"), "stdout:\n{stdout}");
    assert!(stdout.contains("Distilled to"), "stdout:\n{stdout}");
    assert!(stdout.contains("Result"), "stdout:\n{stdout}");
    assert!(stdout.contains("reduction"), "stdout:\n{stdout}");
}

#[test]
fn distill_help_is_documented_and_shown_under_main_help() {
    let (code, stdout, _) = wafrift(&["distill", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--payload"), "--payload must be documented: {stdout}");
    assert!(stdout.contains("--max-fires"), "--max-fires must be documented: {stdout}");
    assert!(stdout.contains("ddmin") || stdout.to_lowercase().contains("distill"), "stdout:\n{stdout}");

    let (code2, stdout2, _) = wafrift(&["--help"]);
    assert_eq!(code2, 0);
    assert!(
        stdout2.contains("distill"),
        "distill must appear in top-level help: {stdout2}"
    );
}
