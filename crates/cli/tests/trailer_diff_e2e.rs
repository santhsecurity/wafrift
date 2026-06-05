//! End-to-end tests for `wafrift trailer-diff`.
//!
//! Spins up a raw TCP mock server that reads chunked-encoded POST bytes
//! and verifies that:
//!
//! 1. The baseline request arrives WITHOUT the trailer field.
//! 2. The attack request arrives WITH the trailer field.
//!
//! We test OUR side — that wafrift sends the right bytes. We do NOT
//! validate WAF behaviour (there is no WAF in these tests; the mock
//! acts only as the origin).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod common;
use common::wafrift;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Spawn a mock server that captures the raw bytes of ONE request, sends
/// a fixed 200 response, then shuts down the accepted connection. The
/// captured bytes are sent back over the returned channel.
async fn spawn_capturing_mock() -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4);

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = b"<html>ok</html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
                let _ = tx.send(raw).await;
            });
        }
    });

    // Settle: wait until the listener accepts a connection, then drain
    // that probe from the channel so the test only sees real wafrift
    // requests. Using a TCP connect-poll instead of a fixed sleep avoids
    // the Windows loopback race, but we must drain the probe hit because
    // the channel-based mock counts every accepted connection.
    // R66 pass-21 §7 DEDUP: shared poll-until-ready helper. The hit
    // drained from `rx` after readiness is preserved — trailer-diff
    // mocks count every accepted connection on `rx` and we must
    // discard the probe so test assertions only see wafrift's
    // production requests.
    common::wait_for_server(addr);
    let _ = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    (addr, rx)
}

// ── Test 1: attack request carries the trailer ───────────────────────────────

#[test]
fn trailer_diff_sends_trailer_in_attack_request() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();

    rt.block_on(async {
        let (addr, mut rx) = spawn_capturing_mock().await;

        // trailer-diff fires two requests in sequence:
        // 1. baseline (no trailer)
        // 2. attack (with trailer)
        // We need to capture BOTH, so we spawn two mock handlers.
        // The simplest approach: run with --format json and inspect
        // the exit code, then verify the captured bytes.

        let handle = tokio::spawn(async move {
            let baseline_raw = tokio::time::timeout(Duration::from_secs(30), rx.recv())
                .await
                .expect("baseline timeout waiting for wafrift subprocess")
                .expect("baseline recv");

            let attack_raw = tokio::time::timeout(Duration::from_secs(30), rx.recv())
                .await
                .expect("attack timeout waiting for wafrift subprocess")
                .expect("attack recv");

            (baseline_raw, attack_raw)
        });

        let (code, stdout, stderr) = wafrift(&[
            "trailer-diff",
            "--url",
            &format!("http://{addr}/"),
            "--header-name",
            "X-Original-URL",
            "--payload",
            "' OR 1=1--",
            "--format",
            "json",
            "--timeout-secs",
            "30",
        ]);

        let (baseline_raw, attack_raw) = handle.await.unwrap();

        // Exit code must be 0.
        assert_eq!(code, 0, "trailer-diff should exit 0; stderr:\n{stderr}");

        // Baseline: declares Trailer header, but the full request must NOT
        // contain `X-Original-URL:` as a trailer value.  The baseline
        // terminates `0\r\n\r\n` so there is nothing after the terminal chunk.
        assert!(
            baseline_raw.contains("Trailer: X-Original-URL"),
            "baseline must declare Trailer: X-Original-URL; got:\n{baseline_raw}"
        );
        // The baseline ends with the terminal chunk + empty trailer section
        // (`0\r\n\r\n`).  The only `X-Original-URL` text that should appear is
        // the `Trailer: X-Original-URL` declaration line; there must be no
        // `X-Original-URL:` (with value) in the request.
        let baseline_trailer_value_count = baseline_raw
            .lines()
            .filter(|l| {
                let lo = l.to_ascii_lowercase();
                lo.starts_with("x-original-url:") && !lo.starts_with("trailer:")
            })
            .count();
        assert_eq!(
            baseline_trailer_value_count, 0,
            "baseline must NOT send X-Original-URL as a trailer value; got:\n{baseline_raw}"
        );

        // Attack: the trailer field value MUST be present somewhere in the
        // captured bytes — wafrift appended it after the terminal chunk.
        assert!(
            attack_raw.contains("Trailer: X-Original-URL"),
            "attack must declare Trailer: X-Original-URL; got:\n{attack_raw}"
        );
        // Find a line that looks like `X-Original-URL: ' OR 1=1--` (the
        // trailer value line, not the `Trailer:` declaration).
        let has_trailer_value = attack_raw.lines().any(|l| {
            let lo = l.to_ascii_lowercase();
            lo.starts_with("x-original-url:") && l.contains("1=1")
        });
        assert!(
            has_trailer_value,
            "attack must send X-Original-URL: ' OR 1=1-- as trailer; got:\n{attack_raw}"
        );

        // JSON output must parse cleanly.
        let parsed: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("JSON parse; stdout:\n{stdout}");
        assert!(
            parsed["severity"].as_str().is_some(),
            "severity field must be present"
        );
        assert!(
            parsed["baseline"].is_object(),
            "baseline object must be present"
        );
        assert!(
            parsed["attack"].is_object(),
            "attack object must be present"
        );
        assert!(
            parsed["divergences"].is_object(),
            "divergences object must be present"
        );
    });
}

// ── Test 2: unreachable target exits 1 ──────────────────────────────────────

#[test]
fn trailer_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "trailer-diff",
        "--url",
        "http://127.0.0.1:1/",
        "--timeout-secs",
        "2",
        "--format",
        "json",
    ]);
    assert_eq!(code, 1, "unreachable target must exit 1; stderr:\n{stderr}");
}
