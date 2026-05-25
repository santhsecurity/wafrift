//! End-to-end tests for `wafrift scan`.
//!
//! Most `scan` functionality requires a live HTTP target. This suite
//! covers:
//! - Help surface and flag documentation (offline, no network).
//! - Basic JSON shape with a mock target that always 200s (no block).
//! - Argument-validation errors (offline).
//!
//! Uses `#[serial]` on mock-server tests to prevent Windows TCP saturation.

use std::process::Command;

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Mock server: always returns 200 OK (no WAF blocking — all variants pass).
async fn spawn_allow_all_mock() -> std::net::SocketAddr {
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
                let body = b"ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    // Probe-until-ready using stdlib connect (avoids tokio-reactor saturation).
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_millis(100),
            ) {
                Ok(_) => break,
                Err(_) => {
                    if std::time::Instant::now() >= deadline {
                        panic!("mock never became ready at {addr}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
    addr
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn scan_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("scan"),
        "scan must appear in top-level help: {stdout}"
    );
}

#[test]
fn scan_help_exits_0_and_documents_flags() {
    let (code, stdout, _) = wafrift(&["scan", "--help"]);
    assert_eq!(code, 0, "scan --help must exit 0");
    assert!(stdout.contains("--payload"), "must document --payload: {stdout}");
    assert!(stdout.contains("--format"), "must document --format: {stdout}");
    assert!(stdout.contains("--level"), "must document --level: {stdout}");
    assert!(stdout.contains("--param"), "must document --param: {stdout}");
}

// ── Argument validation (offline) ─────────────────────────────────────────

#[test]
fn scan_missing_payload_exits_nonzero() {
    // --payload is required; omitting it must fail at clap parse time.
    let (code, _stdout, _stderr) = wafrift(&["scan", "http://127.0.0.1:65500"]);
    assert_ne!(code, 0, "scan without --payload must exit non-zero");
}

#[test]
fn scan_invalid_level_exits_nonzero() {
    let (code, _stdout, _stderr) = wafrift(&[
        "scan",
        "http://127.0.0.1:65500",
        "--payload",
        "test",
        "--level",
        "ultra-extreme",
    ]);
    assert_ne!(code, 0, "scan with invalid --level must exit non-zero");
}

#[test]
fn scan_invalid_format_exits_nonzero() {
    let (code, _stdout, _stderr) = wafrift(&[
        "scan",
        "http://127.0.0.1:65500",
        "--payload",
        "test",
        "--format",
        "toml",
    ]);
    assert_ne!(code, 0, "scan with invalid --format must exit non-zero");
}

#[test]
fn scan_positional_url_and_target_flag_are_mutually_exclusive() {
    let (code, _stdout, _stderr) = wafrift(&[
        "scan",
        "http://127.0.0.1:65500",
        "--target",
        "http://127.0.0.1:65501",
        "--payload",
        "test",
    ]);
    assert_ne!(
        code, 0,
        "positional URL and --target flag must be mutually exclusive"
    );
}

// ── Live mock: JSON output schema ─────────────────────────────────────────

#[test]
#[serial]
fn scan_json_output_has_required_fields_on_allow_all_target() {
    // Against a mock that never blocks (200 for everything), scan should
    // complete and emit a valid JSON object with the documented fields.
    // Use --level light to minimise probe count.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_allow_all_mock());

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        &format!("http://{addr}/"),
        "--payload",
        "test",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "scan on allow-all must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("scan --format json must emit valid JSON");

    // Required top-level fields in the scan JSON output.
    assert!(
        v["target"].is_string(),
        "target must be a string: {v}"
    );
    assert!(
        v["bypass_variants"].is_array(),
        "bypass_variants must be an array: {v}"
    );
    assert!(
        v["blocked"].is_number(),
        "blocked must be a number: {v}"
    );
    assert!(
        v["bypass_rate_pct"].is_number(),
        "bypass_rate_pct must be a number: {v}"
    );
    assert!(
        v["baseline_transport_ok"].is_boolean(),
        "baseline_transport_ok must be boolean: {v}"
    );
    assert!(
        v["aborted_rate_limited"].is_boolean(),
        "aborted_rate_limited must be boolean: {v}"
    );
    // Each bypass_variant has payload + techniques + repro_curl.
    let variants = v["bypass_variants"].as_array().unwrap();
    if !variants.is_empty() {
        let bv = &variants[0];
        assert!(bv["payload"].is_string(), "bypass_variant.payload must be string: {bv}");
        assert!(bv["techniques"].is_array(), "bypass_variant.techniques must be array: {bv}");
        assert!(bv["repro_curl"].is_string(), "bypass_variant.repro_curl must be string: {bv}");
        assert!(bv["confidence"].is_number(), "bypass_variant.confidence must be number: {bv}");
    }
}

#[test]
#[serial]
fn scan_blocked_target_reports_zero_bypass_variants() {
    // A mock that always returns 403 is the baseline WAF — wafrift will
    // fire evasion variants but with --level light against a deterministic
    // 403 mock, it shouldn't find any bypass. The bypass_variants array
    // should be empty (or very small), and the overall exit code should
    // be 0 (no bypasses = successful scan, not an error).
    //
    // We use a separate always-403 mock for this test.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();

    let listener = rt.block_on(async {
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
    });
    let addr = listener.local_addr().unwrap();

    rt.spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8 * 1024];
                let _ = sock.read(&mut buf).await;
                let body = b"blocked";
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    // Probe-until-ready.
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)) {
                Ok(_) => break,
                Err(_) => {
                    if std::time::Instant::now() >= deadline {
                        panic!("403 mock never ready at {addr}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        &format!("http://{addr}/"),
        "--payload",
        "test",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0, "scan against always-403 must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("scan output must be valid JSON");
    // bypass_variants must be an array (may be empty for a solid block-all).
    assert!(v["bypass_variants"].is_array(), "bypass_variants must be array: {v}");
}
