//! End-to-end tests for `wafrift replay`.
//!
//! `replay` fires a single HTTP GET (or POST) with the operator's
//! payload re-encoded through a named technique chain, then reports
//! whether the target blocked or passed the request.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. replay appears in top-level help.
//! 3. JSON output has the required schema (schema_version, status, blocked,
//!    techniques, repro_curl, payload, param, method).
//! 4. repro_curl starts with "curl" and contains the target URL.
//! 5. A mock that returns 200 → blocked=false.
//! 6. A mock that returns 403 → blocked=true.
//! 7. Missing required args exit non-zero.
//! 8. Unknown technique selector exits non-zero.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

/// Spawn a mock that returns `status_code` for every request.
async fn spawn_status_mock(status_code: u16, body: &'static str) -> std::net::SocketAddr {
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
                let reason = match status_code {
                    200 => "OK",
                    403 => "Forbidden",
                    _ => "STATUS",
                };
                let resp = format!(
                    "HTTP/1.1 {status_code} {reason}\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    // Probe-until-ready using stdlib connect (avoids reactor saturation).
    {
        common::wait_for_server(addr);
    }
    addr
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn replay_help_documents_options() {
    let (code, stdout, _) = wafrift(&["replay", "--help"]);
    assert_eq!(code, 0, "replay --help must exit 0");
    assert!(stdout.contains("--target"), "stdout: {stdout}");
    assert!(stdout.contains("--payload"), "stdout: {stdout}");
    assert!(stdout.contains("--technique"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
}

#[test]
fn replay_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("replay"),
        "replay must appear in top-level help: {stdout}"
    );
}

// ── JSON schema ───────────────────────────────────────────────────────────

#[test]
fn replay_json_output_has_required_fields() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_status_mock(200, "ok"));

    let (code, stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        &format!("http://{addr}/"),
        "--payload",
        "union select",
        "--technique",
        "encoding/url/single",
        "--format",
        "json",
        "--quiet",
    ]);
    assert_eq!(code, 0, "replay must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");

    assert_eq!(
        v["schema_version"].as_u64().unwrap_or(0),
        1,
        "schema_version must be 1: {v}"
    );
    assert!(v["status"].is_number(), "status must be a number: {v}");
    assert!(v["blocked"].is_boolean(), "blocked must be boolean: {v}");
    assert!(v["payload"].is_string(), "payload must be string: {v}");
    assert!(v["param"].is_string(), "param must be string: {v}");
    assert!(v["method"].is_string(), "method must be string: {v}");
    assert!(v["techniques"].is_array(), "techniques must be array: {v}");
    assert!(
        v["repro_curl"].is_string(),
        "repro_curl must be string: {v}"
    );
}

#[test]
fn replay_repro_curl_starts_with_curl_and_contains_target() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_status_mock(200, "ok"));

    let (code, stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        &format!("http://{addr}/"),
        "--payload",
        "test-payload",
        "--technique",
        "encoding/url/single",
        "--format",
        "json",
        "--quiet",
    ]);
    assert_eq!(code, 0, "replay must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let repro = v["repro_curl"].as_str().expect("repro_curl string");

    // The curl reproducer may contain comment lines (# Techniques: …) before
    // the actual `curl` command.  Find the first non-comment, non-empty line.
    let curl_line = repro
        .lines()
        .find(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .unwrap_or("");
    assert!(
        curl_line.starts_with("curl"),
        "repro_curl command line must start with 'curl': {repro}"
    );
    assert!(
        repro.contains(&addr.ip().to_string()),
        "repro_curl must contain the target IP: {repro}"
    );
}

// ── blocked field reflects HTTP status ───────────────────────────────────

#[test]
fn replay_200_response_sets_blocked_false() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_status_mock(200, "welcome"));

    let (code, stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        &format!("http://{addr}/"),
        "--payload",
        "test",
        "--technique",
        "encoding/url/single",
        "--format",
        "json",
        "--quiet",
    ]);
    assert_eq!(code, 0, "replay must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"].as_u64().unwrap_or(0),
        200,
        "status must be 200: {v}"
    );
    assert!(
        !v["blocked"].as_bool().unwrap_or(true),
        "200 response must set blocked=false: {v}"
    );
}

#[test]
fn replay_403_response_sets_blocked_true() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_status_mock(403, "forbidden"));

    let (code, stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        &format!("http://{addr}/"),
        "--payload",
        "union select",
        "--technique",
        "encoding/url/single",
        "--format",
        "json",
        "--quiet",
    ]);
    // replay exits 2 when the WAF blocks (blocked=true) — this is the
    // designed behaviour so CI gates can distinguish "bypassed" (exit 0)
    // from "blocked" (exit 2).
    assert_eq!(code, 2, "blocked replay must exit 2; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"].as_u64().unwrap_or(0),
        403,
        "status must be 403: {v}"
    );
    assert!(
        v["blocked"].as_bool().unwrap_or(false),
        "403 response must set blocked=true: {v}"
    );
}

// ── Error paths ───────────────────────────────────────────────────────────

#[test]
fn replay_missing_target_exits_nonzero() {
    let (code, _stdout, stderr) = wafrift(&[
        "replay",
        "--payload",
        "test",
        "--technique",
        "encoding/url/single",
    ]);
    assert_ne!(
        code, 0,
        "missing --target must exit non-zero; stderr: {stderr}"
    );
}

#[test]
fn replay_missing_payload_exits_nonzero() {
    let (code, _stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        "http://127.0.0.1:1/",
        "--technique",
        "encoding/url/single",
    ]);
    assert_ne!(
        code, 0,
        "missing --payload must exit non-zero; stderr: {stderr}"
    );
}

#[test]
fn replay_missing_technique_source_exits_nonzero() {
    // All three technique sources omitted (--technique / --from-host / --from-waf).
    let (code, _stdout, stderr) = wafrift(&[
        "replay",
        "--target",
        "http://127.0.0.1:1/",
        "--payload",
        "test",
        "--format",
        "json",
    ]);
    assert_ne!(
        code, 0,
        "missing technique source must exit non-zero; stderr: {stderr}"
    );
}
