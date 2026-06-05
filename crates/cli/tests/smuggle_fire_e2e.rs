//! End-to-end tests for `wafrift smuggle-fire`.
//!
//! Tests use a minimal TCP mock server that simulates a WAF:
//!   - default: 403 Forbidden (baseline)
//!   - any request with the `X-Wafrift-Canary` header: 200 OK
//!
//! This lets tests verify the bypass-signal classification logic
//! end-to-end against real HTTP responses.

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

/// Spawn a mock server that returns:
/// - 403 Forbidden by default (baseline)
/// - 200 OK if the request carries an `X-Wafrift-Canary` header
async fn spawn_canary_bypass_mock() -> std::net::SocketAddr {
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
                let has_canary = req
                    .lines()
                    .any(|l| l.to_ascii_lowercase().starts_with("x-wafrift-canary:"));
                let (status, reason, body): (&str, &str, &str) = if has_canary {
                    ("200", "OK", "bypassed")
                } else {
                    ("403", "Forbidden", "blocked-by-mock-waf")
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n\
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

/// Spawn a mock that always returns 403 — used to test the
/// "no bypass" path (all probes report bypass_signal=none).
async fn spawn_always_block_mock() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8 * 1024];
                let _ = sock.read(&mut buf).await.unwrap_or(0);
                let body = "blocked";
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
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

/// Spawn a mock that ECHOES the `X-Wafrift-Canary` header value into
/// its 200 response body (simulating a reflecting origin reached past
/// the WAF). Requests with no canary header get a 403 baseline whose
/// body never contains any token.
async fn spawn_canary_reflect_mock() -> std::net::SocketAddr {
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
                let canary = req.lines().find_map(|l| {
                    let (name, val) = l.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("x-wafrift-canary") {
                        Some(val.trim().to_string())
                    } else {
                        None
                    }
                });
                let (status, reason, body) = match canary {
                    Some(token) => ("200", "OK", format!("reflected:{token}")),
                    None => ("403", "Forbidden", "blocked-no-token".to_string()),
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n\
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

/// Spawn a mock that echoes the `X-Wafrift-Canary` value into a
/// RESPONSE HEADER (`X-Echoed-Canary`) while keeping the body free of
/// the token — exercises header-surface reflection that body-only
/// scanning would miss.
async fn spawn_canary_header_reflect_mock() -> std::net::SocketAddr {
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
                let canary = req.lines().find_map(|l| {
                    let (name, val) = l.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("x-wafrift-canary")
                        .then(|| val.trim().to_string())
                });
                let body = "ok-body-has-no-token";
                let resp = match canary {
                    Some(token) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                         X-Echoed-Canary: {token}\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        let b = "blocked";
                        format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        )
                    }
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    common::wait_for_server(addr);
    addr
}

// ── Help + CLI surface ──────────────────────────────────────────

#[test]
fn smuggle_fire_help_lists_target_and_safety_flags() {
    let (code, stdout, _stderr) = wafrift(&["smuggle-fire", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--origin-ip"));
    assert!(stdout.contains("--family"));
    assert!(stdout.contains("--i-have-permission"));
    assert!(stdout.contains("--timeout-secs"));
    assert!(stdout.contains("--delay-ms"));
    assert!(stdout.contains("--limit"));
    assert!(stdout.contains("--canary-header"));
}

#[test]
fn smuggle_fire_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("smuggle-fire"));
}

#[test]
fn smuggle_fire_target_required() {
    let (code, _stdout, stderr) = wafrift(&["smuggle-fire"]);
    assert_ne!(code, 0, "missing --target must exit non-zero");
    assert!(
        stderr.contains("required") || stderr.contains("--target"),
        "stderr should mention --target: {stderr}"
    );
}

// ── Permission gate ─────────────────────────────────────────────

#[test]
fn smuggle_fire_refuses_non_allowlist_target_without_permission() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        "https://random-non-allowlist-host.example.com/",
        "--family",
        "cookie",
        "--limit",
        "1",
    ]);
    assert_eq!(code, 2, "permission gate refuses with exit 2");
    assert!(
        stderr.contains("wafrift refuses"),
        "stderr must explain refusal: {stderr}"
    );
}

// ── Live firing against mock ────────────────────────────────────

#[test]
#[serial]
fn smuggle_fire_emits_one_json_report_per_fired_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "5",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "exactly --limit=3 reports emitted");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert!(v["technique"].as_str().unwrap().starts_with("cookie."));
        assert_eq!(v["canary"].as_str().unwrap().len(), 16);
        assert!(v["status"].is_u64());
        assert!(v["body_len"].is_u64());
        assert!(v["latency_ms"].is_u64());
        assert!(v["baseline_status"].is_u64());
        assert!(v["baseline_body_len"].is_u64());
        assert!(v["bypass_signal"].is_string());
    }
}

#[test]
#[serial]
fn smuggle_fire_reports_none_when_mock_blocks_every_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // Always-block mock returns 403 + same body to every request -> no divergence.
        assert_eq!(v["bypass_signal"].as_str().unwrap(), "none", "line: {line}");
        assert_eq!(v["status"].as_u64().unwrap(), 403);
        assert_eq!(v["baseline_status"].as_u64().unwrap(), 403);
    }
}

// ── --origin-ip WAF go-around ────────────────────────────────────

/// `--origin-ip` pins the target Host to a supplied origin IP at the
/// connector, so probes connect to the origin while keeping the real
/// Host + SNI. Proof: target a `.invalid` host (RFC 6761 — guaranteed
/// never to resolve) pinned to the loopback mock. Without the override
/// no probe could connect at all; with it, every probe (carrying the
/// canary header the mock honours) reaches the origin and returns 200.
/// This is the end-to-end §9 wiring test for the flag.
#[test]
#[serial]
fn smuggle_fire_origin_ip_reaches_origin_for_unresolvable_host() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_bypass_mock());
    // Deliberately non-resolvable Host — the ONLY path to the mock is
    // the --origin-ip override pinning it to loopback.
    let url = format!("http://origin-direct-test.invalid:{}/admin", addr.port());
    let ip = addr.ip().to_string();
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--origin-ip",
        &ip,
        "--family",
        "cookie",
        "--limit",
        "2",
        "--delay-ms",
        "0",
        "--canary-header",
        "X-Wafrift-Canary",
        "--i-have-permission",
        "e2e-origin-direct",
    ]);
    assert_eq!(
        code, 0,
        "origin-direct run should succeed; stderr: {stderr}"
    );
    assert!(
        stderr.contains("origin-direct mode"),
        "run must announce origin-direct mode: {stderr}"
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "exactly --limit=2 reports");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        // The probe carried the canary header, so the mock answered 200
        // — only reachable if the .invalid Host was pinned to the origin.
        assert_eq!(
            v["status"].as_u64().unwrap(),
            200,
            "probe must have reached the origin: {line}"
        );
    }
}

/// A malformed `--origin-ip` must fail fast (exit 2) with a message
/// naming the flag — never silently fall back to normal DNS, which
/// would quietly defeat the operator's go-around intent (a silent
/// fallback is the §9 "flag parsed but ignored" anti-pattern).
#[test]
fn smuggle_fire_origin_ip_rejects_malformed_ip() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        "http://127.0.0.1:9/admin",
        "--origin-ip",
        "not-an-ip",
        "--family",
        "cookie",
        "--limit",
        "1",
    ]);
    assert_eq!(
        code, 2,
        "malformed --origin-ip must exit 2; stderr: {stderr}"
    );
    assert!(
        stderr.contains("origin-ip"),
        "error must name the offending flag: {stderr}"
    );
}

#[test]
#[serial]
fn smuggle_fire_detects_status_divergence_with_canary_header_bypass() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_bypass_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    // Baseline (no canary header) -> 403. Probes (with canary header) -> 200.
    // Every probe should report a divergence signal.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let signal = v["bypass_signal"].as_str().unwrap();
        assert!(
            signal == "status-diverged" || signal == "both-diverged",
            "expected divergence signal, got {signal} for {line}"
        );
        assert_eq!(v["status"].as_u64().unwrap(), 200);
        assert_eq!(v["baseline_status"].as_u64().unwrap(), 403);
    }
}

#[test]
#[serial]
fn smuggle_fire_reports_canary_reflected_when_origin_echoes_token() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_reflect_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // Origin echoed the canary -> strongest signal wins.
        assert_eq!(
            v["bypass_signal"].as_str().unwrap(),
            "canary-reflected",
            "line: {line}"
        );
        // The reflected token must be reported AND equal the probe canary.
        let reflected = v["reflected_canaries"]
            .as_array()
            .expect("reflected_canaries array");
        assert_eq!(reflected.len(), 1, "exactly one reflected token: {line}");
        assert_eq!(
            reflected[0].as_str().unwrap(),
            v["canary"].as_str().unwrap(),
            "reflected token must equal the probe canary: {line}"
        );
    }
    // Summary on stderr must surface a non-zero canary_reflected count.
    let summary_line = stderr
        .lines()
        .find(|l| l.contains("\"kind\":\"summary\""))
        .expect("summary line on stderr");
    let summary: serde_json::Value = serde_json::from_str(summary_line).unwrap();
    assert!(
        summary["canary_reflected"].as_u64().unwrap() >= 1,
        "summary canary_reflected must be >=1: {summary_line}"
    );
    assert!(
        summary["per_signal"]["canary-reflected"].as_u64().unwrap() >= 1,
        "per_signal must tally canary-reflected: {summary_line}"
    );
}

#[test]
#[serial]
fn smuggle_fire_detects_canary_reflected_in_response_header_not_body() {
    // The origin echoes the canary into a response HEADER only; the
    // body never contains it. Header-surface scanning must still flag
    // canary-reflected.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_header_reflect_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty());
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            v["bypass_signal"].as_str().unwrap(),
            "canary-reflected",
            "header echo must flag reflection: {line}"
        );
        let reflected = v["reflected_canaries"].as_array().expect("reflected array");
        assert_eq!(
            reflected[0].as_str().unwrap(),
            v["canary"].as_str().unwrap()
        );
    }
}

#[test]
#[serial]
fn smuggle_fire_no_reflection_without_canary_header_even_if_origin_would_echo() {
    // Without --canary-header the token never hits the wire, so the
    // reflecting mock has nothing to echo -> no canary-reflected
    // signal, and reflected_canaries is omitted from the JSON.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_reflect_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_ne!(
            v["bypass_signal"].as_str().unwrap(),
            "canary-reflected",
            "no token on the wire -> no reflection: {line}"
        );
        assert!(
            v.get("reflected_canaries").is_none(),
            "reflected_canaries must be omitted when empty: {line}"
        );
    }
}

#[test]
#[serial]
fn smuggle_fire_family_filter_restricts_probes_fired() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "auth",
        "--limit",
        "8",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            v["technique"].as_str().unwrap().starts_with("auth."),
            "expected auth.* family: {line}"
        );
    }
}

#[test]
#[serial]
fn smuggle_fire_skips_frame_artifact_families_with_stderr_warning() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    // capsule, quic-datagram, compression are frame families.
    let (code, stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "capsule",
        "--delay-ms",
        "0",
    ]);
    // Filter matches frame family which is excluded -> zero probes -> exit 2.
    assert_eq!(code, 2);
    assert!(stdout.lines().filter(|l| !l.is_empty()).count() == 0);
    assert!(
        stderr.contains("zero non-frame probes"),
        "stderr must explain skip: {stderr}"
    );
}

#[test]
#[serial]
fn smuggle_fire_limit_caps_total_probes_fired() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "",
        "--limit",
        "5",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 5);
}

async fn spawn_echo_path_mock() -> std::net::SocketAddr {
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
                let request_line = req.lines().next().unwrap_or("").to_string();
                let body = request_line;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
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

#[test]
#[serial]
fn smuggle_fire_emits_summary_on_stderr_unless_suppressed() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "2",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    // Find the summary JSON in stderr.
    let summary_line = stderr
        .lines()
        .find(|l| l.contains("\"kind\":\"summary\""))
        .unwrap_or_else(|| panic!("no summary line in stderr: {stderr:?}"));
    let v: serde_json::Value = serde_json::from_str(summary_line).expect("JSON");
    assert_eq!(v["fired"].as_u64().unwrap(), 2);
    assert!(v["per_signal"].is_object());
    assert_eq!(v["baseline_status"].as_u64().unwrap(), 403);
}

#[test]
#[serial]
fn smuggle_fire_no_summary_flag_suppresses_summary_line() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "1",
        "--delay-ms",
        "0",
        "--no-summary",
    ]);
    assert_eq!(code, 0);
    assert!(
        !stderr.contains("\"kind\":\"summary\""),
        "--no-summary must suppress: {stderr:?}"
    );
}

#[test]
#[serial]
fn smuggle_fire_include_reproducer_emits_curl_in_each_report() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/admin");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "2",
        "--delay-ms",
        "0",
        "--include-reproducer",
        "--canary-header",
        "X-Wafrift-Canary",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let curl = v["reproducer_curl"]
            .as_str()
            .expect("reproducer_curl field");
        assert!(curl.starts_with("curl -X "), "expected curl: {curl}");
        assert!(curl.contains("-H 'Cookie:"));
        assert!(curl.contains("-H 'X-Wafrift-Canary:"));
    }
}

#[test]
#[serial]
fn smuggle_fire_without_include_reproducer_omits_reproducer_field() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "1",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        // skip_serializing_if = Option::is_none -> field absent.
        assert!(
            !line.contains("\"reproducer_curl\""),
            "field must be absent without --include-reproducer: {line}"
        );
    }
}

#[test]
#[serial]
fn smuggle_fire_parallel_mode_fires_n_concurrent_probes() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "5",
        "--parallel",
        "4",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 5, "expected --limit=5 reports");
    // Every line must still be valid JSON with the documented shape.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert!(v["technique"].as_str().unwrap().starts_with("cookie."));
        assert!(v["bypass_signal"].is_string());
    }
}

#[test]
#[serial]
fn smuggle_fire_save_bypasses_writes_only_bypassing_reports() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_canary_bypass_mock());
    let url = format!("http://{addr}/");
    let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
    let corpus_path = tmp.path().to_path_buf();
    let (code, _stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--canary-header",
        "X-Wafrift-Canary",
        "--save-bypasses",
        corpus_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let corpus = std::fs::read_to_string(&corpus_path).expect("corpus readable");
    let lines: Vec<&str> = corpus.lines().filter(|l| !l.is_empty()).collect();
    // Canary mock bypasses every probe -> 3 lines saved.
    assert_eq!(
        lines.len(),
        3,
        "expected 3 bypass entries in corpus: {corpus:?}"
    );
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let signal = v["bypass_signal"].as_str().unwrap();
        assert!(
            signal != "none" && signal != "error",
            "corpus must only contain bypasses, got signal={signal}: {line}"
        );
    }
}

#[test]
#[serial]
fn smuggle_fire_save_bypasses_against_blocking_mock_emits_empty_corpus() {
    // Anti-rig: --save-bypasses against a never-bypass mock must
    // produce ZERO entries (not one-per-probe, which would be the
    // bug if the filter is inverted).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");
    let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
    let corpus_path = tmp.path().to_path_buf();
    let (code, _stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "3",
        "--delay-ms",
        "0",
        "--save-bypasses",
        corpus_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let corpus = std::fs::read_to_string(&corpus_path).unwrap_or_default();
    assert!(
        corpus.lines().filter(|l| !l.is_empty()).count() == 0,
        "no bypasses against always-block mock, got: {corpus:?}"
    );
}

#[test]
#[serial]
fn smuggle_fire_prioritize_bypasses_fires_listed_techniques_first() {
    // Build a corpus file with ONE specific cookie technique. Then
    // fire with --prioritize-bypasses and --limit 1 — the prioritized
    // technique must be the one that fires.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/");

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let priority_tech = "cookie.duplicate-name-last-wins";
    let line = serde_json::json!({
        "technique": priority_tech,
        "canary": "ZZZZZZZZZZZZZZZZ",
        "status": 200,
        "body_len": 100,
        "latency_ms": 50,
        "baseline_status": 403,
        "baseline_body_len": 50,
        "bypass_signal": "status-diverged",
    });
    std::fs::write(tmp.path(), format!("{line}\n")).unwrap();

    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "1",
        "--delay-ms",
        "0",
        "--prioritize-bypasses",
        tmp.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let first_line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert_eq!(
        v["technique"].as_str().unwrap(),
        priority_tech,
        "prioritized technique must fire first"
    );
}

#[test]
#[serial]
fn smuggle_fire_prioritize_bypasses_missing_file_exits_1() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        "http://127.0.0.1:1",
        "--family",
        "cookie",
        "--prioritize-bypasses",
        "/tmp/nonexistent-corpus-xyz-wafrift-test.ndjson",
    ]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("failed to load prioritize-bypasses"),
        "stderr must explain: {stderr}"
    );
}

#[test]
#[serial]
fn smuggle_fire_baseline_method_post_sets_correct_baseline_status() {
    // Mock returns 405 Method Not Allowed for POST, 200 OK for GET.
    // With --baseline-method POST, the baseline should show 405.
    let listener_block = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = listener_block.block_on(async {
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
                    let method = req.split_whitespace().next().unwrap_or("?").to_string();
                    let (status, reason, body): (&str, &str, &str) = if method == "POST" {
                        ("405", "Method Not Allowed", "no-post")
                    } else {
                        ("200", "OK", "default-ok-body")
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n\
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
    });
    let url = format!("http://{addr}/");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "cookie",
        "--limit",
        "1",
        "--delay-ms",
        "0",
        "--baseline-method",
        "POST",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    // Baseline was POST -> 405. The cookie probe (a GET) got 200.
    // status-diverged signal expected.
    assert_eq!(v["baseline_status"].as_u64().unwrap(), 405);
    assert_eq!(v["status"].as_u64().unwrap(), 200);
}

#[test]
#[serial]
fn smuggle_fire_baseline_header_propagates_to_baseline_request() {
    // Mock returns 200 OK only when `Cookie: valid=1` is present;
    // 403 otherwise. With --baseline-header passing the cookie,
    // baseline is 200; probes (without the cookie) get 403.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(async {
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
                    let has_valid = req
                        .lines()
                        .any(|l| l.to_ascii_lowercase().contains("cookie: valid=1"));
                    let (status, reason, body): (&str, &str, &str) = if has_valid {
                        ("200", "OK", "authenticated-content")
                    } else {
                        ("403", "Forbidden", "denied")
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n\
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
    });
    let url = format!("http://{addr}/");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "auth",
        "--limit",
        "1",
        "--delay-ms",
        "0",
        "--baseline-header",
        "Cookie: valid=1",
    ]);
    assert_eq!(code, 0);
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    // Baseline (with cookie) -> 200; probe (auth header, no cookie) -> 403.
    assert_eq!(v["baseline_status"].as_u64().unwrap(), 200);
    assert_eq!(v["status"].as_u64().unwrap(), 403);
}

#[test]
#[serial]
fn smuggle_fire_jwt_family_fires_with_bearer_token_in_header() {
    // Mock echoes the request line so we can verify Bearer header
    // arrived intact.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_always_block_mock());
    let url = format!("http://{addr}/api");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "jwt",
        "--limit",
        "3",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "expected at least 1 JWT fire report");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON");
        assert!(v["technique"].as_str().unwrap().starts_with("jwt."));
        // Mock returns 403 for everything -> baseline matches probe.
        assert_eq!(v["bypass_signal"].as_str().unwrap(), "none");
    }
}

#[test]
#[serial]
fn smuggle_fire_path_family_splices_into_url_path() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_echo_path_mock());
    let url = format!("http://{addr}/baseline-path");
    let (code, stdout, _stderr) = wafrift(&[
        "smuggle-fire",
        "--target",
        &url,
        "--family",
        "path",
        "--limit",
        "1",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 0);
    // At least one report — and we can't assert the exact path
    // value in the body because the mock echo includes the
    // request-line which contains the SPLICED path, not the
    // baseline path. The fact that any report came back with a
    // 200 status proves the splice worked.
    let line = stdout.lines().find(|l| !l.is_empty()).expect("at least 1");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["status"].as_u64().unwrap(), 200);
}
