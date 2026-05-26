//! End-to-end tests for `wafrift parser-diff`.
//!
//! All tests except the unreachable-target case run a minimal TCP mock that
//! simulates WAF/origin parser disagreement.  The mock routes requests with
//! a semicolon path-parameter (`/admin;x=y`, `/admin;JSESSIONID=…`) as 200
//! while the baseline `/admin` path returns 403 — exactly the Tomcat-class
//! disagreement `parser-diff` was designed to surface.
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. parser-diff appears in top-level help.
//! 3. JSON format emits the required top-level fields with correct schema.
//! 4. A disagreeing mock produces at least one high-severity divergence.
//! 5. Each divergence carries a curl reproducer.
//! 6. An unreachable target exits 1.
//! 7. --show-equal adds an equals_shown array to the JSON output.
//! 8. Text format (non-quiet) does not emit a JSON object on stdout.

use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Spawn a mock server that simulates the Tomcat semicolon-strip
/// WAF/origin disagreement:
///   - `/admin`          → 403 Forbidden (the WAF-blocked path)
///   - `/admin;…`        → 200 OK   (the WAF lets it through because
///                                    it doesn't recognise the semicolon
///                                    variant as the protected route)
///   - everything else   → 200 OK   (the safe baseline)
///
/// Waits until the OS-level TCP accept queue is open before returning so the
/// wafrift binary can connect immediately.  Uses the stdlib
/// `connect_timeout` probe (not tokio) to avoid reactor saturation when
/// running alongside dozens of other test binaries.
async fn spawn_semicolon_mock() -> std::net::SocketAddr {
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
                // Extract the request-target from the first line.
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();

                // Exact-match `/admin` → WAF-blocks (403)
                // Semicolon-variants → origin serves (200, longer body)
                // Everything else  → origin serves (200, short body)
                let (status, reason, body): (&str, &str, &str) = if path == "/admin" {
                    ("403", "Forbidden", "blocked")
                } else if path.starts_with("/admin;") {
                    ("200", "OK", "admin-panel-content-served-through-semicolon-seam")
                } else {
                    ("200", "OK", "ok")
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
    // Probe until the TCP listen socket is accepting so the wafrift process
    // can connect as soon as it starts.  Uses the OS-level blocking connect
    // rather than tokio's async connect to avoid the reactor-saturation issue
    // that manifests when 20+ test binaries run in parallel on Windows.
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
                        panic!("mock server at {addr} never became ready within 30s");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn parser_diff_help_documents_options() {
    let (code, stdout, _) = wafrift(&["parser-diff", "--help"]);
    assert_eq!(code, 0, "parser-diff --help must exit 0");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
    assert!(stdout.contains("--delay-ms"), "stdout: {stdout}");
    assert!(stdout.contains("--concurrency"), "stdout: {stdout}");
    assert!(stdout.contains("--show-equal"), "stdout: {stdout}");
}

#[test]
fn parser_diff_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("parser-diff"),
        "parser-diff must appear in top-level help: {stdout}"
    );
}

#[test]
fn parser_diff_json_format_emits_required_top_level_fields() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");

    // Top-level structure.
    assert!(v["baseline"].is_object(), "baseline must be an object: {v}");
    assert_eq!(
        v["baseline"]["status"].as_u64().unwrap_or(0),
        403,
        "baseline status must be 403 (WAF-blocked): {v}"
    );
    assert!(
        v["probes_fired"].as_u64().unwrap_or(0) > 0,
        "probes_fired must be > 0: {v}"
    );
    assert!(
        v["divergences"].is_array(),
        "divergences must be an array: {v}"
    );
}

#[test]
fn parser_diff_detects_semicolon_strip_divergence() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    let divergences = v["divergences"].as_array().expect("divergences array");

    assert!(
        !divergences.is_empty(),
        "semicolon-strip mock must produce at least one divergence: {v}"
    );

    // At least one divergence must be the semicolon-strip kind.
    let has_semicolon = divergences
        .iter()
        .any(|d| d["kind"].as_str().unwrap_or("") == "semicolon-strip");
    assert!(
        has_semicolon,
        "at least one divergence must have kind=semicolon-strip: {v}"
    );

    // The semicolon divergence must be high severity (403 → 200 is a status-class flip).
    // parser-diff emits severity in uppercase ("HIGH") consistent with probe_classify.
    let high_semicolon = divergences.iter().any(|d| {
        d["kind"].as_str().unwrap_or("") == "semicolon-strip"
            && matches!(
                d["severity"].as_str().unwrap_or(""),
                "HIGH" | "high"
            )
    });
    assert!(
        high_semicolon,
        "semicolon-strip divergence must carry severity=HIGH/high (403→200): {v}"
    );
}

#[test]
fn parser_diff_divergences_carry_curl_cmd() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    let divergences = v["divergences"].as_array().expect("divergences array");

    for d in divergences {
        let curl = d["curl_cmd"].as_str().expect("curl_cmd must be a string");
        assert!(
            curl.starts_with("curl -s "),
            "curl_cmd must start with 'curl -s ': {curl}"
        );
        // The URL in the curl command must reference the mock host.
        assert!(
            curl.contains(&format!("{}", addr.ip())),
            "curl_cmd must contain the mock host IP: {curl}"
        );
    }
}

#[test]
fn parser_diff_divergences_have_required_fields() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    let divergences = v["divergences"].as_array().expect("divergences array");

    for d in divergences {
        assert!(d["kind"].is_string(), "divergence.kind must be string: {d}");
        assert!(
            d["description"].is_string(),
            "divergence.description must be string: {d}"
        );
        assert!(
            d["variant_path"].is_string(),
            "divergence.variant_path must be string: {d}"
        );
        assert!(
            d["probe_status"].is_number(),
            "divergence.probe_status must be number: {d}"
        );
        assert!(
            d["baseline_status"].is_number(),
            "divergence.baseline_status must be number: {d}"
        );
        assert!(
            d["severity"].is_string(),
            "divergence.severity must be string: {d}"
        );
        assert!(
            d["curl_cmd"].is_string(),
            "divergence.curl_cmd must be string: {d}"
        );
    }
}

#[test]
fn parser_diff_against_unreachable_target_exits_1() {
    let (code, _stdout, _stderr) = wafrift(&[
        "parser-diff",
        "http://127.0.0.1:1/admin",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "5",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(code, 1, "unreachable target must exit 1");
}

#[test]
fn parser_diff_show_equal_adds_equals_shown_array() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--show-equal",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff --show-equal must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    // With --show-equal the equals_shown key is present and is an array.
    assert!(
        v["equals_shown"].is_array(),
        "equals_shown must be an array when --show-equal is passed: {v}"
    );
}

#[test]
fn parser_diff_text_format_is_not_json_on_stdout() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_semicolon_mock());

    let (code, stdout, stderr) = wafrift(&[
        "parser-diff",
        &format!("http://{addr}/admin"),
        "--format",
        "text",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "parser-diff text format must exit 0; stderr: {stderr}");
    // Text format must NOT emit a JSON object as the entire stdout.
    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err()
            || stdout.trim().is_empty(),
        "text format must not be a pure JSON object on stdout: {stdout}"
    );
}
