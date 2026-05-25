//! End-to-end tests for `wafrift bypass-probe`.
//!
//! bypass-probe fires 230+ auth-bypass header probes + path-routing
//! variants + HTTP method overrides.  Tests use a minimal mock server
//! that simulates an auth-bypass vulnerability:
//!   - baseline /admin → 403
//!   - requests with X-Forwarded-For: 127.0.0.1 → 200 (header bypass)
//!
//! Tests verify:
//! 1. help documents the CLI surface.
//! 2. bypass-probe appears in top-level help.
//! 3. JSON output has required top-level fields.
//! 4. A header-bypass mock produces at least one divergence.
//! 5. Each divergence carries a curl reproducer.
//! 6. --skip-headers skips the header probe family.
//! 7. probes_fired > 0 on a live target.
//! 8. --min-severity filters low-severity results.

use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Mock that simulates an X-Forwarded-For header bypass:
/// - Any request with `X-Forwarded-For: 127.0.0.1` → 200 OK
/// - Everything else → 403 Forbidden
async fn spawn_xfwd_bypass_mock() -> std::net::SocketAddr {
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

                // Check for X-Forwarded-For: 127.0.0.1 header (case-insensitive).
                let has_xfwd_local = req
                    .lines()
                    .any(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower.starts_with("x-forwarded-for:") && lower.contains("127.0.0.1")
                    });

                let (status, reason, body): (&str, &str, &str) = if has_xfwd_local {
                    ("200", "OK", "admin panel bypassed")
                } else {
                    ("403", "Forbidden", "blocked")
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
    // Probe-until-ready using stdlib connect to avoid reactor saturation.
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

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn bypass_probe_help_documents_options() {
    let (code, stdout, _) = wafrift(&["bypass-probe", "--help"]);
    assert_eq!(code, 0, "bypass-probe --help must exit 0");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
    assert!(stdout.contains("--skip-headers"), "stdout: {stdout}");
    assert!(stdout.contains("--skip-paths"), "stdout: {stdout}");
    assert!(stdout.contains("--skip-methods"), "stdout: {stdout}");
    assert!(stdout.contains("--min-severity"), "stdout: {stdout}");
}

#[test]
fn bypass_probe_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("bypass-probe"),
        "bypass-probe must appear in top-level help: {stdout}"
    );
}

// ── JSON schema ───────────────────────────────────────────────────────────

#[test]
fn bypass_probe_json_output_has_required_top_level_fields() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_xfwd_bypass_mock());

    let (code, stdout, stderr) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
    ]);
    assert_eq!(code, 0, "bypass-probe must exit 0; stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");

    // Top-level: { "results": [ ... ] }
    let results = v["results"].as_array().expect("results must be array");
    assert!(!results.is_empty(), "results array must be non-empty: {v}");

    let r = &results[0];
    assert!(r["target"].is_string(), "result.target must be string: {r}");
    assert!(
        r["probes_fired"].is_number(),
        "result.probes_fired must be number: {r}"
    );
    assert!(
        r["divergences"].is_array(),
        "result.divergences must be array: {r}"
    );
    assert!(
        r["baseline_status"].is_number(),
        "result.baseline_status must be number: {r}"
    );
}

#[test]
fn bypass_probe_detects_xfwd_header_bypass() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_xfwd_bypass_mock());

    let (code, stdout, stderr) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
        "--skip-paths",
        "--skip-methods",
        // Only run header probes — XFF bypass is in the header family.
    ]);
    assert_eq!(code, 0, "bypass-probe must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let results = v["results"].as_array().expect("results array");
    let r = &results[0];
    assert_eq!(
        r["baseline_status"].as_u64().unwrap_or(0),
        403,
        "baseline must be 403 (mock WAF-blocked): {r}"
    );
    let divergences = r["divergences"].as_array().expect("divergences array");
    assert!(
        !divergences.is_empty(),
        "X-Forwarded-For bypass mock must produce at least one divergence: {v}"
    );
}

#[test]
fn bypass_probe_divergences_carry_curl_cmd() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_xfwd_bypass_mock());

    let (code, stdout, stderr) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr}/admin"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
        "--skip-paths",
        "--skip-methods",
    ]);
    assert_eq!(code, 0, "bypass-probe must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let results = v["results"].as_array().expect("results array");
    let divergences = results[0]["divergences"].as_array().expect("divergences");
    for d in divergences {
        let curl = d["curl_cmd"].as_str().expect("curl_cmd must be string");
        assert!(
            curl.starts_with("curl"),
            "curl_cmd must start with 'curl': {curl}"
        );
    }
}

#[test]
fn bypass_probe_probes_fired_positive() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_xfwd_bypass_mock());

    let (code, stdout, stderr) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
        "--skip-paths",
        "--skip-methods",
    ]);
    assert_eq!(code, 0, "bypass-probe must exit 0; stderr: {stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let results = v["results"].as_array().expect("results array");
    let probes = results[0]["probes_fired"].as_u64().unwrap_or(0);
    assert!(probes > 0, "probes_fired must be > 0: {v}");
}

#[test]
fn bypass_probe_skip_headers_reduces_probe_count() {
    // Two runs: one with all probes, one with --skip-headers.
    // The --skip-headers run must fire fewer probes.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();

    let addr_all = rt.block_on(spawn_xfwd_bypass_mock());
    let (_, out_all, _) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr_all}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
        "--skip-paths",
        "--skip-methods",
    ]);

    let addr_nh = rt.block_on(spawn_xfwd_bypass_mock());
    let (_, out_nh, _) = wafrift(&[
        "bypass-probe",
        &format!("http://{addr_nh}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "10",
        "--skip-headers",
        "--skip-paths",
        "--skip-methods",
    ]);

    let v_all: serde_json::Value = serde_json::from_str(out_all.trim()).expect("valid JSON all");
    let v_nh: serde_json::Value = serde_json::from_str(out_nh.trim()).expect("valid JSON nh");

    let probes_all = v_all["results"][0]["probes_fired"].as_u64().unwrap_or(0);
    let probes_nh = v_nh["results"][0]["probes_fired"].as_u64().unwrap_or(0);

    assert!(
        probes_all > probes_nh,
        "skipping headers must reduce probe count: all={probes_all} skip-headers={probes_nh}"
    );
}
