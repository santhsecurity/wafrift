//! End-to-end test for `wafrift attack`.
//!
//! Spawns a mock origin, drives the real binary, verifies the
//! orchestrator merges all four sub-probe JSON blobs into a unified
//! report with `divergences` totals and per-family sub-objects.

use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn_mock() -> std::net::SocketAddr {
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
                // Mock returns longer body for X-Real-IP localhost (header-diff
                // detection point) and for any request containing the attack
                // token (body-diff / query-diff detection point).
                let internal = req
                    .lines()
                    .any(|l| l.to_ascii_lowercase().starts_with("x-real-ip:") && l.contains("127.0.0.1"));
                let leaked = req.contains("WAFRIFT_ATTACK_TOKEN");
                let body: String = if internal || leaked {
                    "<html>internal / leaked attack — long body</html>".into()
                } else {
                    "<html>baseline</html>".into()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\nServer: nginx/1.25\r\n\r\n{body}",
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

#[serial_test::serial]
#[test]
fn attack_runs_all_four_subprobes_and_merges_into_unified_report() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_mock());

    let (code, stdout, stderr) = wafrift(&[
        "attack",
        &format!("http://{addr}/path"),
        "--param",
        "q",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--concurrency",
        "4",
        "--timeout-secs",
        "5",
        "--probe-timeout-secs",
        "30",
    ]);
    assert_eq!(code, 0, "attack should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse — stdout:\n{stdout}");
    assert_eq!(parsed["target"], format!("http://{addr}/path"));
    assert_eq!(parsed["param"], "q");

    // All six sub-probe objects must be present.
    let probes = parsed["probes"].as_object().expect("probes object");
    for family in ["url_path", "headers", "body", "query", "cache", "h2", "method"] {
        assert!(
            probes.contains_key(family),
            "missing sub-probe family `{family}` in attack output"
        );
    }

    // Totals must be present + numeric.
    let div = parsed["divergences"].as_object().expect("divergences object");
    assert!(div["high"].is_number(), "high must be a number");
    assert!(div["medium"].is_number(), "medium must be a number");
    assert!(div["total"].is_number(), "total must be a number");
    // total = high + medium (consistency check).
    let h = div["high"].as_u64().unwrap();
    let m = div["medium"].as_u64().unwrap();
    let t = div["total"].as_u64().unwrap();
    assert_eq!(t, h + m, "total must equal high + medium: {div:?}");
}

#[serial_test::serial]
#[test]
fn attack_marks_subprobe_failures_without_taking_down_the_whole_run() {
    // Point at unreachable target — every sub-probe should fail
    // its BASELINE probe and report an error, but the orchestrator
    // still exits 0 and emits the unified structure.
    let (code, stdout, stderr) = wafrift(&[
        "attack",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--probe-timeout-secs",
        "5",
        "--timeout-secs",
        "2",
    ]);
    assert_eq!(code, 0, "attack should exit 0 even on subprobe errors — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse");
    let probes = parsed["probes"].as_object().expect("probes");
    // Every sub-probe should either have an "error" field OR an
    // "errors" count > 0 (some probes succeed transport-wise but
    // every probe within fails).
    for (family, body) in probes {
        let has_err = body.get("error").is_some();
        let has_errors = body
            .get("errors")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n > 0)
            .unwrap_or(false);
        assert!(
            has_err || has_errors,
            "sub-probe `{family}` should record failure: {body}"
        );
    }
}

#[test]
fn attack_help_documents_orchestrator_role() {
    let (code, stdout, _) = wafrift(&["attack", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--param"), "stdout:\n{stdout}");
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
    assert!(stdout.contains("--probe-timeout-secs"), "stdout:\n{stdout}");
}

#[test]
fn attack_appears_in_main_help_listing() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("attack"), "attack must appear in top-level help");
}

#[serial_test::serial]
#[test]
fn attack_text_format_emits_per_family_summary_lines() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_mock());
    let (code, stdout, _) = wafrift(&[
        "attack",
        &format!("http://{addr}/p"),
        "--format",
        "text",
        "--delay-ms",
        "0",
        "--concurrency",
        "4",
        "--timeout-secs",
        "5",
        "--probe-timeout-secs",
        "30",
    ]);
    assert_eq!(code, 0);
    for family in ["url-path", "headers", "body", "query", "cache", "h2", "method"] {
        assert!(
            stdout.contains(family),
            "text output missing family `{family}`: {stdout}"
        );
    }
}
