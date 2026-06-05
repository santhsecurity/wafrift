//! End-to-end test for `wafrift attack`.
//!
//! Spawns a mock origin, drives the real binary, verifies the
//! orchestrator merges all seven sub-probe JSON blobs into a unified
//! report with `divergences` totals and per-family sub-objects.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

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
                let internal = req.lines().any(|l| {
                    l.to_ascii_lowercase().starts_with("x-real-ip:") && l.contains("127.0.0.1")
                });
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
    {
        common::wait_for_server(addr);
    }
    addr
}

#[serial_test::serial]
#[test]
fn attack_runs_all_seven_subprobes_and_merges_into_unified_report() {
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
        "30",
        "--probe-timeout-secs",
        "120",
    ]);
    assert_eq!(code, 0, "attack should exit 0 — stderr:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("JSON parse — stdout:\n{stdout}");
    assert_eq!(parsed["target"], format!("http://{addr}/path"));
    assert_eq!(parsed["param"], "q");

    // All six sub-probe objects must be present.
    let probes = parsed["probes"].as_object().expect("probes object");
    for family in [
        "url_path", "headers", "body", "query", "cache", "h2", "method",
    ] {
        assert!(
            probes.contains_key(family),
            "missing sub-probe family `{family}` in attack output"
        );
    }

    // Totals must be present + numeric.
    let div = parsed["divergences"]
        .as_object()
        .expect("divergences object");
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
    // Point at unreachable target — every sub-probe should fail its
    // BASELINE probe. Production contract (R44-I3): when >= 4 of the 7
    // sub-probes error out (i.e. a strict majority), attack exits 1 so
    // the unreachable host is NOT silently treated as "0 divergences".
    // The test asserts exit 1 (not 0) for an all-probes-error run.
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
    // R44-I3: exit 1 when majority of probes errored — not exit 0.
    // A CI consumer must see a non-zero exit when the target is unreachable.
    assert_eq!(
        code, 1,
        "attack must exit 1 when majority of sub-probes error — stderr:\n{stderr}"
    );

    // Even on error, the JSON structure should still be emitted (for
    // tooling that wants to inspect which probes failed).
    if !stdout.trim().is_empty()
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout.trim())
    {
        // When JSON is present, every sub-probe should have recorded its failure.
        // Different sub-probes use different field names:
        //   - most probes: "error" (string) or "errors" (count)
        //   - h2-diff uses "h2_errors" (count)
        //   - h2-diff may also have no top-level "error" if it exited 6 (inconclusive)
        if let Some(probes) = parsed["probes"].as_object() {
            for (family, body) in probes {
                let has_err = body.get("error").is_some();
                let has_errors = body
                    .get("errors")
                    .and_then(serde_json::Value::as_u64)
                    .map(|n| n > 0)
                    .unwrap_or(false);
                // h2-diff uses "h2_errors" for its error count.
                let has_h2_errors = body
                    .get("h2_errors")
                    .and_then(serde_json::Value::as_u64)
                    .map(|n| n > 0)
                    .unwrap_or(false);
                assert!(
                    has_err || has_errors || has_h2_errors,
                    "sub-probe `{family}` should record failure: {body}"
                );
            }
        }
    }
}

/// Regression test for the h2-diff exit-6 false-error bug.
///
/// h2-diff exits 6 when all H2 probes fail (H1-only target — see F78).
/// Pre-fix: `attack` treated exit 6 as an error and surfaced
/// `"error": "subprobe h2-diff exited 6 — stderr: …"` in the unified
/// report. After the fix, exit 6 is recognized as a valid "inconclusive
/// but parseable" result and the h2 sub-probe object must NOT have an
/// "error" field.
#[serial_test::serial]
#[test]
fn attack_h2_exit6_is_not_treated_as_subprobe_error() {
    // Spawn an H1-only mock (never speaks H2). h2-diff will exit 6.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_mock());

    let (code, stdout, stderr) = wafrift(&[
        "attack",
        &format!("http://{addr}/path"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "30",
        "--probe-timeout-secs",
        "120",
    ]);
    assert_eq!(
        code, 0,
        "attack must exit 0 even when h2-diff exits 6 — stderr:\n{stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let h2 = &parsed["probes"]["h2"];
    assert!(
        h2.get("error").is_none(),
        "h2 sub-probe must not have an 'error' field when h2-diff exits 6 (inconclusive); \
         got: {h2}"
    );
    // h2_errors must be present (h2-diff always emits it, exit 6 included).
    // Can't assert > 0 because in some envs HTTP/1.1 mock still negotiates H2 via ALPN.
    assert!(
        h2.get("h2_errors").is_some() || h2.get("probes").is_some(),
        "h2 sub-probe JSON must have h2_errors or probes field: {h2}"
    );
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
// `attack` consolidated under `wafrift diff all` (2026-05). LAW 2: flat
// alias must keep working forever.
fn attack_is_grouped_under_diff_all_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift(&["diff", "all", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff all --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift(&["attack", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift attack --help` must still exit 0 — stderr:\n{stderr3}"
    );
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
        "30",
        "--probe-timeout-secs",
        "120",
    ]);
    assert_eq!(code, 0);
    for family in [
        "url-path", "headers", "body", "query", "cache", "h2", "method",
    ] {
        assert!(
            stdout.contains(family),
            "text output missing family `{family}`: {stdout}"
        );
    }
}
