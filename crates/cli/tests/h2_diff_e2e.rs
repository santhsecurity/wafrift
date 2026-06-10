//! End-to-end test for `wafrift h2-diff`.
//!
//! Mock only speaks HTTP/1.1; H2 negotiation will fail on every
//! probe. h2-diff should exit 0 with per-probe `h2_error` populated
//! — informational, not a build failure.

use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift_resilient;

async fn spawn_h1_mock() -> std::net::SocketAddr {
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
                let body = "<html>ok</html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    // R56 pass-21 §12 TESTING: do NOT call wait_for_server() here — it
    // calls std::thread::sleep inside an async context, which blocks the
    // tokio runtime thread and causes a race / signal-kill flake. The
    // caller must call wait_for_server() after block_on returns (outside
    // the async boundary).
    addr
}

// §12 TESTING: `#[serial]` because this test spawns the wafrift binary
// as a subprocess that does its own multi-threaded H2 probing. When N
// integration-test binaries fork wafrift concurrently the kernel
// OOM-killer (or a cgroup memory limit) signal-kills the heaviest
// subprocess at random; the symptom is exit-code -1 with empty stderr,
// and the bug looks like a wafrift crash when in fact wafrift never
// got the chance to run.
//
// `#[serial]` only orders spawns WITHIN this test binary — it cannot see
// the ~20 OTHER integration-test binaries `cargo test --workspace` runs
// in parallel, each forking its own subprocesses. That cross-binary
// contention is what still SIGKILLs wafrift here at random (observed red
// on CI: `left: -1`). `wafrift_resilient` re-attempts ONLY the signal-kill
// artifact (exit -1 = killed before running, output absent) and never a
// real exit code — so it re-runs an aborted measurement, it does not
// paper over a wrong result.
#[test]
#[serial]
fn h2_diff_against_h1_only_mock_records_h2_errors_per_probe() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_h1_mock());
    // R56 pass-21 §12 flake-fix: wait_for_server must run OUTSIDE
    // block_on so its std::thread::sleep doesn't block the tokio
    // runtime thread (which caused SIGKILL / exit -1 intermittently).
    common::wait_for_server(addr);
    let (code, stdout, stderr) = wafrift_resilient(&[
        "h2-diff",
        &format!("http://{addr}/"),
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--timeout-secs",
        "30",
    ]);
    // F78: when every H2 probe fails (H1-only mock), h2-diff exits 6
    // (inconclusive). Pre-fix the command exited 0 with no divergences,
    // silently hiding the fact that the H2 leg was never measured.
    // Callers must handle exit 6 as "did not cleanly measure H1/H2 diff".
    assert_eq!(
        code, 6,
        "h2-diff must exit 6 (inconclusive) on H1-only target — stderr:\n{stderr}"
    );
    let p: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parse");
    let results = p["results"].as_array().expect("results");
    assert!(!results.is_empty(), "must have probe results");
    // Mock is H1-only → every probe should record an h2_error.
    let h2_errs = p["h2_errors"].as_u64().unwrap_or(0);
    assert!(h2_errs > 0, "H1-only mock must produce h2_errors > 0: {p}");
    // Every probe row has BOTH H1 and H2 curl reproducers.
    for r in results {
        let h1c = r["h1_curl_cmd"].as_str().expect("h1_curl_cmd");
        let h2c = r["h2_curl_cmd"].as_str().expect("h2_curl_cmd");
        assert!(h1c.contains("--http1.1"), "got: {h1c}");
        assert!(h2c.contains("--http2"), "got: {h2c}");
    }
}

#[test]
#[serial]
fn h2_diff_against_unreachable_target_exits_inconclusive() {
    let (code, _stdout, _stderr) = wafrift_resilient(&[
        "h2-diff",
        "http://127.0.0.1:1/",
        "--format",
        "json",
        "--quiet",
        "--timeout-secs",
        "1",
    ]);
    // F78: when every H2 probe fails (unreachable target → all H1+H2
    // probes error), h2-diff exits 6 to signal "inconclusive — not a
    // clean differential measurement." Callers must not treat exit 6 as
    // "no H1/H2 divergence found"; they must treat it as "we could not
    // measure." Exit 0 means "cleanly measured, no divergence."
    assert_eq!(
        code, 6,
        "h2-diff must exit 6 (inconclusive) on unreachable target"
    );
}

#[test]
fn h2_diff_help_documents_options() {
    let (code, stdout, _) = wafrift_resilient(&["h2-diff", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--format"), "stdout:\n{stdout}");
    assert!(stdout.contains("--payload"), "stdout:\n{stdout}");
}

#[test]
// h2-diff consolidated under `wafrift diff h2` (2026-05). LAW 2: flat
// alias must keep working forever.
fn h2_diff_is_grouped_under_diff_with_working_alias() {
    // 1. The unified `diff` command is discoverable in top-level help.
    let (code, stdout, _) = wafrift_resilient(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  diff"),
        "`diff` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Canonical new path exits 0.
    let (code2, _stdout2, stderr2) = wafrift_resilient(&["diff", "h2", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift diff h2 --help` must exit 0 — stderr:\n{stderr2}"
    );

    // 3. Deprecated flat alias still runs (LAW 2 backwards-compat).
    let (code3, _stdout3, stderr3) = wafrift_resilient(&["h2-diff", "--help"]);
    assert_eq!(
        code3, 0,
        "`wafrift h2-diff --help` must still exit 0 — stderr:\n{stderr3}"
    );
}
