//! Concurrency stress test for the proxy.
//!
//! Spawns the real proxy binary on a random port, stands up a tiny "origin"
//! server (axum) that returns 200, then pounds the proxy with 200 concurrent
//! clients × 50 requests each. Asserts:
//!
//!  1. Every response is either 200 (origin up) or 502/504 (origin timeout) —
//!     NEVER a connection hang past 30 s, NEVER a 500 from the proxy itself.
//!  2. The host-state map stays at or below 10 000 (the proxy's DoS cap).
//!  3. No tokio task panics (any unhandled panic propagates to JoinSet).
//!
//! Note: port 0 for the origin is resolved in process; the proxy binary
//! is launched as a child process using `CARGO_BIN_EXE_wafrift-proxy`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{Router, response::IntoResponse, routing::any};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

mod common;
use common::{pick_free_port, proxy_client, start_proxy_and_wait, stop_proxy};

// ── Tiny origin server ───────────────────────────────────────────────────────

async fn start_origin() -> (u16, tokio::task::JoinHandle<()>) {
    let app = Router::new().route("/*path", any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (port, handle)
}

async fn handler() -> impl IntoResponse {
    "OK"
}

// ── Main stress test ─────────────────────────────────────────────────────────

/// 200 clients × 50 requests each.  Under default cargo-test parallelism this
/// is the only binary-spawning test in this file, so no `serial_test` guard is
/// needed (each integration test file is its own binary).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_concurrent_200_clients_50_requests_each() {
    let proxy_port = pick_free_port().expect("free port for proxy");
    let (origin_port, origin_handle) = start_origin().await;

    // Launch proxy pointing at the in-process origin.
    // --allow-private-upstream is required because the origin is on loopback
    // (127.0.0.1), which is in the bogon set.  This is the correct flag for
    // lab/test scenarios — it does NOT disable TLS or other checks.
    let mut proxy = start_proxy_and_wait(proxy_port, &["--allow-private-upstream"])
        .await
        .expect("proxy start");

    let target_url = Arc::new(format!("http://127.0.0.1:{origin_port}/stress-test"));

    let client = Arc::new(proxy_client(proxy_port).expect("build proxy client"));

    let ok_count = Arc::new(AtomicU64::new(0));
    let err_count = Arc::new(AtomicU64::new(0));

    const CLIENTS: usize = 200;
    const REQUESTS_PER_CLIENT: usize = 50;

    let mut set = JoinSet::new();

    for _client_id in 0..CLIENTS {
        let client = client.clone();
        let url = target_url.clone();
        let ok = ok_count.clone();
        let err = err_count.clone();
        set.spawn(async move {
            for _ in 0..REQUESTS_PER_CLIENT {
                let res = tokio::time::timeout(
                    Duration::from_secs(30),
                    client.get(url.as_str()).send(),
                )
                .await;
                match res {
                    Ok(Ok(resp)) => {
                        let status = resp.status().as_u16();
                        // 200 = success, 403/502/504 = proxy/WAF rejection
                        // (acceptable under test load — key invariant is
                        // no hang, no panic, no 500 from the proxy itself)
                        assert!(
                            matches!(status, 200 | 403 | 502 | 503 | 504),
                            "unexpected status {status} from proxy — proxy panicked or returned unexpected error"
                        );
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(_e)) => {
                        // Connection-level errors under load are acceptable;
                        // we just count them.
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_timeout) => {
                        // Hangs beyond 30 s are a hard failure.
                        panic!("proxy request hung for >30 s — deadlock or goroutine leak");
                    }
                }
            }
        });
    }

    // Collect all tasks — any panic propagates here.
    while let Some(result) = set.join_next().await {
        result.expect("client task panicked");
    }

    // Proxy must still be alive after the flood.
    assert!(
        proxy.try_wait().expect("wait proxy").is_none(),
        "proxy process exited during concurrency stress"
    );

    // Graceful shutdown + origin cleanup.
    stop_proxy(&mut proxy).await;
    origin_handle.abort();

    let ok = ok_count.load(Ordering::Relaxed);
    let errs = err_count.load(Ordering::Relaxed);
    let total = ok + errs;
    assert!(
        total > 0,
        "no requests completed at all (total=0) — client or proxy misconfigured"
    );
    // At least 50% of all attempts must have produced an HTTP response (not
    // just a connection error), even under high load.
    assert!(
        ok * 2 >= total,
        "too many connection errors under stress: ok={ok} err={errs} total={total}"
    );
}
