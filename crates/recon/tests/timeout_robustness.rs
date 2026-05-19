//! Slow HTTP upstream: recon must return within `http_timeout` (+ slack), not hang for 60s.

use axum::Router;
use axum::routing::get;
use std::time::{Duration, Instant};
use wafrift_recon::active::{ActiveProbeConfig, ReconProbeError, probe_http_headers};

async fn sixty_second_sleep() {
    tokio::time::sleep(Duration::from_secs(60)).await;
}

#[tokio::test]
async fn http_probe_honours_deadline_before_slow_response() {
    let app = Router::new().route(
        "/",
        get(|| async {
            sixty_second_sleep().await;
            "late"
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("http://{addr}/");
    let limit = Duration::from_millis(400);
    let cfg = ActiveProbeConfig {
        http_timeout: limit,
        ..ActiveProbeConfig::default()
    };

    let start = Instant::now();
    let err = probe_http_headers(&url, &cfg).await.unwrap_err();
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ReconProbeError::HttpDeadline { limit: l } if l == limit),
        "expected HttpDeadline with limit {limit:?}, got {err:?}"
    );
    assert!(
        elapsed <= limit + Duration::from_millis(200),
        "probe took {elapsed:?}, expected <= {:?}",
        limit + Duration::from_millis(200)
    );
}

#[tokio::test]
async fn fast_upstream_negative_completes_under_short_timeout() {
    let app = Router::new().route("/", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("http://{addr}/");
    let cfg = ActiveProbeConfig {
        http_timeout: Duration::from_secs(2),
        ..ActiveProbeConfig::default()
    };
    let start = Instant::now();
    let snap = probe_http_headers(&url, &cfg).await.unwrap();
    assert_eq!(snap.status, 200);
    assert!(start.elapsed() < Duration::from_millis(1500));
}
