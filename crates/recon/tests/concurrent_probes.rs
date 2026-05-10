//! Fifty concurrent HTTP probes against one axum upstream: no panic, all complete.

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wafrift_recon::active::{probe_http_headers, ActiveProbeConfig};

static HITS: AtomicUsize = AtomicUsize::new(0);

async fn counted_response() -> impl IntoResponse {
    HITS.fetch_add(1, Ordering::SeqCst);
    let mut h = HeaderMap::new();
    h.insert(axum::http::header::SERVER, "concurrent-test".parse().unwrap());
    (StatusCode::OK, h)
}

#[tokio::test]
async fn fifty_concurrent_probes_all_finish() {
    HITS.store(0, Ordering::SeqCst);

    let app = Router::new().route("/", get(counted_response));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("http://{addr}/");
    let cfg = ActiveProbeConfig {
        http_timeout: Duration::from_secs(15),
        ..ActiveProbeConfig::default()
    };

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let url = url.clone();
        let cfg = cfg.clone();
        set.spawn(async move { probe_http_headers(&url, &cfg).await });
    }

    let mut ok = 0usize;
    while let Some(joined) = set.join_next().await {
        let res = joined.expect("task join should not panic");
        let _snap = res.expect("each probe should complete successfully");
        ok += 1;
    }

    assert_eq!(ok, 50);
    assert_eq!(HITS.load(Ordering::SeqCst), 50);
}
