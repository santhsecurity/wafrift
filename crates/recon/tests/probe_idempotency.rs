//! Two back-to-back probes against the same mock must yield identical canonical JSON bytes.

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use std::time::Duration;
use wafrift_recon::active::{ActiveProbeConfig, probe_http_headers};

async fn stable_stack() -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::HeaderName::from_static("cf-ray"),
        "idempotent-ray".parse().unwrap(),
    );
    h.insert(axum::http::header::SERVER, "nginx".parse().unwrap());
    (StatusCode::OK, h)
}

#[tokio::test]
async fn two_probes_byte_equal_canonical_json() {
    let app = Router::new().route("/", get(stable_stack));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let url = format!("http://{addr}/");
    let cfg = ActiveProbeConfig {
        http_timeout: Duration::from_secs(5),
        ..ActiveProbeConfig::default()
    };

    let a = probe_http_headers(&url, &cfg).await.unwrap();
    let b = probe_http_headers(&url, &cfg).await.unwrap();

    let ja = a.to_canonical_json().unwrap();
    let jb = b.to_canonical_json().unwrap();
    assert_eq!(
        ja,
        jb,
        "expected byte-identical JSON snapshots; left={} right={}",
        String::from_utf8_lossy(&ja),
        String::from_utf8_lossy(&jb)
    );
}

#[tokio::test]
async fn different_targets_produce_different_bytes_negative() {
    let mk = |cf: &'static str| {
        Router::new().route(
            "/",
            get(move || async move {
                let mut h = HeaderMap::new();
                h.insert(
                    axum::http::header::HeaderName::from_static("cf-ray"),
                    cf.parse().unwrap(),
                );
                (StatusCode::OK, h)
            }),
        )
    };

    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a1 = l1.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l1, mk("ray-aaa")).await.unwrap() });

    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a2 = l2.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l2, mk("ray-bbb")).await.unwrap() });

    tokio::time::sleep(Duration::from_millis(80)).await;

    let cfg = ActiveProbeConfig {
        http_timeout: Duration::from_secs(5),
        ..ActiveProbeConfig::default()
    };
    let u1 = format!("http://{a1}/");
    let u2 = format!("http://{a2}/");
    let s1 = probe_http_headers(&u1, &cfg).await.unwrap();
    let s2 = probe_http_headers(&u2, &cfg).await.unwrap();
    assert_ne!(
        s1.to_canonical_json().unwrap(),
        s2.to_canonical_json().unwrap()
    );
}
