//! Axum mock upstream with canned headers: positive stack fingerprint + negative control.

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use std::time::Duration;
use wafrift_recon::active::{ActiveProbeConfig, StackTag, TagFamily, probe_http_headers};

fn probe_config() -> ActiveProbeConfig {
    ActiveProbeConfig {
        http_timeout: Duration::from_secs(5),
        ..ActiveProbeConfig::default()
    }
}

async fn positive_stack_headers() -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::HeaderName::from_static("cf-ray"),
        "deadbeefcafe".parse().unwrap(),
    );
    h.insert(
        axum::http::header::HeaderName::from_static("x-fastly-request-id"),
        "fastly-req-1".parse().unwrap(),
    );
    h.insert(axum::http::header::SERVER, "cloudflare".parse().unwrap());
    h.insert(
        axum::http::header::HeaderName::from_static("x-powered-by"),
        "Express".parse().unwrap(),
    );
    (StatusCode::OK, h)
}

async fn negative_plain_origin() -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert(axum::http::header::SERVER, "nginx/1.24.0".parse().unwrap());
    (StatusCode::OK, h)
}

async fn spawn_axum(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    format!("http://{addr}/")
}

#[tokio::test]
async fn positive_classifies_waf_cdn_and_framework() {
    let app = Router::new().route("/", get(positive_stack_headers));
    let base = spawn_axum(app).await;
    let snap = probe_http_headers(&base, &probe_config()).await.unwrap();

    assert!(snap.tags.contains(&StackTag {
        family: TagFamily::Waf,
        id: "cloudflare".into(),
    }));
    assert!(snap.tags.contains(&StackTag {
        family: TagFamily::Cdn,
        id: "cloudflare".into(),
    }));
    assert!(snap.tags.contains(&StackTag {
        family: TagFamily::Cdn,
        id: "fastly".into(),
    }));
    assert!(snap.tags.contains(&StackTag {
        family: TagFamily::Framework,
        id: "express".into(),
    }));
}

#[tokio::test]
async fn negative_plain_nginx_has_no_stack_tags() {
    let app = Router::new().route("/", get(negative_plain_origin));
    let base = spawn_axum(app).await;
    let snap = probe_http_headers(&base, &probe_config()).await.unwrap();
    assert!(
        snap.tags.is_empty(),
        "expected no WAF/CDN/framework tags for plain nginx Server header, got {:?}",
        snap.tags
    );
}
