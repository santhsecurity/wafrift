//! Regression tests for Bug 1: Proxy SSRF via HTTP redirect to bogon
//!
//! PRE-FIX BUG: `reqwest::Client` was built with the default redirect policy
//! (up to 10 hops). An attacker-controlled origin that returned
//! `302 Location: http://169.254.169.254/latest/meta-data/` (or any RFC1918 /
//! link-local target) caused the proxy to silently follow the redirect and
//! forward the IMDS response back to the downstream client — one redirect
//! away from full cloud SSRF. Neither `assert_forward_url_allowed` (only run
//! on the original URL) nor `BogonFilteringResolver` (only intercepts DNS,
//! not literal IPs) re-checked the redirect target.
//!
//! POST-FIX: `.redirect(reqwest::redirect::Policy::none())` is set on the
//! client builder. The 302 is returned verbatim to the downstream client,
//! which can then decide whether to follow it.

mod common;
use common::{pick_free_port, start_proxy_and_wait, stop_proxy};

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use tokio::net::TcpListener;

/// Spawn an HTTP server that immediately returns 302 → link-local IMDS.
async fn start_redirect_origin() -> (u16, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async {
            // 169.254.169.254 is the AWS/Azure/GCP Instance Metadata Service —
            // the canonical cloud SSRF target. The proxy MUST surface this 302
            // to the downstream client rather than following it.
            (
                StatusCode::FOUND,
                [("location", "http://169.254.169.254/latest/meta-data/")],
            )
                .into_response()
        }),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind redirect origin");
    let port = listener.local_addr().expect("local addr").port();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("redirect origin serve");
    });
    (port, handle)
}

/// The proxy must surface the 302 to the downstream — NOT follow it.
///
/// Pre-fix: the reqwest client followed redirects by default (up to 10 hops)
/// and returned the IMDS body. Post-fix: Policy::none() means the 302 passes
/// through, so the downstream client sees status 302 (not 200).
#[tokio::test]
async fn proxy_does_not_follow_redirect_to_bogon_imds() {
    let (origin_port, origin_handle) = start_redirect_origin().await;
    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(proxy_port, &["--allow-private-upstream"])
        .await
        .expect("start proxy");

    // The downstream client itself must NOT follow redirects — we want to
    // observe what the PROXY returned, not auto-follow again.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).expect("proxy url"))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");

    let resp = client
        .get(format!("http://127.0.0.1:{origin_port}/"))
        .send()
        .await
        .expect("send request through proxy");

    // The proxy must surface the 302. Any 2xx status means the proxy
    // followed the redirect and potentially returned IMDS data.
    assert_eq!(
        resp.status().as_u16(),
        302,
        "proxy must surface the 302 to downstream, not follow it to the IMDS target \
         (status {} means redirect was followed — SSRF regression)",
        resp.status().as_u16()
    );

    // The Location header must be present and unchanged — we're not
    // supposed to scrub it, just not follow it.
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.contains("169.254.169.254"),
        "Location header must be forwarded verbatim: got {location:?}"
    );

    origin_handle.abort();
    stop_proxy(&mut proxy).await;
}

/// Adversarial twin: RFC1918 redirect target (10.x.x.x) is also bogon.
/// The proxy policy must not follow this either.
#[tokio::test]
async fn proxy_does_not_follow_redirect_to_rfc1918() {
    // Spawn an origin that redirects to an RFC1918 address (10.0.0.1).
    let app = Router::new().route(
        "/rfc1918",
        get(|| async {
            (
                StatusCode::MOVED_PERMANENTLY,
                [("location", "http://10.0.0.1/admin")],
            )
                .into_response()
        }),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(proxy_port, &["--allow-private-upstream"])
        .await
        .expect("start proxy");

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).expect("proxy url"))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");

    let resp = client
        .get(format!("http://127.0.0.1:{port}/rfc1918"))
        .send()
        .await
        .expect("send");

    // Must be 3xx — proxy surfaces the redirect, not the target resource.
    assert!(
        resp.status().is_redirection(),
        "proxy must not follow RFC1918 redirect: got {}",
        resp.status()
    );

    handle.abort();
    stop_proxy(&mut proxy).await;
}
