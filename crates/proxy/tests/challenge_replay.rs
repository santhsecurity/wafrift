use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod common;
use common::{proxy_client, start_proxy_on_free_port, stop_proxy};

#[derive(Debug)]
struct SeenRequest {
    headers: Vec<(String, String)>,
    path: String,
}

async fn start_upstream_server() -> (
    u16,
    Arc<Mutex<Vec<SeenRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    let captured = Arc::new(Mutex::new(Vec::<SeenRequest>::new()));
    let app = Router::new()
        .route("/*path", any(capture_request))
        .with_state(captured.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let port = listener
        .local_addr()
        .expect("upstream listener local addr")
        .port();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("upstream server should serve");
    });
    (port, captured, handle)
}

async fn capture_request(
    State(state): State<Arc<Mutex<Vec<SeenRequest>>>>,
    _method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    _body: Bytes,
) -> impl IntoResponse {
    let seen = SeenRequest {
        path: uri.path().to_string(),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_string()))
            })
            .collect(),
    };
    let mut guard = state.lock().await;
    guard.push(seen);

    match uri.path() {
        "/challenge" => (
            StatusCode::FORBIDDEN,
            [("Set-Cookie", "cf_clearance=fake-token; Path=/; HttpOnly")],
            "challenge blocked",
        )
            .into_response(),
        _ => (StatusCode::OK, "challenge bypass").into_response(),
    }
}

fn has_cookie_header(headers: &[(String, String)], name: &str, expected: &str) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(name) && v.split(';').any(|part| part.trim().starts_with(expected))
    })
}

#[tokio::test]
async fn challenge_replay_must_capture_and_attach_cf_clearance() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let (mut proxy, proxy_port) =
        start_proxy_on_free_port(&["--allow-private-upstream", "--max-evade-retries", "0"])
            .await
            .expect("start proxy");

    let client = proxy_client(proxy_port).expect("proxy client");
    let target = format!("http://127.0.0.1:{upstream_port}/challenge");
    let challenge = client.get(target).send().await.expect("first request");
    assert_eq!(challenge.status(), StatusCode::FORBIDDEN);

    let target = format!("http://127.0.0.1:{upstream_port}/dashboard");
    let second = client.get(target).send().await.expect("second request");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second.text().await.expect("read second response"),
        "challenge bypass"
    );

    let requests = captured.lock().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/challenge");
    assert!(
        !has_cookie_header(&requests[0].headers, "cookie", "cf_clearance"),
        "no cookie should be sent before challenge response is captured"
    );
    assert_eq!(requests[1].path, "/dashboard");
    assert!(has_cookie_header(
        &requests[1].headers,
        "cookie",
        "cf_clearance=fake-token"
    ));

    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}

#[tokio::test]
async fn challenge_replay_must_not_attach_cookie_before_capture() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let (mut proxy, proxy_port) = start_proxy_on_free_port(&["--allow-private-upstream"])
        .await
        .expect("start proxy");
    let client = proxy_client(proxy_port).expect("proxy client");

    let target = format!("http://127.0.0.1:{upstream_port}/dashboard");
    let response = client
        .get(target)
        .send()
        .await
        .expect("request without challenge");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("read response"),
        "challenge bypass"
    );
    let captured_requests = captured.lock().await;
    let request = captured_requests.last().expect("one request");
    assert!(
        !has_cookie_header(&request.headers, "cookie", "cf_clearance"),
        "cookie should not be attached before challenge capture"
    );

    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}
