use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
    Router,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod common;
use common::{pick_free_port, proxy_client, start_proxy_and_wait, stop_proxy};

#[derive(Debug)]
struct SeenRequest {
    headers: Vec<(String, String)>,
    query: String,
    body: String,
}

fn has_header(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(name) && v.eq_ignore_ascii_case(value)
    })
}

fn has_header_prefix(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(name) && v.to_lowercase().starts_with(&value.to_lowercase())
    })
}

async fn start_upstream_server() -> (u16, Arc<Mutex<Vec<SeenRequest>>>, tokio::task::JoinHandle<()>) {
    let captured = Arc::new(Mutex::new(Vec::<SeenRequest>::new()));
    let app = Router::new().route(
        "/*path",
        any(capture_request),
    )
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
            .expect("upstream server should serve")
    });
    (port, captured, handle)
}

async fn capture_request(
    State(state): State<Arc<Mutex<Vec<SeenRequest>>>>,
    _method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| (name.to_string(), value.to_string()))
        })
        .collect();
    let query = uri.query().unwrap_or_default().to_string();
    let body = String::from_utf8_lossy(&body).to_string();
    let mut buf = state.lock().await;
    buf.push(SeenRequest { headers, query, body });
    (StatusCode::OK, [("content-type", "text/plain")], "upstream-response")
}

#[tokio::test]
async fn forward_path_e2e_must_apply_evasion_and_return_response_unchanged() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(
        proxy_port,
        &[
            "--allow-private-upstream",
            "--content-type-switching",
            "--escalation",
            "heavy",
        ],
    )
    .await
    .expect("start proxy");

    let client = proxy_client(proxy_port).expect("proxy client");
    let target = format!("http://127.0.0.1:{upstream_port}/search?q=1'+OR+'1");
    let response = client
        .post(target)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("q=1%2BOR%2B1")
        .send()
        .await
        .expect("send through proxy");
    assert!(response.status().is_success());
    let body = response.text().await.expect("read response body");
    assert_eq!(body, "upstream-response");

    let requests = captured.lock().await;
    let request = requests.last().expect("one request");
    assert!(
        request.query.contains("q="),
        "query was forwarded to upstream"
    );
    assert!(
        !has_header(&request.headers, "content-type", "application/x-www-form-urlencoded"),
        "content-type must be mutated by proxy"
    );
    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}

#[tokio::test]
async fn forward_path_e2e_must_not_apply_evasion_when_off() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(
        proxy_port,
        &[
            "--allow-private-upstream",
            "--content-type-switching",
            "--escalation",
            "heavy",
        ],
    )
    .await
    .expect("start proxy");

    let client = proxy_client(proxy_port).expect("proxy client");
    let target = format!("http://127.0.0.1:{upstream_port}/search?q=1'+OR+'1");
    let response = client
        .post(target)
        .header("x-wafrift-evade", "off")
        .header("content-type", "application/x-www-form-urlencoded")
        .body("q=1%2BOR%2B1")
        .send()
        .await
        .expect("send through proxy");
    assert!(response.status().is_success());
    assert_eq!(response.text().await.expect("read response body"), "upstream-response");

    let requests = captured.lock().await;
    let request = requests.last().expect("one request");
    assert!(
        has_header_prefix(
            &request.headers,
            "content-type",
            "application/x-www-form-urlencoded",
        ),
        "evade off must keep original content-type"
    );
    assert_eq!(request.body, "q=1%2BOR%2B1");
    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}
