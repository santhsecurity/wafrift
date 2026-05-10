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
    query: String,
}

async fn start_upstream_server() -> (u16, Arc<Mutex<Vec<SeenRequest>>>, tokio::task::JoinHandle<()>) {
    let captured = Arc::new(Mutex::new(Vec::<SeenRequest>::new()));
    let app = Router::new()
        .route("/*path", any(capture_request))
        .with_state(captured.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let port = listener.local_addr().expect("upstream listener local addr").port();
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
    _headers: axum::http::HeaderMap,
    _body: Bytes,
) -> impl IntoResponse {
    let query = uri.query().unwrap_or_default().to_string();
    let mut captured = state.lock().await;
    captured.push(SeenRequest { query });
    (StatusCode::OK, [("content-type", "text/plain")], "upstream-response")
}

#[tokio::test]
async fn mutate_url_pipeline_must_percent_encode_query_values() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(proxy_port, &["--allow-private-upstream", "--mutate-url"])
        .await
        .expect("start proxy");
    let client = proxy_client(proxy_port).expect("proxy client");

    let target = format!("http://127.0.0.1:{upstream_port}/search?q=1'+OR+'1");
    let response = client.get(target).send().await.expect("send through proxy");
    assert!(response.status().is_success());
    assert_eq!(response.text().await.expect("read upstream response"), "upstream-response");

    let request = captured.lock().await;
    let request = request.last().expect("one upstream request");
    assert_eq!(request.query.starts_with("q="), true);
    assert_ne!(request.query, "q=1'+OR+'1");
    assert!(
        request.query.contains("q=1%27%2BOR%2B%271"),
        "mutated query should percent-encode apostrophes and plus signs"
    );

    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}

#[tokio::test]
async fn mutate_url_pipeline_must_not_encode_query_when_off() {
    let (upstream_port, captured, upstream_handle) = start_upstream_server().await;
    let proxy_port = pick_free_port().expect("pick proxy port");
    let mut proxy = start_proxy_and_wait(proxy_port, &["--allow-private-upstream"]).await.expect("start proxy");
    let client = proxy_client(proxy_port).expect("proxy client");

    let target = format!("http://127.0.0.1:{upstream_port}/search?q=1'+OR+'1");
    let response = client.get(target).send().await.expect("send through proxy");
    assert!(response.status().is_success());
    assert_eq!(response.text().await.expect("read upstream response"), "upstream-response");

    let request = captured.lock().await;
    let request = request.last().expect("one upstream request");
    assert_eq!(request.query, "q=1%27+OR+%271");

    upstream_handle.abort();
    stop_proxy(&mut proxy).await;
}
