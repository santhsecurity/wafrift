use wafrift_transport::{EvasionClient, is_waf_block, is_waf_block_status};
use wafrift_types::{EvasionConfig, Request};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_evasion_client_creation() {
    let client = EvasionClient::new();
    assert!(client.is_ok(), "Client should build successfully");

    let config = EvasionConfig {
        max_attempts: 5,
        ..Default::default()
    };
    let client2 = EvasionClient::with_config(config);
    assert!(
        client2.is_ok(),
        "Client with config should build successfully"
    );

    let req_client = reqwest::Client::new();
    let client3 = EvasionClient::with_reqwest(req_client, EvasionConfig::default()).unwrap();
    assert_eq!(client3.stats().len(), 0, "Stats should be empty initially");
}

#[tokio::test]
async fn test_is_waf_block_status() {
    assert!(is_waf_block_status(403), "403 should be considered a block");
    assert!(is_waf_block_status(406), "406 should be considered a block");
    assert!(is_waf_block_status(429), "429 should be considered a block");
    assert!(is_waf_block_status(451), "451 should be considered a block");
    assert!(is_waf_block_status(503), "503 should be considered a block");

    assert!(!is_waf_block_status(200), "200 should not be a block");
    assert!(!is_waf_block_status(404), "404 should not be a block");
    assert!(!is_waf_block_status(500), "500 should not be a block");
}

#[tokio::test]
async fn test_is_waf_block_body() {
    let block_body =
        b"<html><body><h1>Access Denied</h1><p>You don't have permission</p></body></html>";
    assert!(
        is_waf_block(200, block_body),
        "Body with 'access denied' should be blocked"
    );

    let normal_body = b"<html><body><h1>Welcome</h1><p>Enjoy your stay</p></body></html>";
    assert!(
        !is_waf_block(200, normal_body),
        "Normal body should not be blocked"
    );

    // Case insensitivity test
    let mixed_case_body = b"AcCeSs DeNiEd";
    assert!(
        is_waf_block(200, mixed_case_body),
        "Body string matching should be case insensitive"
    );
}

#[tokio::test]
async fn test_evasion_client_mocked_server_get() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success!"))
        .mount(&mock_server)
        .await;

    let client = EvasionClient::with_config(EvasionConfig { allow_private_upstream: true, ..Default::default() }).unwrap();
    let target_url = format!("{}/target", mock_server.uri());

    let response = client
        .get(&target_url)
        .await
        .expect("Request should succeed");

    assert_eq!(response.status(), 200, "Should return 200 OK");
    assert!(!response.was_blocked, "Should not be flagged as blocked");
    assert_eq!(response.attempts, 1, "Should succeed on first attempt");

    let body = response.text().await.expect("Body should be readable");
    // Wait, the client actually recreates the body from body_preview! Let's check what it actually returns.
    assert_eq!(
        body, "Success!",
        "Body is returned correctly after fingerprinting"
    );
}

#[tokio::test]
async fn test_evasion_client_mocked_server_waf_block() {
    let mock_server = MockServer::start().await;

    // Simulate a WAF that blocks all requests with a 403
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&mock_server)
        .await;

    let config = EvasionConfig {
        max_attempts: 3,
        allow_private_upstream: true, // wiremock binds 127.0.0.1
        ..Default::default()
    }; // Retry up to 3 times
    let client = EvasionClient::with_config(config).unwrap();

    let target_url = format!("{}/blocked", mock_server.uri());

    let result = client.get(&target_url).await.expect("request completes");

    assert!(
        result.was_blocked,
        "403 WAF response should be classified as blocked"
    );
    assert_eq!(result.attempts, 3, "Should exhaust max_attempts");
}

#[tokio::test]
async fn test_evasion_client_send_post() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(201).set_body_string("Created"))
        .mount(&mock_server)
        .await;

    let client = EvasionClient::with_config(EvasionConfig { allow_private_upstream: true, ..Default::default() }).unwrap();
    let target_url = format!("{}/submit", mock_server.uri());

    let req =
        Request::post(&target_url, b"some data".to_vec()).header("Content-Type", "text/plain");

    let response = client.send(req).await.expect("Request should succeed");

    assert_eq!(response.status(), 201, "Should return 201 Created");
    assert!(!response.was_blocked, "Should not be flagged as blocked");
}
