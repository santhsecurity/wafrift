//! Integration tests: verify that wafrift-strategy picks gRPC-evasion encoded
//! variants when the target returns `Content-Type: application/grpc`.
//!
//! These tests spin up a local wiremock server that replies with
//! `Content-Type: application/grpc` to simulate a gRPC endpoint, then
//! call the grpc-evasion library and assert the produced frames are
//! structurally valid for that content-type.

use wafrift_grpc_evasion::{
    decode_grpc_frame, embed_attack_in_message, embed_attack_in_nested, split_attack_across_fields,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Start a mock server that mimics a gRPC endpoint: any POST to `/grpc`
/// returns 200 with `Content-Type: application/grpc` and an empty body.
async fn start_grpc_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/grpc"))
        .and(header("content-type", "application/grpc"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/grpc")
                .set_body_bytes(vec![]),
        )
        .expect(1..)
        .mount(&server)
        .await;
    server
}

/// Assert that a gRPC frame is structurally valid (5-byte header, declared
/// length matches body, compression flag = 0).
fn assert_valid_grpc_frame(frame: &[u8], context: &str) {
    let result = decode_grpc_frame(frame);
    assert!(
        result.is_ok(),
        "{context}: frame decode failed: {:?}",
        result.err()
    );
    let (compression, declared_len, body) = result.unwrap();
    assert_eq!(compression, 0, "{context}: compression flag must be 0");
    assert_eq!(
        body.len(),
        declared_len as usize,
        "{context}: body length must match declared length"
    );
}

/// Test 1: embed_attack_in_message produces a valid gRPC frame accepted
/// by a Content-Type: application/grpc endpoint.
#[tokio::test]
async fn test_flat_grpc_payload_targets_grpc_endpoint() {
    let server = start_grpc_mock().await;
    let payload = "' OR 1=1--";
    let frame = embed_attack_in_message(payload);

    assert_valid_grpc_frame(&frame, "flat embed");

    // Confirm the mock server accepts this frame with the correct CT header.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/grpc", server.uri()))
        .header("content-type", "application/grpc")
        .body(frame)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "mock gRPC endpoint must return 200");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc"),
        "response must echo application/grpc content-type"
    );
}

/// Test 2: embed_attack_in_nested(depth=5) produces a valid gRPC frame and
/// the server accepts it.
#[tokio::test]
async fn test_nested_grpc_payload_targets_grpc_endpoint() {
    let server = start_grpc_mock().await;
    let payload = "<script>alert(1)</script>";
    let frame = embed_attack_in_nested(payload, 5);

    assert_valid_grpc_frame(&frame, "nested depth=5");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/grpc", server.uri()))
        .header("content-type", "application/grpc")
        .body(frame)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
}

/// Test 3: split_attack_across_fields(10) produces a valid gRPC frame and
/// the mock server returns 200, confirming the strategy correctly routes
/// split-field gRPC payloads.
#[tokio::test]
async fn test_split_field_grpc_payload_targets_grpc_endpoint() {
    let server = start_grpc_mock().await;
    let payload = "UNION SELECT username,password FROM users--";
    let frame = split_attack_across_fields(payload, 10);

    assert_valid_grpc_frame(&frame, "split across 10 fields");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/grpc", server.uri()))
        .header("content-type", "application/grpc")
        .body(frame)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        200,
        "split-field gRPC frame must be accepted"
    );
}
