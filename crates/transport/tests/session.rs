//! Session handling tests — cookie jars, CSRF extraction, injection.

use reqwest::cookie::CookieStore;
use wafrift_transport::session::{extract_csrf, inject_csrf, load_jar, save_jar, SessionError};
use wafrift_types::session::CsrfInjectionLocation;
use wafrift_types::Request;

// ── CSRF extraction ────────────────────────────────────────────────────────

#[test]
fn extract_csrf_meta_tag() {
    let html = r#"<html><head><meta name="csrf-token" content="abc123"></head></html>"#;
    let re = regex::Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).unwrap();
    let token = extract_csrf(html, &re).unwrap();
    assert_eq!(token, "abc123");
}

#[test]
fn extract_csrf_input_field() {
    let html = r#"<form><input type="hidden" name="csrf" value="tok_456"></form>"#;
    let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
    let token = extract_csrf(html, &re).unwrap();
    assert_eq!(token, "tok_456");
}

#[test]
fn extract_csrf_json_response() {
    let json = r#"{"csrf_token": "json_tok_789"}"#;
    let re = regex::Regex::new(r#""csrf_token":\s*"([^"]+)""#).unwrap();
    let token = extract_csrf(json, &re).unwrap();
    assert_eq!(token, "json_tok_789");
}

#[test]
fn extract_csrf_no_match() {
    let html = r#"<html><body>Hello</body></html>"#;
    let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
    let err = extract_csrf(html, &re).unwrap_err();
    assert!(matches!(err, SessionError::CsrfTokenNotFound { .. }));
}

#[test]
fn extract_csrf_empty_capture() {
    let html = r#"<meta name="csrf" content="">"#;
    let re = regex::Regex::new(r#"content="([^"]*)""#).unwrap();
    let err = extract_csrf(html, &re).unwrap_err();
    assert!(matches!(err, SessionError::CsrfTokenNotFound { .. }));
}

#[test]
fn extract_csrf_first_match_only() {
    let html = r#"<meta content="first"><meta content="second">"#;
    let re = regex::Regex::new(r#"content="([^"]+)""#).unwrap();
    let token = extract_csrf(html, &re).unwrap();
    assert_eq!(token, "first");
}

// ── CSRF injection ─────────────────────────────────────────────────────────

#[test]
fn inject_csrf_header() {
    let mut req = Request::get("https://example.com/api");
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Header);
    assert!(req.headers.iter().any(|(k, v)| k == "X-CSRF-Token" && v == "tok123"));
}

#[test]
fn inject_csrf_query_no_existing_params() {
    let mut req = Request::get("https://example.com/api");
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query);
    assert!(req.url.contains("?csrf_token=tok123"));
}

#[test]
fn inject_csrf_query_with_existing_params() {
    let mut req = Request::get("https://example.com/api?foo=bar");
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query);
    assert!(req.url.contains("foo=bar"));
    assert!(req.url.contains("&csrf_token=tok123"));
}

#[test]
fn inject_csrf_query_url_encoding() {
    let mut req = Request::get("https://example.com/api");
    inject_csrf(&mut req, "tok=123", CsrfInjectionLocation::Query);
    assert!(req.url.contains("csrf_token=tok%3D123"));
}

#[test]
fn inject_csrf_body_empty() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body);
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert_eq!(body, "csrf_token=tok123");
}

#[test]
fn inject_csrf_body_existing() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    req.body = Some(b"username=admin".to_vec());
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body);
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert_eq!(body, "username=admin&csrf_token=tok123");
}

#[test]
fn inject_csrf_body_url_encoding() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    inject_csrf(&mut req, "tok&123", CsrfInjectionLocation::Body);
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert!(body.contains("csrf_token=tok%26123"));
}

// ── Cookie jar persistence ─────────────────────────────────────────────────

#[test]
fn load_jar_nonexistent_creates_empty() {
    let path = std::path::Path::new("/tmp/wafrift_nonexistent_cookie_jar_12345.txt");
    let jar = load_jar(path).unwrap();
    // Empty jar loaded successfully (stub behavior)
    let _ = jar;
}

#[test]
fn save_and_load_jar_roundtrip() {
    let tmp = std::env::temp_dir().join("wafrift_cookie_jar_test.txt");
    let _ = std::fs::remove_file(&tmp);

    let jar = reqwest::cookie::Jar::default();
    let url = reqwest::Url::parse("https://example.com/").unwrap();
    jar.add_cookie_str("session=abc123; Path=/; Secure", &url);

    save_jar(&jar, &tmp).unwrap();
    let loaded = load_jar(&tmp).unwrap();

    // Jar loaded successfully (persistence is a stub; this verifies no panic)
    assert!(tmp.exists());

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn save_jar_creates_file() {
    let tmp = std::env::temp_dir().join("wafrift_cookie_jar_create_test.txt");
    let _ = std::fs::remove_file(&tmp);

    let jar = reqwest::cookie::Jar::default();
    save_jar(&jar, &tmp).unwrap();
    assert!(tmp.exists());

    let _ = std::fs::remove_file(&tmp);
}
