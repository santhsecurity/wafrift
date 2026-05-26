//! Session handling tests — cookie jars, CSRF extraction, injection.

use authjar::{AuthSession, SessionSettings, SessionStore};
use wafrift_transport::session::{SessionError, extract_csrf, inject_csrf, load_jar, save_jar};
use wafrift_types::Request;
use wafrift_types::session::CsrfInjectionLocation;

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
    let html = r"<html><body>Hello</body></html>";
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
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Header).unwrap();
    assert!(
        req.headers
            .iter()
            .any(|(k, v)| k == "X-CSRF-Token" && v == "tok123")
    );
}

#[test]
fn inject_csrf_query_no_existing_params() {
    let mut req = Request::get("https://example.com/api");
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query).unwrap();
    assert!(req.url.contains("?csrf_token=tok123"));
}

#[test]
fn inject_csrf_query_with_existing_params() {
    let mut req = Request::get("https://example.com/api?foo=bar");
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Query).unwrap();
    assert!(req.url.contains("foo=bar"));
    assert!(req.url.contains("&csrf_token=tok123"));
}

#[test]
fn inject_csrf_query_url_encoding() {
    let mut req = Request::get("https://example.com/api");
    inject_csrf(&mut req, "tok=123", CsrfInjectionLocation::Query).unwrap();
    assert!(req.url.contains("csrf_token=tok%3D123"));
}

#[test]
fn inject_csrf_body_empty() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    req.headers.push((
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap();
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert_eq!(body, "csrf_token=tok123");
}

#[test]
fn inject_csrf_body_existing() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    req.body = Some(b"username=admin".to_vec());
    req.headers.push((
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap();
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert_eq!(body, "username=admin&csrf_token=tok123");
}

#[test]
fn inject_csrf_body_url_encoding() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    req.headers.push((
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    inject_csrf(&mut req, "tok&123", CsrfInjectionLocation::Body).unwrap();
    let body = String::from_utf8(req.body.unwrap()).unwrap();
    assert!(body.contains("csrf_token=tok%26123"));
}

#[test]
fn inject_csrf_body_rejects_json() {
    let mut req = Request::post("https://example.com/api", Vec::new());
    req.body = Some(b"{\"key\":\"val\"}".to_vec());
    req.headers
        .push(("Content-Type".into(), "application/json".into()));
    let err = inject_csrf(&mut req, "tok123", CsrfInjectionLocation::Body).unwrap_err();
    assert!(matches!(err, SessionError::CsrfInjectIncompatibleBody { .. }));
}

// ── Cookie jar persistence ─────────────────────────────────────────────────

#[test]
fn load_jar_nonexistent_creates_empty() {
    let path = std::path::Path::new("/tmp/wafrift_nonexistent_cookie_jar_12345.txt");
    let store = load_jar(path).unwrap();
    assert!(store.is_empty());
}

#[test]
fn save_and_load_jar_roundtrip() {
    let tmp = std::env::temp_dir().join("wafrift_cookie_jar_test.json");
    let _ = std::fs::remove_file(&tmp);

    let mut store = SessionStore::new();
    let mut session = AuthSession::new("default");
    session.add_cookie("session", "abc123", "example.com");
    store.add(session);

    save_jar(&store, &tmp).unwrap();
    let loaded = load_jar(&tmp).unwrap();

    assert_eq!(loaded.len(), 1);
    let session = loaded.get("default").unwrap();
    let header = session.cookie_header("example.com", &SessionSettings::default());
    assert!(header.contains("session=abc123"));
    assert!(tmp.exists());

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn save_jar_creates_file() {
    let tmp = std::env::temp_dir().join("wafrift_cookie_jar_create_test.json");
    let _ = std::fs::remove_file(&tmp);

    let mut store = SessionStore::new();
    store.add(AuthSession::new("default"));
    save_jar(&store, &tmp).unwrap();
    assert!(tmp.exists());

    let _ = std::fs::remove_file(&tmp);
}
