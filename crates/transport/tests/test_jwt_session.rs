//! Adversarial tests for JWT manipulation and session handling.
//!
//! These cover zero-test areas identified in the audit:
//! - `transport/src/jwt.rs` — `manipulate()` had ZERO tests
//! - `transport/src/session.rs` — `load_jar`, `save_jar`, `extract_csrf`, `inject_csrf` had ZERO tests

use authjar::{AuthSession, SessionStore};
use std::io::Write;
use wafrift_transport::jwt::{b64url_encode, decode_b64url_json};

// ──────────────────────────────────────────────
// JWT adversarial tests
// ──────────────────────────────────────────────

#[test]
fn jwt_manipulate_strip_alg_valid_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let result = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_ok());
    let new_token = result.unwrap();
    // Should have 3 parts
    assert_eq!(new_token.split('.').count(), 3);
    // Header should decode to alg="none"
    let parts: Vec<_> = new_token.split('.').collect();
    let header: serde_json::Value = decode_b64url_json(parts[0]).expect("valid base64url JSON");
    assert_eq!(header["alg"], "none");
}

#[test]
fn jwt_manipulate_rejects_missing_dots() {
    let result = wafrift_transport::jwt::manipulate(
        "not.a.jwt.token",
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn jwt_manipulate_rejects_empty_string() {
    let result = wafrift_transport::jwt::manipulate(
        "",
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn jwt_manipulate_rejects_invalid_base64() {
    let result = wafrift_transport::jwt::manipulate(
        "!!!.payload.signature",
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn jwt_manipulate_rejects_non_json_header() {
    let b64 = b64url_encode(b"not json");
    let result = wafrift_transport::jwt::manipulate(
        &format!("{b64}.payload.signature"),
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_err());
}

#[test]
fn jwt_manipulate_rejects_oversized_header() {
    // Build a JWT with a 20 KiB header (exceeds 16 KiB limit)
    let huge = "x".repeat(20 * 1024);
    let header = serde_json::json!({ "alg": "none", "extra": &huge });
    let header_b64 = b64url_encode(&serde_json::to_vec(&header).unwrap());
    let result = wafrift_transport::jwt::manipulate(
        &format!("{header_b64}.payload.signature"),
        &wafrift_types::session::JwtManipulation::StripAlg,
        None,
    );
    assert!(result.is_err(), "should reject header > 16 KiB");
}

#[test]
fn jwt_manipulate_hs256_requires_key() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let result = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::Hs256WithKey,
        None,
    );
    assert!(result.is_err(), "HS256 manipulation requires a key");
}

#[test]
fn jwt_manipulate_hs256_rejects_none_alg() {
    let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";
    let result = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::Hs256WithKey,
        Some(b"secret"),
    );
    assert!(result.is_err(), "should reject 'none' algorithm for HS256");
}

#[test]
fn jwt_manipulate_jwk_embed_valid() {
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    let jwk = r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#;
    let result = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::JwkEmbed { jwk: jwk.into() },
        None,
    );
    assert!(result.is_ok());
}

#[test]
fn jwt_manipulate_jwk_embed_invalid_json_surfaces_error() {
    // F129 contract: malformed `--jwk` JSON is reported as a structured
    // `InvalidToken` error so the operator knows their input was bad.
    // The pre-F129 behavior silently substituted `jwk: null`, rendering
    // the JWK-validation probe meaningless because the resulting token
    // carried null instead of the intended JWK.
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    let err = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::JwkEmbed {
            jwk: "not valid json".into(),
        },
        None,
    )
    .unwrap_err();
    let reason = match err {
        wafrift_transport::jwt::JwtError::InvalidToken { reason } => reason,
        other => panic!("expected InvalidToken for malformed --jwk JSON, got {other:?}"),
    };
    assert!(
        reason.contains("--jwk") && reason.contains("not valid JSON"),
        "error must name the bad flag and the reason: got {reason:?}"
    );
}

// ──────────────────────────────────────────────
// Session adversarial tests
// ──────────────────────────────────────────────

fn tmp_path(suffix: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::path::PathBuf::from(format!("/tmp/wafrift_test_{pid}_{ts}_{suffix}"))
}

#[test]
fn session_load_jar_missing_file_returns_empty() {
    let path = tmp_path("missing_jar.txt");
    let store = wafrift_transport::session::load_jar(&path);
    assert!(store.is_ok());
    assert!(store.unwrap().is_empty());
}

#[test]
fn session_load_jar_corrupt_line() {
    let path = tmp_path("corrupt_jar.txt");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "bad line without separator").unwrap();
    }
    let result = wafrift_transport::session::load_jar(&path);
    assert!(result.is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_load_jar_invalid_url() {
    let path = tmp_path("invalid_url_jar.txt");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "sessionid=abc | not-a-url").unwrap();
    }
    let result = wafrift_transport::session::load_jar(&path);
    assert!(result.is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_load_jar_valid_line() {
    let path = tmp_path("valid_jar.txt");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# wafrift cookie jar").unwrap();
        writeln!(f, "sessionid=abc123 | https://example.com/").unwrap();
    }
    let result = wafrift_transport::session::load_jar(&path);
    assert!(result.is_ok());
    let store = result.unwrap();
    let session = store.get("default").unwrap();
    let header = session.cookie_header("example.com", &authjar::SessionSettings::default());
    assert!(header.contains("sessionid=abc123"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_save_jar_creates_file() {
    let path = tmp_path("save_jar.json");
    let mut store = SessionStore::new();
    store.add(AuthSession::new("default"));
    let result = wafrift_transport::session::save_jar(&store, &path);
    assert!(result.is_ok());
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("default"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_extract_csrf_found() {
    let body = r#"<input type="hidden" name="csrf" value="token123" />"#;
    let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
    let result = wafrift_transport::session::extract_csrf(body, &re);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "token123");
}

#[test]
fn session_extract_csrf_not_found() {
    let body = "<html><body>no token here</body></html>";
    let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
    let result = wafrift_transport::session::extract_csrf(body, &re);
    assert!(result.is_err());
}

#[test]
fn session_extract_csrf_empty_body() {
    let re = regex::Regex::new(r#"name="csrf" value="([^"]+)""#).unwrap();
    let result = wafrift_transport::session::extract_csrf("", &re);
    assert!(result.is_err());
}

#[test]
fn session_inject_csrf_header() {
    let mut req = wafrift_types::Request::get("https://example.com/");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Header,
    )
    .unwrap();
    assert!(
        req.headers
            .iter()
            .any(|(k, v)| k == "X-CSRF-Token" && v == "tok123")
    );
}

#[test]
fn session_inject_csrf_query() {
    let mut req = wafrift_types::Request::get("https://example.com/");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Query,
    )
    .unwrap();
    assert!(req.url.contains("csrf_token=tok123"));
}

#[test]
fn session_inject_csrf_query_appends() {
    let mut req = wafrift_types::Request::get("https://example.com/?existing=1");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Query,
    )
    .unwrap();
    assert!(req.url.contains("existing=1"));
    assert!(req.url.contains("csrf_token=tok123"));
    assert!(req.url.contains('&'));
}

#[test]
fn session_inject_csrf_body() {
    let mut req = wafrift_types::Request::post("https://example.com/", b"original");
    req.headers.push((
        "Content-Type".into(),
        "application/x-www-form-urlencoded".into(),
    ));
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Body,
    )
    .unwrap();
    let body = req.body.unwrap();
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("csrf_token=tok123"));
    assert!(body_str.contains("original"));
}
