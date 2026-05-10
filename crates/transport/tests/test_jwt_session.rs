//! Adversarial tests for JWT manipulation and session handling.
//!
//! These cover zero-test areas identified in the audit:
//! - `transport/src/jwt.rs` — `manipulate()` had ZERO tests
//! - `transport/src/session.rs` — `load_jar`, `save_jar`, `extract_csrf`, `inject_csrf` had ZERO tests

use base64::Engine;
use std::io::Write;

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
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
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
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
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
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
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
        &wafrift_types::session::JwtManipulation::JwkEmbed {
            jwk: jwk.into(),
        },
        None,
    );
    assert!(result.is_ok());
}

#[test]
fn jwt_manipulate_jwk_embed_invalid_json_falls_back_to_null() {
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    let result = wafrift_transport::jwt::manipulate(
        token,
        &wafrift_types::session::JwtManipulation::JwkEmbed {
            jwk: "not valid json".into(),
        },
        None,
    );
    // Invalid JWK JSON is replaced with Null, so manipulation still succeeds
    assert!(result.is_ok());
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
    let jar = wafrift_transport::session::load_jar(&path);
    assert!(jar.is_ok());
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
    let _ = std::fs::remove_file(&path);
}

#[test]
fn session_save_jar_creates_file() {
    let path = tmp_path("save_jar.txt");
    let jar = reqwest::cookie::Jar::default();
    let result = wafrift_transport::session::save_jar(&jar, &path);
    assert!(result.is_ok());
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("wafrift cookie jar"));
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
    );
    assert!(req.headers.iter().any(|(k, v)| k == "X-CSRF-Token" && v == "tok123"));
}

#[test]
fn session_inject_csrf_query() {
    let mut req = wafrift_types::Request::get("https://example.com/");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Query,
    );
    assert!(req.url.contains("csrf_token=tok123"));
}

#[test]
fn session_inject_csrf_query_appends() {
    let mut req = wafrift_types::Request::get("https://example.com/?existing=1");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Query,
    );
    assert!(req.url.contains("existing=1"));
    assert!(req.url.contains("csrf_token=tok123"));
    assert!(req.url.contains('&'));
}

#[test]
fn session_inject_csrf_body() {
    let mut req = wafrift_types::Request::post("https://example.com/", b"original");
    wafrift_transport::session::inject_csrf(
        &mut req,
        "tok123",
        wafrift_types::session::CsrfInjectionLocation::Body,
    );
    let body = req.body.unwrap();
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("csrf_token=tok123"));
    assert!(body_str.contains("original"));
}
