//! JWT manipulation tests — alg:none, HS256 confusion, JWK embed.

use base64::Engine;
use wafrift_transport::jwt::{manipulate, JwtError};
use wafrift_types::session::JwtManipulation;

fn valid_rs256_jwt() -> String {
    // header: {"alg":"RS256","typ":"JWT"}
    // payload: {"sub":"123"}
    // signature: dummy
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"123"}"#);
    format!("{}.{}.sig", header, payload)
}

#[allow(dead_code)]
fn valid_hs256_jwt() -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"123"}"#);
    format!("{}.{}.sig", header, payload)
}

fn alg_none_jwt() -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"123"}"#);
    format!("{}.{}.sig", header, payload)
}

// ── StripAlg ───────────────────────────────────────────────────────────────

#[test]
fn strip_alg_changes_alg_to_none() {
    let token = valid_rs256_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[2].is_empty()); // signature removed

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "none");
}

#[test]
fn strip_alg_preserves_payload() {
    let token = valid_rs256_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let original_parts: Vec<&str> = token.split('.').collect();
    let new_parts: Vec<&str> = result.split('.').collect();
    assert_eq!(original_parts[1], new_parts[1]);
}

#[test]
fn strip_alg_on_already_none_jwt() {
    let token = alg_none_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "none");
}

// ── Hs256WithKey ───────────────────────────────────────────────────────────

#[test]
fn hs256_changes_alg() {
    let token = valid_rs256_jwt();
    let key = b"secret";
    let result = manipulate(&token, &JwtManipulation::Hs256WithKey, Some(key)).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    assert_eq!(parts.len(), 3);

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "HS256");
}

#[test]
fn hs256_fails_without_key() {
    let token = valid_rs256_jwt();
    let err = manipulate(&token, &JwtManipulation::Hs256WithKey, None).unwrap_err();
    assert!(matches!(err, JwtError::MissingKey));
}

#[test]
fn hs256_fails_on_alg_none() {
    let token = alg_none_jwt();
    let key = b"secret";
    let err = manipulate(&token, &JwtManipulation::Hs256WithKey, Some(key)).unwrap_err();
    assert!(matches!(err, JwtError::UnsupportedAlgorithm { alg } if alg == "none"));
}

// ── JwkEmbed ───────────────────────────────────────────────────────────────

#[test]
fn jwk_embed_adds_jwk_to_header() {
    let token = valid_rs256_jwt();
    let jwk = r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#;
    let result = manipulate(&token, &JwtManipulation::JwkEmbed { jwk: jwk.into() }, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert!(header["jwk"].is_object());
    assert_eq!(header["jwk"]["kty"], "RSA");
}

#[test]
fn jwk_embed_preserves_original_signature() {
    let token = valid_rs256_jwt();
    let jwk = r#"{"kty":"RSA"}"#;
    let result = manipulate(&token, &JwtManipulation::JwkEmbed { jwk: jwk.into() }, None).unwrap();
    let original_parts: Vec<&str> = token.split('.').collect();
    let new_parts: Vec<&str> = result.split('.').collect();
    assert_eq!(original_parts[2], new_parts[2]);
}

#[test]
fn jwk_embed_invalid_json_graceful() {
    let token = valid_rs256_jwt();
    let jwk = "not valid json";
    let result = manipulate(&token, &JwtManipulation::JwkEmbed { jwk: jwk.into() }, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    // Should set jwk to Null instead of panicking
    assert!(header["jwk"].is_null());
}

// ── Invalid input handling ─────────────────────────────────────────────────

#[test]
fn manipulate_invalid_two_parts() {
    let err = manipulate("header.payload", &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

#[test]
fn manipulate_invalid_four_parts() {
    let err = manipulate("a.b.c.d", &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

#[test]
fn manipulate_invalid_base64_header() {
    let err = manipulate("!!!.payload.sig", &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

#[test]
fn manipulate_invalid_json_header() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("not json");
    let token = format!("{}.payload.sig", header);
    let err = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

#[test]
fn manipulate_empty_string() {
    let err = manipulate("", &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

// ── Determinism ────────────────────────────────────────────────────────────

#[test]
fn strip_alg_is_deterministic() {
    let token = valid_rs256_jwt();
    let r1 = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let r2 = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    assert_eq!(r1, r2);
}
