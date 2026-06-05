//! JWT manipulation tests — alg:none, HS256 confusion, JWK embed.

use wafrift_transport::jwt::{JwtError, b64url_encode, decode_b64url_json, manipulate};
use wafrift_types::session::JwtManipulation;

fn valid_rs256_jwt() -> String {
    // header: {"alg":"RS256","typ":"JWT"}
    // payload: {"sub":"123"}
    // signature: dummy
    let header = b64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = b64url_encode(br#"{"sub":"123"}"#);
    format!("{header}.{payload}.sig")
}

fn valid_hs256_jwt() -> String {
    let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url_encode(br#"{"sub":"123"}"#);
    format!("{header}.{payload}.sig")
}

fn alg_none_jwt() -> String {
    let header = b64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64url_encode(br#"{"sub":"123"}"#);
    format!("{header}.{payload}.sig")
}

// ── StripAlg ───────────────────────────────────────────────────────────────

#[test]
fn strip_alg_changes_alg_to_none() {
    let token = valid_rs256_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[2].is_empty()); // signature removed

    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
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
    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
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

    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
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

    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
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
    // Contract: invalid --jwk JSON must be reported as a structured
    // `InvalidToken` error (so the operator gets an actionable message
    // about their broken input), NOT silently swallowed as `jwk: null`.
    // The earlier "graceful fallback to null" behavior silently produced
    // a useless token when the operator typo'd a JWK and gave no
    // feedback — strict validation surfaces the typo at the boundary.
    // The "graceful" in the test name refers to "no panic", which is
    // still satisfied by the Err return path.
    let token = valid_rs256_jwt();
    let jwk = "not valid json";
    let err = manipulate(&token, &JwtManipulation::JwkEmbed { jwk: jwk.into() }, None).unwrap_err();
    match err {
        JwtError::InvalidToken { reason } => {
            assert!(
                reason.contains("--jwk") && reason.contains("not valid JSON"),
                "error must name the bad flag and the reason: got {reason:?}"
            );
        }
        other => panic!("expected InvalidToken for malformed --jwk JSON, got {other:?}"),
    }
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
    let header = b64url_encode(b"not json");
    let token = format!("{header}.payload.sig");
    let err = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

#[test]
fn manipulate_empty_string() {
    let err = manipulate("", &JwtManipulation::StripAlg, None).unwrap_err();
    assert!(matches!(err, JwtError::InvalidToken { .. }));
}

// ── HS256 input paths ──────────────────────────────────────────────────────

/// StripAlg on an HS256 token must produce a valid alg:none token.
/// This is the algorithm-confusion attack surface: downgrade any
/// symmetric-key JWT to alg:none so the signature is stripped and the
/// server (if naively implemented) accepts it unsigned.
#[test]
fn strip_alg_on_hs256_produces_alg_none() {
    let token = valid_hs256_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    assert_eq!(parts.len(), 3, "result must have three dot-delimited parts");
    assert!(parts[2].is_empty(), "signature part must be stripped for alg:none");

    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
    assert_eq!(header["alg"], "none", "alg field must be rewritten to 'none'");
}

/// StripAlg on an HS256 token must preserve the payload claim-set unchanged.
#[test]
fn strip_alg_on_hs256_preserves_payload() {
    let token = valid_hs256_jwt();
    let result = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let original_parts: Vec<&str> = token.split('.').collect();
    let new_parts: Vec<&str> = result.split('.').collect();
    assert_eq!(
        original_parts[1], new_parts[1],
        "payload claim-set must be unchanged after StripAlg"
    );
}

/// Hs256WithKey on an HS256-signed token (same algorithm): the output must
/// still carry alg:HS256 and a non-empty signature — the manipulation is
/// idempotent for the header algorithm field.
#[test]
fn hs256_with_key_on_hs256_token_roundtrips_alg() {
    let token = valid_hs256_jwt();
    let key = b"symmetric-secret";
    let result = manipulate(&token, &JwtManipulation::Hs256WithKey, Some(key)).unwrap();
    let parts: Vec<&str> = result.split('.').collect();
    assert_eq!(parts.len(), 3);

    let header: serde_json::Value =
        decode_b64url_json(parts[0]).expect("valid base64url JSON");
    assert_eq!(
        header["alg"], "HS256",
        "HS256 output of Hs256WithKey must keep alg:HS256"
    );
    assert!(!parts[2].is_empty(), "signature must be present after HS256 re-signing");
}

// ── Determinism ────────────────────────────────────────────────────────────

#[test]
fn strip_alg_is_deterministic() {
    let token = valid_rs256_jwt();
    let r1 = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    let r2 = manipulate(&token, &JwtManipulation::StripAlg, None).unwrap();
    assert_eq!(r1, r2);
}
