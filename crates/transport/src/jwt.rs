use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;
use wafrift_types::session::JwtManipulation;

// ── Base64url primitives (RFC 7515 §2) ──────────────────────────────────────

/// Encode `bytes` as URL-safe base64 without padding (per RFC 7515 §2).
///
/// All JWS/JWT operations use this alphabet: `A-Z a-z 0-9 - _`, no `=`
/// padding.
///
/// §7 DEDUP: the ONE implementation of the base64url alphabet is the audited
/// `base64` crate's `URL_SAFE_NO_PAD` engine — that is the true single source,
/// and these functions are just transport's thin (zero-logic) wrappers over
/// it. Callers WITHIN the transport dependency layer should use these wrappers
/// for ergonomics; lower crates that can't depend on transport (e.g.
/// `wafrift-encoding`) correctly call `URL_SAFE_NO_PAD` directly — same single
/// source, so there is genuinely no alphabet-loop fork to drift. (Never
/// hand-roll a base64url alphabet table; use the crate engine.)
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a URL-safe base64 string (with or without padding) into bytes.
///
/// Returns `None` on any alphabet or padding error so callers can propagate
/// `JwtError::InvalidToken` instead of panicking. Backed by the audited
/// `base64` crate — no hand-rolled lookup tables.
#[must_use]
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    // Accept both padded and unpadded inputs; the `base64` crate handles
    // trailing `=` gracefully under URL_SAFE_NO_PAD.
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Decode a URL-safe base64 JWT segment and parse the result as JSON.
///
/// Returns `None` when the segment is not valid base64url or the bytes are
/// not valid UTF-8/JSON (e.g. a non-JSON payload, a corrupted segment, or
/// an attacker-supplied segment in a differential probe).
#[must_use]
pub fn decode_b64url_json(s: &str) -> Option<serde_json::Value> {
    let bytes = b64url_decode(s)?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Invalid token: {reason}")]
    InvalidToken { reason: String },
    #[error("Missing key")]
    MissingKey,
    #[error("Unsupported algorithm: {alg}")]
    UnsupportedAlgorithm { alg: String },
}

pub fn manipulate(
    token: &str,
    manipulation: &JwtManipulation,
    key: Option<&[u8]>,
) -> Result<String, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidToken {
            reason: "must have 3 parts".into(),
        });
    }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];

    let header_bytes = b64url_decode(header_b64).ok_or_else(|| JwtError::InvalidToken {
        reason: "invalid base64".into(),
    })?;

    // Reject absurdly large headers before feeding them to serde_json to
    // prevent OOM from maliciously crafted tokens.
    const MAX_JWT_HEADER_BYTES: usize = 16 * 1024;
    if header_bytes.len() > MAX_JWT_HEADER_BYTES {
        return Err(JwtError::InvalidToken {
            reason: format!("header exceeds {MAX_JWT_HEADER_BYTES} bytes"),
        });
    }

    let mut header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidToken {
            reason: "invalid json".into(),
        })?;

    // RFC 7515 §4: the JOSE header MUST be a JSON object. Every arm below
    // mutates it via `header["alg"] = …` / `header["jwk"] = …`, and
    // serde_json's `IndexMut<&str>` PANICS ("cannot access key … in JSON
    // {array,string,number,bool}") when the value is not an object (it only
    // promotes `null`). A malicious/fuzzed token whose header decodes to a
    // non-object — e.g. `WzEsMiwzXQ` → `[1,2,3]`, or a bare string/number —
    // would otherwise crash the process (§15 panic-in-production). Reject
    // loudly instead. `null` is also rejected: it is not a valid JOSE header.
    if !header.is_object() {
        return Err(JwtError::InvalidToken {
            reason: "JOSE header must be a JSON object".into(),
        });
    }

    match manipulation {
        JwtManipulation::StripAlg => {
            header["alg"] = serde_json::Value::String("none".into());
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 = b64url_encode(&header_bytes);
            Ok(format!("{new_header_b64}.{payload_b64}."))
        }
        JwtManipulation::Hs256WithKey => {
            let key_bytes = key.ok_or(JwtError::MissingKey)?;
            if header["alg"].as_str() == Some("none") {
                return Err(JwtError::UnsupportedAlgorithm { alg: "none".into() });
            }
            header["alg"] = serde_json::Value::String("HS256".into());
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 = b64url_encode(&header_bytes);
            // Real HMAC-SHA256 over `header.payload` per RFC 7515 §3.1.
            // Pre-fix this returned the literal string "fakesignature"
            // (LAW 1 stub) — the resulting token had a valid alg
            // header but a signature no server would accept. The
            // jwt-diff probe couldn't exercise the "server accepts
            // HS256 with a guessed key" attack class.
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            let signing_input = format!("{new_header_b64}.{payload_b64}");
            let mut mac =
                HmacSha256::new_from_slice(key_bytes).map_err(|e| JwtError::InvalidToken {
                    reason: format!("HMAC key init failed: {e}"),
                })?;
            mac.update(signing_input.as_bytes());
            let sig = mac.finalize().into_bytes();
            let sig_b64 = b64url_encode(&sig);
            Ok(format!("{new_header_b64}.{payload_b64}.{sig_b64}"))
        }
        JwtManipulation::JwkEmbed { jwk } => {
            // F129: pre-fix swallowed JWK parse errors via
            // `unwrap_or(Value::Null)` — operator passes a malformed
            // JWK string, gets back a token with `"jwk": null` and an
            // Ok result. The "test if server validates jwk claim
            // correctly" probe was rendered meaningless because the
            // header carried null instead of the intended JWK. Surface
            // the parse error as InvalidToken so the operator knows
            // their JWK input was bad before sending the request.
            let jwk_value = serde_json::from_str(jwk).map_err(|e| JwtError::InvalidToken {
                reason: format!("--jwk is not valid JSON: {e}"),
            })?;
            header["jwk"] = jwk_value;
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 = b64url_encode(&header_bytes);
            Ok(format!("{}.{}.{}", new_header_b64, payload_b64, parts[2]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_token() -> String {
        // header: {"alg":"HS256","typ":"JWT"}
        // payload: {"sub":"123"}
        // sig: dummy
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dummy".to_string()
    }

    #[test]
    fn manipulate_rejects_malformed_token() {
        let result = manipulate("not.a.jwt", &JwtManipulation::StripAlg, None);
        assert!(matches!(result, Err(JwtError::InvalidToken { .. })));
    }

    #[test]
    fn manipulate_rejects_two_part_token() {
        let result = manipulate("eyJhbGc.a", &JwtManipulation::StripAlg, None);
        assert!(matches!(result, Err(JwtError::InvalidToken { .. })));
    }

    #[test]
    fn manipulate_rejects_non_object_header_does_not_panic() {
        // §15 panic-in-production regression: serde_json's `header["alg"] = …`
        // IndexMut PANICS when the header is a non-object JSON value (it only
        // promotes `null` and inserts into objects). A token whose header
        // decodes to an array/string/number/bool/null must be rejected with
        // InvalidToken across EVERY manipulation arm — never crash the process.
        let payload = b64url_encode(br#"{"sub":"1"}"#);
        let non_object_headers: &[&[u8]] = &[b"[1,2,3]", b"\"hello\"", b"42", b"true", b"null"];
        for raw in non_object_headers {
            let tok = format!("{}.{}.dummy", b64url_encode(raw), payload);
            let label = std::str::from_utf8(raw).unwrap();

            let r = manipulate(&tok, &JwtManipulation::StripAlg, None);
            assert!(
                matches!(r, Err(JwtError::InvalidToken { .. })),
                "StripAlg on non-object header {label:?} must error, not panic: {r:?}"
            );

            let r = manipulate(&tok, &JwtManipulation::Hs256WithKey, Some(b"k"));
            assert!(
                matches!(r, Err(JwtError::InvalidToken { .. })),
                "Hs256WithKey on non-object header {label:?} must error, not panic: {r:?}"
            );

            let r = manipulate(
                &tok,
                &JwtManipulation::JwkEmbed {
                    jwk: r#"{"kty":"oct"}"#.into(),
                },
                None,
            );
            assert!(
                matches!(r, Err(JwtError::InvalidToken { .. })),
                "JwkEmbed on non-object header {label:?} must error, not panic: {r:?}"
            );
        }
    }

    #[test]
    fn manipulate_accepts_object_header_after_guard() {
        // Belt-and-suspenders: the non-object guard must NOT reject a real
        // object header (the legitimate path must still work).
        let out = manipulate(&valid_token(), &JwtManipulation::StripAlg, None).unwrap();
        assert_eq!(out.split('.').count(), 3);
    }

    #[test]
    fn strip_alg_sets_none() {
        let out = manipulate(&valid_token(), &JwtManipulation::StripAlg, None).unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = decode_b64url_json(parts[0]).expect("valid base64url JSON");
        assert_eq!(header["alg"], "none");
    }

    #[test]
    fn hs256_with_key_rejects_missing_key() {
        let result = manipulate(&valid_token(), &JwtManipulation::Hs256WithKey, None);
        assert!(matches!(result, Err(JwtError::MissingKey)));
    }

    #[test]
    fn hs256_with_key_changes_alg() {
        let out = manipulate(
            &valid_token(),
            &JwtManipulation::Hs256WithKey,
            Some(b"secret"),
        )
        .unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        let header: serde_json::Value = decode_b64url_json(parts[0]).expect("valid base64url JSON");
        assert_eq!(header["alg"], "HS256");
    }

    #[test]
    fn hs256_with_key_produces_real_hmac_signature() {
        // Regression for the "fakesignature" stub: the output must
        // be a base64url-encoded 32-byte HMAC-SHA256 over the
        // signing input, not the literal string "fakesignature".
        let out = manipulate(
            &valid_token(),
            &JwtManipulation::Hs256WithKey,
            Some(b"my-secret-key"),
        )
        .unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_ne!(parts[2], "fakesignature", "must not be the stub literal");
        // Decode base64url → 32 bytes (SHA-256 output).
        let sig_bytes = b64url_decode(parts[2]).expect("sig must be valid base64url");
        assert_eq!(sig_bytes.len(), 32, "HMAC-SHA256 produces 32 bytes");

        // Independently compute the expected signature to prove it's
        // a REAL HMAC over the right input.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let mut mac = HmacSha256::new_from_slice(b"my-secret-key").unwrap();
        mac.update(signing_input.as_bytes());
        let expected = mac.finalize().into_bytes();
        assert_eq!(sig_bytes.as_slice(), expected.as_slice());
    }

    #[test]
    fn hs256_signature_is_deterministic_for_same_key_and_payload() {
        let a = manipulate(&valid_token(), &JwtManipulation::Hs256WithKey, Some(b"k")).unwrap();
        let b = manipulate(&valid_token(), &JwtManipulation::Hs256WithKey, Some(b"k")).unwrap();
        assert_eq!(a, b, "HMAC is deterministic");
    }

    #[test]
    fn hs256_signature_differs_per_key() {
        let a = manipulate(&valid_token(), &JwtManipulation::Hs256WithKey, Some(b"k1")).unwrap();
        let b = manipulate(&valid_token(), &JwtManipulation::Hs256WithKey, Some(b"k2")).unwrap();
        let sig_a = a.split('.').nth(2).unwrap();
        let sig_b = b.split('.').nth(2).unwrap();
        assert_ne!(sig_a, sig_b, "different keys must produce different sigs");
    }

    #[test]
    fn hs256_rejects_none_alg() {
        let none_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.dummy";
        let result = manipulate(none_token, &JwtManipulation::Hs256WithKey, Some(b"secret"));
        assert!(matches!(result, Err(JwtError::UnsupportedAlgorithm { .. })));
    }

    #[test]
    fn jwk_embed_adds_jwk() {
        let jwk = r#"{"kty":"RSA","n":"abc"}"#;
        let out = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed { jwk: jwk.into() },
            None,
        )
        .unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        let header: serde_json::Value = decode_b64url_json(parts[0]).expect("valid base64url JSON");
        assert_eq!(header["jwk"]["kty"], "RSA");
    }

    // F129 regression: malformed JWK input MUST surface as Err, not
    // silently substitute `null`. Pre-fix the helper used
    // `unwrap_or(Value::Null)` and the resulting token had `"jwk":
    // null` in its header — operator probing whether the server
    // validates the `jwk` claim got a meaningless probe because the
    // claim was missing the actual key material.
    #[test]
    fn jwk_embed_invalid_json_returns_err() {
        let err = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed {
                jwk: "not json".into(),
            },
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, JwtError::InvalidToken { ref reason } if reason.contains("--jwk")),
            "got: {err:?}"
        );
    }

    #[test]
    fn jwk_embed_empty_string_returns_err() {
        let err = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed { jwk: "".into() },
            None,
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::InvalidToken { .. }));
    }

    #[test]
    fn jwk_embed_partial_json_returns_err() {
        // Half-quoted, missing closing brace — common operator typo.
        let err = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed {
                jwk: r#"{"kty":"RSA""#.into(),
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(err, JwtError::InvalidToken { .. }));
    }

    #[test]
    fn jwk_embed_valid_jwk_string_with_unicode_escapes_preserved() {
        // Anti-rig: a valid JWK with non-ASCII escapes must round-trip
        // intact through the header, not get re-encoded by serde.
        let jwk = r#"{"kty":"oct","k":"é"}"#;
        let out = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed { jwk: jwk.into() },
            None,
        )
        .unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        let header: serde_json::Value = decode_b64url_json(parts[0]).expect("valid base64url JSON");
        // The unicode escape decodes to é (U+00E9).
        assert_eq!(header["jwk"]["k"], "é");
    }

    // ── b64url_encode / b64url_decode boundary + anti-rig ────────────────────
    //
    // These are the canonical primitives used by every JWT code path in the
    // workspace; all contract guarantees live here, not in downstream callers.

    #[test]
    fn b64url_encode_empty_input_produces_empty_string() {
        // Boundary: 0 bytes → 0 chars.
        assert_eq!(b64url_encode(b""), "");
    }

    #[test]
    fn b64url_decode_empty_string_produces_empty_vec() {
        // Boundary: empty string → empty Vec.
        assert_eq!(b64url_decode(""), Some(vec![]));
    }

    #[test]
    fn b64url_round_trip_single_byte() {
        // Boundary: 1 byte (rem==1 code path).
        for byte in [0u8, 1, 127, 255] {
            let enc = b64url_encode(&[byte]);
            let dec = b64url_decode(&enc).expect("single byte round-trip");
            assert_eq!(dec, [byte], "round-trip failed for byte {byte}");
        }
    }

    #[test]
    fn b64url_round_trip_two_bytes() {
        // Boundary: 2 bytes (rem==2 code path).
        let input = b"\xFF\x00";
        let enc = b64url_encode(input);
        let dec = b64url_decode(&enc).expect("two-byte round-trip");
        assert_eq!(dec, input);
    }

    #[test]
    fn b64url_round_trip_three_bytes_exact() {
        // Boundary: exactly 3 bytes (full 4-char group, no remainder).
        let input = b"\x00\x01\x02";
        let enc = b64url_encode(input);
        let dec = b64url_decode(&enc).expect("three-byte round-trip");
        assert_eq!(dec, input);
    }

    #[test]
    fn b64url_encode_uses_url_safe_alphabet_no_padding() {
        // Anti-rig: any output that contains `+`, `/`, or `=` is a bug.
        // Use bytes that map to chars near the boundary of the standard
        // and url-safe alphabets.
        let input = b"\xfb\xff\xff"; // would produce `+///` in std base64
        let enc = b64url_encode(input);
        assert!(!enc.contains('+'), "url-safe: + → -");
        assert!(!enc.contains('/'), "url-safe: / → _");
        assert!(!enc.contains('='), "no padding");
        // Verify correctness: we expect `-__/` → `-__` for 3 bytes.
        let dec = b64url_decode(&enc).expect("decode");
        assert_eq!(dec, input);
    }

    #[test]
    fn b64url_decode_returns_none_on_invalid_character() {
        // `+` and `/` are not in the url-safe alphabet.
        assert!(b64url_decode("abc+").is_none());
        assert!(b64url_decode("ab/c").is_none());
    }

    #[test]
    fn b64url_decode_returns_none_on_garbage() {
        assert!(b64url_decode("!@#$").is_none());
    }

    #[test]
    fn b64url_round_trip_max_useful_size() {
        // Boundary: a 4096-byte payload (max scan window used elsewhere).
        let input: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let enc = b64url_encode(&input);
        let dec = b64url_decode(&enc).expect("4096-byte round-trip");
        assert_eq!(dec, input);
    }

    #[test]
    fn decode_b64url_json_returns_none_for_valid_base64url_but_non_json() {
        // Boundary: valid base64url that decodes to non-UTF-8 / non-JSON.
        let enc = b64url_encode(b"\x80\x81\x82"); // not valid UTF-8
        assert!(decode_b64url_json(&enc).is_none());
    }

    #[test]
    fn decode_b64url_json_returns_none_on_empty_input() {
        // Empty string → empty bytes → not valid JSON.
        assert!(decode_b64url_json("").is_none());
    }

    #[test]
    fn decode_b64url_json_parses_object() {
        let enc = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let v = decode_b64url_json(&enc).expect("valid JSON object");
        assert_eq!(v["alg"], "HS256");
        assert_eq!(v["typ"], "JWT");
    }

    #[test]
    fn b64url_encode_output_is_ascii_only() {
        // Anti-rig: all output characters must be in the url-safe alphabet.
        let input: Vec<u8> = (0u8..=255).collect();
        let enc = b64url_encode(&input);
        assert!(
            enc.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "unexpected character in output: {enc}"
        );
    }
}
