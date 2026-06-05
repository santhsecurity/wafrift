use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Session configuration for authenticated scan workflows.
///
/// Groups all per-session knobs: cookie jar, CSRF token extraction,
/// auth header injection, and JWT manipulation. Consumed by
/// `wafrift-transport`'s session initialisation path (`transport::session`
/// and `transport::jwt`). The constituent enums ([`CsrfInjectionLocation`],
/// [`JwtManipulation`]) are used independently wherever only one axis
/// of session configuration is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionConfig {
    /// Path to a Netscape/curl-format cookie jar file.
    pub cookie_jar_path: Option<PathBuf>,
    /// Regex to extract the CSRF token value from a GET response body.
    pub csrf_extract_regex: Option<String>,
    /// Where to inject the extracted CSRF token into subsequent requests.
    pub csrf_injection: CsrfInjectionLocation,
    /// Verbatim `Authorization` header value (e.g. `"Bearer <token>"`).
    pub auth_header: Option<String>,
    /// JWT manipulation mode applied to `Authorization: Bearer` tokens.
    pub jwt_manipulation: Option<JwtManipulation>,
    /// Signing key for `JwtManipulation::Hs256WithKey`; ignored otherwise.
    pub jwt_signing_key: Option<String>,
}

/// Determines which part of the HTTP request carries the injected CSRF token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CsrfInjectionLocation {
    /// Inject via `X-CSRF-Token` / `X-Requested-With` request header (default).
    #[default]
    Header,
    /// Append as a query parameter (`?csrf_token=…`).
    Query,
    /// Merge into the request body (form-encoded or JSON, depending on content type).
    Body,
}

/// JWT attack mode applied to Bearer tokens in session-authenticated scans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JwtManipulation {
    /// Remove the `alg` header claim — tests for `alg:none` acceptance (CVE class).
    StripAlg,
    /// Re-sign the token with an HMAC-SHA256 key supplied in `SessionConfig::jwt_signing_key`.
    Hs256WithKey,
    /// Embed an attacker-controlled JWK in the token header and self-sign.
    JwkEmbed { jwk: String },
}
