//! Unified upstream HTTP client for `wafrift-proxy`.
//!
//! Wraps either `reqwest::Client` (default, rustls TLS) or
//! `wafrift_transport::StealthClient` (opt-in via the
//! `tls-impersonate` feature on `wafrift-transport`, BoringSSL via
//! `rquest` for browser-identical JA3) behind a single `send()` API.
//!
//! Both paths return the same [`UpstreamResponse`] shape, so the proxy
//! call sites at `forward_wafrift_request` and `forward_passthrough`
//! don't need to know which TLS stack they're talking through.
//!
//! # Why this is a wrapper, not a swap
//!
//! `reqwest::Client` carries a lot of proxy-specific configuration we
//! depend on: SSRF-safe DNS resolver (custom bogon-checking resolver
//! re-runs the policy at connection time), redirect policy, cookie
//! jar, proxy pool, MITM cert handling. None of that is part of the
//! "stealth" goal — JA3 parity only matters for the upstream TLS
//! handshake bytes. So `reqwest` stays as the default; stealth gets
//! plumbed alongside as an alternative *for the upstream-fetch step
//! only*, when the practitioner has explicitly opted in.
//!
//! # Build matrix
//!
//! - Default build: `UpstreamClient::Reqwest` is the only enabled
//!   variant. The `Stealth` variant is `#[cfg(feature =
//!   "tls-impersonate")]`-gated. Practitioners trying
//!   `--tls-impersonate <profile>` against a binary built without the
//!   feature get an actionable error pointing at the cargo flag.
//! - With `tls-impersonate`: both variants compile.

use bytes::Bytes;
use std::time::Duration;
use thiserror::Error;
use wafrift_transport::stealth::ImpersonateProfile;
#[cfg(feature = "tls-impersonate")]
use wafrift_transport::stealth::StealthClient;

/// Upstream-fetch error. Wraps either reqwest's transport error or a
/// stealth-client error.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream request failed: {0}")]
    Request(String),

    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),

    #[error("upstream response too large (cap {cap}): truncated at {got} bytes")]
    BodyTooLarge { got: usize, cap: usize },

    #[error(
        "stealth mode requires the `tls-impersonate` cargo feature; \
         rebuild wafrift-proxy with `cargo build --features \
         wafrift-transport/tls-impersonate`"
    )]
    StealthFeatureDisabled,
}

/// One upstream response, materialised into a uniform shape.
#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

/// Either the default reqwest client or a stealth (rquest) client.
#[derive(Clone)]
pub enum UpstreamClient {
    /// Default rustls-backed reqwest client. Carries SSRF resolver,
    /// redirect policy, proxy-pool, etc.
    Reqwest(reqwest::Client),

    /// Opt-in BoringSSL-backed stealth client. Used only for the
    /// upstream forward step when `--tls-impersonate <profile>` is
    /// set on the proxy command line. Compiled out by default.
    #[cfg(feature = "tls-impersonate")]
    Stealth(std::sync::Arc<StealthClient>),
}

impl UpstreamClient {
    /// Build the default reqwest variant from a pre-configured client.
    /// All the SSRF/resolver/cookie wiring stays where it already is in
    /// `main()`; this is just the wrapping ctor.
    #[must_use]
    pub fn from_reqwest(client: reqwest::Client) -> Self {
        Self::Reqwest(client)
    }

    /// Build a stealth variant wearing the given browser profile.
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamError::StealthFeatureDisabled`] if the binary
    /// was built without `tls-impersonate`.
    pub fn stealth(_profile: ImpersonateProfile) -> Result<Self, UpstreamError> {
        #[cfg(feature = "tls-impersonate")]
        {
            let client = StealthClient::with_timeout(_profile, Duration::from_secs(60))
                .map_err(|e| UpstreamError::Request(e.to_string()))?;
            Ok(Self::Stealth(std::sync::Arc::new(client)))
        }
        #[cfg(not(feature = "tls-impersonate"))]
        {
            Err(UpstreamError::StealthFeatureDisabled)
        }
    }

    /// Send a request and read the response (with body bounded by
    /// `max_body`). Method/URL/headers/body shape mirrors what
    /// `forward_wafrift_request` already builds — the migration is just
    /// "stop calling `client.request(method, url).send()` directly,
    /// call this instead".
    ///
    /// # Body bounding
    ///
    /// Bodies are truncated at `max_body` bytes (no error, the
    /// truncated content is still useful for WAF-block detection —
    /// matches `forward_wafrift_request`'s existing semantics).
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        max_body: usize,
    ) -> Result<UpstreamResponse, UpstreamError> {
        match self {
            Self::Reqwest(client) => {
                let m = reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|_| UpstreamError::InvalidMethod(method.to_string()))?;
                let mut req = client.request(m, url);
                for (k, v) in headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(b) = body {
                    req = req.body(b);
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| UpstreamError::Request(e.to_string()))?;
                let status = http::StatusCode::from_u16(resp.status().as_u16())
                    .map_err(|e| UpstreamError::Request(e.to_string()))?;
                // reqwest's HeaderMap is from http already (re-export), so
                // we can clone it directly.
                let headers = resp.headers().clone();
                // Bound body read.
                let mut buf = Vec::new();
                let mut stream = resp.bytes_stream();
                use futures_util::StreamExt;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;
                    let remaining = max_body.saturating_sub(buf.len());
                    if remaining == 0 {
                        break;
                    }
                    let take = chunk.len().min(remaining);
                    buf.extend_from_slice(&chunk[..take]);
                    if chunk.len() > remaining {
                        break;
                    }
                }
                Ok(UpstreamResponse {
                    status,
                    headers,
                    body: Bytes::from(buf),
                })
            }
            #[cfg(feature = "tls-impersonate")]
            Self::Stealth(client) => {
                let stealth_resp = client
                    .send(method, url, headers, body.as_deref(), max_body)
                    .await
                    .map_err(|e| UpstreamError::Request(e.to_string()))?;
                let status = http::StatusCode::from_u16(stealth_resp.status)
                    .map_err(|e| UpstreamError::Request(e.to_string()))?;
                let mut header_map = http::HeaderMap::with_capacity(stealth_resp.headers.len());
                for (k, v) in &stealth_resp.headers {
                    if let (Ok(name), Ok(val)) = (
                        http::HeaderName::from_bytes(k.as_bytes()),
                        http::HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        header_map.append(name, val);
                    }
                    // Silently drop headers with invalid bytes — same
                    // behaviour as reqwest's parser would have.
                }
                Ok(UpstreamResponse {
                    status,
                    headers: header_map,
                    body: Bytes::from(stealth_resp.body),
                })
            }
        }
    }

    /// Returns the operator-visible name of the active TLS stack, for
    /// log lines / `/_wafrift/status` output.
    #[must_use]
    pub fn tls_stack_name(&self) -> &'static str {
        match self {
            Self::Reqwest(_) => "rustls (default)",
            #[cfg(feature = "tls-impersonate")]
            Self::Stealth(_) => "boringssl (stealth)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_reqwest_wraps_client() {
        let client = reqwest::Client::new();
        let upstream = UpstreamClient::from_reqwest(client);
        assert_eq!(upstream.tls_stack_name(), "rustls (default)");
    }

    #[test]
    fn upstream_error_messages_are_actionable() {
        let err = UpstreamError::InvalidMethod("FUBAR".into());
        assert!(err.to_string().contains("FUBAR"));

        let err = UpstreamError::BodyTooLarge {
            got: 5_000_000,
            cap: 1_000_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000000"));
        assert!(msg.contains("1000000"));

        let err = UpstreamError::StealthFeatureDisabled;
        let msg = err.to_string();
        assert!(
            msg.contains("tls-impersonate") && msg.contains("cargo build"),
            "feature-disabled error must name the cargo flag, got: {msg}"
        );
    }

    #[cfg(not(feature = "tls-impersonate"))]
    #[test]
    fn stealth_constructor_errors_when_feature_off() {
        let err = UpstreamClient::stealth(ImpersonateProfile::Chrome131).unwrap_err();
        assert!(matches!(err, UpstreamError::StealthFeatureDisabled));
    }

    #[cfg(feature = "tls-impersonate")]
    #[test]
    fn stealth_constructor_builds_when_feature_on() {
        let upstream = UpstreamClient::stealth(ImpersonateProfile::Chrome131).unwrap();
        assert_eq!(upstream.tls_stack_name(), "boringssl (stealth)");
    }
}
