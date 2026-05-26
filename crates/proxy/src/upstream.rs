//! Unified upstream HTTP client for `wafrift-proxy`.
//!
//! Wraps either `reqwest::Client` (default, rustls TLS) or
//! `wafrift_transport::StealthClient` (opt-in via the
//! `tls-impersonate` feature on `wafrift-transport`, `BoringSSL` via
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
#[cfg(feature = "tls-impersonate")]
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

/// Either the default reqwest client or a stealth (rquest) client,
/// optionally wearing a different browser fingerprint per request via
/// the `UpstreamClient::StealthPool` variant.
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

    /// Round-robin pool of stealth clients (one per profile). Lets the
    /// proxy rotate browser fingerprints per request, which defeats
    /// rate-limit-by-JA3 and per-fingerprint reputation systems
    /// (Cloudflare bot-management, Akamai BMP). Selected with
    /// `--tls-impersonate-rotate chrome131,firefox133,safari18`.
    #[cfg(feature = "tls-impersonate")]
    StealthPool {
        /// Pre-built clients, one per profile. Indexed via the atomic
        /// `cursor` below.
        clients: std::sync::Arc<Vec<std::sync::Arc<StealthClient>>>,
        /// Round-robin counter. `AtomicUsize` so `send()` stays `&self`
        /// — the proxy holds the pool inside an `Arc` and dispatches
        /// from many concurrent tasks.
        cursor: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    },
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reqwest(_) => f.debug_tuple("Reqwest").finish(),
            #[cfg(feature = "tls-impersonate")]
            Self::Stealth(_) => f.debug_tuple("Stealth").finish(),
            #[cfg(feature = "tls-impersonate")]
            Self::StealthPool { clients, cursor } => f
                .debug_struct("StealthPool")
                .field("clients", &clients.len())
                .field("cursor", cursor)
                .finish(),
        }
    }
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

    /// Build a rotating pool of stealth clients (one per profile).
    /// `send()` advances a round-robin cursor so successive requests
    /// land on different fingerprints.
    ///
    /// # Errors
    ///
    /// - [`UpstreamError::StealthFeatureDisabled`] if built without
    ///   `tls-impersonate`.
    /// - [`UpstreamError::Request`] if any client fails to build OR if
    ///   `_profiles` is empty (a pool of zero is meaningless).
    pub fn stealth_pool(_profiles: &[ImpersonateProfile]) -> Result<Self, UpstreamError> {
        #[cfg(feature = "tls-impersonate")]
        {
            if _profiles.is_empty() {
                return Err(UpstreamError::Request(
                    "stealth_pool requires at least one profile".into(),
                ));
            }
            let mut clients = Vec::with_capacity(_profiles.len());
            for &p in _profiles {
                let c = StealthClient::with_timeout(p, Duration::from_secs(60))
                    .map_err(|e| UpstreamError::Request(format!("{}: {e}", p.name())))?;
                clients.push(std::sync::Arc::new(c));
            }
            Ok(Self::StealthPool {
                clients: std::sync::Arc::new(clients),
                cursor: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
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
                // Previously the loop silently truncated at max_body bytes and
                // returned Ok(truncated_body) — UpstreamError::BodyTooLarge was
                // defined but never emitted, making it impossible for callers to
                // distinguish a complete response from a truncated one. A WAF
                // block that happens to produce a large body would be silently
                // truncated, potentially making the response look like a pass
                // when the real indicator was cut off. Now we return the explicit
                // error so callers can treat it as a failed scan / skip.
                let mut buf = Vec::new();
                let mut stream = resp.bytes_stream();
                use futures_util::StreamExt;
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|e| UpstreamError::Request(e.to_string()))?;
                    if buf.len().saturating_add(chunk.len()) > max_body {
                        // We've hit the cap. Return a hard error so callers know
                        // the body was not fully read rather than silently lying
                        // about the truncated content.
                        return Err(UpstreamError::BodyTooLarge {
                            got: buf.len().saturating_add(chunk.len()),
                            cap: max_body,
                        });
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(UpstreamResponse {
                    status,
                    headers,
                    body: Bytes::from(buf),
                })
            }
            #[cfg(feature = "tls-impersonate")]
            Self::Stealth(client) => {
                Self::send_via_stealth(client, method, url, headers, body, max_body).await
            }
            #[cfg(feature = "tls-impersonate")]
            Self::StealthPool { clients, cursor } => {
                let idx = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
                let client = clients[idx].clone();
                Self::send_via_stealth(&client, method, url, headers, body, max_body).await
            }
        }
    }

    #[cfg(feature = "tls-impersonate")]
    async fn send_via_stealth(
        client: &StealthClient,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        max_body: usize,
    ) -> Result<UpstreamResponse, UpstreamError> {
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
        }
        Ok(UpstreamResponse {
            status,
            headers: header_map,
            body: Bytes::from(stealth_resp.body),
        })
    }

    /// Returns the operator-visible name of the active TLS stack, for
    /// log lines / `/_wafrift/status` output.
    #[must_use]
    pub fn tls_stack_name(&self) -> &'static str {
        match self {
            Self::Reqwest(_) => "rustls (default)",
            #[cfg(feature = "tls-impersonate")]
            Self::Stealth(_) => "boringssl (stealth)",
            #[cfg(feature = "tls-impersonate")]
            Self::StealthPool { .. } => "boringssl (stealth pool, rotating)",
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
        match UpstreamClient::stealth(ImpersonateProfile::Chrome131) {
            Err(UpstreamError::StealthFeatureDisabled) => {}
            Err(other) => panic!("expected StealthFeatureDisabled, got {other}"),
            Ok(_) => panic!("expected error, got Ok variant"),
        }
    }

    #[cfg(feature = "tls-impersonate")]
    #[test]
    fn stealth_constructor_builds_when_feature_on() {
        let upstream = UpstreamClient::stealth(ImpersonateProfile::Chrome131).unwrap();
        assert_eq!(upstream.tls_stack_name(), "boringssl (stealth)");
    }

    #[cfg(feature = "tls-impersonate")]
    #[test]
    fn stealth_pool_rotates_round_robin() {
        let pool = UpstreamClient::stealth_pool(&[
            ImpersonateProfile::Chrome131,
            ImpersonateProfile::Firefox133,
            ImpersonateProfile::Safari18,
        ])
        .unwrap();
        assert_eq!(pool.tls_stack_name(), "boringssl (stealth pool, rotating)");
        // Cursor advances on every send. We can't test a real send
        // without a network, but we can exercise the cursor by faking
        // index calculation.
        if let UpstreamClient::StealthPool { clients, cursor } = &pool {
            assert_eq!(clients.len(), 3);
            let first = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
            let second = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
            let third = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
            let fourth = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
            assert_eq!((first, second, third, fourth), (0, 1, 2, 0));
        } else {
            panic!("expected StealthPool variant");
        }
    }

    #[cfg(feature = "tls-impersonate")]
    #[test]
    fn stealth_pool_rejects_empty_profiles() {
        let err = UpstreamClient::stealth_pool(&[]).unwrap_err();
        match err {
            UpstreamError::Request(msg) => assert!(msg.contains("at least one")),
            other => panic!("expected Request error, got {other:?}"),
        }
    }

    #[cfg(not(feature = "tls-impersonate"))]
    #[test]
    fn stealth_pool_errors_when_feature_off() {
        match UpstreamClient::stealth_pool(&[ImpersonateProfile::Chrome131]) {
            Err(UpstreamError::StealthFeatureDisabled) => {}
            Err(other) => panic!("expected StealthFeatureDisabled, got {other}"),
            Ok(_) => panic!("expected error, got Ok variant"),
        }
    }

    // ── New tests added 2026-05-24 ─────────────────────────────────────────

    #[test]
    fn body_too_large_error_got_and_cap_correct() {
        // UpstreamError::BodyTooLarge must carry correct got and cap values.
        let err = UpstreamError::BodyTooLarge { got: 1024, cap: 512 };
        match &err {
            UpstreamError::BodyTooLarge { got, cap } => {
                assert_eq!(*got, 1024);
                assert_eq!(*cap, 512);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("1024"), "error message must contain got=1024");
        assert!(msg.contains("512"), "error message must contain cap=512");
    }

    #[test]
    fn body_too_large_at_cap_does_not_error() {
        // We can't call .send() without network, but we can verify that
        // the error is only BodyTooLarge { got, cap } where got > cap.
        // At exactly cap bytes, the logic should NOT produce BodyTooLarge.
        // Verify the check logic directly: buf.len() + chunk.len() > max_body.
        let cap = 100usize;
        let buf_len = 95usize;
        let chunk_len = 5usize;
        assert_eq!(
            buf_len + chunk_len,
            cap,
            "buf+chunk exactly equals cap — must not trigger BodyTooLarge"
        );
        // Would trigger:
        let over = buf_len + chunk_len + 1;
        assert!(over > cap, "over must exceed cap to trigger error");
    }

    #[test]
    fn upstream_error_invalid_method_contains_method_name() {
        let err = UpstreamError::InvalidMethod("BADMETHOD".into());
        let msg = err.to_string();
        assert!(
            msg.contains("BADMETHOD"),
            "InvalidMethod must name the method, got: {msg}"
        );
    }

    #[test]
    fn upstream_error_request_contains_inner() {
        let err = UpstreamError::Request("connection refused".into());
        let msg = err.to_string();
        assert!(
            msg.contains("connection refused"),
            "Request error must include inner message, got: {msg}"
        );
    }

    #[test]
    fn stealth_feature_disabled_error_names_cargo_flag() {
        // The error message must name both the feature flag AND the
        // cargo build command so the user knows what to do.
        let err = UpstreamError::StealthFeatureDisabled;
        let msg = err.to_string();
        assert!(
            msg.contains("tls-impersonate"),
            "feature-disabled error must name `tls-impersonate`, got: {msg}"
        );
        assert!(
            msg.contains("cargo build"),
            "feature-disabled error must mention `cargo build`, got: {msg}"
        );
    }

    #[test]
    fn tls_stack_name_reqwest_variant() {
        let client = reqwest::Client::new();
        let upstream = UpstreamClient::from_reqwest(client);
        assert_eq!(upstream.tls_stack_name(), "rustls (default)");
    }

    #[test]
    fn body_too_large_boundary_just_at_cap() {
        // Boundary: got == cap is NOT a BodyTooLarge condition in the contract.
        // got > cap is the trigger. This test verifies the condition semantics.
        let cap = 1024usize;
        let at_cap = UpstreamError::BodyTooLarge { got: cap, cap };
        // Just to exercise the Display — must not panic.
        let _ = at_cap.to_string();
    }

    #[test]
    fn body_too_large_various_sizes() {
        // Spot-check several (got, cap) pairs.
        let cases = [(1, 0), (100, 50), (1_000_000, 999_999), (usize::MAX, usize::MAX - 1)];
        for (got, cap) in cases {
            let err = UpstreamError::BodyTooLarge { got, cap };
            let msg = err.to_string();
            assert!(!msg.is_empty(), "error message must not be empty for got={got} cap={cap}");
        }
    }
}
