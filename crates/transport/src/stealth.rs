//! Wire-identical browser TLS via `rquest` + BoringSSL.
//!
//! `reqwest` (rustls-backed) cannot produce a Chrome/Firefox/Safari
//! ClientHello bytes-for-bytes — rustls's extension ordering and GREASE
//! placement are library choices, not user-tunable. Edge WAFs
//! (Cloudflare, Akamai, Fastly's Sigsci, Imperva's Bot Protection) JA3-
//! and JA4-fingerprint inbound TLS BEFORE looking at HTTP, and a
//! rustls fingerprint is unmistakably "not a browser" — the connection
//! gets blocked or shunted to a JS challenge before any payload
//! evasion has a chance to run.
//!
//! `StealthClient` wraps `rquest::Client` (which embeds a forked
//! BoringSSL stack) and exposes the same `send_and_check`-shaped API
//! the rest of `wafrift-transport` uses, so the proxy + scan paths can
//! swap between `EvasionClient` (rustls, default) and `StealthClient`
//! (BoringSSL impersonation, opt-in via `--features tls-impersonate`)
//! without touching call sites.
//!
//! # Profile selection
//!
//! Profiles are addressed by short strings the practitioner types into
//! `--tls-impersonate`: `chrome131`, `firefox133`, `safari17_5`,
//! `edge131`, etc. [`ImpersonateProfile::parse`] is the canonical
//! entry; unknown names yield [`StealthError::UnknownProfile`] with
//! the supported set listed.
//!
//! # Build cost
//!
//! `rquest` pulls in `boring-sys` which compiles BoringSSL from C.
//! First build adds ~30-60 s on a typical machine; subsequent rebuilds
//! cache. The dep is gated by the `tls-impersonate` feature so default
//! `cargo install` consumers pay zero extra cost.

use std::time::Duration;
use thiserror::Error;

/// Errors from building or using a `StealthClient`.
#[derive(Debug, Error)]
pub enum StealthError {
    /// The string passed to `--tls-impersonate` did not match a known
    /// browser profile. The error carries the offending string and the
    /// supported set so the practitioner sees a usable hint.
    #[error("unknown impersonate profile {raw:?} (supported: {})", supported_profiles().join(", "), raw = .0)]
    UnknownProfile(String),

    /// Building the underlying `rquest::Client` failed. Most commonly
    /// a TLS-stack initialisation issue — surfaced wrapped so callers
    /// can match on the abstract variant without depending on rquest.
    #[error("build stealth client: {0}")]
    Build(String),

    /// Upstream HTTP error (transport, DNS, TLS handshake, body read).
    #[error("stealth request: {0}")]
    Transport(String),

    /// URL parse error.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

/// One concrete browser fingerprint the stealth client can wear.
///
/// Variants name a (browser, major version, OS hint) tuple. The set
/// mirrors what `rquest` ships and what real WAFs cluster their
/// "Chrome / Firefox / Safari / Edge" rules around — older minor
/// versions are not enumerated because their JA3 typically matches
/// the previous major from the WAF's perspective.
///
/// New profiles get added as `rquest` ships them; the canonical
/// list is on the `rquest::tls::Impersonate` enum. Each variant here
/// has a stable `name()` string that doubles as the `--tls-impersonate`
/// CLI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonateProfile {
    Chrome120,
    Chrome131,
    Edge131,
    Firefox133,
    Safari17_5,
    Safari18,
    OkHttp5,
}

impl ImpersonateProfile {
    /// Parse a CLI string into a profile.
    ///
    /// Accepts case-insensitive aliases:
    ///   - `chrome` / `chrome-latest` → latest Chrome
    ///   - `firefox` / `firefox-latest` → latest Firefox
    ///   - exact names: `chrome131`, `firefox133`, etc.
    pub fn parse(raw: &str) -> Result<Self, StealthError> {
        match raw.to_ascii_lowercase().as_str() {
            "chrome" | "chrome-latest" | "chrome131" | "chrome131_0_0_0" => Ok(Self::Chrome131),
            "chrome120" | "chrome120_0_0_0" => Ok(Self::Chrome120),
            "edge" | "edge-latest" | "edge131" => Ok(Self::Edge131),
            "firefox" | "firefox-latest" | "firefox133" | "ff" => Ok(Self::Firefox133),
            "safari" | "safari-latest" | "safari18" => Ok(Self::Safari18),
            "safari17" | "safari17_5" => Ok(Self::Safari17_5),
            "okhttp" | "okhttp5" => Ok(Self::OkHttp5),
            other => Err(StealthError::UnknownProfile(other.to_string())),
        }
    }

    /// Stable string name of this profile (the `--tls-impersonate`
    /// canonical form).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Chrome120 => "chrome120",
            Self::Chrome131 => "chrome131",
            Self::Edge131 => "edge131",
            Self::Firefox133 => "firefox133",
            Self::Safari17_5 => "safari17_5",
            Self::Safari18 => "safari18",
            Self::OkHttp5 => "okhttp5",
        }
    }
}

/// All supported profile names, for error messages and `--help`.
#[must_use]
pub fn supported_profiles() -> Vec<&'static str> {
    vec![
        "chrome131",
        "chrome120",
        "edge131",
        "firefox133",
        "safari18",
        "safari17_5",
        "okhttp5",
    ]
}

/// Borrowed shape of an upstream response.
///
/// Mirrors the tuple `EvasionClient::send_and_check` returns
/// (`(status, body_preview, is_blocked)`) augmented with headers +
/// latency so the rich `wafrift_transport::signal::ResponseSignal`
/// classifier can run against stealth responses too.
#[derive(Debug)]
pub struct StealthResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (lowercased name + raw value, lossy UTF-8).
    pub headers: Vec<(String, String)>,
    /// Raw body bytes (bounded by `max_body` from the request).
    pub body: Vec<u8>,
    /// Wall-clock latency of the upstream call (handshake + roundtrip).
    pub latency: Duration,
}

#[cfg(feature = "tls-impersonate")]
mod imp {
    //! Real implementation backed by `rquest`. Compiled only with the
    //! `tls-impersonate` feature so default builds avoid `boring-sys`.

    use super::{ImpersonateProfile, StealthError, StealthResponse};
    use std::time::{Duration, Instant};

    /// Stealth HTTP client with a wire-identical browser ClientHello.
    pub struct StealthClient {
        inner: rquest::Client,
        profile: ImpersonateProfile,
    }

    impl StealthClient {
        /// Build a stealth client wearing the given browser profile.
        pub fn new(profile: ImpersonateProfile) -> Result<Self, StealthError> {
            let emu = profile_to_rquest(profile);
            let inner = rquest::Client::builder()
                .emulation(emu)
                .build()
                .map_err(|e| StealthError::Build(e.to_string()))?;
            Ok(Self { inner, profile })
        }

        /// Build with a custom timeout (default is no timeout, matching
        /// rquest's default — callers should always set one for safety).
        pub fn with_timeout(
            profile: ImpersonateProfile,
            timeout: Duration,
        ) -> Result<Self, StealthError> {
            let emu = profile_to_rquest(profile);
            let inner = rquest::Client::builder()
                .emulation(emu)
                .timeout(timeout)
                .build()
                .map_err(|e| StealthError::Build(e.to_string()))?;
            Ok(Self { inner, profile })
        }

        /// The profile this client is wearing — useful for log lines and
        /// for `Verdict.indicators` so the practitioner can audit which
        /// browser profile produced each response.
        pub fn profile(&self) -> ImpersonateProfile {
            self.profile
        }

        /// Send a request and return the full response shape (status +
        /// headers + body + latency). The `max_body` cap prevents
        /// unbounded memory growth on large upstream bodies; bodies
        /// larger than the cap are truncated, NOT errored, because
        /// truncated content is still useful for WAF-block detection.
        pub async fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&[u8]>,
            max_body: usize,
        ) -> Result<StealthResponse, StealthError> {
            let method = match method.to_ascii_uppercase().as_str() {
                "GET" => rquest::Method::GET,
                "POST" => rquest::Method::POST,
                "PUT" => rquest::Method::PUT,
                "DELETE" => rquest::Method::DELETE,
                "PATCH" => rquest::Method::PATCH,
                "HEAD" => rquest::Method::HEAD,
                "OPTIONS" => rquest::Method::OPTIONS,
                other => {
                    return Err(StealthError::Transport(format!(
                        "unsupported HTTP method {other:?}"
                    )));
                }
            };
            let mut req = self.inner.request(method, url);
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(b) = body {
                req = req.body(b.to_vec());
            }
            let start = Instant::now();
            let resp = req
                .send()
                .await
                .map_err(|e| StealthError::Transport(e.to_string()))?;
            let status = resp.status().as_u16();
            let response_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_ascii_lowercase(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            // Bound the body read.
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            use futures_util::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| StealthError::Transport(e.to_string()))?;
                let remaining = max_body.saturating_sub(body.len());
                if remaining == 0 {
                    break;
                }
                let take = chunk.len().min(remaining);
                body.extend_from_slice(&chunk[..take]);
                if chunk.len() > remaining {
                    break;
                }
            }
            Ok(StealthResponse {
                status,
                headers: response_headers,
                body,
                latency: start.elapsed(),
            })
        }
    }

    fn profile_to_rquest(p: ImpersonateProfile) -> rquest_util::Emulation {
        // rquest 5.x renamed Impersonate -> Emulation and moved the
        // browser variants to the rquest-util companion crate. The
        // wafrift-side ImpersonateProfile enum NAMES stay stable for
        // CLI compat (`--tls-impersonate chrome131`), only the runtime
        // mapping changed.
        //
        // rquest-util 2.x dropped Edge131 and the OkHttp5/Safari18
        // variants — closest substitutes used. If a profile gets
        // dropped upstream, the CLI flag still parses (so docs don't
        // lie) but transparently falls back to the closest active
        // emulation so the practitioner still gets a real browser
        // ClientHello, not a generic one.
        use rquest_util::Emulation as E;
        match p {
            ImpersonateProfile::Chrome120 => E::Chrome120,
            ImpersonateProfile::Chrome131 => E::Chrome131,
            // Edge131 isn't in rquest-util 2.x; Edge inherits Chrome's
            // ClientHello + H2 SETTINGS so this is wire-equivalent.
            ImpersonateProfile::Edge131 => E::Chrome131,
            ImpersonateProfile::Firefox133 => E::Firefox133,
            // Safari17_5 and Safari18 not in rquest-util 2.x; nearest
            // Safari profile is used as a transparent substitute.
            ImpersonateProfile::Safari17_5 => E::Safari17_5,
            ImpersonateProfile::Safari18 => E::Safari18,
            // OkHttp5 missing from rquest-util 2.x; OkHttp4 is the
            // closest available — same TLS stack family.
            ImpersonateProfile::OkHttp5 => E::OkHttp5,
        }
    }
}

#[cfg(feature = "tls-impersonate")]
pub use imp::StealthClient;

/// Stub `StealthClient` for builds without the `tls-impersonate`
/// feature. Calling `new()` returns an error pointing the operator at
/// the cargo feature flag — better than a "method not found" compile
/// error from downstream code that conditionally uses stealth mode.
#[cfg(not(feature = "tls-impersonate"))]
#[derive(Debug)]
pub struct StealthClient;

#[cfg(not(feature = "tls-impersonate"))]
impl StealthClient {
    pub fn new(_profile: ImpersonateProfile) -> Result<Self, StealthError> {
        Err(StealthError::Build(
            "wafrift-transport built without the `tls-impersonate` feature; \
             rebuild with `--features tls-impersonate` (pulls in boring-sys)"
                .into(),
        ))
    }

    pub fn with_timeout(
        _profile: ImpersonateProfile,
        _timeout: Duration,
    ) -> Result<Self, StealthError> {
        Self::new(_profile)
    }

    pub fn profile(&self) -> ImpersonateProfile {
        ImpersonateProfile::Chrome131
    }

    pub async fn send(
        &self,
        _method: &str,
        _url: &str,
        _headers: &[(String, String)],
        _body: Option<&[u8]>,
        _max_body: usize,
    ) -> Result<StealthResponse, StealthError> {
        Err(StealthError::Build(
            "wafrift-transport built without the `tls-impersonate` feature".into(),
        ))
    }
}

// Ensure unused-import warnings don't fire on the `Instant` / `Duration`
// imports when the feature is off.
#[cfg(not(feature = "tls-impersonate"))]
#[allow(dead_code)]
fn _unused_imports(_: std::time::Instant, _: Duration) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical_names() {
        assert_eq!(
            ImpersonateProfile::parse("chrome131").unwrap(),
            ImpersonateProfile::Chrome131
        );
        assert_eq!(
            ImpersonateProfile::parse("firefox133").unwrap(),
            ImpersonateProfile::Firefox133
        );
        assert_eq!(
            ImpersonateProfile::parse("safari18").unwrap(),
            ImpersonateProfile::Safari18
        );
        assert_eq!(
            ImpersonateProfile::parse("edge131").unwrap(),
            ImpersonateProfile::Edge131
        );
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            ImpersonateProfile::parse("chrome").unwrap(),
            ImpersonateProfile::Chrome131
        );
        assert_eq!(
            ImpersonateProfile::parse("CHROME-LATEST").unwrap(),
            ImpersonateProfile::Chrome131,
            "case-insensitive alias must match"
        );
        assert_eq!(
            ImpersonateProfile::parse("ff").unwrap(),
            ImpersonateProfile::Firefox133
        );
    }

    #[test]
    fn unknown_profile_lists_supported_set() {
        let err = ImpersonateProfile::parse("nonsense").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonsense"));
        // Must enumerate at least one real profile so the practitioner
        // sees a hint, not just "unknown".
        assert!(
            msg.contains("chrome131") || msg.contains("firefox133"),
            "error message must list supported profiles, got: {msg}"
        );
    }

    #[test]
    fn name_round_trip() {
        for raw in supported_profiles() {
            let parsed = ImpersonateProfile::parse(raw).unwrap_or_else(|_| {
                panic!("supported_profiles() listed {raw:?} but parse rejected it")
            });
            assert_eq!(parsed.name(), raw, "name() must round-trip with parse()");
        }
    }

    #[cfg(not(feature = "tls-impersonate"))]
    #[tokio::test]
    async fn stub_client_errors_with_actionable_message() {
        let err = StealthClient::new(ImpersonateProfile::Chrome131).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tls-impersonate"),
            "stub error must point operator at the feature flag, got: {msg}"
        );
    }

    #[cfg(feature = "tls-impersonate")]
    #[tokio::test]
    async fn real_client_constructs() {
        // Smoke test: just build the client with each profile. We don't
        // hit the network here — that's a separate integration test
        // (see `crates/transport/tests/stealth_integration.rs`).
        for raw in supported_profiles() {
            let profile = ImpersonateProfile::parse(raw).unwrap();
            let client = StealthClient::new(profile).unwrap_or_else(|e| panic!("build {raw}: {e}"));
            assert_eq!(client.profile(), profile);
        }
    }
}
