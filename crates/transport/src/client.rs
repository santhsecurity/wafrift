//! Evasion-aware HTTP client — wraps reqwest with automatic WAF bypass.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use wafrift_strategy::HostState;
use wafrift_strategy::strategy::evade;
use wafrift_types::{EvasionConfig, Request};

use crate::response::{EvasionResponse, is_waf_block, is_waf_block_status};

/// Maximum body size to read for WAF detection (100KB).
/// WAF block pages are typically small; large responses are likely legitimate downloads.
const MAX_BODY_READ_SIZE: usize = 100_000;

/// An HTTP client that automatically applies WAF evasion techniques.
///
/// Wraps `reqwest::Client` with per-host state tracking and adaptive
/// evasion escalation. When a WAF blocks a request, the client automatically
/// retries with more aggressive evasion.
pub struct EvasionClient {
    /// Underlying HTTP client.
    inner: reqwest::Client,
    /// Evasion configuration.
    config: EvasionConfig,
    /// Per-host evasion state (thread-safe for concurrent use).
    host_states: Mutex<HashMap<String, HostState>>,
    /// FIFO insertion order for deterministic eviction when the map
    /// exceeds its cap.
    host_fifo: Mutex<VecDeque<String>>,
}

impl EvasionClient {
    /// Acquire the host-state lock, recovering from poisoning.
    ///
    /// If a thread previously panicked while holding the lock, we recover
    /// the guard rather than propagating the panic. Losing some evasion
    /// state is acceptable; crashing the client is not.
    fn lock_states(&self) -> std::sync::MutexGuard<'_, HashMap<String, HostState>> {
        self.host_states
            .lock()
            .unwrap_or_else(|poisoned: std::sync::PoisonError<_>| poisoned.into_inner())
    }
    /// Create a new evasion client with default configuration.
    ///
    /// # Errors
    ///
    /// Returns `EvasionError::Transport` if the underlying reqwest client
    /// fails to build (e.g., TLS backend unavailable).
    pub fn new() -> Result<Self, EvasionError> {
        Self::with_config(EvasionConfig::default())
    }

    /// Create a new evasion client with custom configuration.
    pub fn with_config(config: EvasionConfig) -> Result<Self, EvasionError> {
        config.validate().map_err(EvasionError::InvalidRequest)?;

        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.insecure_tls)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::from_secs(
                wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
            ));

        #[cfg(feature = "proxy-pool")]
        if !config.proxies.is_empty()
            && let Some(pool) =
                wafrift_pool::ProxyPool::new(&config.proxies).map_err(EvasionError::InvalidUrl)?
        {
            let pool_for_proxy = pool.clone();
            let custom_proxy = reqwest::Proxy::custom(move |_url| {
                if pool_for_proxy.is_empty() {
                    None
                } else {
                    Some(pool_for_proxy.next_url())
                }
            });
            builder = builder.proxy(custom_proxy);
        }

        for (domain, ip) in &config.origin_bypass {
            let addr = std::net::SocketAddr::new(*ip, 80);
            let addr_tls = std::net::SocketAddr::new(*ip, 443);
            builder = builder.resolve(domain, addr).resolve(domain, addr_tls);
        }

        let inner = builder.build().map_err(EvasionError::Transport)?;

        Ok(Self {
            inner,
            config,
            host_states: Mutex::new(HashMap::new()),
        })
    }

    /// Create with a custom reqwest client.
    ///
    /// # Errors
    ///
    /// Same validation as [`Self::with_config`]: invalid `EvasionConfig` values
    /// return [`EvasionError::InvalidRequest`].
    pub fn with_reqwest(
        client: reqwest::Client,
        config: EvasionConfig,
    ) -> Result<Self, EvasionError> {
        config.validate().map_err(EvasionError::InvalidRequest)?;
        Ok(Self {
            inner: client,
            config,
            host_states: Mutex::new(HashMap::new()),
        })
    }

    /// Send a GET request with automatic evasion.
    pub async fn get(&self, url: &str) -> Result<EvasionResponse, EvasionError> {
        let request = Request::get(url);
        self.send(request).await
    }

    /// Send a POST request with automatic evasion.
    pub async fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<EvasionResponse, EvasionError> {
        let request = Request::post(url, body.to_vec()).header("Content-Type", content_type);
        self.send(request).await
    }

    /// Send a request with automatic evasion and retry on WAF block.
    pub async fn send(&self, request: Request) -> Result<EvasionResponse, EvasionError> {
        let host = extract_host(&request.url)?;
        let max_attempts = self.config.max_attempts as usize;

        for attempt in 0..max_attempts {
            // Get current host state and apply evasion
            let (evaded, techniques) = {
                let states = self.lock_states();
                let state = states.get(&host).cloned().unwrap_or_default();
                let result = evade(&request, &state, &self.config);
                (result.request, result.techniques)
            };

            // Convert to reqwest request
            let mut req_builder = match evaded.method.as_str() {
                "GET" => self.inner.get(&evaded.url),
                "POST" => self.inner.post(&evaded.url),
                "PUT" => self.inner.put(&evaded.url),
                "DELETE" => self.inner.delete(&evaded.url),
                "PATCH" => self.inner.patch(&evaded.url),
                "HEAD" => self.inner.head(&evaded.url),
                "OPTIONS" => self.inner.request(reqwest::Method::OPTIONS, &evaded.url),
                _ => self.inner.request(
                    reqwest::Method::from_bytes(evaded.method.as_str().as_bytes())
                        .map_err(|e| EvasionError::InvalidRequest(format!("invalid method {e}")))?,
                    &evaded.url,
                ),
            };

            // Apply headers
            for (key, value) in &evaded.headers {
                match (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    (Ok(name), Ok(val)) => {
                        req_builder = req_builder.header(name, val);
                    }
                    (Err(e), _) => {
                        tracing::warn!("Invalid header name '{}': {}", key, e);
                    }
                    (_, Err(e)) => {
                        tracing::warn!("Invalid header value for '{}': {}", key, e);
                    }
                }
            }

            // Apply body
            if let Some(ref body) = evaded.body {
                req_builder = req_builder.body(body.clone());
            }

            // Send and get response with body (CRITICAL FIX #1)
            // We need to read the body for WAF fingerprinting, but also preserve it
            // for the caller. We use a bounded read to avoid memory issues.
            let (status, body_preview, is_blocked) =
                Self::send_and_check(req_builder, &host).await?;

            if is_blocked && attempt + 1 < max_attempts {
                let technique_keys: Vec<String> =
                    techniques.iter().map(ToString::to_string).collect();
                tracing::info!(
                    host = %host,
                    status = status,
                    body_preview_size = body_preview.as_ref().map(|b| b.len()).unwrap_or(0),
                    techniques = %technique_keys.join(","),
                    attempt = attempt + 1,
                    max = max_attempts,
                    "WAF block detected — escalating evasion"
                );
                let mut states = self.lock_states();
                if states.len() >= 10_000 && !states.contains_key(&host) {
                    let key_to_remove = states.keys().next().cloned().unwrap_or_default();
                    states.remove(&key_to_remove);
                }
                let state = states.entry(host.clone()).or_default();
                if technique_keys.is_empty() {
                    state.record_block();
                } else {
                    state.record_block_for_many(&technique_keys);
                }
                continue;
            }

            // Not blocked (or last attempt) — record success and return
            if !is_blocked {
                let mut states = self.lock_states();
                if states.len() >= 10_000 && !states.contains_key(&host) {
                    let key_to_remove = states.keys().next().cloned().unwrap_or_default();
                    states.remove(&key_to_remove);
                }
                let state = states.entry(host.clone()).or_default();
                if !techniques.is_empty() {
                    state.record_success_for_many(&techniques);
                }
            }

            // Build response - note: body was consumed for fingerprinting
            // The response in EvasionResponse will have empty body since we read it
            // Callers should check was_blocked flag
            let response = reqwest::Response::from(
                http::Response::builder()
                    .status(status)
                    .body(body_preview.unwrap_or_default())
                    .map_err(|e| EvasionError::InvalidResponse(e.to_string()))?,
            );

            return Ok(EvasionResponse {
                inner: response,
                techniques_applied: techniques,
                was_blocked: is_blocked,
                attempts: attempt as u32 + 1,
            });
        }

        Err(EvasionError::MaxAttemptsReached {
            host,
            attempts: max_attempts,
        })
    }

    /// Get the current evasion state for a host.
    pub fn host_state(&self, host: &str) -> Option<HostState> {
        self.lock_states().get(host).cloned()
    }

    /// Get all tracked hosts and their block/success counts.
    pub fn stats(&self) -> Vec<(String, u32, u32)> {
        self.lock_states()
            .iter()
            .map(|(host, state): (&String, &HostState)| {
                (host.clone(), state.blocks, state.successes)
            })
            .collect()
    }

    /// Reset evasion state for all hosts.
    pub fn reset(&self) {
        self.lock_states().clear();
    }

    /// Send request and check for WAF block using status + body fingerprinting.
    ///
    /// This helper sends the request, reads a bounded portion of the body,
    /// and checks both status codes and body content for WAF indicators.
    /// Returns (status, body_preview, is_blocked).
    async fn send_and_check(
        req_builder: reqwest::RequestBuilder,
        _host: &str,
    ) -> Result<(u16, Option<Vec<u8>>, bool), EvasionError> {
        let response = req_builder.send().await.map_err(EvasionError::Transport)?;
        let status = response.status().as_u16();

        // Read bounded body for WAF fingerprinting
        let body_preview = Self::read_body_preview_from_response(response).await;

        // Check both status and body for WAF indicators
        let blocked_by_status = is_waf_block_status(status);
        let blocked_by_body = body_preview
            .as_ref()
            .map(|b| is_waf_block(status, b))
            .unwrap_or(false);
        let is_blocked = blocked_by_status || blocked_by_body;

        Ok((status, body_preview, is_blocked))
    }

    /// Read a bounded preview of the response body for WAF fingerprinting.
    ///
    /// Takes ownership of the response and reads up to `MAX_BODY_READ_SIZE` bytes.
    /// Returns `Some(bytes)` with body content, or `None` if the body couldn't be read.
    async fn read_body_preview_from_response(response: reqwest::Response) -> Option<Vec<u8>> {
        // Check content length header to skip large downloads
        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Skip body check for large content (> 10MB) - likely a download, not a WAF page
        if let Some(len) = content_length
            && len > 10_000_000
        {
            return None;
        }

        // Read up to MAX_BODY_READ_SIZE bytes
        // For very large bodies, we limit what we read for WAF detection
        match response.bytes().await {
            Ok(bytes) => {
                let preview_size = bytes.len().min(MAX_BODY_READ_SIZE);
                if preview_size == 0 {
                    None
                } else {
                    Some(bytes[..preview_size].to_vec())
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "Failed to read response body for WAF detection");
                None
            }
        }
    }
}

impl Default for EvasionClient {
    fn default() -> Self {
        Self::new().expect("failed to build default reqwest client — this is a bug")
    }
}

/// Errors from the evasion client.
#[derive(Debug, thiserror::Error)]
pub enum EvasionError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("WAF blocked all {attempts} evasion attempts for {host}")]
    MaxAttemptsReached { host: String, attempts: usize },

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Extract host from URL.
///
/// Properly handles IPv6 addresses (e.g., `[::1]`) and IPv4/hostname.
fn extract_host(url: &str) -> Result<String, EvasionError> {
    let url = url.trim();
    if url.is_empty() {
        return Err(EvasionError::InvalidUrl("Empty URL provided".into()));
    }

    // Ensure scheme exists for parsing
    let parse_url = if !url.starts_with("http://") && !url.starts_with("https://") {
        std::borrow::Cow::Owned(format!("https://{url}"))
    } else {
        std::borrow::Cow::Borrowed(url)
    };

    let parsed =
        reqwest::Url::parse(&parse_url).map_err(|e| EvasionError::InvalidUrl(e.to_string()))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| EvasionError::InvalidUrl("missing host component".into()))?;

    let mut h = host.to_ascii_lowercase();
    if h.starts_with('[') && h.ends_with(']') {
        h = h[1..h.len() - 1].to_string();
    }

    if h.is_empty() {
        return Err(EvasionError::InvalidUrl("empty host parsed".into()));
    }

    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST 1-15: extract_host comprehensive tests
    #[test]
    fn extract_host_basic() {
        assert_eq!(
            extract_host("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_host("http://api.example.com:8080/v1").unwrap(),
            "api.example.com"
        );
        assert_eq!(extract_host("example.com").unwrap(), "example.com");
    }

    #[test]
    fn extract_host_https_url() {
        assert_eq!(
            extract_host("https://secure.site.com/api").unwrap(),
            "secure.site.com"
        );
    }

    #[test]
    fn extract_host_http_url() {
        assert_eq!(
            extract_host("http://insecure.site.com/page").unwrap(),
            "insecure.site.com"
        );
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("https://example.com:8443/path").unwrap(),
            "example.com"
        );
        assert_eq!(extract_host("http://localhost:3000").unwrap(), "localhost");
    }

    #[test]
    fn extract_host_ip_address() {
        assert_eq!(
            extract_host("https://192.168.1.1/api").unwrap(),
            "192.168.1.1"
        );
        assert_eq!(extract_host("http://10.0.0.1:8080").unwrap(), "10.0.0.1");
    }

    #[test]
    fn extract_host_ipv6_address() {
        // IPv6 addresses should be properly extracted from bracket notation
        assert_eq!(extract_host("https://[::1]/local").unwrap(), "::1");
        assert_eq!(
            extract_host("https://[2001:db8::1]:8080/path").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn extract_host_subdomain() {
        assert_eq!(
            extract_host("https://api.v2.example.com/endpoint").unwrap(),
            "api.v2.example.com"
        );
    }

    #[test]
    fn extract_host_with_query_params() {
        assert_eq!(
            extract_host("https://example.com/path?key=value").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn extract_host_with_fragment() {
        assert_eq!(
            extract_host("https://example.com/page#section").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn extract_host_root_path() {
        assert_eq!(extract_host("https://example.com/").unwrap(), "example.com");
    }

    #[test]
    fn extract_host_no_path() {
        assert_eq!(extract_host("https://example.com").unwrap(), "example.com");
    }

    #[test]
    fn extract_host_uppercase() {
        assert_eq!(
            extract_host("https://EXAMPLE.COM/Path").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn extract_host_mixed_case() {
        assert_eq!(extract_host("https://Example.Com/").unwrap(), "example.com");
    }

    #[test]
    fn extract_host_empty_string() {
        assert!(extract_host("").is_err());
    }

    #[test]
    fn extract_host_just_domain() {
        assert_eq!(
            extract_host("example.com:8080/path").unwrap(),
            "example.com"
        );
    }

    // TEST 16-25: EvasionClient configuration and state
    #[test]
    fn new_client_default_config() {
        let client = EvasionClient::new().unwrap();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn stats_empty_initially() {
        let client = EvasionClient::new().unwrap();
        assert_eq!(client.stats().len(), 0);
    }

    #[test]
    fn reset_clears_state() {
        let client = EvasionClient::new().unwrap();
        client.reset();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn custom_config() {
        let config = EvasionConfig {
            max_attempts: 10,
            content_type_switching: false,
            ..Default::default()
        };
        let client = EvasionClient::with_config(config).unwrap();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn host_state_none_for_unknown() {
        let client = EvasionClient::new().unwrap();
        assert!(client.host_state("unknown.com").is_none());
    }

    #[test]
    fn client_with_maximum_config() {
        let config = EvasionConfig::maximum();
        let client = EvasionClient::with_config(config).unwrap();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn client_with_encoding_only_config() {
        let config = EvasionConfig::encoding_only();
        let client = EvasionClient::with_config(config).unwrap();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn client_default_implements_default() {
        let client: EvasionClient = Default::default();
        assert!(client.stats().is_empty());
    }

    #[test]
    fn client_with_reqwest_custom_client() {
        let reqwest_client = reqwest::Client::new();
        let config = EvasionConfig::default();
        let client = EvasionClient::with_reqwest(reqwest_client, config).unwrap();
        assert!(client.stats().is_empty());
    }

    // TEST 26-30: EvasionError tests
    #[test]
    fn evasion_error_max_attempts_display() {
        let err = EvasionError::MaxAttemptsReached {
            host: "example.com".to_string(),
            attempts: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("example.com"));
        assert!(msg.contains('5'));
    }

    #[test]
    fn evasion_error_max_attempts_different_hosts() {
        let err1 = EvasionError::MaxAttemptsReached {
            host: "host1.com".to_string(),
            attempts: 3,
        };
        let err2 = EvasionError::MaxAttemptsReached {
            host: "host2.com".to_string(),
            attempts: 5,
        };
        assert_ne!(err1.to_string(), err2.to_string());
    }

    #[test]
    fn evasion_error_debug_format() {
        let err = EvasionError::MaxAttemptsReached {
            host: "test.com".to_string(),
            attempts: 3,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("MaxAttemptsReached"));
    }

    #[test]
    fn evasion_error_max_attempts_variants() {
        let err1 = EvasionError::MaxAttemptsReached {
            host: "a.com".to_string(),
            attempts: 1,
        };
        let err2 = EvasionError::MaxAttemptsReached {
            host: "b.com".to_string(),
            attempts: 10,
        };
        assert!(err1.to_string().contains('1'));
        assert!(err2.to_string().contains("10"));
    }

    #[test]
    fn evasion_error_display_formatting() {
        let err = EvasionError::MaxAttemptsReached {
            host: "example.org".to_string(),
            attempts: 5,
        };
        let display = format!("{err}");
        assert!(display.contains("WAF blocked all 5 evasion attempts for example.org"));
    }
}
