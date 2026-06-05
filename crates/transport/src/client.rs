//! Evasion-aware HTTP client — wraps reqwest with automatic WAF bypass.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use wafrift_strategy::HostState;
use wafrift_strategy::strategy::evade;
use wafrift_types::{EvasionConfig, Request, ip_addr_is_bogon};

use crate::response::EvasionResponse;
use crate::signal::{BlockClass, ResponseProfileDb, ResponseSignal};

/// Maximum body size to read for WAF detection.
///
/// CLAUDE.md §7 DEDUPLICATION note (R49 pass-11 I3): this is a
/// TRANSPORT-layer cap for WAF block-page classification — distinct
/// from `cli::safe_body::HEADROOM_MAX_RESPONSE_BYTES` (64 MiB) which
/// caps operator-controlled response bodies for the CLI. They differ
/// 600x because the use cases differ:
///   - Block pages (this cap): Cloudflare interstitials ~80 KB,
///     CAPTCHA pages with embedded JS ~200 KB. 256 KiB comfortably
///     covers every modern challenge page.
///   - CLI response reads (the cli cap): operator-specified targets
///     that may legitimately stream MiB of attack-response data.
///
/// Pre-R49 this was 100 KB which silently truncated CAPTCHA pages
/// (~200 KB) and could miscategorize them as "no WAF" because the
/// block-class markers near the end of the JS payload were missed.
const MAX_BODY_READ_SIZE: usize = 256 * 1024;

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
    /// Compiled-in WAF response profiles for rich classification.
    profile_db: ResponseProfileDb,
}

fn shared_browser_headers() -> Result<reqwest::header::HeaderMap, EvasionError> {
    guise::http::default_browser_header_map_without_compression().map_err(|e| {
        EvasionError::InvalidRequest(format!("build shared stealth browser headers: {e}"))
    })
}

fn apply_shared_browser_headers(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, EvasionError> {
    Ok(builder
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .default_headers(shared_browser_headers()?))
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

    /// FIFO-evict at the workspace-canonical cap if needed, then register
    /// `host` in the states map if absent and push it onto the FIFO tail.
    /// Returns a mutable reference to the (possibly freshly-inserted)
    /// HostState.
    ///
    /// Lock-ordering contract (states → fifo) lives in this ONE
    /// place so the three send-loop branches (HardBlock /
    /// RateLimit / Pass) and any future caller can't inherit the
    /// wrong order. Takes the states guard as a parameter so the
    /// caller still owns the critical-section boundary.
    fn ensure_host_registered<'a>(
        &self,
        states: &'a mut HashMap<String, HostState>,
        host: &str,
    ) -> &'a mut HostState {
        // Cap-evict if at the bound AND the new key isn't already
        // present (already-present means no growth).
        if states.len() >= wafrift_types::HOST_STATES_CAP && !states.contains_key(host) {
            let mut fifo = self
                .host_fifo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while let Some(key_to_remove) = fifo.pop_front() {
                if states.remove(&key_to_remove).is_some() {
                    break;
                }
            }
        }
        let is_new = !states.contains_key(host);
        if is_new {
            let mut fifo = self
                .host_fifo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            fifo.push_back(host.to_string());
        }
        states.entry(host.to_string()).or_default()
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

        let mut builder = apply_shared_browser_headers(crate::http_builder::base_client_builder(
            wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
            config.insecure_tls,
            None,
        ))?
        // §15 SSRF: bogon-safe redirect policy (refuses 302 → cloud-metadata
        // / RFC1918 / loopback, stops cross-origin auth leaks) — the core
        // engine must be at least as safe as the CLI diff commands, which
        // already use this. Canonical impl in `http_builder`; shared.
        .redirect(crate::http_builder::safe_redirect_policy(
            wafrift_types::DEFAULT_MAX_REDIRECTS,
        ));

        #[cfg(feature = "proxy-pool")]
        if !config.proxies.is_empty() {
            // Validate every proxy URL through proxywire's canonical strict
            // parser (rejects bad schemes, embedded paths/queries — the SSRF
            // guard) before any traffic is routed. We then round-robin the
            // original credential-bearing strings: proxywire's
            // `ProxyEndpoint::to_url()` intentionally drops `user:pass@`
            // userinfo, which reqwest's custom-proxy URL form needs, so the
            // raw strings (already validated) are what we rotate.
            for proxy in &config.proxies {
                proxywire::ProxyEndpoint::from_url(proxy)
                    .map_err(|e| EvasionError::InvalidUrl(e.to_string()))?;
            }
            let urls: Vec<reqwest::Url> = config
                .proxies
                .iter()
                .filter_map(|p| reqwest::Url::parse(p).ok())
                .collect();
            if !urls.is_empty() {
                let cursor = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let custom_proxy = reqwest::Proxy::custom(move |_url| {
                    let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Some(urls[i % urls.len()].clone())
                });
                builder = builder.proxy(custom_proxy);
            }
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
            host_fifo: Mutex::new(VecDeque::new()),
            profile_db: ResponseProfileDb::compiled_in(),
        })
    }

    /// Create with a custom reqwest client.
    ///
    /// # SSRF / bogon filtering
    ///
    /// Unlike [`Self::with_config`] — which installs the
    /// `BogonFilteringResolver` so hostnames resolving to a bogon
    /// (loopback / RFC1918 / link-local metadata) are refused at connect
    /// time — this constructor trusts the CALLER's `client` as-is. If
    /// untrusted hostnames may reach it, wire your own SSRF-safe DNS
    /// resolver into the client before passing it. The upfront literal-IP
    /// bogon rejection in [`Self::send`] still applies regardless, so
    /// literal-bogon URLs are blocked either way.
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
            host_fifo: Mutex::new(VecDeque::new()),
            profile_db: ResponseProfileDb::compiled_in(),
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
        // Audit (2026-05-10): EvasionClient's reqwest::Client is built
        // without BogonFilteringResolver (the resolver lives in
        // wafrift-proxy which sits ABOVE wafrift-transport). As a
        // defence-in-depth, reject literal-IP URLs in the bogon set
        // upfront so a misconfigured scan can't accidentally hit
        // 127.0.0.1, 169.254.169.254 (IMDS), CGN, Teredo, etc.
        //
        // Operators targeting a lab upstream on loopback or RFC1918
        // (or running mock-server tests against wiremock) opt in via
        // EvasionConfig.allow_private_upstream.
        if !self.config.allow_private_upstream
            && let Ok(parsed) = reqwest::Url::parse(&request.url)
            && let Some(host) = parsed.host_str()
            && let Ok(ip) = host.parse::<std::net::IpAddr>()
            && ip_addr_is_bogon(ip)
        {
            return Err(EvasionError::InvalidUrl(format!(
                "EvasionClient refuses literal-IP upstream {ip} (private/loopback/CGN/Teredo). \
                 Set EvasionConfig.allow_private_upstream = true if intentional."
            )));
        }
        let host = extract_host(&request.url)?;
        let max_attempts = self.config.max_attempts as usize;

        for attempt in 0..max_attempts {
            // Get current host state and apply evasion.
            //
            // Snapshot the per-host state under the lock, then RELEASE
            // the lock BEFORE the CPU-heavy `evade()` (regex-driven
            // payload mutation, which can run for a noticeable time on
            // large request bodies). Holding `host_states` across
            // `evade` serialised EVERY host's request behind one host's
            // mutation work — a global bottleneck under concurrent /
            // multi-host load. The proxy crate already learned this
            // (it snapshots state then runs `evade` in spawn_blocking
            // outside the lock); the transport client now matches.
            // `evade` borrows only `&request`/`&state`/`&self.config` —
            // never the locked map — so the early release is sound.
            let state = {
                let states = self.lock_states();
                states.get(&host).cloned().unwrap_or_default()
            };
            let (evaded, techniques) = {
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
            let (status, body_preview, signal) = match self.send_and_check(req_builder, &host).await
            {
                Ok(result) => result,
                Err(EvasionError::Transport(ref e)) if attempt + 1 < max_attempts => {
                    tracing::warn!(
                        host = %host,
                        error = %e,
                        attempt = attempt + 1,
                        max = max_attempts,
                        "transient transport error — will retry"
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };

            let classification = signal.classification;
            let matched_waf = signal.matched_waf;
            let prioritize = signal.prioritize;
            let avoid = signal.avoid;
            let inspection_model = signal.inspection_model;
            let technique_keys: Vec<String> = techniques.iter().map(ToString::to_string).collect();

            // Audit (2026-05-10): rich classification replaces binary is_waf_block.
            // RateLimit / Challenge → back off (don't penalize technique).
            // HardBlock / SoftBlock → escalate evasion.
            // Pass → return response.
            match classification {
                BlockClass::HardBlock | BlockClass::SoftBlock if attempt + 1 < max_attempts => {
                    tracing::info!(
                        host = %host,
                        status = status,
                        body_preview_size = body_preview.as_ref().map_or(0, std::vec::Vec::len),
                        techniques = %technique_keys.join(","),
                        attempt = attempt + 1,
                        max = max_attempts,
                        classification = ?classification,
                        "WAF block detected — escalating evasion"
                    );
                    {
                        let mut states = self.lock_states();
                        let state = self.ensure_host_registered(&mut states, &host);
                        state.record_signal(
                            classification == BlockClass::HardBlock,
                            classification == BlockClass::SoftBlock,
                            false,
                            false,
                            matched_waf.as_deref(),
                            &prioritize,
                            &avoid,
                            inspection_model.as_deref(),
                            &technique_keys,
                        );
                    }
                    continue;
                }
                BlockClass::RateLimit | BlockClass::Challenge if attempt + 1 < max_attempts => {
                    tracing::info!(
                        host = %host,
                        status = status,
                        classification = ?classification,
                        attempt = attempt + 1,
                        max = max_attempts,
                        "Rate-limit or challenge detected — backing off"
                    );
                    {
                        let mut states = self.lock_states();
                        let state = self.ensure_host_registered(&mut states, &host);
                        state.record_signal(
                            false,
                            false,
                            classification == BlockClass::RateLimit,
                            classification == BlockClass::Challenge,
                            matched_waf.as_deref(),
                            &prioritize,
                            &avoid,
                            inspection_model.as_deref(),
                            &technique_keys,
                        );
                    }
                    // Simple 1-second backoff to avoid thundering herd.
                    // Per-host because the retry loop is per-host.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                _ => {
                    // Pass or last attempt — record success (if Pass) and return
                    if !classification.is_blocked() {
                        let mut states = self.lock_states();
                        let state = self.ensure_host_registered(&mut states, &host);
                        if !techniques.is_empty() {
                            state.record_success_for_many(&techniques);
                        }
                        // Ingest WAF profile hints even on Pass (first-contact profiling).
                        if let Some(ref waf) = matched_waf
                            && state.waf_name.is_none()
                        {
                            state.waf_name = Some(waf.clone());
                            state.waf_confirmed = true;
                        }
                        // 200 cap is both the per-event source slice cap
                        // AND the cumulative cap on the per-host Vec.
                        // Without the cumulative cap, a long-running scan
                        // session against a heavily-blocked host would
                        // accumulate hundreds of KB of unique technique
                        // names in HostState; the contains() guard only
                        // prevents duplicates within one push batch.
                        // Canonical value: wafrift_types::HOST_TECHNIQUE_HINTS_CAP,
                        // shared with strategy::host_state::MAX_HINTS_PER_LIST
                        // so both enforcement sites stay in sync.
                        let hints_cap = wafrift_types::HOST_TECHNIQUE_HINTS_CAP;
                        for tech in prioritize.iter().take(hints_cap) {
                            if !state.prioritized_techniques.contains(tech) {
                                if state.prioritized_techniques.len() >= hints_cap {
                                    state.prioritized_techniques.remove(0);
                                }
                                state.prioritized_techniques.push(tech.clone());
                            }
                        }
                        for tech in avoid.iter().take(hints_cap) {
                            if !state.avoided_techniques.contains(tech) {
                                if state.avoided_techniques.len() >= hints_cap {
                                    state.avoided_techniques.remove(0);
                                }
                                state.avoided_techniques.push(tech.clone());
                            }
                        }
                        if let Some(ref model) = inspection_model
                            && state.inspection_model.is_none()
                        {
                            state.inspection_model = Some(model.clone());
                        }
                    }

                    // Build response - note: body was consumed for fingerprinting
                    let response = reqwest::Response::from(
                        http::Response::builder()
                            .status(status)
                            .body(body_preview.unwrap_or_default())
                            .map_err(|e| EvasionError::InvalidResponse(e.to_string()))?,
                    );

                    return Ok(EvasionResponse {
                        inner: response,
                        techniques_applied: techniques,
                        was_blocked: classification.is_blocked(),
                        attempts: attempt as u32 + 1,
                    });
                }
            }
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
    ///
    /// Atomically clears both `host_states` and `host_fifo` under
    /// the same lock acquisition order used everywhere else in
    /// this module (states first, fifo second). Pre-fix the two
    /// clears were separated by a guard drop — a concurrent
    /// `send()` between them could register a new host that
    /// survived the fifo clear, orphaning it in `host_states`
    /// where the FIFO cap could never evict it.
    pub fn reset(&self) {
        let mut states = self.lock_states();
        let mut fifo = self
            .host_fifo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.clear();
        fifo.clear();
    }

    /// Send request and check for WAF block using rich signal classification.
    ///
    /// Audit (2026-05-10): upgraded from binary `is_waf_block` to
    /// `ResponseProfileDb::classify` using compiled-in profiles. This lets
    /// the retry loop distinguish HardBlock / SoftBlock / RateLimit /
    /// Challenge / Pass and apply the correct action (escalate vs back off).
    async fn send_and_check(
        &self,
        req_builder: reqwest::RequestBuilder,
        _host: &str,
    ) -> Result<(u16, Option<Vec<u8>>, ResponseSignal), EvasionError> {
        let response = req_builder.send().await.map_err(EvasionError::Transport)?;
        let status = response.status().as_u16();

        // Extract headers BEFORE consuming the body for fingerprinting.
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();

        // Read bounded body for WAF fingerprinting
        let body_preview = Self::read_body_preview_from_response(response).await;

        // Rich classification using compiled-in profiles
        let signal = self.profile_db.classify(
            status,
            &headers,
            body_preview.as_deref().unwrap_or_default(),
        );

        Ok((status, body_preview, signal))
    }

    /// Read a bounded preview of the response body for WAF fingerprinting.
    ///
    /// Takes ownership of the response and reads up to `MAX_BODY_READ_SIZE` bytes
    /// from the decompressed stream. The cap is enforced BEFORE full
    /// materialisation: we read chunk-by-chunk via `Response::chunk()` and abort
    /// the moment the running total would exceed the cap. This prevents a
    /// hostile target from serving a ~1 KB gzip bomb that expands to GBs
    /// (decompression-bomb / OOM attack — §15 AUDIT HUNT, R49).
    ///
    /// The `Content-Length` pre-check skips bodies the server CLAIMS are large
    /// (> 10 MB); the chunk loop caps the actual decompressed bytes for every
    /// other case (including chunked responses that omit `Content-Length`).
    ///
    /// Uses `reqwest::Response::chunk()` (no `futures_util` dependency needed)
    /// so this fix is compile-time safe under every feature flag combination.
    async fn read_body_preview_from_response(response: reqwest::Response) -> Option<Vec<u8>> {
        // Check content length header to skip large downloads
        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Skip body check for large content (> 10MB) — likely a download, not a WAF page.
        if let Some(len) = content_length
            && len > 10_000_000
        {
            return None;
        }

        // §15 OOM / decompression-bomb defence: read chunk-by-chunk, aborting
        // as soon as the decompressed running total exceeds MAX_BODY_READ_SIZE.
        // The old `.bytes().await` called here materialised the ENTIRE
        // decompressed body before slicing to MAX_BODY_READ_SIZE — a
        // Content-Length-less gzip bomb bypassed the pre-check above and
        // expanded to gigabytes in memory before we could truncate.
        let mut acc: Vec<u8> = Vec::with_capacity(MAX_BODY_READ_SIZE.min(16 * 1024));
        let mut response = response;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if acc.len().saturating_add(chunk.len()) > MAX_BODY_READ_SIZE {
                        // Abort: cap exceeded. We already have `acc` bytes;
                        // return what we have — it's sufficient for WAF
                        // block-page classification.
                        tracing::debug!(
                            cap = MAX_BODY_READ_SIZE,
                            accumulated = acc.len(),
                            chunk_len = chunk.len(),
                            "body preview cap exceeded — truncating (decompression-bomb defence)"
                        );
                        let remaining = MAX_BODY_READ_SIZE - acc.len();
                        acc.extend_from_slice(&chunk[..remaining]);
                        break;
                    }
                    acc.extend_from_slice(&chunk);
                }
                Ok(None) => break, // EOF
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to read response body for WAF detection");
                    if acc.is_empty() {
                        return None;
                    }
                    break; // return whatever we accumulated before the error
                }
            }
        }

        if acc.is_empty() { None } else { Some(acc) }
    }
}

impl Default for EvasionClient {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback: build with absolutely minimal config if default fails
            // (e.g. TLS backend unavailable in exotic environments).
            let mut fallback_builder = reqwest::Client::builder()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .timeout(std::time::Duration::from_secs(
                    wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
                ));
            match shared_browser_headers() {
                Ok(headers) => {
                    fallback_builder = fallback_builder.default_headers(headers);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "shared browser headers unavailable in default fallback");
                }
            }
            let reqwest_client = match fallback_builder.build() {
                Ok(client) => client,
                Err(e) => {
                    tracing::warn!(error = %e, "minimal reqwest client failed, using fallback");
                    reqwest::Client::new()
                }
            };
            Self {
                inner: reqwest_client,
                config: EvasionConfig::default(),
                host_states: std::sync::Mutex::new(std::collections::HashMap::new()),
                host_fifo: std::sync::Mutex::new(std::collections::VecDeque::new()),
                profile_db: ResponseProfileDb::compiled_in(),
            }
        })
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
/// Thin Result-returning wrapper around
/// [`crate::url_util::host_from_url`] (shared with the 3 cli sites
/// that previously had their own copy). The Option → Result mapping
/// converts the canonical None into the existing EvasionError
/// variant so this call's contract is unchanged.
fn extract_host(url: &str) -> Result<String, EvasionError> {
    let h = crate::url_util::host_from_url(url)
        .ok_or_else(|| EvasionError::InvalidUrl(format!("could not extract host from {url:?}")))?;

    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guise::fingerprint::default_profile_facts;

    fn captured_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        raw.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    async fn capture_evasion_request(client: &EvasionClient) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let url = format!("http://{}/", listener.local_addr().expect("local addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write response");
            String::from_utf8(request).expect("request is utf8")
        });

        let response = client.get(&url).await.expect("send capture request");
        assert_eq!(response.inner.status().as_u16(), 204);
        server.await.expect("server joins")
    }

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

    // ── bogon regression tests ─────────────────────────────────
    // Keep in sync with wafrift-proxy::upstream_policy::ip_addr_is_bogon.

    #[test]
    fn bogon_v4_loopback() {
        assert!(ip_addr_is_bogon("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn bogon_v4_public_ok() {
        assert!(!ip_addr_is_bogon("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn bogon_v4_cgnat() {
        assert!(ip_addr_is_bogon("100.64.0.1".parse().unwrap()));
        assert!(ip_addr_is_bogon("100.127.255.255".parse().unwrap()));
        assert!(!ip_addr_is_bogon("100.63.0.1".parse().unwrap()));
    }

    #[test]
    fn bogon_v6_loopback_mapped() {
        assert!(ip_addr_is_bogon("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn bogon_v6_6to4_embeds_private_v4() {
        // 6to4 encodes 127.0.0.1 => 2002:7f00:1:: — MUST be rejected.
        assert!(ip_addr_is_bogon("2002:7f00:1::".parse().unwrap()));
        assert!(ip_addr_is_bogon("2002:c0a8:101::".parse().unwrap())); // 192.168.1.1
        assert!(!ip_addr_is_bogon("2002:808:808::".parse().unwrap())); // 8.8.8.8
    }

    #[test]
    fn bogon_v6_teredo() {
        assert!(ip_addr_is_bogon("2001::1".parse().unwrap()));
    }

    #[test]
    fn bogon_v6_discard() {
        assert!(ip_addr_is_bogon("0100::1".parse().unwrap()));
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

    #[tokio::test]
    async fn default_transport_client_uses_shared_stealth_headers() {
        let config = EvasionConfig {
            allow_private_upstream: true,
            fingerprint_rotation: false,
            max_attempts: 1,
            ..Default::default()
        };
        let client = EvasionClient::with_config(config).unwrap();
        let raw_request = capture_evasion_request(&client).await;
        let facts = default_profile_facts();

        assert_eq!(
            captured_header(&raw_request, "User-Agent"),
            Some(facts.user_agent)
        );
        assert_eq!(captured_header(&raw_request, "Accept"), Some(facts.accept));
        assert_eq!(
            captured_header(&raw_request, "Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(
            captured_header(&raw_request, "Sec-Fetch-Mode"),
            Some("navigate")
        );
        assert_eq!(captured_header(&raw_request, "Accept-Encoding"), None);
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

    // ── reset() atomicity ─────────────────────────────────────

    #[test]
    fn reset_clears_both_states_and_fifo() {
        let client = EvasionClient::default();
        // Plant a state by directly mutating under the same lock
        // order reset() uses, so the post-reset inspection is
        // unambiguous.
        {
            let mut states = client.lock_states();
            let mut fifo = client
                .host_fifo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            states.insert("a.com".to_string(), HostState::default());
            states.insert("b.com".to_string(), HostState::default());
            fifo.push_back("a.com".to_string());
            fifo.push_back("b.com".to_string());
        }
        client.reset();
        // Both must be empty — if either survives, the FIFO cap
        // could leak entries indefinitely.
        assert!(client.lock_states().is_empty(), "states not cleared");
        let fifo_len = client
            .host_fifo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert_eq!(fifo_len, 0, "fifo not cleared");
    }

    #[test]
    fn reset_holds_both_locks_simultaneously() {
        // Lock-order regression test: take `host_fifo` first from
        // this thread, then spawn a thread that calls reset(). If
        // reset() ever changed to acquire fifo BEFORE states,
        // this would deadlock. The 50 ms join timeout is loose
        // enough to absorb scheduling jitter on any platform.
        use std::sync::Arc;
        let client = Arc::new(EvasionClient::default());
        {
            let _fifo = client
                .host_fifo
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Reset on a background thread — must be waiting on
            // `host_states` (which we don't hold), not on
            // `host_fifo` (which we do). When we drop our guard
            // it should proceed.
            let c = Arc::clone(&client);
            let handle = std::thread::spawn(move || c.reset());
            // Tiny sleep so the thread definitely tries to grab
            // states before we drop fifo.
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(_fifo);
            handle
                .join()
                .expect("reset thread must finish, not deadlock");
        }
    }

    // ── §15 OOM / decompression-bomb anti-regression ─────────

    /// Pin that `read_body_preview_from_response` uses chunk-by-chunk
    /// reading (`response.chunk().await`) and NOT the old unbounded
    /// `.bytes().await`. The old code called `.bytes().await` then
    /// sliced AFTER full materialisation — a hostile server could send
    /// a gzip bomb (no Content-Length) that expanded to GBs before the
    /// slice occurred.
    #[test]
    fn read_body_preview_uses_chunk_loop_not_unbounded_bytes() {
        let src = include_str!("client.rs");
        // New bounded pattern must be present.
        assert!(
            src.contains("response.chunk().await"),
            "read_body_preview_from_response must read via .chunk() loop, not .bytes().await"
        );
        // Old unbounded pattern must be absent (built with concat! to
        // avoid matching itself).
        let banned = concat!("response.", "bytes().", "await");
        assert!(
            !src.contains(banned),
            "transport client.rs must not call unbounded .bytes().await \
             in read_body_preview_from_response — decompression-bomb regression"
        );
    }

    /// Pin that the WAF body preview cap constant is reasonable:
    /// large enough to cover any challenge page, small enough to
    /// bound memory under an adversarial target.
    #[test]
    fn max_body_read_size_is_bounded_and_sufficient() {
        // Must cover a 200 KB Cloudflare CAPTCHA page.
        assert!(
            MAX_BODY_READ_SIZE >= 200 * 1024,
            "MAX_BODY_READ_SIZE too small — CAPTCHA pages up to 200 KB"
        );
        // Must not OOM the machine: cap at something well below free RAM.
        assert!(
            MAX_BODY_READ_SIZE <= 4 * 1024 * 1024,
            "MAX_BODY_READ_SIZE too large — decompression-bomb cap should be <= 4 MiB"
        );
    }
}
