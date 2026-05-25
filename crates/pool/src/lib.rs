//! Proxy pool rotation for wafrift. Provides round-robin HTTP/SOCKS5 proxy rotation.
//!
//! # Examples
//!
//! ```
//! use wafrift_pool::ProxyPool;
//!
//! // Empty input → Ok(None) so the caller can branch into the
//! // no-proxy path without an error.
//! assert!(ProxyPool::new(&[]).unwrap().is_none());
//!
//! // Round-robin rotation across two proxies.
//! let pool = ProxyPool::new(&[
//!     "http://127.0.0.1:8080".to_string(),
//!     "socks5://127.0.0.1:9050".to_string(),
//! ]).unwrap().unwrap();
//! assert_eq!(pool.len(), 2);
//! assert_eq!(pool.next_url().as_str(), "http://127.0.0.1:8080/");
//! assert_eq!(pool.next_url().as_str(), "socks5://127.0.0.1:9050");
//! assert_eq!(pool.next_url().as_str(), "http://127.0.0.1:8080/");
//!
//! // A malformed URL fails fast with the offending URL named.
//! let err = ProxyPool::new(&["not-a-url".to_string()]).unwrap_err();
//! assert!(err.to_string().contains("not-a-url"));
//! ```

use reqwest::Url;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Errors that can occur when constructing or using a [`ProxyPool`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    /// One or more proxy URLs could not be parsed.
    #[error("invalid proxy URL '{url}': {source}")]
    InvalidUrl {
        /// The raw URL string that failed parsing.
        url: String,
        /// The underlying parse error.
        #[source]
        source: url::ParseError,
    },
    /// A URL scheme that is not a supported proxy transport.
    ///
    /// Only `http`, `https`, `socks4`, and `socks5` are valid proxy schemes.
    /// Accepting arbitrary schemes (e.g. `javascript:`, `ftp:`) would let a
    /// misconfigured or attacker-supplied proxy list inject URLs that look
    /// valid but are silently forwarded to the underlying HTTP client in a
    /// way that can bypass intent (SSRF via `file://`, JS execution context
    /// confusion, etc.).
    #[error("unsupported proxy scheme '{scheme}' in URL '{url}' (expected http|https|socks4|socks5)")]
    UnsupportedScheme {
        /// The scheme that was rejected.
        scheme: String,
        /// The full URL string.
        url: String,
    },
}

/// A thread-safe, round-robin rotating pool of proxy URLs.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    urls: Arc<Vec<Url>>,
    index: Arc<AtomicUsize>,
}

impl ProxyPool {
    /// Create a new proxy pool from a list of proxy string URLs.
    /// Supports SOCKS5 and HTTP proxies.
    /// Returns `None` if the input list is empty.
    ///
    /// # Errors
    /// Returns an error string if any proxy URL fails to parse.
    pub fn new(url_strs: &[String]) -> Result<Option<Self>, PoolError> {
        if url_strs.is_empty() {
            return Ok(None);
        }

        let mut urls = Vec::with_capacity(url_strs.len());
        for url_str in url_strs {
            let parsed = Url::parse(url_str).map_err(|e| PoolError::InvalidUrl {
                url: url_str.clone(),
                source: e,
            })?;
            // Reject any scheme that is not a recognised HTTP/SOCKS proxy
            // transport. Permitting arbitrary schemes (javascript:, ftp:,
            // file:, data:) lets a malformed or attacker-controlled wordlist
            // silently inject URLs the reqwest proxy engine will forward
            // verbatim, creating an SSRF or security-context confusion vector.
            let scheme = parsed.scheme();
            if !matches!(scheme, "http" | "https" | "socks4" | "socks5") {
                return Err(PoolError::UnsupportedScheme {
                    scheme: scheme.to_string(),
                    url: url_str.clone(),
                });
            }
            urls.push(parsed);
        }

        Ok(Some(Self {
            urls: Arc::new(urls),
            index: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Retrieve the next proxy URL in the round-robin sequence.
    #[must_use]
    pub fn next_url(&self) -> Url {
        let idx = self.index.fetch_add(1, Ordering::Relaxed);
        let url = &self.urls[idx % self.urls.len()];
        url.clone()
    }

    /// Number of proxies loaded in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.urls.len()
    }

    /// Check if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_none_for_empty_input() {
        let pool = ProxyPool::new(&[]).expect("empty pool should not error");
        assert!(pool.is_none());
    }

    #[test]
    fn new_rejects_invalid_urls() {
        let err = ProxyPool::new(&[String::from("not-a-url")]).expect_err("invalid URL");
        assert!(err.to_string().contains("invalid proxy URL"));
    }

    #[test]
    fn round_robin_cycles_through_urls() {
        let pool = ProxyPool::new(&[
            String::from("http://127.0.0.1:8080"),
            String::from("socks5://127.0.0.1:9050"),
        ])
        .expect("pool construction")
        .expect("non-empty pool");

        assert_eq!(pool.next_url().as_str(), "http://127.0.0.1:8080/");
        assert_eq!(pool.next_url().as_str(), "socks5://127.0.0.1:9050");
        assert_eq!(pool.next_url().as_str(), "http://127.0.0.1:8080/");
    }

    #[test]
    fn len_and_is_empty_reflect_loaded_urls() {
        let pool = ProxyPool::new(&[String::from("http://127.0.0.1:8080")])
            .expect("pool construction")
            .expect("non-empty pool");

        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
    }
}
