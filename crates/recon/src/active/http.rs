//! HTTP GET probe: collect response headers and classify via [`super::HeaderRules`].

use super::error::ReconProbeError;
use super::rules::HeaderRules;
use super::{HttpHeaderProbeSnapshot, StackTag};
use std::collections::BTreeMap;

use super::ActiveProbeConfig;

/// Perform a GET request, normalize headers, and classify with embedded TOML rules.
///
/// # Errors
///
/// - [`ReconProbeError::HttpDeadline`] when the overall request exceeds `config.http_timeout`.
/// - [`ReconProbeError::Http`] for other transport failures.
pub async fn probe_http_headers(
    url: &str,
    config: &ActiveProbeConfig,
) -> Result<HttpHeaderProbeSnapshot, ReconProbeError> {
    probe_http_headers_with_rules(url, config, &HeaderRules::embedded()).await
}

/// Same as [`probe_http_headers`] but uses caller-supplied rules (e.g. loaded from disk).
pub async fn probe_http_headers_with_rules(
    url: &str,
    config: &ActiveProbeConfig,
    rules: &HeaderRules,
) -> Result<HttpHeaderProbeSnapshot, ReconProbeError> {
    let client = reqwest::Client::builder()
        .connect_timeout(config.http_timeout)
        .timeout(config.http_timeout)
        .build()?;

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return Err(ReconProbeError::HttpDeadline {
                    limit: config.http_timeout,
                });
            }
            return Err(ReconProbeError::Http(e));
        }
    };

    let status = resp.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in resp.headers() {
        let key = name.as_str().to_ascii_lowercase();
        // Hyper injects `Date` on every response; it would make back-to-back snapshots
        // non-deterministic for idempotency tests and corpus diffing.
        if key == "date" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.insert(key, v.to_string());
        } else {
            headers.insert(key, String::from_utf8_lossy(value.as_bytes()).into_owned());
        }
    }

    // Drain body so the connection can be pooled; bounded by client timeout.
    let _ = resp.bytes().await;

    let tags: Vec<StackTag> = rules.classify(&headers);
    Ok(HttpHeaderProbeSnapshot {
        status,
        headers,
        tags,
    })
}
