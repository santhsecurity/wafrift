//! Differential parameter mining.
//!
//! Send N baseline requests to establish the response-shape envelope
//! (status code + body length range), then for each candidate parameter
//! in the wordlist, send one extra request with that parameter attached
//! (`?<word>=wafrift_canary`). If the response status changes, OR the
//! body length deviates by more than `body_length_threshold` (relative
//! to the baseline mean), OR the response time exceeds the baseline
//! mean by `response_time_threshold_ms`, treat the parameter as
//! "discovered" and emit it as an injection point.
//!
//! Concurrency is governed by `MiningConfig::concurrency`. Per-request
//! delay (`delay_ms`) is honoured between the START of consecutive
//! candidate probes — the baseline burst at the top is unmetered.

use crate::discovery::openapi::DiscoveryError;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use wafrift_types::Method;
use wafrift_types::discovery::{
    DiscoveredEndpoint, DiscoverySource, InjectionPoint, ParameterLocation,
};
use wafrift_types::injection_context::InjectionContext;

const CANARY: &str = "wafrift_canary_x9k2";

/// Hard cap on body bytes read per probe.
///
/// Without this, a target returning a multi-gigabyte response would
/// OOM the miner. 4 MiB is well above any realistic web page (the
/// 95th percentile is ~3 MB per HTTPArchive 2026) yet small enough
/// that 100 candidate probes won't combined-OOM the process even on
/// a small workstation.
const MAX_PROBE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for parameter mining.
#[derive(Debug, Clone)]
pub struct MiningConfig {
    /// Maximum concurrent in-flight probe requests.
    pub concurrency: usize,
    /// Delay between issuing consecutive candidate probes (per worker).
    pub delay_ms: u64,
    /// Number of baseline requests to characterise the no-extra-param shape.
    pub baseline_requests: usize,
    /// Body-length deviation (fraction of baseline mean) that flags a hit.
    pub body_length_threshold: f64,
    /// Response-time delta (ms above baseline mean) that flags a hit.
    pub response_time_threshold_ms: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            delay_ms: 50,
            baseline_requests: 5,
            body_length_threshold: 0.10,
            response_time_threshold_ms: 500,
        }
    }
}

/// Probe `target` with each parameter from `wordlist` and return the
/// ones whose response shape diverges from the baseline.
///
/// # Errors
///
/// - [`DiscoveryError::WordlistEmpty`] if no candidates are supplied.
/// - [`DiscoveryError::GraphQlEndpointNotFound`] (re-used as a generic
///   transport error) if the target is unreachable for baseline probing.
pub async fn mine_params(
    target: &str,
    client: &reqwest::Client,
    wordlist: &[String],
    config: &MiningConfig,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    if wordlist.is_empty() {
        return Err(DiscoveryError::WordlistEmpty);
    }

    let baseline = collect_baseline(target, client, config.baseline_requests.max(1)).await?;

    let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut tasks = Vec::with_capacity(wordlist.len());
    for word in wordlist {
        let permit_sem = sem.clone();
        let target = target.to_string();
        let word = word.clone();
        let client = client.clone();
        let delay = config.delay_ms;
        tasks.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire_owned().await.ok()?;
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            probe_one(&target, &word, &client).await
        }));
    }

    let mut hits = Vec::new();
    for task in tasks {
        let Ok(Some(probe)) = task.await else {
            continue;
        };
        if is_hit(&probe, &baseline, config) {
            hits.push(probe.word);
        }
    }

    if hits.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![DiscoveredEndpoint {
        url: target.to_string(),
        method: Method::Get,
        injection_points: hits
            .into_iter()
            .map(|name| InjectionPoint {
                name,
                location: ParameterLocation::Query,
                context: InjectionContext::UrlQuery,
                content_type_hint: None,
                required: false,
            })
            .collect(),
        source: DiscoverySource::ParamMining,
    }])
}

#[derive(Debug, Clone)]
struct BaselineEnvelope {
    status: u16,
    mean_body_len: f64,
    mean_latency_ms: f64,
}

#[derive(Debug)]
struct ProbeResult {
    word: String,
    status: u16,
    body_len: usize,
    latency_ms: u64,
}

async fn collect_baseline(
    target: &str,
    client: &reqwest::Client,
    n: usize,
) -> Result<BaselineEnvelope, DiscoveryError> {
    let mut statuses = Vec::with_capacity(n);
    let mut lens = Vec::with_capacity(n);
    let mut lats = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let resp = client.get(target).send().await.map_err(|_| {
            DiscoveryError::GraphQlEndpointNotFound {
                url: target.to_string(),
            }
        })?;
        let status = resp.status().as_u16();
        let body_len = read_bounded_len(resp).await;
        statuses.push(status);
        lens.push(body_len);
        lats.push(start.elapsed().as_millis() as u64);
    }
    let mean_body_len = lens.iter().copied().sum::<usize>() as f64 / lens.len().max(1) as f64;
    let mean_latency_ms = lats.iter().copied().sum::<u64>() as f64 / lats.len().max(1) as f64;
    // Use the modal status; baseline assumes a stable shape.
    let status = mode_status(&statuses);
    Ok(BaselineEnvelope {
        status,
        mean_body_len,
        mean_latency_ms,
    })
}

async fn probe_one(target: &str, word: &str, client: &reqwest::Client) -> Option<ProbeResult> {
    let sep = if target.contains('?') { "&" } else { "?" };
    let url = format!("{}{}{}={}", target, sep, word, CANARY);
    let start = Instant::now();
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body_len = read_bounded_len(resp).await;
    Some(ProbeResult {
        word: word.to_string(),
        status,
        body_len,
        latency_ms: start.elapsed().as_millis() as u64,
    })
}

/// Stream a response body and return ONLY the byte count, capped at
/// [`MAX_PROBE_BODY_BYTES`]. We don't keep the bytes — only the length
/// is consumed by the differential signal — so streaming + dropping
/// chunks gives us a fixed memory ceiling regardless of upstream size.
///
/// Returns the bounded count (matches actual bytes received up to the
/// cap; capped responses report exactly `MAX_PROBE_BODY_BYTES` rather
/// than the true upstream length, which is fine for differential
/// detection — the divergence still fires).
async fn read_bounded_len(resp: reqwest::Response) -> usize {
    use futures_util::StreamExt;
    let mut len = 0usize;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        let remaining = MAX_PROBE_BODY_BYTES.saturating_sub(len);
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        len = len.saturating_add(take);
        if chunk.len() > remaining {
            break;
        }
    }
    len
}

fn is_hit(probe: &ProbeResult, baseline: &BaselineEnvelope, config: &MiningConfig) -> bool {
    if probe.status != baseline.status {
        return true;
    }
    let len_delta = (probe.body_len as f64 - baseline.mean_body_len).abs();
    let len_relative = if baseline.mean_body_len > 0.0 {
        len_delta / baseline.mean_body_len
    } else {
        len_delta
    };
    if len_relative > config.body_length_threshold {
        return true;
    }
    let lat_delta = (probe.latency_ms as f64 - baseline.mean_latency_ms).max(0.0);
    if lat_delta > config.response_time_threshold_ms as f64 {
        return true;
    }
    false
}

fn mode_status(statuses: &[u16]) -> u16 {
    let mut counts = std::collections::HashMap::new();
    for s in statuses {
        *counts.entry(*s).or_insert(0u32) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(s, _)| s)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(status: u16, body_len: f64, latency: f64) -> BaselineEnvelope {
        BaselineEnvelope {
            status,
            mean_body_len: body_len,
            mean_latency_ms: latency,
        }
    }

    fn probe(word: &str, status: u16, body_len: usize, latency_ms: u64) -> ProbeResult {
        ProbeResult {
            word: word.into(),
            status,
            body_len,
            latency_ms,
        }
    }

    #[test]
    fn hit_on_status_change() {
        let cfg = MiningConfig::default();
        let b = baseline(200, 1000.0, 100.0);
        assert!(is_hit(&probe("admin", 403, 1000, 100), &b, &cfg));
    }

    #[test]
    fn hit_on_body_length_deviation() {
        let cfg = MiningConfig {
            body_length_threshold: 0.10,
            ..Default::default()
        };
        let b = baseline(200, 1000.0, 100.0);
        // 1100 is +10% — should NOT trigger (threshold is strict gt).
        assert!(!is_hit(&probe("a", 200, 1100, 100), &b, &cfg));
        // 1200 is +20% — triggers.
        assert!(is_hit(&probe("b", 200, 1200, 100), &b, &cfg));
        // 800 is -20% — also triggers (absolute deviation).
        assert!(is_hit(&probe("c", 200, 800, 100), &b, &cfg));
    }

    #[test]
    fn hit_on_latency_spike() {
        let cfg = MiningConfig {
            response_time_threshold_ms: 500,
            ..Default::default()
        };
        let b = baseline(200, 1000.0, 100.0);
        // +400ms doesn't cross threshold.
        assert!(!is_hit(&probe("a", 200, 1000, 500), &b, &cfg));
        // +600ms does.
        assert!(is_hit(&probe("b", 200, 1000, 700), &b, &cfg));
    }

    #[test]
    fn no_hit_on_baseline_match() {
        let cfg = MiningConfig::default();
        let b = baseline(200, 1000.0, 100.0);
        assert!(!is_hit(&probe("benign", 200, 1000, 100), &b, &cfg));
    }

    #[test]
    fn empty_wordlist_errors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = reqwest::Client::new();
        let err = rt
            .block_on(mine_params(
                "https://example.com/",
                &client,
                &[],
                &MiningConfig::default(),
            ))
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::WordlistEmpty));
    }

    #[test]
    fn mode_status_picks_majority() {
        assert_eq!(mode_status(&[200, 200, 404, 200]), 200);
        assert_eq!(mode_status(&[404, 404, 500]), 404);
    }

    #[test]
    fn mode_status_empty_returns_zero() {
        assert_eq!(mode_status(&[]), 0);
    }
}
