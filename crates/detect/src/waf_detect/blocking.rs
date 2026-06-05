//! Lightweight blocked-response heuristics.

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use serde::Deserialize;

/// Block-page body indicators loaded from `rules/blocking/indicators.toml`.
///
/// Tier-B community-extensible data — the Aho-Corasick scanner is O(n)
/// in body length regardless of the rule count, so contributors can
/// keep appending to the TOML file at zero scan-time cost.
#[derive(Deserialize)]
struct BlockingRules {
    indicator: Vec<BlockingIndicator>,
}

#[derive(Deserialize)]
struct BlockingIndicator {
    phrase: String,
    /// Human-readable label in TOML; not consumed at runtime.
    #[serde(rename = "description", default)]
    _description: String,
}

static BLOCK_INDICATORS: Lazy<Vec<String>> = Lazy::new(|| {
    let raw = include_str!("../../rules/blocking/indicators.toml");
    let parsed: BlockingRules =
        toml::from_str(raw).expect("rules/blocking/indicators.toml must parse");
    parsed.indicator.into_iter().map(|i| i.phrase).collect()
});

/// Block-indicator patterns compiled into a single Aho-Corasick automaton.
///
/// Scanning the response body is O(n) regardless of how many patterns
/// exist, instead of O(n × patterns) with per-pattern `.contains()`.
static BLOCK_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(BLOCK_INDICATORS.iter().map(String::as_str))
        .expect("block indicators are valid AC patterns")
});

/// Returns `true` when an HTTP response looks like a WAF block page —
/// **broad, learning-phase** classifier.
///
/// Used by the detection/learning pipeline to decide "is this response
/// WAF-ish enough to feed into the model?". Sits between the two siblings
/// on the FP↔FN spectrum: status-code list is wide (every CDN error a WAF
/// might emit) and the body indicators are TOML-driven so contributors
/// can extend them without touching code.
///
/// **Do not unify** with the other two classifiers — they answer different
/// questions with different cost asymmetries. See the doc comments on
/// `wafrift_transport::response::is_waf_block` and
/// `wafrift_types::calibration::analyze_calibration` (intra-crate
/// links not used to avoid pulling those crates into wafrift-detect's
/// rustdoc dep graph).
///
/// Status codes include common WAF and CDN error codes:
/// - `401`, `403`, `405`, `406`, `407`, `429`
/// - `499`, `502`, `503`, `504`
/// - Cloudflare custom codes `520`–`526`
#[must_use]
pub fn is_blocked_response(status: u16, body: &[u8]) -> bool {
    if matches!(
        status,
        401 | 403 | 405 | 406 | 407 | 429 | 499 | 502 | 503 | 504 | 520..=526
    ) {
        return true;
    }

    // Scan only the first BLOCK_SCAN_BODY_WINDOW bytes — block pages are always in the head.
    let window = &body[..body.len().min(wafrift_types::BLOCK_SCAN_BODY_WINDOW)];
    BLOCK_AC.is_match(window)
}
