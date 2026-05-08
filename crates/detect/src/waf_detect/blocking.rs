//! Lightweight blocked-response heuristics.

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;

/// Block-indicator patterns compiled into a single Aho-Corasick automaton.
///
/// Scanning the response body is O(n) regardless of how many patterns
/// exist, instead of O(n × patterns) with per-pattern `.contains()`.
static BLOCK_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(BLOCK_INDICATORS)
        .expect("block indicators are valid AC patterns")
});

/// Fixed set of block-page indicators.
///
/// Extending this list is free — the AC automaton handles any count
/// with the same single-pass scan.
const BLOCK_INDICATORS: &[&str] = &[
    "access denied",
    "blocked",
    "forbidden",
    "captcha",
    "challenge",
    "request denied",
    "security policy",
    "not acceptable",
    "rate limit",
    "too many requests",
    "waf",
    "firewall",
    "request blocked",
];

/// Returns `true` when an HTTP response looks like a WAF block page.
///
/// This heuristic does not identify the vendor. It only answers whether the
/// response likely represents an interception event.
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

    // Scan only the first 4 KiB — block pages are always in the head.
    let window = &body[..body.len().min(4096)];
    BLOCK_AC.is_match(window)
}
