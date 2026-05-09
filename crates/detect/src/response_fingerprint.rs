//! Response fingerprinting for silent-block detection.
//!
//! Many WAFs perform "silent blocking" — returning HTTP 200 with a
//! modified response body instead of an obvious 403. This module
//! creates compact fingerprints of HTTP responses that enable the
//! strategy engine to detect when a response differs from a known
//! baseline, even when the status code is identical.
//!
//! # How it works
//!
//! 1. Send a benign "baseline" request and fingerprint the response.
//! 2. Send attack payloads and fingerprint each response.
//! 3. Compare fingerprints — a large drift indicates silent blocking.
//!
//! # Fingerprint components
//!
//! - Body length bucket (8 size ranges)
//! - Content-Type header
//! - Title tag content (if HTML)
//! - Presence of common WAF block-page markers
//! - Body hash (first 4KB, for exact-match detection)

use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Lazily-compiled `<title>` extractor. Was being compiled per call —
/// hot path runs once per upstream response, so the per-call cost
/// scaled linearly with traffic.
static TITLE_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"<title\b[^>]*>(.*?)</title>")
        .expect("hardcoded title regex must compile")
});

/// A compact fingerprint of an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseFingerprint {
    /// HTTP status code.
    pub status: u16,
    /// Content-Type header value (lowercase, truncated to media type).
    pub content_type: String,
    /// Body length bucket (logarithmic grouping).
    pub length_bucket: LengthBucket,
    /// Title tag content (lowercase), if present in HTML.
    pub title: Option<String>,
    /// Whether the response contains known WAF block-page markers.
    pub has_block_markers: bool,
    /// Hash of the first 4KB of the response body.
    pub body_hash: u64,
}

/// Logarithmic body size buckets for fuzzy comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LengthBucket {
    /// 0 bytes.
    Empty,
    /// 1–100 bytes.
    Tiny,
    /// 101–1,000 bytes.
    Small,
    /// 1,001–5,000 bytes.
    Medium,
    /// 5,001–20,000 bytes.
    Large,
    /// 20,001–100,000 bytes.
    VeryLarge,
    /// 100,001–1,000,000 bytes.
    Huge,
    /// > 1,000,000 bytes.
    Massive,
}

/// Result of comparing two response fingerprints.
#[derive(Debug, Clone)]
pub struct FingerprintDrift {
    /// Overall drift score (0.0 = identical, 1.0 = completely different).
    pub score: f64,
    /// Which components changed.
    pub changed: Vec<&'static str>,
    /// Whether this drift likely indicates a WAF block.
    pub likely_blocked: bool,
}

/// Create a fingerprint from an HTTP response.
#[must_use]
pub fn fingerprint(status: u16, headers: &[(String, String)], body: &[u8]) -> ResponseFingerprint {
    let content_type = extract_content_type(headers);
    let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]);
    let title = extract_title(&body_str);
    let has_block_markers = check_block_markers(&body_str);
    let body_hash = hash_body(&body[..body.len().min(4096)]);
    let length_bucket = categorize_length(body.len());

    ResponseFingerprint {
        status,
        content_type,
        length_bucket,
        title,
        has_block_markers,
        body_hash,
    }
}

/// Compare two fingerprints and compute drift.
///
/// Weight rationale (empirical, based on observed baseline->block transitions):
/// - `status_code` (0.30): strongest single indicator of interception.
/// - `body_length` (0.20): block pages often truncate or replace content.
/// - `block_markers_appeared` (0.30): explicit WAF text is a decisive signal.
/// - `content_type` (0.15): some WAFs switch to text/html for block pages.
/// - `title_tag` (0.15): HTML block pages usually change the title.
/// - `body_content` (0.10): catches exact-body mismatches (low weight because
///   benign pages also vary between requests).
///
/// A drift score above 0.5 with block markers is a strong signal
/// of silent WAF blocking.
#[must_use]
pub fn compare(baseline: &ResponseFingerprint, sample: &ResponseFingerprint) -> FingerprintDrift {
    let mut score: f64 = 0.0;
    let mut changed = Vec::new();

    if baseline.status != sample.status {
        score += 0.3;
        changed.push("status_code");
    }

    if baseline.content_type != sample.content_type {
        score += 0.15;
        changed.push("content_type");
    }

    if baseline.length_bucket != sample.length_bucket {
        score += 0.2;
        changed.push("body_length");
    }

    if baseline.title != sample.title {
        score += 0.15;
        changed.push("title_tag");
    }

    if baseline.body_hash != sample.body_hash {
        score += 0.1;
        changed.push("body_content");
    }

    if !baseline.has_block_markers && sample.has_block_markers {
        score += 0.3;
        changed.push("block_markers_appeared");
    }

    let likely_blocked =
        sample.has_block_markers || (score >= 0.4 && sample.status >= 400) || (score >= 0.6);

    FingerprintDrift {
        score: score.min(1.0),
        changed,
        likely_blocked,
    }
}

// ─────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────

/// Extract Content-Type from headers, normalized to lowercase media type.
fn extract_content_type(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

/// Extract `<title ...>` tag content from HTML.
///
/// Handles attributes inside the opening tag (`<title lang="en">`)
/// and whitespace variations.
fn extract_title(body: &str) -> Option<String> {
    // Match <title followed by optional attributes/whitespace, then >
    let caps = TITLE_RE.captures(body)?;
    let title = caps.get(1)?.as_str();
    Some(title.trim().to_ascii_lowercase())
}

/// Check whether the response body contains common WAF block-page markers.
///
/// Uses a compiled Aho-Corasick automaton for O(n) scanning regardless
/// of pattern count.
fn check_block_markers(body: &str) -> bool {
    use aho_corasick::AhoCorasick;
    use once_cell::sync::Lazy;

    static MARKER_AC: Lazy<AhoCorasick> = Lazy::new(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([
                "access denied",
                "request blocked",
                "forbidden",
                "web application firewall",
                "security violation",
                "attack detected",
                "malicious request",
                "your request has been blocked",
                "this request was blocked",
                "suspicious activity",
                "waf",
                "challenge-platform",
                "just a moment",
                "checking your browser",
                "ray id",
                "incident id",
                "reference #",
                "error code:",
                "attention required",
            ])
            .expect("block markers are valid AC patterns")
    });

    MARKER_AC.is_match(body)
}

/// Compute a hash of the body for exact-match comparison.
fn hash_body(body: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

/// Categorize body length into logarithmic buckets.
fn categorize_length(length: usize) -> LengthBucket {
    match length {
        0 => LengthBucket::Empty,
        1..=100 => LengthBucket::Tiny,
        101..=1_000 => LengthBucket::Small,
        1_001..=5_000 => LengthBucket::Medium,
        5_001..=20_000 => LengthBucket::Large,
        20_001..=100_000 => LengthBucket::VeryLarge,
        100_001..=1_000_000 => LengthBucket::Huge,
        _ => LengthBucket::Massive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html_response(status: u16, body: &str) -> ResponseFingerprint {
        let headers = vec![(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )];
        fingerprint(status, &headers, body.as_bytes())
    }

    #[test]
    fn identical_responses_zero_drift() {
        let a = html_response(200, "<html><title>Hello</title><body>OK</body></html>");
        let b = html_response(200, "<html><title>Hello</title><body>OK</body></html>");
        let drift = compare(&a, &b);
        assert!((drift.score - 0.0).abs() < f64::EPSILON);
        assert!(drift.changed.is_empty());
        assert!(!drift.likely_blocked);
    }

    #[test]
    fn status_change_detected() {
        let baseline = html_response(200, "<html><body>OK</body></html>");
        let blocked = html_response(403, "<html><body>Access Denied</body></html>");
        let drift = compare(&baseline, &blocked);
        assert!(drift.score >= 0.3);
        assert!(drift.changed.contains(&"status_code"));
        assert!(drift.likely_blocked);
    }

    #[test]
    fn silent_block_detected() {
        let baseline = html_response(
            200,
            "<html><title>My App</title><body>Search results for: test</body></html>",
        );
        let silently_blocked = html_response(
            200,
            "<html><title>Access Denied</title><body>Your request has been blocked by our web application firewall.</body></html>",
        );
        let drift = compare(&baseline, &silently_blocked);
        assert!(
            drift.score >= 0.5,
            "drift score should be high: {}",
            drift.score
        );
        assert!(drift.likely_blocked, "should detect as blocked");
    }

    #[test]
    fn cloudflare_challenge_detected() {
        let baseline = html_response(200, "<html><body>OK</body></html>");
        let challenge = html_response(
            503,
            "<html><title>Just a moment...</title><body>Checking your browser before accessing. challenge-platform</body></html>",
        );
        let drift = compare(&baseline, &challenge);
        assert!(drift.likely_blocked);
        assert!(drift.changed.contains(&"block_markers_appeared"));
    }

    #[test]
    fn length_bucket_classification() {
        assert_eq!(categorize_length(0), LengthBucket::Empty);
        assert_eq!(categorize_length(50), LengthBucket::Tiny);
        assert_eq!(categorize_length(500), LengthBucket::Small);
        assert_eq!(categorize_length(3000), LengthBucket::Medium);
        assert_eq!(categorize_length(10000), LengthBucket::Large);
        assert_eq!(categorize_length(50000), LengthBucket::VeryLarge);
        assert_eq!(categorize_length(500_000), LengthBucket::Huge);
        assert_eq!(categorize_length(2_000_000), LengthBucket::Massive);
    }

    #[test]
    fn title_extraction() {
        let fp = html_response(
            200,
            "<html><title>My Application</title><body>Hello</body></html>",
        );
        assert_eq!(fp.title.as_deref(), Some("my application"));
    }
}
