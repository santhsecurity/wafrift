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
    regex::Regex::new(r"<title\b[^>]*>(.*?)</title>").expect("hardcoded title regex must compile")
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
    let body_str =
        String::from_utf8_lossy(&body[..body.len().min(wafrift_types::BLOCK_SCAN_BODY_WINDOW)]);
    let title = extract_title(&body_str);
    let has_block_markers = check_block_markers(&body_str);
    let body_hash = hash_body(&body[..body.len().min(wafrift_types::BLOCK_SCAN_BODY_WINDOW)]);
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

/// Drift weight for a status-code change.
const STATUS_DRIFT_WEIGHT: f64 = 0.30;
/// Drift weight for a content-type change.
const CONTENT_TYPE_DRIFT_WEIGHT: f64 = 0.15;
/// Drift weight for a body-length-bucket change.
const LENGTH_DRIFT_WEIGHT: f64 = 0.20;
/// Drift weight for a title-tag change.
const TITLE_DRIFT_WEIGHT: f64 = 0.15;
/// Drift weight for a body-hash (exact-content) change.
const BODY_HASH_DRIFT_WEIGHT: f64 = 0.10;
/// Drift weight when block markers appear in the sample but not the baseline.
const BLOCK_MARKERS_DRIFT_WEIGHT: f64 = 0.30;
/// Threshold: score at which drift + 4xx status is considered a likely block.
const LIKELY_BLOCKED_SCORE_4XX_THRESHOLD: f64 = 0.40;
/// Threshold: score at which drift alone is considered a likely block.
const LIKELY_BLOCKED_SCORE_THRESHOLD: f64 = 0.60;

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
        score += STATUS_DRIFT_WEIGHT;
        changed.push("status_code");
    }

    if baseline.content_type != sample.content_type {
        score += CONTENT_TYPE_DRIFT_WEIGHT;
        changed.push("content_type");
    }

    if baseline.length_bucket != sample.length_bucket {
        score += LENGTH_DRIFT_WEIGHT;
        changed.push("body_length");
    }

    if baseline.title != sample.title {
        score += TITLE_DRIFT_WEIGHT;
        changed.push("title_tag");
    }

    if baseline.body_hash != sample.body_hash {
        score += BODY_HASH_DRIFT_WEIGHT;
        changed.push("body_content");
    }

    if !baseline.has_block_markers && sample.has_block_markers {
        score += BLOCK_MARKERS_DRIFT_WEIGHT;
        changed.push("block_markers_appeared");
    }

    let likely_blocked = sample.has_block_markers
        || (score >= LIKELY_BLOCKED_SCORE_4XX_THRESHOLD && sample.status >= 400)
        || (score >= LIKELY_BLOCKED_SCORE_THRESHOLD);

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
                // F95: bare 3-char "waf" matched "wafer", "WAFER",
                // and any case-insensitive substring with those
                // three letters in sequence — flipped likely_blocked
                // to true on completely benign pages. The "web
                // application firewall" pattern above covers the
                // intended phrase; drop the 3-char form.
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

    // ── Anti-rig: pin drift-weight constants ────────────────────────────

    /// Anti-rig: every weight is named and used by `compare`. If someone
    /// re-tunes a weight to improve a single benchmark, the drift
    /// semantics silently change everywhere. Pin them all.
    #[test]
    fn drift_weight_status_is_30_percent() {
        assert!(
            (STATUS_DRIFT_WEIGHT - 0.30).abs() < f64::EPSILON,
            "STATUS_DRIFT_WEIGHT changed: {STATUS_DRIFT_WEIGHT}"
        );
    }

    #[test]
    fn drift_weight_content_type_is_15_percent() {
        assert!(
            (CONTENT_TYPE_DRIFT_WEIGHT - 0.15).abs() < f64::EPSILON,
            "CONTENT_TYPE_DRIFT_WEIGHT changed: {CONTENT_TYPE_DRIFT_WEIGHT}"
        );
    }

    #[test]
    fn drift_weight_length_is_20_percent() {
        assert!(
            (LENGTH_DRIFT_WEIGHT - 0.20).abs() < f64::EPSILON,
            "LENGTH_DRIFT_WEIGHT changed: {LENGTH_DRIFT_WEIGHT}"
        );
    }

    #[test]
    fn drift_weight_title_is_15_percent() {
        assert!(
            (TITLE_DRIFT_WEIGHT - 0.15).abs() < f64::EPSILON,
            "TITLE_DRIFT_WEIGHT changed: {TITLE_DRIFT_WEIGHT}"
        );
    }

    #[test]
    fn drift_weight_body_hash_is_10_percent() {
        assert!(
            (BODY_HASH_DRIFT_WEIGHT - 0.10).abs() < f64::EPSILON,
            "BODY_HASH_DRIFT_WEIGHT changed: {BODY_HASH_DRIFT_WEIGHT}"
        );
    }

    #[test]
    fn drift_weight_block_markers_is_30_percent() {
        assert!(
            (BLOCK_MARKERS_DRIFT_WEIGHT - 0.30).abs() < f64::EPSILON,
            "BLOCK_MARKERS_DRIFT_WEIGHT changed: {BLOCK_MARKERS_DRIFT_WEIGHT}"
        );
    }

    /// Anti-rig: the likely-blocked threshold for 4xx + drift.
    /// If someone raises it, subtle WAF blocks stop being detected.
    #[test]
    fn likely_blocked_4xx_threshold_is_0_40() {
        assert!(
            (LIKELY_BLOCKED_SCORE_4XX_THRESHOLD - 0.40).abs() < f64::EPSILON,
            "4xx block threshold changed: {LIKELY_BLOCKED_SCORE_4XX_THRESHOLD}"
        );
    }

    #[test]
    fn likely_blocked_threshold_is_0_60() {
        assert!(
            (LIKELY_BLOCKED_SCORE_THRESHOLD - 0.60).abs() < f64::EPSILON,
            "block-alone threshold changed: {LIKELY_BLOCKED_SCORE_THRESHOLD}"
        );
    }

    // ── LengthBucket boundary values ────────────────────────────────────

    /// Anti-rig: pin the exact thresholds. If someone changes 100 to 128
    /// the bucket boundaries silently shift, breaking benchmark scoring.
    #[test]
    fn length_bucket_exact_boundaries() {
        // Exact boundary values (one less and one more than the documented boundary).
        assert_eq!(categorize_length(1), LengthBucket::Tiny, "1 → Tiny");
        assert_eq!(categorize_length(100), LengthBucket::Tiny, "100 → Tiny");
        assert_eq!(categorize_length(101), LengthBucket::Small, "101 → Small");
        assert_eq!(
            categorize_length(1_000),
            LengthBucket::Small,
            "1000 → Small"
        );
        assert_eq!(
            categorize_length(1_001),
            LengthBucket::Medium,
            "1001 → Medium"
        );
        assert_eq!(
            categorize_length(5_000),
            LengthBucket::Medium,
            "5000 → Medium"
        );
        assert_eq!(
            categorize_length(5_001),
            LengthBucket::Large,
            "5001 → Large"
        );
        assert_eq!(
            categorize_length(20_000),
            LengthBucket::Large,
            "20000 → Large"
        );
        assert_eq!(
            categorize_length(20_001),
            LengthBucket::VeryLarge,
            "20001 → VeryLarge"
        );
        assert_eq!(
            categorize_length(100_000),
            LengthBucket::VeryLarge,
            "100000 → VeryLarge"
        );
        assert_eq!(
            categorize_length(100_001),
            LengthBucket::Huge,
            "100001 → Huge"
        );
        assert_eq!(
            categorize_length(1_000_000),
            LengthBucket::Huge,
            "1000000 → Huge"
        );
        assert_eq!(
            categorize_length(1_000_001),
            LengthBucket::Massive,
            "1000001 → Massive"
        );
    }

    // ── compare() additivity / score cap ───────────────────────────────

    /// Score is capped at 1.0 even when multiple high-weight components change.
    #[test]
    fn compare_score_never_exceeds_1_0() {
        let baseline = html_response(200, "hello");
        let worst_case = fingerprint(
            503,
            &[(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            b"access denied request blocked web application firewall forbidden",
        );
        let drift = compare(&baseline, &worst_case);
        assert!(
            drift.score <= 1.0,
            "drift score must be capped at 1.0, got {}",
            drift.score
        );
    }

    /// Both block-markers present in baseline and sample — no new marker drift.
    #[test]
    fn compare_block_markers_both_present_no_marker_drift() {
        let body = "access denied by firewall";
        let a = html_response(403, body);
        let b = html_response(403, body);
        let drift = compare(&a, &b);
        assert!(!drift.changed.contains(&"block_markers_appeared"));
    }

    /// Neither baseline nor sample has block markers — no marker signal.
    #[test]
    fn compare_no_block_markers_in_either_no_marker_drift() {
        let a = html_response(200, "welcome to my site");
        let b = html_response(200, "another page");
        let drift = compare(&a, &b);
        assert!(!drift.changed.contains(&"block_markers_appeared"));
    }

    /// Block markers present in baseline but not sample does NOT trigger
    /// the `block_markers_appeared` signal (it only fires on NEW appearance).
    #[test]
    fn compare_block_markers_disappear_no_drift_signal() {
        let baseline = html_response(403, "access denied");
        let sample = html_response(200, "welcome");
        let drift = compare(&baseline, &sample);
        assert!(!drift.changed.contains(&"block_markers_appeared"));
    }

    // ── fingerprint() ────────────────────────────────────────────────────

    /// Empty body produces Empty bucket and zero hash is distinct from
    /// any real-data hash.
    #[test]
    fn fingerprint_empty_body() {
        let fp = fingerprint(200, &[], &[]);
        assert_eq!(fp.length_bucket, LengthBucket::Empty);
        assert!(fp.title.is_none());
        assert!(!fp.has_block_markers);
    }

    /// Body larger than 4 KB: fingerprint uses first 4 KB only (hash
    /// must equal the hash of the truncated view, not the full body).
    #[test]
    fn fingerprint_body_truncated_at_4kb_for_hash() {
        let small_body: Vec<u8> = vec![b'A'; 4096];
        let large_body: Vec<u8> = {
            let mut v = small_body.clone();
            v.extend(vec![b'B'; 4096]); // second 4 KB differs
            v
        };
        let fp_small = fingerprint(200, &[], &small_body);
        let fp_large = fingerprint(200, &[], &large_body);
        // Both should hash the same first 4 KB.
        assert_eq!(
            fp_small.body_hash, fp_large.body_hash,
            "hash must use first 4 KB only"
        );
    }

    /// Title tag with attributes (e.g. `lang`) must still be extracted.
    #[test]
    fn fingerprint_title_with_attributes() {
        let fp = html_response(200, r#"<html><title lang="en">Hello World</title></html>"#);
        assert_eq!(fp.title.as_deref(), Some("hello world"));
    }

    /// Content-Type with charset parameter must be stripped to media type.
    #[test]
    fn fingerprint_content_type_stripped_of_params() {
        let fp = fingerprint(
            200,
            &[(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            b"body",
        );
        assert_eq!(fp.content_type, "text/html");
    }

    /// Content-Type header is case-insensitive.
    #[test]
    fn fingerprint_content_type_case_insensitive_header_name() {
        let fp = fingerprint(
            200,
            &[("CONTENT-TYPE".to_string(), "application/json".to_string())],
            b"{}",
        );
        assert_eq!(fp.content_type, "application/json");
    }

    /// No Content-Type header → empty string.
    #[test]
    fn fingerprint_missing_content_type_is_empty_string() {
        let fp = fingerprint(200, &[], b"body");
        assert_eq!(fp.content_type, "");
    }

    // ── Block markers ─────────────────────────────────────────────────────

    /// Anti-rig: every canonical block marker keyword must trigger detection.
    #[test]
    fn block_marker_access_denied_detected() {
        let fp = html_response(403, "access denied by policy");
        assert!(fp.has_block_markers);
    }

    #[test]
    fn block_marker_request_blocked_detected() {
        let fp = html_response(403, "request blocked by firewall");
        assert!(fp.has_block_markers);
    }

    #[test]
    fn block_marker_forbidden_detected() {
        let fp = html_response(403, "<html>forbidden</html>");
        assert!(fp.has_block_markers);
    }

    #[test]
    fn block_marker_just_a_moment_detected() {
        let fp = html_response(503, "<title>Just a moment...</title>");
        assert!(fp.has_block_markers);
    }

    #[test]
    fn block_marker_ray_id_detected() {
        let fp = html_response(403, "Ray ID: abc123def456");
        assert!(fp.has_block_markers);
    }

    #[test]
    fn block_marker_checking_your_browser_detected() {
        let fp = html_response(200, "Checking your browser before accessing...");
        assert!(fp.has_block_markers);
    }

    /// Anti-rig: bare "waf" (3-letter substring) must NOT trigger detection.
    /// This was fixed in F95 — revert would cause false positives on words
    /// like "wafer", "wafting", "WAFER-cookie", etc.
    #[test]
    fn bare_waf_substring_does_not_trigger_block_marker() {
        let fp = html_response(200, "I enjoy wafers and wafting breezes");
        assert!(
            !fp.has_block_markers,
            "bare 'waf' substring must NOT trigger block marker (F95 regression)"
        );
    }

    #[test]
    fn benign_html_no_block_markers() {
        let fp = html_response(200, "<html><body>Welcome to my store</body></html>");
        assert!(!fp.has_block_markers);
    }

    // ── Concurrent fingerprinting ─────────────────────────────────────────

    /// `fingerprint()` is stateless — same input from N threads must
    /// produce identical output.
    #[test]
    fn concurrent_fingerprint_is_deterministic() {
        use std::sync::Arc;
        use std::thread;

        let body = b"<html><title>Test Page</title><body>Hello World</body></html>";
        let headers = vec![("content-type".to_string(), "text/html".to_string())];
        let reference = Arc::new(fingerprint(200, &headers, body));
        let headers = Arc::new(headers);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let r = reference.clone();
                let h = headers.clone();
                thread::spawn(move || {
                    let result = fingerprint(200, &h, body);
                    assert_eq!(result, *r, "concurrent fingerprint result differs");
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread must not panic");
        }
    }
}
