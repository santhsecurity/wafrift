//! Response wrapper that tracks WAF block detection.

use wafrift_types::Technique;

/// Response from an evasion-aware request.
#[derive(Debug)]
pub struct EvasionResponse {
    /// The underlying reqwest response.
    pub inner: reqwest::Response,
    /// Evasion techniques that were applied to this request.
    pub techniques_applied: Vec<Technique>,
    /// Whether the response appears to be a WAF block.
    pub was_blocked: bool,
    /// Number of retry attempts made.
    pub attempts: u32,
}

impl EvasionResponse {
    /// Get the HTTP status code.
    #[must_use]
    pub fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
    }

    /// Consume the response and get the body as bytes.
    pub async fn bytes(self) -> Result<bytes::Bytes, reqwest::Error> {
        self.inner.bytes().await
    }

    /// Consume the response and get the body as text.
    pub async fn text(self) -> Result<String, reqwest::Error> {
        self.inner.text().await
    }

    /// Get response headers.
    #[must_use]
    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        self.inner.headers()
    }
}

/// Check if an HTTP status code alone indicates a WAF block.
///
/// Use this when the response body is not yet available (e.g., in a
/// retry loop where consuming the body would prevent forwarding).
#[must_use]
pub fn is_waf_block_status(status: u16) -> bool {
    // Audit (2026-05-10): removed 429 (rate-limit) and 451 (legal takedown).
    // Rate-limit is NOT a technique failure — the engine must back off, not
    // escalate evasion. 451 is "Unavailable For Legal Reasons" (GDPR geo-block,
    // DMCA) — retrying with different payloads is pointless and wastes requests.
    matches!(status, 403 | 406 | 503)
}

/// Check if a response looks like a WAF block — **strict, post-request** classifier.
///
/// Used by the transport retry loop to decide "did THIS request get blocked,
/// should I rotate technique?". This is the **FN-cheap** end of the spectrum:
/// a false positive here means the engine wastes a request rotating evasion
/// when the response was actually fine, so the rules are deliberately tight
/// (no bare vendor names; 200 OK blog posts mentioning Cloudflare must NOT
/// trigger).
///
/// **Do not unify** with the other two classifiers — they answer different
/// questions with different cost asymmetries (see below). Past consolidation
/// attempts regressed evasion behaviour. The three diverge by design.
///
/// See also:
/// - [`wafrift_detect::waf_detect::is_blocked_response`] — broad WAF-ish
///   detection for the learning phase (FN-balanced; TOML-driven indicators).
/// - [`wafrift_types::calibration::analyze_calibration`] — calibration probe
///   classification (FN-EXPENSIVE → broad, bare vendor names ARE wanted; an
///   FN here means scanning a real WAF with no evasion).
#[must_use]
pub fn is_waf_block(status: u16, body: &[u8]) -> bool {
    // Status-based detection
    if is_waf_block_status(status) {
        return true;
    }

    // 404 pages commonly contain WAF-ish strings like "forbidden" or
    // "access denied" in custom error pages (e.g. nginx/Apache defaults).
    // Do not misclassify them as WAF blocks.
    if status == 404 {
        return false;
    }

    // Body-based detection (check first 4KB)
    let scan_limit = body.len().min(4096);
    let body_str = String::from_utf8_lossy(&body[..scan_limit]).to_ascii_lowercase();

    // Audit (2026-05-10): removed vendor-name-only indicators
    // (cloudflare, akamai, sucuri, imperva, incapsula) and high-FP
    // generic terms (forbidden, security check, firewall). A benign
    // 200 OK blog post ABOUT Cloudflare or a networking tutorial
    // mentioning "firewall" must NOT be classified as a WAF block.
    // Keep only explicit block-page markers.
    let indicators = [
        "access denied",
        "request blocked",
        "attention required",
        "captcha",
        "blocked by",
        "malicious request",
        "automated request",
        "challenge-platform",
        "ray id",
        "aws waf",
        "request id:",
        "reference #",
    ];

    indicators
        .iter()
        .any(|indicator| body_str.contains(indicator))
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST 1-7: Original tests
    #[test]
    fn detect_403_block() {
        assert!(is_waf_block(403, b"Forbidden"));
    }

    #[test]
    fn detect_429_not_a_block() {
        // Audit (2026-05-10): 429 is rate-limit, not a WAF rule block.
        // The engine must back off, not escalate evasion.
        assert!(!is_waf_block(429, b"Too Many Requests"));
        assert!(!is_waf_block_status(429));
    }

    #[test]
    fn detect_cloudflare_challenge() {
        assert!(is_waf_block(
            200,
            b"<html>Attention Required! challenge-platform Cloudflare Ray ID</html>"
        ));
    }

    #[test]
    fn detect_aws_waf() {
        assert!(is_waf_block(
            200,
            b"<html>Request blocked by AWS WAF</html>"
        ));
    }

    #[test]
    fn normal_200_not_blocked() {
        assert!(!is_waf_block(200, b"<html>Welcome to our site</html>"));
    }

    #[test]
    fn detect_akamai_reference() {
        assert!(is_waf_block(200, b"Access Denied. Reference #18.abc123"));
    }

    #[test]
    fn empty_body_status_only() {
        assert!(is_waf_block(503, b""));
        assert!(!is_waf_block(200, b""));
    }

    // TEST 8-17: Status code detection tests
    #[test]
    fn detect_406_not_acceptable() {
        assert!(is_waf_block_status(406));
    }

    #[test]
    fn detect_451_not_a_block() {
        // Audit (2026-05-10): 451 is legal takedown (GDPR/DMCA).
        // Changing payload cannot bypass a legal block.
        assert!(!is_waf_block_status(451));
        assert!(!is_waf_block(451, b"Unavailable For Legal Reasons"));
    }

    #[test]
    fn detect_503_service_unavailable() {
        assert!(is_waf_block(503, b"Service temporarily unavailable"));
    }

    #[test]
    fn detect_captcha_in_body() {
        assert!(is_waf_block(
            200,
            b"Please complete the captcha to continue"
        ));
    }

    #[test]
    fn detect_firewall_block() {
        assert!(is_waf_block(200, b"Blocked by Web Application Firewall"));
    }

    #[test]
    fn detect_access_denied() {
        assert!(is_waf_block(
            200,
            b"Access Denied - You don't have permission"
        ));
    }

    #[test]
    fn detect_sucuri_waf() {
        assert!(is_waf_block(
            200,
            b"Access Denied - Sucuri Website Firewall"
        ));
    }

    #[test]
    fn detect_incapsula_imperva() {
        // Pre-fix relied on vendor-name-only indicators.
        // Now requires explicit block-page language.
        assert!(is_waf_block(
            200,
            b"Access Denied. Incapsula incident ID: IMPERVA protection"
        ));
    }

    #[test]
    fn detect_malicious_request() {
        assert!(is_waf_block(200, b"Malicious request detected and blocked"));
    }

    #[test]
    fn detect_automated_request() {
        assert!(is_waf_block(200, b"Automated request detected"));
    }

    // TEST 18-22: Non-blocked responses
    #[test]
    fn normal_json_response_not_blocked() {
        assert!(!is_waf_block(200, b"{\"status\": \"ok\", \"data\": []}"));
    }

    #[test]
    fn normal_html_response_not_blocked() {
        assert!(!is_waf_block(
            200,
            b"<!DOCTYPE html><html><head><title>Welcome</title></head><body>Hello</body></html>"
        ));
    }

    #[test]
    fn redirect_302_not_blocked() {
        assert!(!is_waf_block(302, b"Found"));
    }

    #[test]
    fn not_found_404_not_blocked() {
        assert!(!is_waf_block(404, b"Page not found"));
    }

    #[test]
    fn created_201_not_blocked() {
        assert!(!is_waf_block(201, b"Resource created successfully"));
    }

    // TEST 23-30: Edge cases and body detection
    #[test]
    fn mixed_case_indicators() {
        // Vendor-name-only indicators removed — must require block-page text.
        assert!(
            !is_waf_block(200, b"CLOUDFLARE PROTECTION"),
            "benign page mentioning Cloudflare must NOT be a block"
        );
        assert!(is_waf_block(200, b"Akamai Reference #123"));
        assert!(is_waf_block(200, b"AwS WaF Block"));
    }

    #[test]
    fn detect_access_denied_in_context() {
        // Uses "access denied" — an explicit block-page marker retained
        // after the 2026-05-10 audit that removed high-FP terms like
        // "security check" and "firewall".
        assert!(is_waf_block(
            200,
            b"Access denied - your request was rejected"
        ));
    }

    #[test]
    fn detect_request_blocked() {
        assert!(is_waf_block(200, b"Request blocked by security"));
    }

    #[test]
    fn large_body_with_indicator_at_start() {
        let mut body = vec![b' '; 5000];
        body[100..107].copy_from_slice(b"captcha");
        assert!(is_waf_block(200, &body));
    }

    #[test]
    fn waf_indicator_beyond_4kb_not_detected() {
        let mut body = vec![b' '; 5000];
        body[4100..4107].copy_from_slice(b"captcha");
        assert!(!is_waf_block(200, &body));
    }

    #[test]
    fn partial_word_matches() {
        // Uses "blocked by" — an explicit block-page marker retained
        // after the 2026-05-10 audit that removed high-FP "firewall".
        assert!(is_waf_block(200, b"Request blocked by security policy"));
    }

    #[test]
    fn detect_ray_id() {
        assert!(is_waf_block(200, b"Ray ID: 1234567890abcdef"));
    }

    #[test]
    fn detect_challenges() {
        assert!(is_waf_block(200, b"challenge-platform"));
    }

    // ── Adversarial twins: vendor names in benign content must NOT block ──

    #[test]
    fn benign_blog_post_about_cloudflare_not_blocked() {
        let body = b"<h1>How Cloudflare protects sites from DDoS</h1>\
            <p>Cloudflare is a CDN and WAF provider...</p>";
        assert!(
            !is_waf_block(200, body),
            "benign 200 blog post about Cloudflare must NOT be classified as a block"
        );
    }

    #[test]
    fn benign_tutorial_with_firewall_not_blocked() {
        let body = b"<h1>Setting up a firewall with iptables</h1>\
            <p>A firewall protects your network...</p>";
        assert!(
            !is_waf_block(200, body),
            "benign 200 tutorial mentioning firewall must NOT be classified as a block"
        );
    }

    #[test]
    fn benign_page_with_forbidden_not_blocked() {
        let body = b"<h1>HTTP Status Codes Explained</h1>\
            <p>403 Forbidden means the server understood the request but refuses it.</p>";
        assert!(
            !is_waf_block(200, body),
            "benign 200 tutorial mentioning 'Forbidden' must NOT be classified as a block"
        );
    }

    #[test]
    fn api_rate_limit_429_must_not_trigger_evasion() {
        // A legitimate API returning 429 should NOT cause the evasion
        // engine to switch techniques — it should back off.
        assert!(
            !is_waf_block(429, b"Rate limit exceeded. Retry after 60s."),
            "429 must NOT be treated as a WAF block"
        );
    }

    #[test]
    fn legal_takedown_451_must_not_trigger_evasion() {
        assert!(
            !is_waf_block(451, b"Unavailable For Legal Reasons"),
            "451 legal takedown must NOT be treated as a WAF block"
        );
    }

    #[test]
    fn ffuf_404_with_wafish_strings_not_blocked() {
        // Directory bruteforcing produces many 404s whose bodies may
        // contain "forbidden", "access denied", etc. These must NOT be
        // misclassified as WAF blocks.
        assert!(!is_waf_block(
            404,
            b"Forbidden - you cannot access this resource"
        ));
        assert!(!is_waf_block(404, b"Access Denied - page not found"));
        assert!(!is_waf_block(
            404,
            b"Request blocked - this path does not exist"
        ));
        assert!(!is_waf_block(
            404,
            b"<html><h1>Not Found</h1><p>Access to /admin is forbidden</p></html>"
        ));
    }

    #[test]
    fn normal_404_empty_body_not_blocked() {
        assert!(!is_waf_block(404, b""));
        assert!(!is_waf_block(404, b"Not Found"));
    }
}
