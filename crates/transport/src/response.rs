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
    matches!(status, 403 | 406 | 429 | 451 | 503)
}

/// Check if a response looks like a WAF block.
///
/// Combines status code detection with body content analysis. The body
/// is scanned up to the first 4 KiB for known WAF fingerprints.
#[must_use]
pub fn is_waf_block(status: u16, body: &[u8]) -> bool {
    // Status-based detection
    if is_waf_block_status(status) {
        return true;
    }

    // Body-based detection (check first 4KB)
    let scan_limit = body.len().min(4096);
    let body_str = String::from_utf8_lossy(&body[..scan_limit]).to_ascii_lowercase();

    let indicators = [
        "access denied",
        "request blocked",
        "forbidden",
        "security check",
        "attention required",
        "captcha",
        "firewall",
        "blocked by",
        "malicious request",
        "cloudflare",
        "challenge-platform",
        "ray id",
        "aws waf",
        "request id:",
        "automated request",
        "sucuri",
        "incapsula",
        "imperva",
        "akamai",
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
    fn detect_429_rate_limit() {
        assert!(is_waf_block(429, b"Too Many Requests"));
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
    fn detect_451_unavailable_for_legal_reasons() {
        assert!(is_waf_block_status(451));
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
        assert!(is_waf_block(
            200,
            b"Incapsula incident ID: IMPERVA protection"
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
        assert!(is_waf_block(200, b"CLOUDFLARE PROTECTION"));
        assert!(is_waf_block(200, b"Akamai Reference #123"));
        assert!(is_waf_block(200, b"AwS WaF Block"));
    }

    #[test]
    fn detect_security_check() {
        assert!(is_waf_block(200, b"Performing security check..."));
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
        assert!(is_waf_block(200, b"Web Application Firewall blocked you"));
    }

    #[test]
    fn detect_ray_id() {
        assert!(is_waf_block(200, b"Ray ID: 1234567890abcdef"));
    }

    #[test]
    fn detect_challenges() {
        assert!(is_waf_block(200, b"challenge-platform"));
    }
}
