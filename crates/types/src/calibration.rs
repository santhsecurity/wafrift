//! WAF calibration — detect whether a target has a WAF at all.
//!
//! One job: send known-bad payloads, observe the response, decide if
//! evasion is necessary.  If the target has no WAF, evasion is wasted
//! effort (and extra noise in logs).

use crate::Request;

/// Known payloads that EVERY WAF should block.
///
/// If these go through, the target has no WAF (skip evasion entirely).
pub const CALIBRATION_PAYLOADS: &[&str] = &[
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "; cat /etc/passwd",
];

// F90: enforce non-empty at compile time. `calibration_request` does
// `CALIBRATION_PAYLOADS[0]` which would panic at runtime on the first
// probe if a future refactor empties the array. Promote the invariant
// to a const assertion so the build breaks instead.
const _: () = assert!(
    !CALIBRATION_PAYLOADS.is_empty(),
    "CALIBRATION_PAYLOADS must contain at least one payload — \
     calibration_request indexes [0]"
);

/// Result of WAF calibration check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CalibrationResult {
    /// WAF is present and blocking — use evasion.
    WafPresent,
    /// No WAF detected — skip evasion (faster scanning).
    NoWaf,
    /// Uncertain — use evasion as a precaution.
    Uncertain,
}

/// Generate a calibration request to test if a WAF is present.
///
/// Send this request first — if it goes through unblocked, no WAF
/// exists and evasion is unnecessary.
#[must_use]
pub fn calibration_request(base_url: &str) -> Request {
    Request::get(format!(
        "{}?wafrift_calibrate={}",
        base_url,
        urlencoding::encode(CALIBRATION_PAYLOADS[0])
    ))
}

/// Analyze a calibration response to determine if WAF is present —
/// **broad, FN-expensive** classifier.
///
/// Used by the one-shot calibration probe to decide "should I turn evasion
/// ON for this target?". This is the **FN-EXPENSIVE** end of the spectrum:
/// a false negative here means wafrift scans a real WAF with evasion OFF
/// and gets 100% blocked. A false positive only wastes some CPU. So the
/// indicator list is **deliberately broad** (bare vendor names like
/// `cloudflare`/`akamai`/`incapsula` ARE wanted) — do **not** apply the
/// 2026-05-10 `transport::is_waf_block` audit here.
///
/// **Do not unify** with the other two classifiers. See the doc comments
/// on [`crate::Request`]-adjacent siblings:
/// - `wafrift_transport::response::is_waf_block` — strict post-request
///   retry-loop classifier (FN-cheap, NO bare vendor names).
/// - `wafrift_detect::waf_detect::is_blocked_response` — broad learning-
///   phase classifier (TOML-driven, FN-balanced).
///
/// # Decision logic
///
/// - 403/406/429/503 → WAF present (definite block codes)
/// - 301/302/307/308 → Uncertain (redirects often contain WAF-like text)
/// - Body contains WAF indicators → WAF present
/// - 200/404 with clean body → No WAF
/// - Anything else → Uncertain
#[must_use]
pub fn analyze_calibration(status: u16, body: &[u8]) -> CalibrationResult {
    if matches!(status, 403 | 406 | 429 | 503) {
        return CalibrationResult::WafPresent;
    }

    // Redirect statuses are ambiguous — they frequently contain WAF-like
    // keywords as informational text without actually indicating blocking.
    if matches!(status, 301 | 302 | 307 | 308) {
        return CalibrationResult::Uncertain;
    }

    let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
    let waf_indicators = [
        "blocked",
        "firewall",
        "access denied",
        "security",
        "captcha",
        "challenge",
        "cloudflare",
        "incapsula",
        "akamai",
    ];

    if waf_indicators.iter().any(|ind| body_str.contains(ind)) {
        return CalibrationResult::WafPresent;
    }

    if status == 200 || status == 404 {
        CalibrationResult::NoWaf
    } else {
        CalibrationResult::Uncertain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_request_includes_payload() {
        let req = calibration_request("https://example.com");
        assert!(req.url.contains("wafrift_calibrate"));
    }

    #[test]
    fn analyze_403_is_waf() {
        assert_eq!(
            analyze_calibration(403, b"Forbidden"),
            CalibrationResult::WafPresent
        );
    }

    #[test]
    fn analyze_200_clean_is_no_waf() {
        assert_eq!(
            analyze_calibration(200, b"Welcome"),
            CalibrationResult::NoWaf
        );
    }

    #[test]
    fn analyze_redirect_is_uncertain() {
        assert_eq!(
            analyze_calibration(301, b"Moved. Firewall notice"),
            CalibrationResult::Uncertain
        );
        assert_eq!(
            analyze_calibration(302, b"Redirect"),
            CalibrationResult::Uncertain
        );
    }

    #[test]
    fn analyze_body_firewall_is_waf() {
        assert_eq!(
            analyze_calibration(200, b"Blocked by firewall"),
            CalibrationResult::WafPresent
        );
    }

    #[test]
    fn analyze_unknown_status_is_uncertain() {
        assert_eq!(
            analyze_calibration(500, b"Internal Server Error"),
            CalibrationResult::Uncertain
        );
    }

    #[test]
    fn calibration_payloads_not_empty() {
        assert!(!CALIBRATION_PAYLOADS.is_empty());
    }
}
