//! wafrift-detect — WAF detection and response fingerprint analysis.
//!
//! Identifies WAFs from response headers and body content.
//! Detects silent blocking via response fingerprint drift analysis.
//!
//! # Examples
//!
//! Identify a WAF from a 403 response that carries a vendor header:
//!
//! ```
//! use wafrift_detect::detect;
//!
//! let headers = vec![
//!     ("Server".to_string(), "cloudflare".to_string()),
//!     ("CF-Ray".to_string(), "abc123-LHR".to_string()),
//! ];
//! let body = b"<html>Cloudflare blocked your request</html>";
//! let results = detect(403, &headers, body);
//! assert!(!results.is_empty(), "should identify Cloudflare");
//! assert!(
//!     results.iter().any(|r| r.name.to_lowercase().contains("cloudflare")),
//!     "Cloudflare must be in the result set: got {:?}",
//!     results.iter().map(|r| &r.name).collect::<Vec<_>>()
//! );
//! ```
//!
//! A clean 200 response with no WAF signatures gives an empty result
//! set:
//!
//! ```
//! use wafrift_detect::detect;
//!
//! let headers = vec![("Server".to_string(), "nginx/1.25.0".to_string())];
//! let body = b"<html><body>Welcome</body></html>";
//! let results = detect(200, &headers, body);
//! assert!(results.is_empty(), "no WAF should match a benign response");
//! ```

pub mod response_fingerprint;
pub mod waf_detect;

pub use response_fingerprint::FingerprintDrift;
pub use waf_detect::{
    DetectConfig, DetectRulesError, DetectedWaf, ProbePayload, ProbeResult, RuleEngine,
    active_probe, classify_drift, detect, is_blocked_response, reload_rules, suggest_evasion,
    supported_wafs,
};

pub mod explain;
