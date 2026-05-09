//! Per-payload rule attribution.
//!
//! Given a payload string and a detected WAF, return the list of
//! WAF-rule classes the payload would have triggered. Used by
//! `strategy::explain::explain_bypass` to produce audit-grade reports
//! showing exactly *what* about a payload tripped the WAF — and what
//! the bypass technique removed.
//!
//! # Implementation
//!
//! We don't have access to vendor-private rulesets (Cloudflare's,
//! Akamai's, etc.) — those aren't published. What we DO have is
//! community knowledge about the *categories* of patterns those WAFs
//! match: SQL keywords, XSS tags, CMD separators, traversal sequences,
//! etc. This module scans the payload against those categories and
//! returns one attribution per match. The categories mirror OWASP CRS's
//! rule families, which is the public reference WAFs cluster around.
//!
//! Per-WAF tuning is layered on top: if the matched WAF profile lists
//! an `inspection_model` (e.g. `single_pass_url_decode`), the rule's
//! `confidence` is biased to reflect how aggressively that WAF inspects
//! that pattern.

use crate::waf_detect::DetectedWaf;
use wafrift_types::explanation::RuleAttribution;

/// Categories of payload content that real WAFs attribute to specific rules.
/// Patterns are case-insensitive substrings — same matching shape OWASP CRS,
/// AWS WAF managed rules, and Cloudflare managed rules use for the basic
/// "keyword present" tier. (Vendor-internal regex tuning is not public; this
/// is the closest correct approximation.)
const RULE_CATEGORIES: &[(&str, &str, &[&str])] = &[
    // (rule_id, rule_name, substrings)
    (
        "SQLI-001",
        "SQL keyword presence",
        &[
            "select ", "union ", "insert ", "update ", "delete ", "drop ",
            " from ", " where ", "order by", "group by", " having ",
            " sleep(", " benchmark(", " waitfor delay",
        ],
    ),
    (
        "SQLI-002",
        "SQL tautology / boolean blind",
        &[
            "1=1", "1 = 1", "'a'='a'", " or 1=1", " and 1=1", " or true",
            "' or '",
        ],
    ),
    (
        "SQLI-003",
        "SQL string-quote escape",
        &["';", "\";", "'--", "\"--", "'/*", "\"/*"],
    ),
    (
        "SQLI-004",
        "SQL inline comment obfuscation",
        &["/*!", "/**/", "-- ", "#"],
    ),
    (
        "XSS-001",
        "HTML script/iframe/object tag",
        &[
            "<script", "<iframe", "<object", "<embed", "<applet",
            "<svg", "<math",
        ],
    ),
    (
        "XSS-002",
        "JS event handler attribute",
        &[
            "onerror=", "onload=", "onclick=", "onfocus=", "onmouseover=",
            "ontoggle=", "onbegin=", "onstart=", "onsubmit=",
        ],
    ),
    (
        "XSS-003",
        "JS execution function",
        &[
            "alert(", "eval(", "function(", "settimeout(", "setinterval(",
            "constructor(", "new function",
        ],
    ),
    (
        "XSS-004",
        "javascript: pseudo-protocol",
        &["javascript:", "data:text/html"],
    ),
    (
        "CMDI-001",
        "Shell separator",
        &["; ", "| ", "|| ", "&& ", "`", "$("],
    ),
    (
        "CMDI-002",
        "Common shell command",
        &[
            "cat ", "ls ", "id;", "id|", " whoami", "wget ", "curl ",
            "ping ", " nc ",
        ],
    ),
    (
        "LFI-001",
        "Path traversal sequence",
        &["../", "..\\", "%2e%2e", "%2e%2e%2f", "....//"],
    ),
    (
        "LFI-002",
        "Sensitive system path",
        &[
            "/etc/passwd", "/etc/shadow", "/proc/self/environ",
            "/proc/self/cmdline", "/bin/sh", "c:\\windows\\system32",
        ],
    ),
    (
        "RFI-001",
        "Remote file inclusion",
        &["http://", "https://", "ftp://", "php://input", "data://"],
    ),
    (
        "SSTI-001",
        "Template expression delimiter",
        &["{{", "}}", "${", "<%=", "#{", "${{"],
    ),
    (
        "SSRF-001",
        "Cloud metadata endpoint",
        &[
            "169.254.169.254", "metadata.google.internal", "metadata.azure.com",
        ],
    ),
    (
        "PROTO-001",
        "HTTP smuggling header",
        &[
            "transfer-encoding: chunked",
            "transfer-encoding:chunked",
            "content-length: 0",
        ],
    ),
];

/// Match a payload against the known rule categories.
///
/// Returns one [`RuleAttribution`] per matched category. For each match,
/// `matched_substring` is the substring from the payload that triggered
/// it; `matched_pattern` is the category's listed pattern. `confidence`
/// is biased by the matched WAF's inspection model (more aggressive
/// inspection → higher confidence the WAF actually fires on this rule).
#[must_use]
pub fn explain_block(payload: &str, waf: &DetectedWaf) -> Vec<RuleAttribution> {
    let lower = payload.to_ascii_lowercase();
    let confidence_bias = inspection_model_bias(&waf.name);
    let mut attributions = Vec::new();

    for (rule_id, rule_name, patterns) in RULE_CATEGORIES {
        for pattern in *patterns {
            if let Some(idx) = lower.find(pattern) {
                let end = (idx + pattern.len()).min(payload.len());
                let start = idx.min(payload.len());
                attributions.push(RuleAttribution {
                    rule_id: (*rule_id).to_string(),
                    rule_name: (*rule_name).to_string(),
                    matched_substring: payload[start..end].to_string(),
                    matched_pattern: (*pattern).to_string(),
                    confidence: (waf.confidence * confidence_bias).clamp(0.0, 1.0),
                });
                // Only one hit per category — avoid one payload generating
                // 12 SQLI-001 attributions when it has 12 SQL keywords.
                break;
            }
        }
    }

    attributions
}

/// How aggressively a WAF is known to inspect requests, mapped to a
/// confidence multiplier on detected rule matches.
///
/// Reference points (community-known):
///   - Cloudflare / Imperva / Akamai: high (0.95) — production-grade WAFs
///     with anomaly scoring and multi-decode.
///   - AWS WAF / ModSecurity: medium-high (0.85) — solid managed rules.
///   - Sucuri / generic CDN-WAF: medium (0.70) — keyword-tier only.
///   - Unknown / unidentified: 0.5 — substring matched something but we
///     have no signal whether the WAF in front actually inspects it.
fn inspection_model_bias(waf_name: &str) -> f64 {
    let lower = waf_name.to_ascii_lowercase();
    if lower.contains("cloudflare")
        || lower.contains("imperva")
        || lower.contains("akamai")
    {
        0.95
    } else if lower.contains("aws") || lower.contains("modsec") {
        0.85
    } else if lower.contains("sucuri") || lower.contains("generic") {
        0.70
    } else {
        0.5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cf_waf() -> DetectedWaf {
        DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.9,
            indicators: vec![],
        }
    }

    fn unknown_waf() -> DetectedWaf {
        DetectedWaf {
            name: "Unknown".into(),
            confidence: 0.5,
            indicators: vec![],
        }
    }

    #[test]
    fn sql_union_select_attributed() {
        let attrs = explain_block("' UNION SELECT password FROM users--", &cf_waf());
        assert!(attrs.iter().any(|a| a.rule_id == "SQLI-001"));
        // The exact pattern hit depends on declaration order in the
        // RULE_CATEGORIES table — `select ` happens to come first.
        // What we actually care about: SOME SQL keyword from the table fired.
        let sqli = attrs.iter().find(|a| a.rule_id == "SQLI-001").unwrap();
        assert!(
            ["select ", "union ", " from "].contains(&sqli.matched_pattern.as_str()),
            "expected an SQL keyword, got {:?}",
            sqli.matched_pattern
        );
    }

    #[test]
    fn xss_script_tag_attributed() {
        let attrs = explain_block("<script>alert(1)</script>", &cf_waf());
        assert!(attrs.iter().any(|a| a.rule_id == "XSS-001"));
        assert!(attrs.iter().any(|a| a.rule_id == "XSS-003"));
    }

    #[test]
    fn cmd_injection_attributed() {
        let attrs = explain_block("; cat /etc/passwd", &cf_waf());
        assert!(attrs.iter().any(|a| a.rule_id == "CMDI-001"));
        assert!(attrs.iter().any(|a| a.rule_id == "CMDI-002"));
        assert!(attrs.iter().any(|a| a.rule_id == "LFI-002"));
    }

    #[test]
    fn double_url_encoded_payload_does_not_match() {
        // The whole point: %2575nion (double-encoded UNION) should not
        // light up the bare-keyword rule. A real bypass.
        let attrs = explain_block("%2575nion %2553elect", &cf_waf());
        assert!(!attrs.iter().any(|a| a.rule_id == "SQLI-001"));
    }

    #[test]
    fn benign_payload_no_attributions() {
        let attrs = explain_block("hello world this is fine", &cf_waf());
        assert!(attrs.is_empty());
    }

    #[test]
    fn confidence_scales_with_waf_aggressiveness() {
        let attrs_cf = explain_block("' OR 1=1--", &cf_waf());
        let attrs_unknown = explain_block("' OR 1=1--", &unknown_waf());
        let cf_confidence = attrs_cf
            .iter()
            .find(|a| a.rule_id == "SQLI-002")
            .unwrap()
            .confidence;
        let unknown_confidence = attrs_unknown
            .iter()
            .find(|a| a.rule_id == "SQLI-002")
            .unwrap()
            .confidence;
        assert!(cf_confidence > unknown_confidence);
    }

    #[test]
    fn ssti_template_attributed() {
        let attrs = explain_block("{{7*7}}", &cf_waf());
        assert!(attrs.iter().any(|a| a.rule_id == "SSTI-001"));
    }

    #[test]
    fn ssrf_metadata_attributed() {
        let attrs = explain_block("http://169.254.169.254/latest/meta-data/", &cf_waf());
        assert!(attrs.iter().any(|a| a.rule_id == "SSRF-001"));
        assert!(attrs.iter().any(|a| a.rule_id == "RFI-001"));
    }

    #[test]
    fn one_attribution_per_category_no_dupes() {
        let attrs = explain_block(
            "SELECT UNION INSERT UPDATE DELETE DROP FROM WHERE ORDER BY",
            &cf_waf(),
        );
        // 9 SQL keywords match SQLI-001 but we report it ONCE.
        let sqli_001_count = attrs.iter().filter(|a| a.rule_id == "SQLI-001").count();
        assert_eq!(sqli_001_count, 1);
    }
}
