//! WAF-aware strategy advisor.
//!
//! Consults the detected WAF and response fingerprint drift to
//! recommend the optimal evasion strategy for the next request.

use serde::Deserialize;
use wafrift_detect::response_fingerprint::FingerprintDrift;
use wafrift_detect::waf_detect::DetectedWaf;
use wafrift_encoding::encoding;
use wafrift_types::injection_context::InjectionContext;

/// A recommended evasion plan based on WAF detection.
#[derive(Debug, Clone, Default)]
pub struct EvasionPlan {
    /// Recommended encoding strategies, in priority order.
    pub encoding_strategies: Vec<encoding::Strategy>,
    /// Whether grammar mutations should be applied.
    pub use_grammar: bool,
    /// Whether header obfuscation should be applied.
    pub use_header_obfuscation: bool,
    /// Whether content-type switching should be applied.
    pub use_content_type_switch: bool,
    /// Whether smuggling should be attempted.
    pub use_smuggling: bool,
    /// Whether H2 evasion should be attempted.
    pub use_h2: bool,
    /// Injection-context hint for contextual encoding (LAW 9 wiring).
    /// When `Some(ctx)`, `strategy::evade_adaptive` uses
    /// `wafrift_encoding::contextual::encode_in_context` instead of
    /// the plain encoder — the encoder then escapes/normalises for
    /// the target context (JSON string, XML CDATA, header value, ...).
    /// `None` (Default) preserves the pre-wiring behaviour: plain
    /// `encoding::encode` with no context-aware escape. Backwards
    /// compat — callers that don't set this see no change.
    pub context: Option<InjectionContext>,
    /// Rationale for each recommendation.
    pub rationale: Vec<String>,
}

/// TOML schema for advisor rules.
#[derive(Debug, Clone, Deserialize)]
pub struct AdvisorRules {
    #[serde(default)]
    pub waf: Vec<WafAdviceRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafAdviceRule {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub encoding_strategies: Vec<String>,
    #[serde(default)]
    pub use_grammar: bool,
    #[serde(default)]
    pub use_header_obfuscation: bool,
    #[serde(default)]
    pub use_content_type_switch: bool,
    #[serde(default)]
    pub use_smuggling: bool,
    #[serde(default)]
    pub use_h2: bool,
    #[serde(default)]
    pub rationale: String,
}

static DEFAULT_ADVISOR_TOML: &str = r#"
[[waf]]
name = "Cloudflare"
encoding_strategies = ["OverlongUtf8", "DoubleUrlEncode", "UnicodeEncode", "ChunkedSplit"]
use_content_type_switch = true
use_smuggling = false
use_h2 = true
rationale = "cloudflare: prioritizing overlong UTF-8 and unicode, avoiding smuggling"

[[waf]]
name = "AWS WAF"
encoding_strategies = ["CaseAlternation", "SqlCommentInsertion", "UnicodeEncode"]
use_content_type_switch = true
use_grammar = true
rationale = "aws waf: regex-heavy, case alternation and comment insertion effective"

[[waf]]
name = "ModSecurity"
aliases = ["CRS", "OWASP CRS"]
encoding_strategies = ["SqlCommentInsertion", "WhitespaceInsertion", "DoubleUrlEncode", "CaseAlternation"]
use_grammar = true
use_content_type_switch = true
rationale = "modsecurity/crs: comment insertion and whitespace bypass CRS anomaly scoring"

[[waf]]
name = "Imperva/Incapsula"
encoding_strategies = ["TripleUrlEncode", "OverlongUtf8", "ChunkedSplit"]
use_smuggling = true
use_h2 = true
rationale = "imperva: deep inspection, using triple encoding and smuggling paths"

[[waf]]
name = "Akamai"
encoding_strategies = ["DoubleUrlEncode", "UnicodeEncode", "ParameterPollution"]
use_content_type_switch = true
use_grammar = true
rationale = "akamai: parameter pollution and unicode effective at edge"

[[waf]]
name = "F5 BIG-IP"
encoding_strategies = ["CaseAlternation", "SqlCommentInsertion", "DoubleUrlEncode"]
use_smuggling = true
rationale = "f5 big-ip: smuggling historically effective, case alternation bypasses ASM"
"#;

fn parse_strategy(name: &str) -> Option<encoding::Strategy> {
    match name {
        "UrlEncode" => Some(encoding::Strategy::UrlEncode),
        "DoubleUrlEncode" => Some(encoding::Strategy::DoubleUrlEncode),
        "TripleUrlEncode" => Some(encoding::Strategy::TripleUrlEncode),
        "UnicodeEncode" => Some(encoding::Strategy::UnicodeEncode),
        "HtmlEntityEncode" => Some(encoding::Strategy::HtmlEntityEncode),
        "CaseAlternation" => Some(encoding::Strategy::CaseAlternation),
        "WhitespaceInsertion" => Some(encoding::Strategy::WhitespaceInsertion),
        "SqlCommentInsertion" => Some(encoding::Strategy::SqlCommentInsertion),
        "NullByteInsertion" => None, // Not present in encoding crate
        "OverlongUtf8" => Some(encoding::Strategy::OverlongUtf8),
        "ChunkedSplit" => Some(encoding::Strategy::ChunkedSplit),
        "ParameterPollution" => None, // Not present in encoding crate
        _ => None,
    }
}

fn load_default_rules() -> AdvisorRules {
    toml::from_str(DEFAULT_ADVISOR_TOML).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "embedded advisor TOML failed to parse; returning empty rules");
        AdvisorRules { waf: Vec::new() }
    })
}

fn match_waf(name: &str, rules: &AdvisorRules) -> Option<WafAdviceRule> {
    let lower = name.to_lowercase();
    for rule in &rules.waf {
        if rule.name.to_lowercase() == lower {
            return Some(rule.clone());
        }
        for alias in &rule.aliases {
            if alias.to_lowercase() == lower || lower.contains(&alias.to_lowercase()) {
                return Some(rule.clone());
            }
        }
        if lower.contains(&rule.name.to_lowercase()) {
            return Some(rule.clone());
        }
    }
    None
}

/// Generate an evasion plan based on detected WAF.
#[must_use]
pub fn advise(waf: Option<&DetectedWaf>, drift: Option<&FingerprintDrift>) -> EvasionPlan {
    let mut plan = default_plan();
    let rules = load_default_rules();

    if let Some(detected) = waf {
        // N11 fix (dogfood R29 cohort): default_plan() seeds the
        // rationale with "no WAF detected, using balanced defaults"
        // — that string is wrong the moment we know a WAF. Clear
        // it before appending the WAF-specific rationale so the
        // operator does not see both "no WAF detected" AND
        // "cloudflare: prioritizing …" in the same scan.
        plan.rationale.clear();
        if let Some(rule) = match_waf(&detected.name, &rules) {
            apply_rule(&mut plan, &rule);
        } else {
            // Unknown WAF: be aggressive
            plan.encoding_strategies = encoding::all_strategies().to_vec();
            plan.use_smuggling = true;
            plan.use_h2 = true;
            plan.rationale.push(format!(
                "unknown WAF '{}': trying all techniques",
                detected.name
            ));
        }
    }

    if let Some(d) = drift {
        adapt_to_drift(&mut plan, d);
    }

    plan
}

fn apply_rule(plan: &mut EvasionPlan, rule: &WafAdviceRule) {
    plan.encoding_strategies = rule
        .encoding_strategies
        .iter()
        .filter_map(|s| parse_strategy(s))
        .collect();
    plan.use_grammar = rule.use_grammar;
    plan.use_header_obfuscation = rule.use_header_obfuscation;
    plan.use_content_type_switch = rule.use_content_type_switch;
    plan.use_smuggling = rule.use_smuggling;
    plan.use_h2 = rule.use_h2;
    plan.rationale.push(rule.rationale.clone());
}

fn default_plan() -> EvasionPlan {
    EvasionPlan {
        encoding_strategies: vec![
            encoding::Strategy::DoubleUrlEncode,
            encoding::Strategy::UnicodeEncode,
            encoding::Strategy::CaseAlternation,
        ],
        use_grammar: true,
        use_header_obfuscation: true,
        use_content_type_switch: true,
        use_smuggling: false,
        use_h2: false,
        context: None,
        rationale: vec!["no WAF detected, using balanced defaults".into()],
    }
}

/// Public helper for callers (e.g. scan, hunt) that have already
/// detected the request's injection context from the Content-Type
/// header — set it on the plan so contextual encoding fires in
/// `evade_adaptive`. Matches LAW 9: every detected context flows
/// into the executor; no half-wired feature.
pub fn context_from_content_type(content_type: Option<&str>) -> Option<InjectionContext> {
    let ct = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    match ct.as_str() {
        "application/json" | "application/json-patch+json" | "application/vnd.api+json" => {
            Some(InjectionContext::JsonString)
        }
        "application/xml" | "text/xml" | "application/soap+xml" => Some(InjectionContext::XmlText),
        "text/html" | "application/xhtml+xml" => Some(InjectionContext::HtmlText),
        "application/x-www-form-urlencoded" => Some(InjectionContext::UrlQuery),
        "multipart/form-data" => Some(InjectionContext::MultipartField),
        _ => None,
    }
}

fn adapt_to_drift(plan: &mut EvasionPlan, drift: &FingerprintDrift) {
    if drift.likely_blocked {
        if !plan
            .encoding_strategies
            .contains(&encoding::Strategy::TripleUrlEncode)
        {
            plan.encoding_strategies
                .push(encoding::Strategy::TripleUrlEncode);
        }
        if !plan
            .encoding_strategies
            .contains(&encoding::Strategy::OverlongUtf8)
        {
            plan.encoding_strategies
                .push(encoding::Strategy::OverlongUtf8);
        }
        plan.use_grammar = true;
        plan.use_smuggling = true;
        plan.rationale.push(format!(
            "response drift {:.0}% suggests blocking, escalating",
            drift.score * 100.0
        ));
    }
    if drift.changed.contains(&"body_length") && !drift.likely_blocked {
        plan.use_content_type_switch = true;
        plan.rationale
            .push("body length drift without block: WAF may be modifying response".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plan_is_balanced() {
        let plan = advise(None, None);
        assert!(plan.use_grammar);
        assert!(plan.use_header_obfuscation);
        assert!(!plan.use_smuggling);
        assert!(!plan.encoding_strategies.is_empty());
    }

    /// LAW 2 backwards-compat pin: a default-constructed EvasionPlan
    /// has `context: None` so callers that don't opt into contextual
    /// encoding see no behavioural change after the B-3 wiring landed.
    #[test]
    fn default_plan_has_no_context() {
        let plan = advise(None, None);
        assert_eq!(plan.context, None);
        let plan2 = EvasionPlan::default();
        assert_eq!(plan2.context, None);
    }

    /// Producer wiring: content-type → injection-context mapping
    /// covers the common cases (JSON, XML, HTML, form, multipart).
    /// Everything else returns None so the caller falls back to the
    /// plain (non-contextual) encoder.
    #[test]
    fn context_from_content_type_maps_common_types() {
        assert_eq!(
            context_from_content_type(Some("application/json")),
            Some(InjectionContext::JsonString)
        );
        assert_eq!(
            context_from_content_type(Some("application/xml")),
            Some(InjectionContext::XmlText)
        );
        assert_eq!(
            context_from_content_type(Some("text/html")),
            Some(InjectionContext::HtmlText)
        );
        assert_eq!(
            context_from_content_type(Some("application/x-www-form-urlencoded")),
            Some(InjectionContext::UrlQuery)
        );
        assert_eq!(
            context_from_content_type(Some("multipart/form-data")),
            Some(InjectionContext::MultipartField)
        );
    }

    /// Content-Type parameters (charset, boundary) must be stripped
    /// before matching. Pre-fix, `application/json; charset=utf-8`
    /// would have fallen through to None.
    #[test]
    fn context_from_content_type_strips_params() {
        assert_eq!(
            context_from_content_type(Some("application/json; charset=utf-8")),
            Some(InjectionContext::JsonString)
        );
        assert_eq!(
            context_from_content_type(Some("multipart/form-data; boundary=----abc")),
            Some(InjectionContext::MultipartField)
        );
    }

    /// Case-insensitive: HTTP header values are case-insensitive per
    /// RFC 9110 §8.3 — `Application/JSON` must match the same as
    /// `application/json`. LAW 12 boundary test.
    #[test]
    fn context_from_content_type_is_case_insensitive() {
        assert_eq!(
            context_from_content_type(Some("Application/JSON")),
            Some(InjectionContext::JsonString)
        );
        assert_eq!(
            context_from_content_type(Some("TEXT/HTML")),
            Some(InjectionContext::HtmlText)
        );
    }

    /// Anti-rig: an unknown content-type returns None — the caller
    /// then uses the plain encoder, NOT a default-guessed context.
    /// (LAW 1: never guess what we don't know.)
    #[test]
    fn context_from_content_type_unknown_is_none() {
        assert_eq!(context_from_content_type(Some("application/octet-stream")), None);
        assert_eq!(context_from_content_type(Some("text/plain")), None);
        assert_eq!(context_from_content_type(Some("")), None);
        assert_eq!(context_from_content_type(None), None);
    }

    /// Vendor JSON variants (jsonapi, json-patch) all map to
    /// JsonString — they're all JSON-shaped on the wire.
    #[test]
    fn context_from_content_type_vendor_json_variants() {
        assert_eq!(
            context_from_content_type(Some("application/vnd.api+json")),
            Some(InjectionContext::JsonString)
        );
        assert_eq!(
            context_from_content_type(Some("application/json-patch+json")),
            Some(InjectionContext::JsonString)
        );
    }

    #[test]
    fn cloudflare_avoids_smuggling() {
        let waf = DetectedWaf {
            name: "Cloudflare".into(),
            confidence: 0.9,
            indicators: vec!["cf-ray header".into()],
        };
        let plan = advise(Some(&waf), None);
        assert!(!plan.use_smuggling);
        assert!(plan.use_h2);
        assert!(
            plan.encoding_strategies
                .contains(&encoding::Strategy::OverlongUtf8)
        );
    }

    #[test]
    fn case_insensitive_matching() {
        let waf = DetectedWaf {
            name: "cloudflare".into(),
            confidence: 0.9,
            indicators: vec![],
        };
        let plan = advise(Some(&waf), None);
        assert!(!plan.use_smuggling);
    }

    #[test]
    fn substring_matching() {
        let waf = DetectedWaf {
            name: "AWS WAF v2".into(),
            confidence: 0.9,
            indicators: vec![],
        };
        let plan = advise(Some(&waf), None);
        assert!(plan.use_grammar);
    }

    #[test]
    fn f5_enables_smuggling() {
        let waf = DetectedWaf {
            name: "F5 BIG-IP".into(),
            confidence: 0.8,
            indicators: vec!["server: bigip".into()],
        };
        let plan = advise(Some(&waf), None);
        assert!(plan.use_smuggling);
    }

    #[test]
    fn drift_escalates_encoding() {
        let drift = FingerprintDrift {
            score: 0.7,
            changed: vec!["status_code", "body_content"],
            likely_blocked: true,
        };
        let plan = advise(None, Some(&drift));
        assert!(plan.use_grammar);
        assert!(plan.use_smuggling);
        assert!(
            plan.encoding_strategies
                .contains(&encoding::Strategy::TripleUrlEncode)
        );
    }

    #[test]
    fn unknown_waf_tries_everything() {
        let waf = DetectedWaf {
            name: "SomeNewWAF".into(),
            confidence: 0.5,
            indicators: vec!["unknown header".into()],
        };
        let plan = advise(Some(&waf), None);
        assert!(plan.use_smuggling);
        assert!(plan.use_h2);
        assert!(plan.encoding_strategies.len() > 5);
    }
}
