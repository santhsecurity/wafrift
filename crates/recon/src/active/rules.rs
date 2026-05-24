//! Load and apply TOML `[[rule]]` rows for HTTP response header classification.

use super::error::ReconProbeError;
use serde::Deserialize;
use std::collections::BTreeMap;

use super::{StackTag, TagFamily};

const EMBEDDED_RULES: &str = include_str!("../../rules/stack_headers.toml");

/// Parsed header-matching rules (typically from TOML).
#[derive(Debug, Clone)]
pub struct HeaderRules {
    rules: Vec<HeaderRule>,
}

#[derive(Debug, Clone)]
struct HeaderRule {
    family: TagFamily,
    id: String,
    /// Lowercase header name
    header_key: String,
    value_prefix: Option<String>,
    value_contains: Option<String>,
}

#[derive(Deserialize)]
struct RulesFile {
    rule: Vec<RuleToml>,
}

#[derive(Deserialize)]
struct RuleToml {
    family: String,
    id: String,
    header: String,
    value_prefix: Option<String>,
    value_contains: Option<String>,
}

impl HeaderRules {
    /// Built-in rules shipped with the crate (`rules/stack_headers.toml`).
    #[must_use]
    pub fn embedded() -> Self {
        Self::from_toml_str(EMBEDDED_RULES).expect("embedded stack header rules must parse")
    }

    /// Parse rules from a TOML document (same shape as `rules/stack_headers.toml`).
    ///
    /// # Errors
    ///
    /// Returns [`ReconProbeError::RulesToml`] when the document is malformed or uses an unknown `family`.
    pub fn from_toml_str(source: &str) -> Result<Self, ReconProbeError> {
        let parsed: RulesFile = toml::from_str(source)
            .map_err(|e| ReconProbeError::RulesToml(format!("parse: {e}")))?;
        let mut rules = Vec::with_capacity(parsed.rule.len());
        for r in parsed.rule {
            let family = match r.family.to_ascii_lowercase().as_str() {
                "waf" => TagFamily::Waf,
                "cdn" => TagFamily::Cdn,
                "framework" => TagFamily::Framework,
                other => {
                    return Err(ReconProbeError::RulesToml(format!(
                        "unknown family `{other}` (expected waf|cdn|framework)"
                    )));
                }
            };
            let header_key = r.header.trim().to_ascii_lowercase();
            if header_key.is_empty() {
                return Err(ReconProbeError::RulesToml("empty `header` in rule".into()));
            }
            rules.push(HeaderRule {
                family,
                id: r.id,
                header_key,
                value_prefix: r.value_prefix,
                value_contains: r.value_contains,
            });
        }
        Ok(Self { rules })
    }

    /// Classify normalized response headers into stack tags (sorted, deduplicated).
    #[must_use]
    pub fn classify(&self, headers: &BTreeMap<String, String>) -> Vec<StackTag> {
        let mut tags = Vec::new();
        for rule in &self.rules {
            let Some(value) = headers.get(rule.header_key.as_str()) else {
                continue;
            };
            if let Some(prefix) = &rule.value_prefix
                && !starts_with_ascii_ci(value, prefix)
            {
                continue;
            }
            if let Some(needle) = &rule.value_contains
                && !contains_ascii_ci(value, needle)
            {
                continue;
            }
            tags.push(StackTag {
                family: rule.family,
                id: rule.id.clone(),
            });
        }
        tags.sort();
        tags.dedup();
        tags
    }
}

fn starts_with_ascii_ci(haystack: &str, prefix: &str) -> bool {
    let h = haystack.as_bytes();
    let p = prefix.as_bytes();
    h.len() >= p.len() && h[..p.len()].eq_ignore_ascii_case(p)
}

fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hmap(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), (*v).to_string()))
            .collect()
    }

    // ── starts_with_ascii_ci / contains_ascii_ci ──────────────

    #[test]
    fn starts_with_ascii_ci_matches_lowercase_prefix() {
        assert!(starts_with_ascii_ci("cloudflare-nginx/1.0", "cloudflare"));
    }

    #[test]
    fn starts_with_ascii_ci_is_case_insensitive() {
        assert!(starts_with_ascii_ci("CloudFlare-nginx", "cloudflare"));
        assert!(starts_with_ascii_ci("cloudflare", "CLOUDFLARE"));
    }

    #[test]
    fn starts_with_ascii_ci_rejects_off_match() {
        assert!(!starts_with_ascii_ci("nginx", "cloudflare"));
        // Empty haystack with non-empty prefix.
        assert!(!starts_with_ascii_ci("", "x"));
    }

    #[test]
    fn starts_with_ascii_ci_empty_prefix_is_true() {
        // A zero-length prefix matches every string — both sides
        // of the length check pass.
        assert!(starts_with_ascii_ci("anything", ""));
    }

    #[test]
    fn contains_ascii_ci_empty_needle_is_true() {
        assert!(contains_ascii_ci("anything", ""));
        assert!(contains_ascii_ci("", ""));
    }

    #[test]
    fn contains_ascii_ci_finds_needle_anywhere() {
        assert!(contains_ascii_ci("AWSALB=value; path=/", "awsalb"));
        assert!(contains_ascii_ci("a-AwsAlB-z", "awsalb"));
    }

    #[test]
    fn contains_ascii_ci_rejects_when_too_short() {
        // needle longer than haystack → windows() yields nothing.
        assert!(!contains_ascii_ci("ab", "abcd"));
    }

    // ── from_toml_str ─────────────────────────────────────────

    #[test]
    fn embedded_rules_parses() {
        let r = HeaderRules::embedded();
        // The embedded ruleset must produce at least one rule —
        // otherwise the include_str! has gone empty.
        assert!(!r.rules.is_empty());
    }

    #[test]
    fn from_toml_str_round_trips_a_known_rule() {
        let src = r#"
[[rule]]
family = "waf"
id = "cloudflare"
header = "Server"
value_contains = "cloudflare"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].id, "cloudflare");
        assert_eq!(r.rules[0].header_key, "server"); // lowercased on parse
        assert_eq!(r.rules[0].family, TagFamily::Waf);
    }

    #[test]
    fn from_toml_str_accepts_each_family_case_insensitive() {
        for family in &["waf", "WAF", "Cdn", "framework", "FRAMEWORK"] {
            let src = format!(
                r#"[[rule]]
family = "{family}"
id = "x"
header = "h"
"#
            );
            assert!(HeaderRules::from_toml_str(&src).is_ok(), "family={family}");
        }
    }

    #[test]
    fn from_toml_str_rejects_unknown_family() {
        let src = r#"
[[rule]]
family = "loadbalancer"
id = "x"
header = "h"
"#;
        let err = HeaderRules::from_toml_str(src).unwrap_err();
        assert!(matches!(err, ReconProbeError::RulesToml(_)));
        let s = format!("{err:?}");
        assert!(s.contains("loadbalancer"), "must name the bad family: {s}");
    }

    #[test]
    fn from_toml_str_rejects_empty_header() {
        let src = r#"
[[rule]]
family = "waf"
id = "x"
header = "   "
"#;
        let err = HeaderRules::from_toml_str(src).unwrap_err();
        assert!(matches!(err, ReconProbeError::RulesToml(_)));
        let s = format!("{err:?}");
        assert!(s.to_lowercase().contains("empty"), "got: {s}");
    }

    #[test]
    fn from_toml_str_rejects_malformed_toml() {
        let src = "this is not toml [[[";
        assert!(HeaderRules::from_toml_str(src).is_err());
    }

    // ── classify ──────────────────────────────────────────────

    #[test]
    fn classify_zero_rules_yields_empty_tags() {
        // Empty rule list — `rule = []` is the well-formed
        // zero-entries shape (a fully empty TOML doc fails parse
        // because the `rule` field is required).
        let r = HeaderRules::from_toml_str("rule = []").unwrap();
        let tags = r.classify(&hmap(&[("server", "nginx")]));
        assert!(tags.is_empty());
    }

    #[test]
    fn classify_returns_empty_when_no_header_matches() {
        let src = r#"
[[rule]]
family = "waf"
id = "cloudflare"
header = "cf-ray"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        let tags = r.classify(&hmap(&[("server", "nginx")]));
        assert!(tags.is_empty());
    }

    #[test]
    fn classify_matches_on_header_presence_alone() {
        // No value_prefix / value_contains constraints — header
        // existence is enough.
        let src = r#"
[[rule]]
family = "waf"
id = "cloudflare"
header = "cf-ray"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        let tags = r.classify(&hmap(&[("cf-ray", "abc-def")]));
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].id, "cloudflare");
        assert_eq!(tags[0].family, TagFamily::Waf);
    }

    #[test]
    fn classify_enforces_value_prefix() {
        let src = r#"
[[rule]]
family = "cdn"
id = "akamai-cdn"
header = "server"
value_prefix = "AkamaiGHost"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        assert_eq!(r.classify(&hmap(&[("server", "AkamaiGHost")])).len(), 1);
        // Wrong prefix → no match.
        assert!(
            r.classify(&hmap(&[("server", "nginx-AkamaiGHost")]))
                .is_empty()
        );
    }

    #[test]
    fn classify_value_prefix_is_case_insensitive() {
        let src = r#"
[[rule]]
family = "cdn"
id = "akamai-cdn"
header = "server"
value_prefix = "akamaighost"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        assert_eq!(r.classify(&hmap(&[("server", "AKAMAIGHOST/9.0")])).len(), 1);
    }

    #[test]
    fn classify_enforces_value_contains() {
        let src = r#"
[[rule]]
family = "waf"
id = "awsalb"
header = "set-cookie"
value_contains = "AWSALB="
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        assert_eq!(
            r.classify(&hmap(&[("set-cookie", "AWSALB=abc; path=/; HttpOnly")]))
                .len(),
            1
        );
        assert!(r.classify(&hmap(&[("set-cookie", "session=x")])).is_empty());
    }

    #[test]
    fn classify_requires_both_constraints_when_both_set() {
        let src = r#"
[[rule]]
family = "waf"
id = "imperva"
header = "set-cookie"
value_prefix = "visid_incap"
value_contains = "expires"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        // Both satisfied.
        assert_eq!(
            r.classify(&hmap(&[(
                "set-cookie",
                "visid_incap_x=y; expires=...; path=/"
            )]))
            .len(),
            1
        );
        // Prefix only — needs contains.
        assert!(
            r.classify(&hmap(&[("set-cookie", "visid_incap_x=y; path=/")]))
                .is_empty()
        );
        // Contains only — needs prefix.
        assert!(
            r.classify(&hmap(&[("set-cookie", "session=x; expires=tomorrow")]))
                .is_empty()
        );
    }

    #[test]
    fn classify_returns_tags_sorted_and_deduped() {
        // Two rules pointing at the same StackTag (same family +
        // id) on the same header — must dedup. Three rules on
        // different headers, classified out of declaration order,
        // must come back sorted.
        let src = r#"
[[rule]]
family = "framework"
id = "zzz"
header = "x-framework"

[[rule]]
family = "waf"
id = "aaa"
header = "x-waf"

[[rule]]
family = "waf"
id = "aaa"
header = "x-waf-alt"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        let tags = r.classify(&hmap(&[
            ("x-framework", "any"),
            ("x-waf", "yes"),
            ("x-waf-alt", "yes"),
        ]));
        // Dedup collapses the two `waf/aaa` matches.
        assert_eq!(tags.len(), 2);
        // Sorted: TagFamily::Waf orders before Framework
        // (PartialOrd derive on enum follows variant declaration
        // order — Waf first per mod.rs).
        assert_eq!(tags[0].family, TagFamily::Waf);
        assert_eq!(tags[0].id, "aaa");
        assert_eq!(tags[1].family, TagFamily::Framework);
        assert_eq!(tags[1].id, "zzz");
    }

    #[test]
    fn classify_header_lookup_uses_lowercase_key() {
        // Rule's header was Stored lowercased; classify uses that
        // key as-is on the BTreeMap. We hand it a lowercased map
        // (which mirrors what http.rs builds), so this confirms
        // the round-trip.
        let src = r#"
[[rule]]
family = "cdn"
id = "fastly"
header = "FaStLy-DeBuG-DiGeSt"
"#;
        let r = HeaderRules::from_toml_str(src).unwrap();
        let tags = r.classify(&hmap(&[("fastly-debug-digest", "abc")]));
        assert_eq!(tags.len(), 1);
    }
}
