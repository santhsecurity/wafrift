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
