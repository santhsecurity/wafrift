//! CNAME-rule engine — compiles the TOML catalog into regexes and
//! scores `DnsProbe`s against the rules.
//!
//! Rule format mirrors `waf_detect`'s schema for consistency:
//!
//! ```toml
//! [[cname]]
//! name = "Fastly (CNAME)"
//! vendor = "Fastly"
//! confidence_threshold = 0.5
//! evasions = ["CaseAlternation", ...]
//!
//! [[cname.signature]]
//!   host_regex = "\\.map\\.fastly\\.net$"
//!   weight = 0.7
//! ```
//!
//! Every `host_regex` is wrapped `(?i)` at compile time — DNS is
//! case-insensitive per RFC 1035 §2.3.3 and matching `Cloudflare`
//! against `cloudflare` (or vice versa) should always succeed.

use crate::waf_detect::DetectedWaf;
use regex::Regex;
use serde::Deserialize;

/// NFA compile-size limit — workspace-canonical value from
/// [`wafrift_types::REGEX_NFA_SIZE_LIMIT`].  Mirrors `waf_detect/rules.rs`.
/// Caps compile-time NFA explosion so a crafted TOML with a pattern like
/// `(a?){200}` returns a fast `Err` instead of hanging.  Even though the
/// current production path only compiles the embedded TOML (known-good
/// patterns), `from_toml` is `pub` and future callers may pass untrusted
/// input.  Defence-in-depth cost: zero.
const CNAME_REGEX_SIZE_LIMIT: usize = wafrift_types::REGEX_NFA_SIZE_LIMIT;

use super::types::DnsProbe;

/// On-disk shape of one CNAME rule's signature.
#[derive(Debug, Deserialize)]
struct RawCnameSignature {
    /// Regex pattern matched against ANY host in the chain.
    pub host_regex: String,
    /// Weight (0..=1) added to the rule's score when the regex
    /// matches a hop.
    pub weight: f64,
}

/// On-disk shape of a CNAME-rule block.  The optional `source`
/// field is accepted for documentation purposes but discarded
/// (provenance lives in the TOML, not at runtime).
#[derive(Debug, Deserialize)]
struct RawCnameRule {
    pub name: String,
    pub vendor: String,
    pub confidence_threshold: f64,
    #[serde(default)]
    pub evasions: Vec<String>,
    #[serde(default, rename = "source")]
    pub _source: Option<String>,
    pub signature: Vec<RawCnameSignature>,
}

#[derive(Debug, Deserialize)]
struct RawCnameDb {
    #[serde(default)]
    pub cname: Vec<RawCnameRule>,
}

#[derive(Debug, Clone)]
struct CompiledCnameSignature {
    host_regex: Regex,
    weight: f64,
}

#[derive(Debug, Clone)]
struct CompiledCnameRule {
    name: String,
    vendor: String,
    confidence_threshold: f64,
    evasions: Vec<String>,
    signatures: Vec<CompiledCnameSignature>,
}

/// Loaded CNAME-detection ruleset.
#[derive(Debug, Default, Clone)]
pub struct CnameRuleEngine {
    rules: Vec<CompiledCnameRule>,
}

const EMBEDDED_CNAME_TOML: &str = include_str!("../../rules/detect/cname/cname.toml");

impl CnameRuleEngine {
    /// Load the compile-time embedded ruleset.  This is what ships in
    /// `cargo install wafrift` binaries.
    pub fn load_embedded() -> Result<Self, String> {
        Self::from_toml(EMBEDDED_CNAME_TOML)
    }

    /// Parse a TOML rule file into a compiled engine.
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let raw: RawCnameDb =
            toml::from_str(toml_str).map_err(|e| format!("parse CNAME rules TOML: {e}"))?;
        let mut rules = Vec::with_capacity(raw.cname.len());
        for r in raw.cname {
            let mut signatures = Vec::with_capacity(r.signature.len());
            for s in r.signature {
                // CNAME hostnames are case-insensitive per RFC 1035
                // §2.3.3, so every signature regex is wrapped (?i)
                // automatically — same convention as waf_detect.
                let full = if s.host_regex.starts_with("(?i)") || s.host_regex.starts_with("(?-i)")
                {
                    s.host_regex.clone()
                } else {
                    format!("(?i){}", s.host_regex)
                };
                // §15 ReDoS defence: use size_limit to prevent a crafted
                // TOML pattern from causing O(2^N) NFA expansion during
                // compile (e.g. `(a?){200}`). Matches the protection in
                // waf_detect/rules.rs::compile_ci_regex and
                // wafmodel/oracle.rs. The `(?i)` prefix was already added
                // above, so pass the combined `full` string to the builder.
                let re = regex::RegexBuilder::new(&full)
                    .size_limit(CNAME_REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| format!("bad CNAME regex '{}': {e}", s.host_regex))?;
                signatures.push(CompiledCnameSignature {
                    host_regex: re,
                    weight: s.weight,
                });
            }
            rules.push(CompiledCnameRule {
                name: r.name,
                vendor: r.vendor,
                confidence_threshold: r.confidence_threshold,
                evasions: r.evasions,
                signatures,
            });
        }
        Ok(Self { rules })
    }

    /// Score a CNAME chain against every rule.  Multiple WAF/CDN
    /// vendors can fire when the chain layers them (e.g. Cloudflare
    /// in front of Cloudfront) — every layer surfaces in the
    /// returned vector, sorted by confidence descending.
    pub fn detect(&self, probe: &DnsProbe) -> Vec<DetectedWaf> {
        let tagged = probe.tagged_hosts();
        let mut out: Vec<DetectedWaf> = Vec::new();
        for rule in &self.rules {
            let mut score = 0.0;
            let mut indicators: Vec<String> = Vec::new();
            for sig in &rule.signatures {
                for (label, host) in &tagged {
                    if sig.host_regex.is_match(host) {
                        score += sig.weight;
                        // Two signatures within the same rule can
                        // match the same host (e.g. Fastly's two
                        // *.map.fastly.net + *.fastly.net rules
                        // both fire on `reddit.map.fastly.net`).
                        // Dedup indicators so the output isn't
                        // visually noisy with repeated lines.  The
                        // `label` (cname / ptr / asn) makes
                        // attribution unambiguous downstream.
                        let ind = format!("{label}: {host}");
                        if !indicators.contains(&ind) {
                            indicators.push(ind);
                        }
                        break;
                    }
                }
            }
            if score >= rule.confidence_threshold {
                out.push(DetectedWaf {
                    name: rule.name.clone(),
                    confidence: score.min(1.0),
                    indicators,
                });
            }
        }
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    /// Number of compiled rules — for diagnostics.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when no rules are loaded — for diagnostics.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Vendor display string for a detected CNAME rule.  Returns
    /// `None` when the name isn't in the catalog.  Mirrors
    /// `waf_detect::RuleEngine::evasions_for` for callers that
    /// want a single API across both detection layers.
    pub fn vendor_for(&self, name: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.vendor.as_str())
    }

    /// Suggested evasion technique names for a detected CNAME rule.
    /// Empty when the name isn't in the catalog (callers usually
    /// fall back to a default list).
    pub fn evasions_for(&self, name: &str) -> Vec<&str> {
        self.rules
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.evasions.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}
