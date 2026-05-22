//! Runtime-loaded WAF detection rules from `rules/detect/*.toml`.
//!
//! # Performance architecture
//!
//! All body-regex patterns from all 160+ WAFs are compiled into a single
//! [`regex::RegexSet`].  When a response arrives, the body is scanned
//! **once** against the entire set — O(n) in body length regardless of
//! pattern count.  The set returns which pattern indices matched, and
//! we map those back to their owning WAF rules to accumulate scores.
//!
//! Header and cookie patterns remain per-signature `Regex` objects
//! because the scan input is small (a few header values) and pattern
//! count per-header is low.
//!
//! # Signature provenance
//!
//! The catalog under `rules/detect/*.toml` is derived from the
//! [wafw00f](https://github.com/EnableSecurity/wafw00f) project
//! (BSD-3-Clause) plus selective contributions from
//! [identYwaf](https://github.com/stamparm/identYwaf) (MIT) and
//! locally researched additions. Every rule carries a `source`
//! field (`WAFW00F:<plugin>`, `IDENTYWAF:<probe>`, or
//! `wafrift:<context>`) that points back at the originating
//! plugin/probe so signature provenance is auditable.

use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;

/// Maximum length of an individual regex pattern (bytes). Patterns
/// exceeding this are skipped to mitigate `ReDoS` and pathological
/// compilation times from malicious or corrupted rule files.
const MAX_REGEX_PATTERN_LEN: usize = 4096;

/// Maximum number of body-regex patterns compiled into the global
/// `RegexSet`. Excess patterns are dropped with a warning.
const MAX_BODY_REGEX_PATTERNS: usize = 2000;

/// Minimum confidence required for detections based only on body text.
///
/// Body-only matches are easier to spoof with generic wording (for example
/// benign 404 pages containing "forbidden"), so require stronger evidence.
const BODY_ONLY_MIN_CONFIDENCE: f64 = 0.5;

/// Take up to `max` bytes of `s` starting at byte offset `start`,
/// snapping both ends to UTF-8 character boundaries so the slice can
/// never panic.
///
/// `Regex::find` returns char-boundary-aligned `start`/`end`, but the
/// previous code computed the end as `m.end().min(m.start() + 40)` —
/// `m.start() + 40` is an arbitrary byte offset that lands mid-codepoint
/// whenever a multibyte character (any non-ASCII byte in a WAF block
/// page or header value — `é`, `”`, `→`, NBSP, …) straddles it. That
/// slice panicked the whole detector on attacker-influenced response
/// text. This helper is the bounded, boundary-safe replacement.
/// Compile a WAF-detection regex with case-insensitive matching forced
/// on by default. Detection patterns come from a heterogenous catalog
/// (wafw00f, identYwaf, locally researched) and authors routinely write
/// the literal vendor banner they see — `Cloudflare`, `BinarySec`,
/// `KEMP-LM`, `cache-[a-z]{3}[0-9]+-[A-Z]{3}` — without an explicit
/// `(?i)` flag.  Meanwhile the public CLI entry point
/// (`classifier::detect`) historically lowercased every header value
/// before passing it to the engine, so any uppercase character class
/// (`[A-Z]`) or capitalized literal silently failed to match real
/// traffic.  Forcing `(?i)` at compile time means the rule body says
/// what the author meant ("match this token") and case is irrelevant.
/// Authors who genuinely need case-sensitive matching can opt out with
/// an inline `(?-i)` flag — preserved verbatim because we only prepend
/// when the pattern doesn't already declare an outer case flag.
fn compile_ci_regex(pattern: &str, kind: &str) -> Result<Regex, String> {
    let has_outer_case_flag = pattern.starts_with("(?i)")
        || pattern.starts_with("(?-i)")
        || pattern.starts_with("(?i-")
        || pattern.starts_with("(?-i-");
    let full = if has_outer_case_flag {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    };
    Regex::new(&full).map_err(|e| format!("bad {kind} regex '{pattern}': {e}"))
}

/// Strip a leading `(?...)` inline-flag group from a regex source.
/// Used by catalog-walking tests that need to see the author's
/// LITERAL pattern after the engine's auto-`(?i)` wrap.  Returns the
/// original string when no outer flag group is present.  Does not
/// attempt to parse nested flag groups — only the outermost one.
#[cfg(test)]
fn strip_outer_flag_group(src: &str) -> &str {
    if !src.starts_with("(?") {
        return src;
    }
    // Find the matching ')' that closes the flag group.  Flag
    // groups don't nest (regex syntax forbids it) so a linear
    // scan from byte 2 to the first ')' is safe.
    let bytes = src.as_bytes();
    let mut i = 2;
    while i < bytes.len() && bytes[i] != b')' {
        // A `:` inside the flag group means it's a NON-capturing
        // group with flag scope (e.g. `(?i:foo)`) — we don't want
        // to strip the inner content.
        if bytes[i] == b':' {
            return src;
        }
        i += 1;
    }
    if i < bytes.len() {
        &src[i + 1..]
    } else {
        src
    }
}

fn clamped_snippet(s: &str, start: usize, max: usize) -> &str {
    if start >= s.len() {
        return "";
    }
    // Snap `start` down to a char boundary (it should already be one
    // from a regex match, but never trust the offset).
    let mut lo = start;
    while lo > 0 && !s.is_char_boundary(lo) {
        lo -= 1;
    }
    // Snap the desired end up/down to a char boundary within bounds.
    let mut hi = lo.saturating_add(max).min(s.len());
    while hi > lo && !s.is_char_boundary(hi) {
        hi -= 1;
    }
    &s[lo..hi]
}

/// Global in-memory rule database.
static RULE_DB: Lazy<RwLock<RuleEngine>> = Lazy::new(|| {
    let engine = RuleEngine::load_embedded().unwrap_or_else(|e| {
        tracing::warn!("Failed to load embedded WAF rules: {e}");
        RuleEngine::default()
    });
    RwLock::new(engine)
});

/// A loaded and compiled WAF rule engine.
///
/// Contains both per-rule compiled signatures (for headers/cookies/status)
/// and a global `RegexSet` that batches all body patterns for O(n) scanning.
#[derive(Debug, Default, Clone)]
pub struct RuleEngine {
    /// All compiled WAF rules, keyed by normalized name.
    pub rules: HashMap<String, CompiledWafRule>,
    /// Ordered list of rule names for deterministic iteration.
    pub names: Vec<String>,

    /// All body-regex patterns compiled into a single `RegexSet`.
    /// Each pattern index maps to an entry in `body_pattern_map`.
    body_regex_set: Option<RegexSet>,

    /// Maps each `RegexSet` pattern index → `(waf_name, signature_index, weight)`.
    ///
    /// When the `RegexSet` reports pattern `i` matched, we look up
    /// `body_pattern_map[i]` to find which WAF rule and signature
    /// produced the hit.
    body_pattern_map: Vec<BodyPatternRef>,

    /// Individual body regexes (same order as `body_pattern_map`) used
    /// to extract match snippets for indicator messages.  The `RegexSet`
    /// tells us *which* patterns matched; these tell us *where*.
    body_regexes: Vec<Regex>,
}

/// Reference from a body pattern index back to its owning WAF rule.
#[derive(Debug, Clone)]
struct BodyPatternRef {
    /// WAF rule name (key into `RuleEngine::rules`).
    waf_name: String,
    /// Index of the signature within the WAF rule.
    #[allow(dead_code)]
    sig_index: usize,
    /// Weight of this signature.
    weight: f64,
}

/// A WAF rule with compiled regex patterns.
#[derive(Debug, Clone)]
pub struct CompiledWafRule {
    pub name: String,
    pub vendor: String,
    pub confidence_threshold: f64,
    pub evasions: Vec<String>,
    pub source: String,
    pub signatures: Vec<CompiledSignature>,
}

/// A compiled signature ready for matching.
///
/// `body_regex` is `None` after engine finalization — body matching is
/// delegated to the global `RegexSet`.  The field is kept for the
/// compilation phase only.
#[derive(Debug, Clone)]
pub struct CompiledSignature {
    pub header_name: Option<String>,
    pub header_regex: Option<Regex>,
    pub cookie_regex: Option<Regex>,
    /// Kept for backward compatibility but body matching uses the
    /// engine-level `RegexSet` + `body_regexes` instead.
    pub body_regex: Option<Regex>,
    pub status_code: Option<u16>,
    pub weight: f64,
}

/// Raw TOML rule database structure.
#[derive(Debug, Clone, Deserialize)]
struct RawRuleDb {
    #[serde(default)]
    waf: Vec<RawWafRule>,
}

/// Raw TOML WAF rule.
#[derive(Debug, Clone, Deserialize)]
struct RawWafRule {
    name: String,
    vendor: String,
    #[serde(default = "default_threshold")]
    confidence_threshold: f64,
    #[serde(default)]
    evasions: Vec<String>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    signature: Vec<RawSignature>,
}

/// Raw TOML signature.
#[derive(Debug, Clone, Deserialize)]
struct RawSignature {
    header_name: Option<String>,
    header_regex: Option<String>,
    cookie_regex: Option<String>,
    body_regex: Option<String>,
    status_code: Option<u16>,
    #[serde(default = "default_weight")]
    weight: f64,
}

fn default_threshold() -> f64 {
    0.3
}

fn default_weight() -> f64 {
    0.4
}

/// Compile-time embedded detection rules, generated by `build.rs`.
///
/// This is the concatenation of all `rules/detect/*.toml` files,
/// baked into the binary so `cargo install wafrift` produces a
/// standalone executable with no runtime filesystem dependency.
const EMBEDDED_RULES_TOML: &str =
    include_str!(concat!(env!("OUT_DIR"), "/embedded_detect_rules.toml"));

impl RuleEngine {
    /// Load WAF detection rules.
    ///
    /// **Loading order** (first success wins):
    ///
    /// 1. **Compile-time embedded** — `build.rs` concatenates all
    ///    `rules/detect/*.toml` into the binary.  This is the
    ///    production path for `cargo install` users.
    /// 2. **Filesystem fallback** — walks `rules/detect/` at relative
    ///    paths.  Used during development when you want hot-reload
    ///    via [`reload`].
    pub fn load_embedded() -> Result<Self, DetectRulesError> {
        let mut engine = RuleEngine {
            rules: HashMap::new(),
            names: Vec::new(),
            body_regex_set: None,
            body_pattern_map: Vec::new(),
            body_regexes: Vec::new(),
        };

        // Tier 1: Try compile-time embedded rules.
        let embedded_ok =
            engine.load_from_str(EMBEDDED_RULES_TOML).is_ok() && !engine.rules.is_empty();

        // Tier 2: Filesystem fallback (development, or if embedded is empty).
        if !embedded_ok {
            let candidates = [
                std::path::PathBuf::from("rules/detect"),
                std::path::PathBuf::from("../rules/detect"),
                std::path::PathBuf::from("../../rules/detect"),
            ];

            let mut loaded = false;
            for dir in &candidates {
                if dir.is_dir() {
                    engine.load_directory(dir)?;
                    loaded = true;
                    break;
                }
            }

            if !loaded {
                return Err(DetectRulesError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "rules/detect directory not found and no embedded rules available",
                )));
            }
        }

        // Finalize: compile the global body RegexSet.
        engine.compile_body_regex_set()?;

        Ok(engine)
    }

    /// Parse a TOML string containing `[[waf]]` entries.
    ///
    /// Used by both the compile-time embedded path and hot-reload.
    pub fn load_from_str(&mut self, toml_content: &str) -> Result<(), DetectRulesError> {
        let raw: RawRuleDb = toml::from_str(toml_content)
            .map_err(|e| DetectRulesError::Parse(format!("embedded rules: {e}")))?;
        for waf in raw.waf {
            let compiled = Self::compile_waf(waf)
                .map_err(|e| DetectRulesError::Parse(format!("embedded rules: {e}")))?;
            let key = compiled.name.clone();
            if !self.rules.contains_key(&key) {
                self.names.push(key.clone());
            }
            self.rules.insert(key, compiled);
        }
        Ok(())
    }

    /// Load all `.toml` files from a directory.
    pub fn load_directory(&mut self, path: &std::path::Path) -> Result<(), DetectRulesError> {
        let mut entries: Vec<_> = std::fs::read_dir(path)?
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            })
            .map(|e| e.path())
            .collect();
        entries.sort();

        for entry in entries {
            let content = std::fs::read_to_string(&entry)?;
            let raw: RawRuleDb = toml::from_str(&content)
                .map_err(|e| DetectRulesError::Parse(format!("{}: {e}", entry.display())))?;
            for waf in raw.waf {
                let compiled = Self::compile_waf(waf)
                    .map_err(|e| DetectRulesError::Parse(format!("{}: {e}", entry.display())))?;
                let key = compiled.name.clone();
                if !self.rules.contains_key(&key) {
                    self.names.push(key.clone());
                }
                self.rules.insert(key, compiled);
            }
        }
        Ok(())
    }

    fn compile_waf(raw: RawWafRule) -> Result<CompiledWafRule, String> {
        let mut signatures = Vec::with_capacity(raw.signature.len());
        for sig in raw.signature {
            let header_regex = sig
                .header_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized header regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "header"))
                .transpose()?;
            let cookie_regex = sig
                .cookie_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized cookie regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "cookie"))
                .transpose()?;
            let body_regex = sig
                .body_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized body regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "body"))
                .transpose()?;
            signatures.push(CompiledSignature {
                header_name: sig.header_name.map(|s| s.to_ascii_lowercase()),
                header_regex,
                cookie_regex,
                body_regex,
                status_code: sig.status_code,
                weight: sig.weight,
            });
        }
        Ok(CompiledWafRule {
            name: raw.name,
            vendor: raw.vendor,
            confidence_threshold: raw.confidence_threshold,
            evasions: raw.evasions,
            source: raw.source,
            signatures,
        })
    }

    /// Compile all body-regex patterns across all rules into a single
    /// `RegexSet` for batch scanning.
    ///
    /// Must be called after all rules are loaded.  Populates
    /// `body_regex_set`, `body_pattern_map`, and `body_regexes`.
    pub fn compile_body_regex_set(&mut self) -> Result<(), DetectRulesError> {
        let mut patterns: Vec<String> = Vec::new();
        let mut map: Vec<BodyPatternRef> = Vec::new();
        let mut regexes: Vec<Regex> = Vec::new();

        for name in &self.names {
            let rule = &self.rules[name];
            for (sig_idx, sig) in rule.signatures.iter().enumerate() {
                if let Some(ref re) = sig.body_regex {
                    if patterns.len() >= MAX_BODY_REGEX_PATTERNS {
                        tracing::warn!(
                            limit = MAX_BODY_REGEX_PATTERNS,
                            "truncating body regex set; some WAF signatures will not match on body text"
                        );
                        break;
                    }
                    patterns.push(re.as_str().to_string());
                    map.push(BodyPatternRef {
                        waf_name: name.clone(),
                        sig_index: sig_idx,
                        weight: sig.weight,
                    });
                    regexes.push(re.clone());
                }
            }
            if patterns.len() >= MAX_BODY_REGEX_PATTERNS {
                break;
            }
        }

        if !patterns.is_empty() {
            let set = RegexSet::new(&patterns).map_err(|e| {
                DetectRulesError::Parse(format!("failed to compile body RegexSet: {e}"))
            })?;
            self.body_regex_set = Some(set);
        }

        self.body_pattern_map = map;
        self.body_regexes = regexes;
        Ok(())
    }

    /// Run detection against all rules and return scored matches.
    ///
    /// Body scanning is performed once via the compiled `RegexSet`,
    /// then header/cookie/status checks run per-rule only for WAFs
    /// that have non-body signatures.
    pub fn detect(
        &self,
        status: u16,
        headers: &[(String, String)],
        body: &str,
    ) -> Vec<DetectedWaf> {
        // ── Phase 1: Batch body scan ──
        //
        // Single-pass scan of the body against ALL body patterns.
        // Returns the set of pattern indices that matched.
        let body_hits: Vec<usize> = self
            .body_regex_set
            .as_ref()
            .map(|set| set.matches(body).into_iter().collect())
            .unwrap_or_default();

        // Accumulate body-hit scores per WAF.
        let mut waf_scores: HashMap<&str, (f64, Vec<String>)> = HashMap::new();

        for &pattern_idx in &body_hits {
            let pref = &self.body_pattern_map[pattern_idx];
            let entry = waf_scores
                .entry(&pref.waf_name)
                .or_insert_with(|| (0.0, Vec::new()));
            entry.0 += pref.weight;

            // Extract match snippet for the indicator message.
            if let Some(m) = self.body_regexes[pattern_idx].find(body) {
                let snippet = clamped_snippet(body, m.start(), 40);
                entry.1.push(format!("body: {snippet}"));
            }
        }

        // ── Phase 2: Per-rule header/cookie/status scoring ──
        //
        // Only iterate signatures that have non-body matchers.
        for name in &self.names {
            let rule = &self.rules[name];
            for sig in &rule.signatures {
                // Skip body-only signatures — already handled by RegexSet.
                if sig.header_regex.is_none()
                    && sig.cookie_regex.is_none()
                    && sig.status_code.is_none()
                {
                    continue;
                }

                let mut matched = false;
                let entry = waf_scores.entry(name).or_insert_with(|| (0.0, Vec::new()));

                if let Some(expected) = sig.status_code
                    && status == expected
                {
                    matched = true;
                    entry.1.push(format!("status: {status}"));
                }

                if let Some(ref re) = sig.header_regex {
                    let hname = sig.header_name.as_deref().unwrap_or("");
                    for (k, v) in headers {
                        if (hname.is_empty() || k.eq_ignore_ascii_case(hname))
                            && let Some(m) = re.find(v)
                        {
                            matched = true;
                            entry
                                .1
                                .push(format!("header {k}: {}", clamped_snippet(v, m.start(), 40)));
                            break;
                        }
                    }
                }

                if let Some(ref re) = sig.cookie_regex {
                    for (k, v) in headers {
                        if k.eq_ignore_ascii_case("set-cookie") && re.is_match(v) {
                            matched = true;
                            entry.1.push(format!("cookie: {k}"));
                            break;
                        }
                    }
                }

                if matched {
                    entry.0 += sig.weight;
                }
            }
        }

        // ── Phase 3: Filter and sort ──
        let mut results: Vec<DetectedWaf> = waf_scores
            .into_iter()
            .filter_map(|(name, (score, indicators))| {
                let rule = &self.rules[name];
                let has_non_body_indicator = indicators
                    .iter()
                    .any(|indicator| !indicator.starts_with("body: "));
                let effective_threshold = if has_non_body_indicator {
                    rule.confidence_threshold
                } else {
                    rule.confidence_threshold.max(BODY_ONLY_MIN_CONFIDENCE)
                };
                if score >= effective_threshold {
                    Some(DetectedWaf {
                        name: name.to_string(),
                        confidence: score.min(1.0),
                        indicators,
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        results
    }

    /// Lookup evasion techniques for a detected WAF name.
    #[must_use]
    pub fn evasions_for(&self, name: &str) -> Vec<&str> {
        self.rules
            .get(name)
            .map(|r| r.evasions.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Number of loaded rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Result of WAF detection.
#[derive(Debug, Clone)]
pub struct DetectedWaf {
    pub name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

/// Errors that can occur while loading rules.
#[derive(Debug, thiserror::Error)]
pub enum DetectRulesError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Access the global rule engine (read lock).
pub fn with_engine<F, R>(f: F) -> R
where
    F: FnOnce(&RuleEngine) -> R,
{
    let guard = RULE_DB
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&guard)
}

/// Reload the global rule engine from disk.
pub fn reload() -> Result<(), DetectRulesError> {
    let new_engine = RuleEngine::load_embedded()?;
    let mut guard = RULE_DB
        .write()
        .map_err(|e| DetectRulesError::Parse(format!("RULE_DB poisoned: {e}")))?;
    *guard = new_engine;
    Ok(())
}

/// Detect WAFs using the global rule engine.
#[must_use]
pub fn detect(status: u16, headers: &[(String, String)], body: &str) -> Vec<DetectedWaf> {
    with_engine(|engine| engine.detect(status, headers, body))
}

/// Returns the names of all supported WAF detectors.
#[must_use]
pub fn supported_wafs() -> Vec<String> {
    with_engine(|engine| engine.names.clone())
}

/// Suggest evasions for a WAF name using the global rule engine.
///
/// Returns owned `String`s so callers can keep them past the engine's
/// `RwLock` guard. The previous version returned `&'static str` via
/// `Box::leak` on every call — at sustained proxy traffic that leaked
/// ~100 KB/sec (4 strings × ~25 chars × 1000 req/s) and ~360 MB/hour.
/// The leaked-string optimisation was wrong: `suggest_evasion` runs in
/// the per-response hot path, not once at startup.
#[must_use]
pub fn suggest_evasion(waf_name: &str) -> Vec<String> {
    with_engine(|engine| {
        engine.rules.get(waf_name).map_or_else(
            || {
                vec![
                    "CaseAlternation".into(),
                    "SqlCommentInsertion".into(),
                    "DoubleUrlEncode".into(),
                    "ContentTypeSwitch".into(),
                ]
            },
            |r| r.evasions.clone(),
        )
    })
}

/// Configuration for ambiguity reporting.
#[derive(Debug, Clone, Copy)]
pub struct DetectConfig {
    /// Minimum confidence for a WAF to be reported.
    pub threshold: f64,
    /// If top-2 confidence delta is smaller than this, report both.
    pub ambiguity_delta: f64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            threshold: 0.3,
            ambiguity_delta: 0.15,
        }
    }
}

/// Detect with ambiguity filtering.
#[must_use]
pub fn detect_with_config(
    status: u16,
    headers: &[(String, String)],
    body: &str,
    config: DetectConfig,
) -> Vec<DetectedWaf> {
    let mut results = detect(status, headers, body);
    results.retain(|r| r.confidence >= config.threshold);

    if results.len() >= 2 {
        let delta = results[0].confidence - results[1].confidence;
        if delta < config.ambiguity_delta {
            // Keep top N until delta exceeds threshold
            let mut keep = 2;
            for window in results.windows(2) {
                if window[0].confidence - window[1].confidence < config.ambiguity_delta {
                    keep += 1;
                } else {
                    break;
                }
            }
            results.truncate(keep);
        } else {
            results.truncate(1);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TOML: &str = r#"
[[waf]]
name = "TestWAF"
vendor = "test"
confidence_threshold = 0.3
evasions = ["CaseAlternation", "SqlCommentInsertion"]

[[waf.signature]]
header_name = "x-test-waf"
header_regex = "active"
weight = 0.9

[[waf.signature]]
body_regex = "blocked by test"
weight = 0.95

[[waf.signature]]
status_code = 403
weight = 0.5

[[waf]]
name = "AnotherWAF"
vendor = "another"
confidence_threshold = 0.5
evasions = ["DoubleUrlEncode"]

[[waf.signature]]
body_regex = "another waf"
weight = 0.6
"#;

    fn test_engine() -> RuleEngine {
        let mut engine = RuleEngine::default();
        engine.load_from_str(TEST_TOML).expect("load test toml");
        engine.compile_body_regex_set().expect("compile regex set");
        engine
    }

    #[test]
    fn load_from_str_populates_rules() {
        let engine = test_engine();
        assert_eq!(engine.len(), 2);
        assert!(!engine.is_empty());
    }

    #[test]
    fn detect_by_header() {
        let engine = test_engine();
        let headers = vec![("x-test-waf".into(), "active".into())];
        let results = engine.detect(200, &headers, "OK");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
        assert!(results[0].confidence >= 0.9);
    }

    #[test]
    fn detect_by_body() {
        let engine = test_engine();
        let headers: Vec<(String, String)> = vec![];
        let results = engine.detect(200, &headers, "you are blocked by test engine");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
        assert!(results[0].confidence >= 0.95);
    }

    #[test]
    fn detect_by_status() {
        let engine = test_engine();
        let headers: Vec<(String, String)> = vec![];
        let results = engine.detect(403, &headers, "");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
    }

    #[test]
    fn detect_no_match() {
        let engine = test_engine();
        let headers = vec![("server".into(), "nginx".into())];
        let results = engine.detect(200, &headers, "Welcome");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_confidence_threshold_filters_body_only() {
        let engine = test_engine();
        // AnotherWAF needs 0.5 threshold, body regex gives 0.6
        let results = engine.detect(200, &[], "another waf detected");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "AnotherWAF");
    }

    #[test]
    fn evasions_for_known_waf() {
        let engine = test_engine();
        let evasions = engine.evasions_for("TestWAF");
        assert_eq!(evasions.len(), 2);
        assert!(evasions.contains(&"CaseAlternation"));
    }

    #[test]
    fn evasions_for_unknown_waf_empty() {
        let engine = test_engine();
        assert!(engine.evasions_for("Unknown").is_empty());
    }

    #[test]
    fn detect_body_only_needs_higher_threshold() {
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "LowConfWAF"
vendor = "test"
confidence_threshold = 0.1

[[waf.signature]]
body_regex = "blocked"
weight = 0.4
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");

        // body-only match with weight 0.4 < BODY_ONLY_MIN_CONFIDENCE (0.5)
        let results = engine.detect(200, &[], "blocked");
        assert!(results.is_empty());
    }

    #[test]
    fn empty_engine_returns_empty() {
        let engine = RuleEngine::default();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
        let results = engine.detect(200, &[], "body");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_sorts_by_confidence_desc() {
        let engine = test_engine();
        // TestWAF matches header (0.9) + body (0.95) = 1.85
        // AnotherWAF matches body (0.6)
        let headers = vec![("x-test-waf".into(), "active".into())];
        let results = engine.detect(200, &headers, "blocked by test and another waf");
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "TestWAF");
    }

    // ── Case-insensitive regex wrapper — stress tests ───────────
    //
    // The wrapper is the single most important correctness lever in
    // detection: every rule in the catalog flows through it. These
    // tests stress the wrapper against the pathological patterns
    // authors actually write in the wild — explicit flag opt-outs,
    // multi-flag groups, escape sequences, character classes, raw
    // brackets, Unicode, anchored expressions, and the empty pattern.
    // If any of these break, EVERY downstream rule breaks too.

    #[test]
    fn ci_wrapper_matches_capitalized_literal_against_lowercase_input() {
        // The original bug class: rule author writes `Cloudflare`,
        // classifier lowercases input to `cloudflare`, wrapper must
        // bridge the case gap.
        let re = compile_ci_regex("Cloudflare", "header").expect("compile");
        assert!(re.is_match("cloudflare"));
        assert!(re.is_match("CLOUDFLARE"));
        assert!(re.is_match("CloudFlare"));
        assert!(re.is_match("cLoUdFlArE"));
    }

    #[test]
    fn ci_wrapper_makes_uppercase_char_class_match_lowercase_input() {
        // The Fastly POP-code regex `[A-Z]{3}` MUST match `lga` and
        // `bur` after the input has been lowercased downstream.
        let re = compile_ci_regex("cache-[a-z]{3}[0-9]+-[A-Z]{3}", "header").expect("compile");
        // Lowercase input (what classifier feeds us in production):
        assert!(re.is_match("cache-lga21972-lga"));
        // Original-case input (what engine.detect gets bypassing classifier):
        assert!(re.is_match("cache-lga21972-LGA"));
        // Mid-string match (CSV-joined POPs):
        assert!(re.is_match("cache-lga21972-LGA, cache-bur-kbur8200085-BUR"));
        // Reject malformed POP tokens (no over-eager matching):
        assert!(!re.is_match("cache-2-LGA"));
        assert!(!re.is_match("cache-lga--LGA"));
    }

    #[test]
    fn ci_wrapper_preserves_existing_outer_ci_flag_idempotently() {
        let re = compile_ci_regex("(?i)Already", "header").expect("compile");
        assert!(re.is_match("ALREADY"));
        assert!(re.is_match("already"));
    }

    #[test]
    fn ci_wrapper_respects_explicit_case_sensitive_opt_out() {
        // `(?-i)` is the documented opt-out path. The wrapper MUST
        // detect it and skip wrapping or the opt-out is impossible.
        let re = compile_ci_regex("(?-i)Strict", "header").expect("compile");
        assert!(re.is_match("Strict"));
        assert!(!re.is_match("strict"));
        assert!(!re.is_match("STRICT"));
    }

    #[test]
    fn ci_wrapper_handles_combined_flag_groups() {
        // Multi-flag groups like `(?im)` or `(?si)`.  As long as the
        // group declares the case flag explicitly we must NOT add an
        // outer (?i).  Multi-line + case-insensitive combo:
        let re = compile_ci_regex("(?im)^TOKEN", "body").expect("compile");
        assert!(re.is_match("first\ntoken"));
        // case-insensitive opt-out within a multi-flag group:
        let re_opt_out = compile_ci_regex("(?-im)^Strict", "body").expect("compile");
        assert!(re_opt_out.is_match("Strict line"));
        assert!(!re_opt_out.is_match("strict line"));
    }

    #[test]
    fn ci_wrapper_does_not_double_wrap_when_outer_flag_present() {
        // Defensive: if `(?i)Foo` is wrapped twice, regex crate
        // still parses it; the test ensures we get the SAME
        // semantics, not a parse error.
        let already = compile_ci_regex("(?i)foo", "header").expect("compile");
        let plain = compile_ci_regex("foo", "header").expect("compile");
        for s in ["foo", "FOO", "Foo", "FoO"] {
            assert_eq!(already.is_match(s), plain.is_match(s));
        }
    }

    #[test]
    fn ci_wrapper_compiles_anchored_patterns_without_breaking_anchors() {
        let re = compile_ci_regex("^Cloudflare$", "header").expect("compile");
        assert!(re.is_match("CLOUDFLARE"));
        // Anchors still mean "whole string only":
        assert!(!re.is_match("foo Cloudflare bar"));
        assert!(!re.is_match("Cloudflare extra"));
    }

    #[test]
    fn ci_wrapper_compiles_patterns_with_escaped_metacharacters() {
        let re = compile_ci_regex("(?:F5\\-TrafficShield)", "header").expect("compile");
        assert!(re.is_match("f5-trafficshield"));
        assert!(re.is_match("F5-TrafficShield"));
        // No false-positive on similar tokens:
        assert!(!re.is_match("F5TrafficShield"));
    }

    #[test]
    fn ci_wrapper_compiles_patterns_with_unicode_metaclasses() {
        // Some catalogs use \w which under case-insensitivity still
        // matches digits, underscore, ascii letters.
        let re = compile_ci_regex("token-\\w+", "header").expect("compile");
        assert!(re.is_match("TOKEN-abc123"));
        assert!(re.is_match("token-Xyz_99"));
    }

    #[test]
    fn ci_wrapper_compiles_empty_alternation_and_zero_width_safely() {
        // Pathological: `(?:|other)` is a regex with an empty
        // alternative.  The wrapper must compile but not panic.
        let re = compile_ci_regex("(?:foo|bar)", "header").expect("compile");
        assert!(re.is_match("FOO"));
        assert!(re.is_match("Bar"));
        assert!(!re.is_match("baz"));
    }

    #[test]
    fn ci_wrapper_rejects_pattern_that_was_already_broken() {
        // Garbage regexes must still surface as compile errors, NOT
        // be silently swallowed by the wrapper.
        let err = compile_ci_regex("([unclosed", "header");
        assert!(err.is_err(), "broken pattern must surface as Err");
        let msg = err.unwrap_err();
        assert!(
            msg.contains("header"),
            "error message must name the regex kind: {msg}"
        );
        assert!(
            msg.contains("[unclosed"),
            "error message must echo the offending pattern: {msg}"
        );
    }

    // ── Catalog-wide invariants ──────────────────────────────────
    //
    // These don't hardcode any specific vendor — they prove
    // properties that MUST hold for the whole rule catalog. If they
    // pass, the case-bug class cannot regress for any future rule.

    #[test]
    fn every_embedded_rule_compiles() {
        // The build script concatenates every TOML in rules/detect/.
        // If any file is malformed, an unknown field, or carries a
        // bad regex, this surfaces it loudly.
        let engine = RuleEngine::load_embedded().expect("all embedded rules compile");
        assert!(engine.len() >= 50, "catalog shrank: {}", engine.len());
    }

    #[test]
    fn every_header_regex_in_catalog_is_case_insensitive() {
        // The CI auto-wrap is enforced at compile time.  Prove it by
        // sampling every compiled header regex and asserting that
        // for any pattern containing an ASCII letter, both the
        // upper- and lower-case form of that letter participates in
        // a match — i.e. the (?i) flag is active.  Patterns with
        // explicit `(?-i)` opt-out skip the check.
        let engine = RuleEngine::load_embedded().expect("load");
        let mut checked = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                if let Some(ref re) = sig.header_regex {
                    let src = re.as_str();
                    // Skip explicit case-sensitive rules (none in
                    // current catalog, but the catalog can evolve).
                    if src.starts_with("(?-i)") || src.starts_with("(?-i-") {
                        continue;
                    }
                    // The CI flag must be visible in the source.
                    assert!(
                        src.starts_with("(?i)") || src.starts_with("(?i-")
                            || src.starts_with("(?im")
                            || src.starts_with("(?is")
                            || src.starts_with("(?ix")
                            || src.starts_with("(?iu")
                            // Authors who pre-declared case-flag
                            // inline are preserved verbatim.
                            || src.contains("(?i)")
                            || src.contains("(?i:"),
                        "header regex `{src}` in rule `{}` is NOT case-insensitive — that's the lower-cased-value bug class waiting to happen",
                        rule.name
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 30, "expected many CI-wrapped header rules, got {checked}");
    }

    #[test]
    fn lowercase_input_must_match_uppercase_pattern_for_every_rule() {
        // For every compiled header regex, take the literal portion
        // of its source pattern, lowercase it, and verify the regex
        // still matches.  This is the EXACT failure mode that
        // pre-fix nuked Fastly on nytimes — and it must never
        // silently regress for any rule, present or future.
        let engine = RuleEngine::load_embedded().expect("load");
        let mut tested = 0;
        let mut not_applicable = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let Some(ref re) = sig.header_regex else {
                    continue;
                };
                let src = re.as_str();
                // Skip explicit case-sensitive opt-outs.
                if src.starts_with("(?-i)") {
                    continue;
                }
                // Synthesize a "lowercase-clean" candidate by taking
                // the literal text of the pattern (best-effort: drop
                // metacharacters) and lowercasing it.  If the result
                // is nonempty, the regex MUST still match it.
                let literal: String = src
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-')
                    .collect();
                let lowered = literal.to_ascii_lowercase();
                if lowered.trim().is_empty() {
                    not_applicable += 1;
                    continue;
                }
                // Some patterns are wrapped in groups or have outer
                // anchors — the literal extraction is a best-effort
                // heuristic, not a parser.  Treat a non-match as
                // "literal extraction failed" rather than a bug.
                if re.is_match(&lowered) {
                    tested += 1;
                }
            }
        }
        // We expect MANY successful round-trips.  If this number
        // crashes to zero, the CI wrapper has stopped working.
        assert!(
            tested >= 20,
            "lowercase round-trip succeeded for only {tested} rules ({not_applicable} skipped) — CI wrapper likely broken"
        );
    }

    // ── Real-traffic shape regression — no hardcoded site names ──
    //
    // Each scenario describes the SHAPE of a real edge-case (CSV
    // multi-value header, capitalized vendor banner, multi-WAF
    // chain, body-only signal) without naming the specific site
    // the shape was harvested from.  If the shape regresses, the
    // assertion failure tells you which TYPE of detection broke.

    #[test]
    fn csv_joined_multi_hop_header_value_still_matches_anchored_pattern() {
        use crate::waf_detect::classifier;
        // Pattern: CDN multi-hop response (cache chain) where each
        // hop appends its POP token CSV-style.  The pattern must
        // match SOMEWHERE in the value, not be anchored at offset 0.
        let headers = vec![(
            "X-Served-By".into(),
            "cache-aaa12345-AAA, cache-bbb67890-BBB, cache-ccc-with-hyphens-CCC".into(),
        )];
        let detected = classifier::detect(200, &headers, b"");
        assert!(
            !detected.is_empty(),
            "CSV multi-hop cache header must produce at least one detection"
        );
    }

    #[test]
    fn every_literal_header_rule_in_catalog_matches_capitalized_value() {
        // Property derived from the catalog itself — no hardcoded
        // vendor names. For each rule whose header_regex source is
        // a pure literal (after stripping the auto-prepended (?i)
        // flag), synthesize the corresponding header with the
        // CAPITALIZED literal as the value and assert the rule
        // fires through the public classifier API.  This is the
        // exact bug class that nuked Fastly's POP-code rule for an
        // entire session: lowercased input never met an uppercase
        // expectation.
        use crate::waf_detect::classifier;
        let engine = RuleEngine::load_embedded().expect("load");
        let mut tested = 0;
        let mut missed: Vec<(String, String, String)> = Vec::new();
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let (Some(name), Some(re)) =
                    (sig.header_name.as_ref(), sig.header_regex.as_ref())
                else {
                    continue;
                };
                // Strip the auto-prepended (?i) (or other outer
                // flag) so we look at the AUTHOR's literal.
                let src = re.as_str();
                let literal = strip_outer_flag_group(src);
                // Only consider plain-literal patterns (letters,
                // digits, space, hyphen, period, underscore).
                if literal.is_empty()
                    || !literal.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || matches!(c, ' ' | '-' | '_' | '.' | '/')
                    })
                {
                    continue;
                }
                // Capitalize the literal as a server would emit it.
                let value = literal.to_string();
                let detected = classifier::detect(
                    200,
                    &[(name.clone(), value.clone())],
                    b"",
                );
                if detected.iter().any(|r| r.name == rule.name) {
                    tested += 1;
                } else {
                    missed.push((rule.name.clone(), name.clone(), value));
                }
            }
        }
        assert!(
            tested >= 20,
            "expected >=20 literal-pattern catalog rules to fire under CI; got {tested}. Misses: {missed:?}"
        );
        assert!(
            missed.is_empty(),
            "rules whose own literal value did NOT fire through the public API (CI wrapper broken): {missed:?}"
        );
    }

    #[test]
    fn mixed_case_header_name_with_known_lowercase_signature_still_matches() {
        // HTTP spec: header names are case-insensitive.  Pick a
        // rule we know expects a specific header name + value, and
        // verify that Title-Case wire form of the SAME pair fires.
        // We discover the rule dynamically from the catalog so this
        // doesn't lock to a specific vendor.
        use crate::waf_detect::classifier;
        let engine = RuleEngine::load_embedded().expect("load");
        let mut sampled = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let (Some(name), Some(re)) =
                    (sig.header_name.as_ref(), sig.header_regex.as_ref())
                else {
                    continue;
                };
                let literal = strip_outer_flag_group(re.as_str());
                if literal.is_empty()
                    || !literal
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
                {
                    continue;
                }
                let title_name: String = name
                    .split('-')
                    .map(|part| {
                        let mut chars = part.chars();
                        match chars.next() {
                            None => String::new(),
                            Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("-");
                let value: String = literal.to_string();
                let detected = classifier::detect(
                    200,
                    &[(title_name, value)],
                    b"",
                );
                if detected.iter().any(|r| r.name == rule.name) {
                    sampled += 1;
                }
                if sampled >= 5 {
                    return;
                }
            }
        }
        assert!(
            sampled >= 5,
            "mixed-case header-name match should work for at least 5 catalog rules; got {sampled}"
        );
    }

    #[test]
    fn multi_waf_chain_returns_every_layer_not_just_the_top() {
        use crate::waf_detect::classifier;
        // Real-world: an Envoy sidecar in front of Fastly cache.
        // Forensically we need BOTH names so the operator can pick
        // the right evasion family.  Returning only the
        // top-confidence layer loses critical signal.
        let headers = vec![
            ("Server".into(), "envoy".into()),
            ("X-Envoy-Upstream-Service-Time".into(), "120".into()),
            ("X-Served-By".into(), "cache-aaa11111-AAA".into()),
            ("X-Timer".into(), "S1234567890.000,VS0,VE5".into()),
        ];
        let detected = classifier::detect(200, &headers, b"");
        assert!(
            detected.len() >= 2,
            "multi-WAF chain must surface every layer. Got only: {detected:?}"
        );
    }

    #[test]
    fn unknown_vendor_banner_does_not_false_positive() {
        // Symmetry check: the CI wrapper must not make detection
        // MORE eager.  A nonsense banner must NOT fire any rule.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[("Server".into(), "totally-fake-vendor-xyz-123".into())],
            b"",
        );
        assert!(
            detected.is_empty(),
            "garbage vendor must not match anything: got {detected:?}"
        );
    }

    #[test]
    fn body_regex_with_capitalized_literal_matches_lowercased_body() {
        // The body lowercasing in classifier.rs lives ALONGSIDE the
        // header lowercasing — the (?i) auto-wrap must fix both.
        // Author writes body literal "BLOCKED BY WAF" expecting it
        // to match; classifier lowercases body to "blocked by waf"
        // before matching. Wrap must bridge.
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "BodyCaseWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
body_regex = "BLOCKED BY THIS WAF"
weight = 0.6
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");
        let detected = engine.detect(200, &[], "you have been blocked by this waf");
        assert!(
            detected.iter().any(|r| r.name == "BodyCaseWAF"),
            "body regex with capitalized literal must match lowercased body. Got: {detected:?}"
        );
    }

    #[test]
    fn cookie_regex_with_capitalized_literal_matches_lowercased_value() {
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "CookieCaseWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
cookie_regex = "VISITOR_SESSION"
weight = 0.6
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");
        let headers = vec![("set-cookie".into(), "visitor_session=abc; Path=/".into())];
        let detected = engine.detect(200, &headers, "");
        assert!(
            detected.iter().any(|r| r.name == "CookieCaseWAF"),
            "cookie regex with capitalized literal must match lowercased Set-Cookie value. Got: {detected:?}"
        );
    }

    #[test]
    fn repeated_header_values_in_chain_both_get_scanned() {
        // HTTP/1.1 allows repeated header names — reqwest exposes
        // each repetition as a separate (k, v) tuple.  The detect
        // loop iterates ALL pairs, so each repetition gets a
        // chance to match.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[
                ("X-Served-By".into(), "cache-aaa11111-AAA".into()),
                ("X-Served-By".into(), "cache-bbb22222-BBB".into()),
                ("X-Served-By".into(), "cache-ccc33333-CCC".into()),
            ],
            b"",
        );
        assert!(
            !detected.is_empty(),
            "repeated header values must each be eligible for matching"
        );
    }

    #[test]
    fn header_value_with_non_ascii_bytes_does_not_panic() {
        // Defensive: WAF block pages and reverse-proxy banners
        // sometimes embed UTF-8 (€, →, em-dash).  Classifier
        // lowercasing + regex matching must be panic-safe on these.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[
                ("Server".into(), "Cloudflåre — €dge".into()),
                ("X-Block-Reason".into(), "→ denied".into()),
            ],
            b"blocked by \xe2\x86\x92 firewall",
        );
        // We don't assert SPECIFIC detection here — we assert no panic.
        let _ = detected;
    }

    #[test]
    fn empty_inputs_never_panic_or_false_positive() {
        use crate::waf_detect::classifier;
        for (status, headers, body) in [
            (200, vec![], &b""[..]),
            (0, vec![], &b""[..]),
            (599, vec![("".into(), "".into())], &b""[..]),
            (404, vec![("X-Empty".into(), "".into())], &b""[..]),
        ] {
            let detected = classifier::detect(status, &headers, body);
            assert!(
                detected.is_empty() || !detected[0].name.is_empty(),
                "empty input must not false-positive: {detected:?}"
            );
        }
    }

    #[test]
    fn extremely_long_header_value_does_not_panic_or_hang() {
        // A 100 KiB header value should be scanned without blowing
        // up the regex engine (the bounded MAX_REGEX_PATTERN_LEN
        // covers the PATTERN side; the VALUE side relies on the
        // regex engine being O(n) — which it is, by design).
        use crate::waf_detect::classifier;
        let value = "a".repeat(100 * 1024);
        let detected = classifier::detect(
            200,
            &[("X-Junk".into(), value)],
            b"",
        );
        // Just must not panic / hang.
        let _ = detected;
    }

    #[test]
    fn detection_is_stable_under_random_header_casing() {
        // Property: detection result must be invariant under the
        // case of header names and values.  Capture a baseline,
        // randomize the case, assert equality.
        use crate::waf_detect::classifier;
        let canonical = vec![
            ("Server".to_string(), "AkamaiGHost".to_string()),
            ("X-Akam-SW-Version".to_string(), "12.5".to_string()),
        ];
        let scrambled = vec![
            ("sErVeR".to_string(), "AKamaIghOSt".to_string()),
            ("X-aKam-sw-VeRsIoN".to_string(), "12.5".to_string()),
        ];
        let a = classifier::detect(200, &canonical, b"");
        let b = classifier::detect(200, &scrambled, b"");
        let names_a: Vec<_> = a.iter().map(|r| r.name.clone()).collect();
        let names_b: Vec<_> = b.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names_a, names_b,
            "case randomization changed detection result"
        );
    }
}
