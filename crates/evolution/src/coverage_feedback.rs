//! WAF rule-coverage feedback for MAP-Elites quality-diversity search.
//!
//! When the bench fires against a ModSec-fronted target, the response body
//! may contain the specific CRS `rule_id` that fired (parsed by
//! `wafrift_oracle::signal_body_marker::BlockReason::RuleId`).  This module
//! turns that signal into a 2-D MAP-Elites *behavior descriptor*:
//!
//! ```text
//!  (PayloadClass, Option<RuleId>)
//! ```
//!
//! The grid cell is `(attack-class × rule-id)`.  When a cell is
//! undiscovered the mutation strategy can target it deliberately, so
//! bypasses are found ACROSS the rule corpus rather than concentrated on
//! the rules the engine accidentally hits first.
//!
//! # Usage
//!
//! ```
//! use wafrift_evolution::coverage_feedback::{
//!     RuleCoverage, PayloadClass, RuleId, map_elites_descriptor,
//! };
//!
//! let mut cov = RuleCoverage::default();
//! let desc = map_elites_descriptor("' OR 1=1--", Some("942100"));
//! cov.record("' OR 1=1--", desc.1.as_deref());
//!
//! let report = cov.coverage_report();
//! assert!(!report.is_empty());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Types ─────────────────────────────────────────────────────────────────────

/// The attack-class dimension of the MAP-Elites grid.
///
/// Derived from the payload content (or from the bench case's `class` field
/// if the caller has it).  Comparison is case-insensitive; values are stored
/// as lower-case canonical strings so cells are stable across equivalent
/// representations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadClass(pub String);

impl PayloadClass {
    /// Construct from an arbitrary string.  The value is lower-cased and
    /// stripped of leading/trailing whitespace so grid cells are stable.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self(raw.trim().to_ascii_lowercase())
    }

    /// Classify a raw payload string heuristically.
    ///
    /// The classifier is intentionally lightweight — it looks for the
    /// strongest textual signal in the payload rather than doing full
    /// parse-tree analysis.  The categories match the wafrift bench corpus
    /// class identifiers so coverage reports are directly comparable.
    #[must_use]
    pub fn from_payload(payload: &str) -> Self {
        let lower = payload.to_ascii_lowercase();
        if lower.contains("select")
            || lower.contains("union")
            || lower.contains("insert")
            || lower.contains("update")
            || lower.contains("delete")
            || lower.contains("drop")
            || lower.contains("' or ")
            || lower.contains("or 1=1")
        {
            return Self::new("sql");
        }
        if lower.contains("<script")
            || lower.contains("onerror")
            || lower.contains("onload")
            || lower.contains("javascript:")
            || lower.contains("alert(")
        {
            return Self::new("xss");
        }
        if lower.contains("../")
            || lower.contains("..\\")
            || lower.contains("%2e%2e")
            || lower.contains("etc/passwd")
        {
            return Self::new("path");
        }
        if lower.contains("$(")
            || lower.contains("`")
            || lower.contains("|bash")
            || lower.contains("cmd.exe")
            || lower.contains("/bin/sh")
        {
            return Self::new("cmdi");
        }
        if lower.contains("{{")
            || lower.contains("{%")
            || lower.contains("#{")
            || lower.contains("${'")
        {
            return Self::new("ssti");
        }
        if lower.contains("ldap://") || lower.contains("(uid=") || lower.contains("(cn=") {
            return Self::new("ldap");
        }
        if lower.contains("http://") || lower.contains("https://") || lower.contains("ssrf") {
            return Self::new("ssrf");
        }
        if lower.contains("<!entity") || lower.contains("<!doctype") || lower.contains("xxe") {
            return Self::new("xxe");
        }
        if lower.contains("${jndi:") || lower.contains("log4j") || lower.contains("log4shell") {
            return Self::new("log4shell");
        }
        Self::new("unknown")
    }

    /// The canonical string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A CRS / WAF rule identifier.
///
/// Stored as a canonical lower-case ASCII string so that `942100` and
/// `RULE_942100` resolve to the same cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl RuleId {
    /// Normalise: trim whitespace, strip common prefix noise, lower-case.
    ///
    /// Accepts:
    ///  - bare numbers: `"942100"` → `"942100"`
    ///  - prefixed:     `"RULE_942100"`, `"rule-942100"` → `"942100"`
    ///  - mixed case:   `"SQL_942100"` → `"sql_942100"` (prefix retained
    ///    only when it doesn't match `rule`/`RULE_`)
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let s = raw.trim().to_ascii_lowercase();
        // Strip "rule_" / "rule-" prefix if present — it adds no information
        // for grid binning (every entry is a rule) and bloats cell keys.
        let s = s
            .strip_prefix("rule_")
            .or_else(|| s.strip_prefix("rule-"))
            .unwrap_or(&s);
        Self(s.to_string())
    }

    /// The canonical identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ── Coverage tracker ─────────────────────────────────────────────────────────

/// Accumulates `(payload, rule_id)` observations from live bench runs and
/// exposes coverage analytics used by the `--coverage-report` flag.
///
/// Two complementary indices are maintained:
///
/// * `by_rule`  — `rule_id → set of distinct payloads that triggered it`
/// * `by_class` — `payload_class → set of rule_ids it has reached`
///
/// Both are updated atomically on every [`record`][RuleCoverage::record]
/// call so the coverage report is always consistent.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleCoverage {
    /// `rule_id → set of payload fingerprints (first 64 chars) observed`.
    pub by_rule: BTreeMap<RuleId, BTreeSet<String>>,
    /// `payload_class → set of rule_ids reached from that class`.
    pub by_class: BTreeMap<PayloadClass, BTreeSet<RuleId>>,
}

impl RuleCoverage {
    /// Create an empty coverage tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one `(payload, rule_id)` observation.
    ///
    /// `rule_id = None` means the request was not blocked (or the block
    /// reason couldn't be extracted) — the payload class is still indexed
    /// in `by_class` under a synthetic sentinel so "no rule triggered"
    /// coverage is visible in the report.
    pub fn record(&mut self, payload: &str, rule_id: Option<&str>) {
        let cls = PayloadClass::from_payload(payload);
        // Fingerprint: first 64 chars of the payload, trimmed to ASCII
        // printable range to keep the report file human-readable.
        let fp: String = payload
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();

        if let Some(rid_raw) = rule_id {
            let rid = RuleId::new(rid_raw);
            self.by_rule.entry(rid.clone()).or_default().insert(fp);
            self.by_class.entry(cls).or_default().insert(rid);
        } else {
            // Sentinel: no rule blocked this payload.
            let sentinel = RuleId::new("__unblocked__");
            self.by_class.entry(cls).or_default().insert(sentinel);
        }
    }

    /// Produce a human-readable coverage summary.
    ///
    /// Each line is `rule_id  payload_count` separated by a tab, sorted
    /// by rule id.  Suitable for `--coverage-report` output.
    #[must_use]
    pub fn coverage_report(&self) -> String {
        let mut lines = Vec::with_capacity(self.by_rule.len() + 4);
        lines.push(format!(
            "# wafrift rule-coverage report — {} distinct rules triggered",
            self.by_rule.len()
        ));
        lines.push(format!(
            "# payload classes observed: {}",
            self.by_class.len()
        ));
        lines.push("# rule_id\tpayloads_observed".to_string());
        for (rule_id, payloads) in &self.by_rule {
            lines.push(format!("{}\t{}", rule_id.as_str(), payloads.len()));
        }
        lines.push("# per-class summary".to_string());
        for (cls, rules) in &self.by_class {
            lines.push(format!(
                "#   {}: {} rule(s) — {}",
                cls.as_str(),
                rules.len(),
                rules
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        lines.join("\n")
    }

    /// Number of distinct rule IDs observed so far.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        // Exclude the synthetic "__unblocked__" sentinel from the headline.
        self.by_rule
            .keys()
            .filter(|r| r.0 != "__unblocked__")
            .count()
    }

    /// Rules that have been triggered at least once in this run.
    #[must_use]
    pub fn triggered_rules(&self) -> Vec<&RuleId> {
        self.by_rule
            .keys()
            .filter(|r| r.0 != "__unblocked__")
            .collect()
    }

    /// Serialize the coverage map to compact JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails (only possible
    /// if the in-memory types contain non-string-keyed maps, which they
    /// cannot for `BTreeMap<RuleId, _>`).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a coverage map from JSON produced by [`to_json`].
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` on malformed JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ── Descriptor ───────────────────────────────────────────────────────────────

/// Produce the 2-D MAP-Elites behavior descriptor for one `(payload, rule_id)`
/// observation.
///
/// The descriptor is `(PayloadClass, Option<RuleId>)`:
///  - `Some(RuleId)` — the payload was blocked by a specific rule; the grid
///    cell is `(class × rule_id)`.
///  - `None` — the payload was not blocked (or the rule_id could not be
///    extracted); the grid cell collapses to class-only, matching the
///    pre-coverage behavior.
///
/// Stability guarantee: the same `(payload, rule_id)` pair always produces
/// the same descriptor.  The classifier is deterministic.
#[must_use]
pub fn map_elites_descriptor(
    payload: &str,
    rule_id: Option<&str>,
) -> (PayloadClass, Option<RuleId>) {
    let cls = PayloadClass::from_payload(payload);
    let rid = rule_id.map(RuleId::new);
    (cls, rid)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. Empty coverage tracker ──────────────────────────────────────────────

    #[test]
    fn empty_coverage_has_no_rules() {
        let cov = RuleCoverage::new();
        assert_eq!(cov.rule_count(), 0);
        assert!(cov.by_rule.is_empty());
        assert!(cov.by_class.is_empty());
    }

    // ── 2. Single rule_id observation ─────────────────────────────────────────

    #[test]
    fn single_rule_id_recorded_correctly() {
        let mut cov = RuleCoverage::new();
        cov.record("' OR 1=1--", Some("942100"));
        assert_eq!(cov.rule_count(), 1);
        let rid = RuleId::new("942100");
        assert!(cov.by_rule.contains_key(&rid));
        let cls = PayloadClass::new("sql");
        assert!(cov.by_class.contains_key(&cls));
    }

    // ── 3. Mixed classes — distinct cells ─────────────────────────────────────

    #[test]
    fn mixed_classes_produce_distinct_cells() {
        let mut cov = RuleCoverage::new();
        cov.record("' OR 1=1--", Some("942100")); // sql
        cov.record("<script>alert(1)</script>", Some("941100")); // xss
        cov.record("../../../etc/passwd", Some("930100")); // path

        assert_eq!(cov.rule_count(), 3);
        // Three distinct classes must be present.
        assert!(cov.by_class.contains_key(&PayloadClass::new("sql")));
        assert!(cov.by_class.contains_key(&PayloadClass::new("xss")));
        assert!(cov.by_class.contains_key(&PayloadClass::new("path")));
    }

    // ── 4. Descriptor stability — same input → same descriptor ────────────────

    #[test]
    fn descriptor_is_stable_for_same_input() {
        let payload = "' UNION SELECT 1,2,3--";
        let rule = Some("942190");
        let d1 = map_elites_descriptor(payload, rule);
        let d2 = map_elites_descriptor(payload, rule);
        assert_eq!(d1, d2);
    }

    // ── 5. Descriptor with no rule_id → class only ────────────────────────────

    #[test]
    fn descriptor_without_rule_id_has_none_dimension() {
        let (cls, rid) = map_elites_descriptor("' OR 1=1--", None);
        assert_eq!(cls, PayloadClass::new("sql"));
        assert!(rid.is_none());
    }

    // ── 6. JSON round-trip ────────────────────────────────────────────────────

    #[test]
    fn json_roundtrip_preserves_coverage() {
        let mut cov = RuleCoverage::new();
        cov.record("' OR 1=1--", Some("942100"));
        cov.record("<script>alert(1)</script>", Some("941100"));

        let json = cov.to_json().expect("serialization must not fail");
        let restored = RuleCoverage::from_json(&json).expect("deserialization must not fail");

        assert_eq!(restored.rule_count(), cov.rule_count());
        assert_eq!(restored.by_rule.len(), cov.by_rule.len());
        assert_eq!(restored.by_class.len(), cov.by_class.len());
    }

    // ── 7. rule_id case-folding ───────────────────────────────────────────────

    #[test]
    fn rule_id_case_folding_normalises() {
        // All three forms should resolve to the same canonical RuleId.
        let r1 = RuleId::new("942100");
        let r2 = RuleId::new("RULE_942100");
        let r3 = RuleId::new("rule-942100");
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    // ── 8. Rule ID with unusual prefix (no "rule_" prefix) stays intact ───────

    #[test]
    fn rule_id_without_rule_prefix_preserved() {
        let r = RuleId::new("sql_942100");
        // Should NOT strip "sql_" — only "rule_" is stripped.
        assert_eq!(r.as_str(), "sql_942100");
    }

    // ── 9. PayloadClass from SQL payload ──────────────────────────────────────

    #[test]
    fn payload_class_detects_sql() {
        let cls = PayloadClass::from_payload("' UNION SELECT username, password FROM users--");
        assert_eq!(cls, PayloadClass::new("sql"));
    }

    // ── 10. PayloadClass from XSS payload ─────────────────────────────────────

    #[test]
    fn payload_class_detects_xss() {
        let cls = PayloadClass::from_payload("<script>alert(document.cookie)</script>");
        assert_eq!(cls, PayloadClass::new("xss"));
    }

    // ── 11. Multiple payloads hitting the same rule accumulate ────────────────

    #[test]
    fn same_rule_accumulates_multiple_payloads() {
        let mut cov = RuleCoverage::new();
        cov.record("' OR 1=1--", Some("942100"));
        cov.record("' OR 'x'='x'--", Some("942100"));
        cov.record("1 AND 1=1--", Some("942100"));
        let rid = RuleId::new("942100");
        // All three payloads are distinct fingerprints.
        assert_eq!(cov.by_rule[&rid].len(), 3);
        // Still only one rule.
        assert_eq!(cov.rule_count(), 1);
    }

    // ── 12. coverage_report contains expected rule ─────────────────────────────

    #[test]
    fn coverage_report_contains_triggered_rule() {
        let mut cov = RuleCoverage::new();
        cov.record("' OR 1=1--", Some("942100"));
        let report = cov.coverage_report();
        assert!(report.contains("942100"), "report must mention rule 942100");
        assert!(report.contains("1"), "report must show payload count");
    }
}
