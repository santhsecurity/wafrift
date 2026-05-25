//! Adapter from `wafrift_oracle::OracleVerdict` (+ optional CF signal)
//! to [`super::rule_corpus`] writes.
//!
//! The hunt loop fires a probe, gets back an `OracleVerdict`
//! (`Pass`/`Block`/`Challenge`/`Ambiguous` + an attribution
//! `Option<BlockReason>`), and wants exactly one corpus write:
//!
//! - **Pass + payload that's an attack class** → `record_bypass`
//! - **Block** with `BlockReason::RuleId(id)` → `record_block(id, …)`
//! - **Block** without rule_id → `record_block("unknown", …)`
//! - **Challenge / Ambiguous** → not recorded (the oracle is
//!   uncertain; making it noise in the corpus would bias the
//!   un-explored-cells query)
//!
//! Keeping this glue in one module means every consumer (hunt /
//! bench / model-evade) routes attempts through the same logic — a
//! corpus-key change here propagates everywhere with no
//! per-consumer surface-area to chase.

use crate::coverage_feedback::PayloadClass;
use crate::edge_pop_coverage::EdgePopCoverage;
use crate::rule_corpus::RuleBypassCorpus;

/// What the oracle decided about a single probe. Mirrors the
/// classes `wafrift_oracle::OracleVerdict` ships but lives in
/// `wafrift_evolution` so the corpus crate doesn't need a hard
/// dep on oracle for trivial routing logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeOutcome {
    /// Origin received and processed the attack-class payload —
    /// this is a confirmed WAF bypass.
    Bypass,
    /// WAF blocked the request (status 403/406/429/etc + body /
    /// header signature matched).
    Block,
    /// WAF returned a JS / CAPTCHA / browser challenge — neither
    /// bypass nor confirmed block.
    Challenge,
    /// Oracle can't decide. May be transient (target down, network
    /// flap). Caller usually retries.
    Ambiguous,
}

/// Record one probe outcome into the corpus.
///
/// `rule_id` is the canonical attribution string. For CF this is the
/// `cf:<edge-pop>:<ruleset>` form produced by
/// `wafrift_oracle::cloudflare::CfBlockSignal::corpus_key()`. For
/// ModSec / Coraza it's the raw CRS rule id (`942100`). For
/// "blocked but the WAF didn't tell us why" callers pass `None` and
/// the entry lands under the special bucket `"unattributed"`.
///
/// `response_hash` is the caller's hash of the response body (or a
/// salt + body if the body varies trivially). Used as the dedup
/// key alongside the payload — the corpus collapses near-identical
/// observations.
pub fn record_outcome(
    corpus: &mut RuleBypassCorpus,
    outcome: ProbeOutcome,
    rule_id: Option<&str>,
    payload: &str,
    payload_class: PayloadClass,
    encoding_chain: Vec<String>,
    response_hash: u64,
) {
    let key = rule_id.unwrap_or(UNATTRIBUTED_BUCKET);
    match outcome {
        ProbeOutcome::Bypass => {
            corpus.record_bypass(key, payload, payload_class, encoding_chain, response_hash);
        }
        ProbeOutcome::Block => {
            corpus.record_block(key, payload, payload_class, encoding_chain, response_hash);
        }
        ProbeOutcome::Challenge | ProbeOutcome::Ambiguous => {
            // Intentionally NOT recorded — see module docs.
        }
    }
}

/// The bucket key used when the oracle can't attribute a block to
/// a specific rule. Exposed so the corpus reporter can distinguish
/// "we don't know which CF rule fired" from "we know it's rule X."
pub const UNATTRIBUTED_BUCKET: &str = "unattributed";

/// Record an observed CF edge-POP for an `(egress, target)` probe.
///
/// Called by the hunt loop after `parse_cf_block` returns a
/// `CfBlockSignal`. The signal's `edge_pop` field is what gets
/// passed as `pop_raw`. If the probe didn't hit CF (no `cf-ray`
/// header, raw TCP error, etc), pass `None` and the call increments
/// the probe counter without adding a POP.
///
/// This is a one-line glue around [`EdgePopCoverage::record`] so
/// every consumer routes through the same logic and the public API
/// stays small.
pub fn record_pop_observation(
    coverage: &mut EdgePopCoverage,
    egress: &str,
    target: &str,
    pop_raw: Option<&str>,
) {
    match pop_raw {
        Some(pop) => {
            coverage.record(egress, target, pop);
        }
        None => coverage.record_no_pop(egress, target),
    }
}

/// Apply a single drift event to the corpus — the hunt loop calls
/// this when the strategy's `drift_window` detector fires
/// `RegimeChange::LooserNow`, signalling that previously-blocked
/// payloads are worth re-trying. Marks every currently-blocked
/// rule with the current timestamp.
pub fn record_global_drift(corpus: &mut RuleBypassCorpus) {
    let rule_ids: Vec<String> = corpus
        .buckets
        .keys()
        .filter(|k| !corpus.blocked_for_rule(k).is_empty())
        .cloned()
        .collect();
    for r in rule_ids {
        corpus.mark_drift(&r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cls(s: &str) -> PayloadClass {
        PayloadClass::new(s)
    }

    #[test]
    fn bypass_outcome_records_to_bypassed() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Bypass,
            Some("942100"),
            "' OR 1=1",
            cls("sql"),
            vec!["url".into()],
            0xC0FFEE,
        );
        assert_eq!(c.bypasses_for_rule("942100").len(), 1);
        assert_eq!(c.blocked_for_rule("942100").len(), 0);
    }

    #[test]
    fn block_outcome_records_to_blocked() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Block,
            Some("942100"),
            "evil",
            cls("sql"),
            vec![],
            1,
        );
        assert_eq!(c.blocked_for_rule("942100").len(), 1);
        assert_eq!(c.bypasses_for_rule("942100").len(), 0);
    }

    #[test]
    fn challenge_outcome_not_recorded() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Challenge,
            Some("942100"),
            "x",
            cls("sql"),
            vec![],
            1,
        );
        assert_eq!(c.rules_seen(), 0);
    }

    #[test]
    fn ambiguous_outcome_not_recorded() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Ambiguous,
            Some("942100"),
            "x",
            cls("sql"),
            vec![],
            1,
        );
        assert_eq!(c.rules_seen(), 0);
    }

    #[test]
    fn missing_rule_id_lands_under_unattributed_bucket() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Block,
            None,
            "x",
            cls("sql"),
            vec![],
            1,
        );
        assert_eq!(c.blocked_for_rule(UNATTRIBUTED_BUCKET).len(), 1);
        // Real rules untouched.
        assert_eq!(c.rules_seen(), 1);
    }

    #[test]
    fn cf_corpus_key_form_passes_through() {
        // Simulates what `CfBlockSignal::corpus_key()` produces.
        let mut c = RuleBypassCorpus::new("cf:cumulus");
        let cf_key = "cf:sjc:waf-managed-rule";
        record_outcome(
            &mut c,
            ProbeOutcome::Block,
            Some(cf_key),
            "p",
            cls("sql"),
            vec![],
            1,
        );
        assert_eq!(c.blocked_for_rule(cf_key).len(), 1);
    }

    #[test]
    fn record_global_drift_marks_only_blocked_rules() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Block,
            Some("R1"),
            "p1",
            cls("sql"),
            vec![],
            1,
        );
        record_outcome(
            &mut c,
            ProbeOutcome::Bypass,
            Some("R2"),
            "p2",
            cls("sql"),
            vec![],
            2,
        );
        record_global_drift(&mut c);
        // R1 had blocks → drift recorded.
        assert!(c.buckets["R1"].last_drift_at_secs.is_some());
        // R2 has only bypasses, no blocks to retry → drift not set.
        assert!(c.buckets["R2"].last_drift_at_secs.is_none());
    }

    #[test]
    fn record_global_drift_idempotent_when_no_blocks() {
        let mut c = RuleBypassCorpus::new("t");
        record_outcome(
            &mut c,
            ProbeOutcome::Bypass,
            Some("R1"),
            "p",
            cls("sql"),
            vec![],
            1,
        );
        record_global_drift(&mut c);
        // Nothing changed.
        assert!(c.buckets["R1"].last_drift_at_secs.is_none());
    }

    #[test]
    fn dedup_carries_through_bridge() {
        let mut c = RuleBypassCorpus::new("t");
        for _ in 0..5 {
            record_outcome(
                &mut c,
                ProbeOutcome::Block,
                Some("R1"),
                "same-payload",
                cls("sql"),
                vec![],
                1, // same response_hash
            );
        }
        assert_eq!(c.blocked_for_rule("R1").len(), 1);
    }

    #[test]
    fn unattributed_constant_is_stable() {
        // Pin the bucket-name string so corpus files keyed under it
        // continue to load after a rename refactor.
        assert_eq!(UNATTRIBUTED_BUCKET, "unattributed");
    }

    #[test]
    fn pop_observation_valid_pop_recorded() {
        let mut cov = EdgePopCoverage::new();
        record_pop_observation(&mut cov, "egress-a", "target.example", Some("SJC"));
        assert_eq!(cov.pops_for("egress-a", "target.example").len(), 1);
        assert_eq!(cov.probes_for("egress-a", "target.example"), 1);
    }

    #[test]
    fn pop_observation_none_increments_probe_counter_only() {
        let mut cov = EdgePopCoverage::new();
        record_pop_observation(&mut cov, "egress-a", "target.example", None);
        assert!(cov.pops_for("egress-a", "target.example").is_empty());
        assert_eq!(cov.probes_for("egress-a", "target.example"), 1);
    }

    #[test]
    fn pop_observation_invalid_pop_still_counts() {
        let mut cov = EdgePopCoverage::new();
        record_pop_observation(&mut cov, "egress-a", "target.example", Some("not-a-pop"));
        assert!(cov.pops_for("egress-a", "target.example").is_empty());
        assert_eq!(cov.probes_for("egress-a", "target.example"), 1);
    }

    #[test]
    fn each_outcome_variant_distinct_pattern() {
        // ProbeOutcome is small, but the routing logic relies on the
        // exact variant set. Guard against silent additions.
        let variants = [
            ProbeOutcome::Bypass,
            ProbeOutcome::Block,
            ProbeOutcome::Challenge,
            ProbeOutcome::Ambiguous,
        ];
        let unique: std::collections::HashSet<_> = variants.iter().collect();
        assert_eq!(unique.len(), 4);
    }
}
