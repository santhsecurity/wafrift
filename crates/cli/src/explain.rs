//! `--explain` trace: surface which techniques ran, which were skipped,
//! and why. Drives both text output and the JSON `--quiet` mode.

use colored::Colorize;
use serde_json::{Value, json};
use wafrift_encoding::encoding::Strategy;

use crate::technique_filter::strategy_path;

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Strategy ran and contributed `variant_count` unique variants.
    Applied { variant_count: usize },
    /// Strategy ran but every output was already produced by another path.
    AllDuplicates,
    /// Excluded by `--target-context` rules.
    NotApplicableToContext(&'static str),
    /// Encoding returned an error for this payload (e.g. invalid UTF-8).
    EncodingError(String),
}

#[derive(Debug)]
pub struct ExplainEntry {
    pub strategy: Strategy,
    pub outcome: Outcome,
}

/// Per-tamper explain entry — tampers are a separate variant
/// axis from the encoding `Strategy` enum, so the trace tracks
/// them in a parallel collection.  Each entry pairs the tamper
/// name with whether the transform produced a unique variant or
/// was a no-op / duplicate.
#[derive(Debug)]
pub struct TamperExplainEntry {
    pub name: String,
    pub outcome: TamperOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperOutcome {
    /// Tamper transformed the payload into a NEW variant.
    Applied,
    /// Tamper produced a byte-identical output (no transform
    /// applicable to this payload — e.g. `postgres_dollar_quote`
    /// on a payload without single-quoted literals).
    Idempotent,
    /// Tamper output collided with an already-produced variant
    /// (encoding strategy or earlier tamper produced the same
    /// bytes).
    DuplicateOfExisting,
}

#[derive(Debug, Default)]
pub struct ExplainTrace {
    pub entries: Vec<ExplainEntry>,
    pub tampers: Vec<TamperExplainEntry>,
}

impl ExplainTrace {
    /// Record an outcome. `Applied` entries are merged so each strategy
    /// has at most one Applied line summing all variants it produced.
    pub fn record(&mut self, strategy: Strategy, outcome: Outcome) {
        if let Outcome::Applied { variant_count } = outcome {
            if let Some(entry) = self
                .entries
                .iter_mut()
                .find(|e| e.strategy == strategy && matches!(e.outcome, Outcome::Applied { .. }))
            {
                if let Outcome::Applied { variant_count: n } = &mut entry.outcome {
                    *n += variant_count;
                }
                return;
            }
            self.entries.push(ExplainEntry {
                strategy,
                outcome: Outcome::Applied { variant_count },
            });
            return;
        }
        // For non-Applied outcomes, fold repeat observations of the same
        // (strategy, outcome-variant) into a single entry. Without this,
        // a strategy that produces a duplicate on every grammar
        // mutation prints "folded" N times — the trace becomes scroll
        // noise instead of a summary.
        let already_recorded = self.entries.iter().any(|e| {
            e.strategy == strategy
                && std::mem::discriminant(&e.outcome) == std::mem::discriminant(&outcome)
        });
        if already_recorded {
            return;
        }
        self.entries.push(ExplainEntry { strategy, outcome });
    }

    /// Promote any strategy that recorded `AllDuplicates` AND later
    /// `Applied` into just `Applied` (the duplicate observation was per-call).
    pub fn finalize(&mut self) {
        let applied: Vec<Strategy> = self
            .entries
            .iter()
            .filter_map(|e| matches!(e.outcome, Outcome::Applied { .. }).then_some(e.strategy))
            .collect();
        self.entries.retain(|e| {
            !(matches!(e.outcome, Outcome::AllDuplicates) && applied.contains(&e.strategy))
        });
    }

    /// Record a tamper outcome (transform applied / no-op /
    /// duplicate).  Tampers run AFTER the encoding pipeline so
    /// the trace surfaces them in a separate section.
    pub fn record_tamper(&mut self, name: impl Into<String>, outcome: TamperOutcome) {
        let name = name.into();
        // Fold repeat observations of the same (name, outcome)
        // pair so the explain trace stays compact even when a
        // tamper is invoked across many variant attempts.
        let already = self
            .tampers
            .iter()
            .any(|e| e.name == name && e.outcome == outcome);
        if already {
            return;
        }
        self.tampers
            .push(TamperExplainEntry { name, outcome });
    }

    pub fn print_text(&self) {
        println!("\n{}", "─ Explain ─".bold().cyan());
        if self.entries.is_empty() && self.tampers.is_empty() {
            println!("  (no techniques considered)");
            return;
        }
        for e in &self.entries {
            let path = strategy_path(e.strategy);
            match &e.outcome {
                Outcome::Applied { variant_count } => println!(
                    "  {} {path}: produced {variant_count} variant(s)",
                    "✓".green().bold()
                ),
                Outcome::AllDuplicates => println!(
                    "  {} {path}: output identical to other variants — folded",
                    "·".dimmed()
                ),
                Outcome::NotApplicableToContext(why) => println!(
                    "  {} {path}: not applicable in this context — {why}",
                    "·".yellow()
                ),
                Outcome::EncodingError(msg) => {
                    println!("  {} {path}: encoding failed — {msg}", "✗".red())
                }
            }
        }
        if !self.tampers.is_empty() {
            // Visually separate tamper section so the operator can
            // see at a glance that tampers were considered (and
            // why each fired or didn't).
            for t in &self.tampers {
                let path = format!("tamper/{}", t.name);
                match t.outcome {
                    TamperOutcome::Applied => println!(
                        "  {} {path}: tamper produced a variant",
                        "✓".green().bold()
                    ),
                    TamperOutcome::Idempotent => println!(
                        "  {} {path}: payload unchanged — tamper not applicable to this input",
                        "·".yellow()
                    ),
                    TamperOutcome::DuplicateOfExisting => println!(
                        "  {} {path}: output identical to an existing variant — folded",
                        "·".dimmed()
                    ),
                }
            }
        }
    }

    pub fn to_json(&self) -> Value {
        let mut entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                let (status, detail) = match &e.outcome {
                    Outcome::Applied { variant_count } => {
                        ("applied", json!({ "variants": variant_count }))
                    }
                    Outcome::AllDuplicates => ("duplicate", json!({})),
                    Outcome::NotApplicableToContext(why) => {
                        ("not_applicable", json!({ "reason": why }))
                    }
                    Outcome::EncodingError(msg) => ("error", json!({ "reason": msg })),
                };
                json!({
                    "technique": strategy_path(e.strategy),
                    "status": status,
                    "detail": detail,
                })
            })
            .collect();
        // Tampers — same shape as encoding entries but with the
        // `tamper/<name>` path under `technique` so a downstream
        // consumer can union the two collections without losing
        // attribution.
        for t in &self.tampers {
            let status = match t.outcome {
                TamperOutcome::Applied => "applied",
                TamperOutcome::Idempotent => "idempotent",
                TamperOutcome::DuplicateOfExisting => "duplicate",
            };
            entries.push(json!({
                "technique": format!("tamper/{}", t.name),
                "status": status,
                "detail": {},
            }));
        }
        json!({ "explain": entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_entries_merge() {
        let mut t = ExplainTrace::default();
        t.record(Strategy::UrlEncode, Outcome::Applied { variant_count: 2 });
        t.record(Strategy::UrlEncode, Outcome::Applied { variant_count: 3 });
        assert_eq!(t.entries.len(), 1);
        match t.entries[0].outcome {
            Outcome::Applied { variant_count } => assert_eq!(variant_count, 5),
            _ => panic!("expected Applied"),
        }
    }

    #[test]
    fn repeated_non_applied_outcomes_fold_to_one_entry() {
        // Smoke-test gap: build_variants_explained iterates strategies
        // inside the grammar-mutation loop, so a strategy can record
        // AllDuplicates dozens of times. The trace must collapse them.
        let mut t = ExplainTrace::default();
        for _ in 0..30 {
            t.record(Strategy::WhitespaceInsertion, Outcome::AllDuplicates);
        }
        assert_eq!(
            t.entries.len(),
            1,
            "30 identical AllDuplicates records must collapse to 1"
        );
    }

    #[test]
    fn distinct_non_applied_outcomes_per_strategy_still_separate() {
        let mut t = ExplainTrace::default();
        t.record(
            Strategy::WhitespaceInsertion,
            Outcome::NotApplicableToContext("test"),
        );
        t.record(Strategy::WhitespaceInsertion, Outcome::AllDuplicates);
        // Different outcome variants for the same strategy: keep both.
        assert_eq!(t.entries.len(), 2);
    }

    #[test]
    fn finalize_drops_duplicate_when_strategy_also_applied() {
        let mut t = ExplainTrace::default();
        t.record(Strategy::UrlEncode, Outcome::AllDuplicates);
        t.record(Strategy::UrlEncode, Outcome::Applied { variant_count: 1 });
        t.finalize();
        assert_eq!(t.entries.len(), 1);
        assert!(matches!(t.entries[0].outcome, Outcome::Applied { .. }));
    }

    #[test]
    fn json_output_shape() {
        let mut t = ExplainTrace::default();
        t.record(
            Strategy::Base64Encode,
            Outcome::NotApplicableToContext("compression"),
        );
        let v = t.to_json();
        assert_eq!(v["explain"][0]["status"], "not_applicable");
        assert_eq!(v["explain"][0]["technique"], "encoding/base64/standard");
    }

    // ── Tamper-trace tests (added 2026-05) ──────────────────

    #[test]
    fn tamper_record_applied_creates_entry() {
        let mut t = ExplainTrace::default();
        t.record_tamper("zero_width_inject", TamperOutcome::Applied);
        assert_eq!(t.tampers.len(), 1);
        assert_eq!(t.tampers[0].name, "zero_width_inject");
        assert_eq!(t.tampers[0].outcome, TamperOutcome::Applied);
    }

    #[test]
    fn tamper_record_idempotent_creates_entry() {
        let mut t = ExplainTrace::default();
        t.record_tamper("postgres_dollar_quote", TamperOutcome::Idempotent);
        assert_eq!(t.tampers.len(), 1);
        assert_eq!(t.tampers[0].outcome, TamperOutcome::Idempotent);
    }

    #[test]
    fn tamper_record_duplicate_creates_entry() {
        let mut t = ExplainTrace::default();
        t.record_tamper("url_encode", TamperOutcome::DuplicateOfExisting);
        assert_eq!(t.tampers.len(), 1);
        assert_eq!(t.tampers[0].outcome, TamperOutcome::DuplicateOfExisting);
    }

    #[test]
    fn tamper_record_folds_duplicate_observations() {
        // Repeated (name, outcome) pairs collapse to one entry.
        let mut t = ExplainTrace::default();
        for _ in 0..5 {
            t.record_tamper("zero_width_inject", TamperOutcome::Applied);
        }
        assert_eq!(t.tampers.len(), 1);
    }

    #[test]
    fn tamper_record_distinguishes_different_outcomes() {
        // Same tamper, two different outcomes → two entries
        // (operator wants to see both signals).
        let mut t = ExplainTrace::default();
        t.record_tamper("zero_width_inject", TamperOutcome::Applied);
        t.record_tamper("zero_width_inject", TamperOutcome::Idempotent);
        assert_eq!(t.tampers.len(), 2);
    }

    #[test]
    fn tamper_record_distinguishes_different_names() {
        let mut t = ExplainTrace::default();
        t.record_tamper("a", TamperOutcome::Applied);
        t.record_tamper("b", TamperOutcome::Applied);
        assert_eq!(t.tampers.len(), 2);
    }

    #[test]
    fn json_includes_tamper_entries_alongside_strategies() {
        let mut t = ExplainTrace::default();
        t.record(Strategy::UrlEncode, Outcome::Applied { variant_count: 1 });
        t.record_tamper("zero_width_inject", TamperOutcome::Applied);
        let v = t.to_json();
        let entries = v["explain"].as_array().expect("explain is array");
        assert_eq!(entries.len(), 2);
        // Strategy first, then tamper.
        assert_eq!(entries[0]["technique"], "encoding/url/single");
        assert_eq!(entries[1]["technique"], "tamper/zero_width_inject");
        assert_eq!(entries[1]["status"], "applied");
    }

    #[test]
    fn json_tamper_status_maps_correctly() {
        let mut t = ExplainTrace::default();
        t.record_tamper("a", TamperOutcome::Applied);
        t.record_tamper("b", TamperOutcome::Idempotent);
        t.record_tamper("c", TamperOutcome::DuplicateOfExisting);
        let v = t.to_json();
        let entries = v["explain"].as_array().unwrap();
        assert_eq!(entries[0]["status"], "applied");
        assert_eq!(entries[1]["status"], "idempotent");
        assert_eq!(entries[2]["status"], "duplicate");
    }

    #[test]
    fn empty_trace_emits_empty_explain_array() {
        let t = ExplainTrace::default();
        let v = t.to_json();
        assert!(v["explain"].as_array().unwrap().is_empty());
    }

    #[test]
    fn tamper_outcome_equality_works() {
        // The fold dedup relies on PartialEq.
        assert_eq!(TamperOutcome::Applied, TamperOutcome::Applied);
        assert_ne!(TamperOutcome::Applied, TamperOutcome::Idempotent);
        assert_ne!(
            TamperOutcome::Idempotent,
            TamperOutcome::DuplicateOfExisting
        );
    }

    #[test]
    fn print_text_does_not_panic_with_tampers_present() {
        // Smoke test the print path (output is to stdout, not
        // captured here — we just verify no panic).
        let mut t = ExplainTrace::default();
        t.record(Strategy::UrlEncode, Outcome::Applied { variant_count: 3 });
        t.record_tamper("zero_width_inject", TamperOutcome::Applied);
        t.record_tamper("postgres_dollar_quote", TamperOutcome::Idempotent);
        t.print_text();
    }
}
