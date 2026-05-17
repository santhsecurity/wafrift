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
    /// Strategy was in the pool but the level cap kept it from running.
    NotInLevelPool,
    /// Strategy filtered out by `--exclude` or absent from `--only`.
    FilteredOut,
}

#[derive(Debug)]
pub struct ExplainEntry {
    pub strategy: Strategy,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct ExplainTrace {
    pub entries: Vec<ExplainEntry>,
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

    pub fn print_text(&self) {
        println!("\n{}", "─ Explain ─".bold().cyan());
        if self.entries.is_empty() {
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
                Outcome::NotInLevelPool => println!(
                    "  {} {path}: above current --level threshold (use a higher level or --only)",
                    "·".dimmed()
                ),
                Outcome::FilteredOut => println!(
                    "  {} {path}: filtered out by --only/--exclude",
                    "·".dimmed()
                ),
            }
        }
    }

    pub fn to_json(&self) -> Value {
        let entries: Vec<Value> = self
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
                    Outcome::NotInLevelPool => ("not_in_level_pool", json!({})),
                    Outcome::FilteredOut => ("filtered_out", json!({})),
                };
                json!({
                    "technique": strategy_path(e.strategy),
                    "status": status,
                    "detail": detail,
                })
            })
            .collect();
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
}
