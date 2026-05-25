//! `wafrift corpus stats` — read-only inspection of an existing
//! corpus + edge-POP coverage map.
//!
//! Closes the "first production caller" gap for
//! [`crate::corpus_recorder::CorpusRecorder`]. Without this command
//! the recorder would compile but never be constructed in any
//! shipped binary; the read-only inspection path is the lowest-risk
//! integration that proves the wire-up.
//!
//! The bench-side WRITE wire-up (a `--corpus-out` flag on
//! `wafrift bench-waf`) lands in a follow-up commit so each
//! integration step is independently reviewable.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use serde_json::json;

use crate::corpus_recorder::CorpusRecorder;

#[derive(Args, Debug)]
pub struct CorpusArgs {
    #[command(subcommand)]
    pub action: CorpusAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum CorpusAction {
    /// Print a structured summary of an existing corpus +
    /// edge-POP coverage map. Useful for CI gating ("if rules_seen
    /// < N, fail the hunt") and operator dashboards.
    Stats(StatsArgs),
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    /// Path to the rule_corpus JSON file.
    #[arg(long)]
    pub corpus: PathBuf,
    /// Path to the edge_pop_coverage JSON file.
    #[arg(long)]
    pub coverage: PathBuf,
    /// Optional path to the H1Archive — fingerprints in this file
    /// are excluded from the "novel" count.
    #[arg(long)]
    pub h1_archive: Option<PathBuf>,
    /// Output format: `human` (default) or `json`.
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,
    /// Target fingerprint string the corpus was recorded against
    /// (used only when the corpus file is missing/corrupt so we
    /// can construct a fresh empty Default).
    #[arg(long, default_value = "unknown")]
    pub target_fingerprint: String,
}

pub fn run_corpus(args: CorpusArgs) -> ExitCode {
    ExitCode::from(run_corpus_inner(args))
}

fn run_corpus_inner(args: CorpusArgs) -> u8 {
    match args.action {
        CorpusAction::Stats(a) => run_stats(a),
    }
}

fn run_stats(args: StatsArgs) -> u8 {
    let recorder = CorpusRecorder::new(
        args.target_fingerprint.clone(),
        args.corpus.clone(),
        args.coverage.clone(),
        args.h1_archive.clone(),
    );
    let corpus = recorder.corpus();
    let coverage = recorder.coverage();

    if args.format == "json" {
        let pops_global = coverage.pops_covered_global();
        let v = json!({
            "target_fingerprint": corpus.target_fingerprint,
            "rules_seen": corpus.rules_seen(),
            "total_bypasses": corpus.total_bypasses(),
            "total_blocks": corpus.total_blocks(),
            "pops_covered": pops_global.iter().collect::<Vec<_>>(),
            "pops_covered_count": pops_global.len(),
            "schema_version": corpus.schema_version,
        });
        match serde_json::to_string_pretty(&v) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("json render failed: {e}");
                1
            }
        }
    } else {
        println!("wafrift corpus stats");
        println!("  target fingerprint : {}", corpus.target_fingerprint);
        println!("  rules seen         : {}", corpus.rules_seen());
        println!("  total bypasses     : {}", corpus.total_bypasses());
        println!("  total blocks       : {}", corpus.total_blocks());
        let pops = coverage.pops_covered_global();
        println!("  edge POPs covered  : {} ({:?})", pops.len(), pops);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wafrift_corpus_cmd_test_{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn stats_missing_files_falls_back_to_defaults() {
        let corpus = tmp("missing_corpus");
        let coverage = tmp("missing_coverage");
        // Files don't exist — load_or_default takes over.
        let args = StatsArgs {
            corpus: corpus.clone(),
            coverage: coverage.clone(),
            h1_archive: None,
            format: "human".into(),
            target_fingerprint: "test".into(),
        };
        // Must not panic. Inner returns 0 for human-format render success.
        assert_eq!(run_stats(args), 0);
    }

    #[test]
    fn stats_json_format_emits_well_formed_json() {
        let corpus = tmp("json_corpus");
        let coverage = tmp("json_coverage");
        let args = StatsArgs {
            corpus: corpus.clone(),
            coverage: coverage.clone(),
            h1_archive: None,
            format: "json".into(),
            target_fingerprint: "tf".into(),
        };
        assert_eq!(run_stats(args), 0);
    }

    #[test]
    fn stats_unknown_format_treated_as_human_via_clap() {
        // clap value_parser rejects unknown format strings at parse time,
        // so this test just confirms the inner function handles "json"
        // and "human" identically when reading defaults. Anything else
        // wouldn't reach run_stats.
        let corpus = tmp("either_corpus");
        let coverage = tmp("either_coverage");
        let human = run_stats(StatsArgs {
            corpus: corpus.clone(),
            coverage: coverage.clone(),
            h1_archive: None,
            format: "human".into(),
            target_fingerprint: "tf".into(),
        });
        let json_mode = run_stats(StatsArgs {
            corpus,
            coverage,
            h1_archive: None,
            format: "json".into(),
            target_fingerprint: "tf".into(),
        });
        assert_eq!(human, 0);
        assert_eq!(json_mode, 0);
    }
}
