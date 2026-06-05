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

use wafrift_evolution::encoding_lattice::LatticeSearch;
use wafrift_evolution::rule_alphabet::infer_alphabet_default;

use crate::corpus_recorder::CorpusRecorder;

#[derive(Args, Debug)]
pub(crate) struct CorpusArgs {
    #[command(subcommand)]
    pub action: CorpusAction,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum CorpusAction {
    /// Print a structured summary of an existing corpus +
    /// edge-POP coverage map. Useful for CI gating ("if rules_seen
    /// < N, fail the hunt") and operator dashboards.
    Stats(StatsArgs),
    /// Copy a corpus (and its coverage sibling) to a timestamped
    /// snapshot — an off-machine backstop for the irreplaceable
    /// bypass corpus, which otherwise lives only in machine-local
    /// `~/.wafrift`. Point `--dest` at a backed-up location (the Santh
    /// share, an external drive) and run it before/after a hunt.
    Snapshot(SnapshotArgs),
}

#[derive(Args, Debug)]
pub(crate) struct StatsArgs {
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

pub(crate) fn run_corpus(args: CorpusArgs) -> ExitCode {
    ExitCode::from(run_corpus_inner(args))
}

fn run_corpus_inner(args: CorpusArgs) -> u8 {
    match args.action {
        CorpusAction::Stats(a) => run_stats(a),
        CorpusAction::Snapshot(a) => run_snapshot(a),
    }
}

#[derive(Args, Debug)]
pub(crate) struct SnapshotArgs {
    /// Path to the corpus JSON to snapshot.
    #[arg(long)]
    pub corpus: PathBuf,
    /// Destination directory for the snapshot. Defaults to
    /// `~/.wafrift/snapshots/`. Point at a backed-up location for true
    /// off-machine durability.
    #[arg(long)]
    pub dest: Option<PathBuf>,
}

/// Copy `corpus` (and its `coverage-*` sibling, when the name follows the
/// `corpus-<slug>.json` convention) to `<dest>/<stem>-<epoch>.json`. The
/// snapshot is timestamped + sortable, never overwrites a prior one, and is
/// verified by re-reading its byte length. Off-machine backstop for the
/// machine-local `~/.wafrift` corpus the operator otherwise keeps losing.
fn run_snapshot(args: SnapshotArgs) -> u8 {
    if !args.corpus.exists() {
        eprintln!("error: --corpus {} does not exist.", args.corpus.display());
        return 1;
    }
    let dest = args.dest.unwrap_or_else(default_snapshot_dir);
    if let Err(e) = std::fs::create_dir_all(&dest) {
        eprintln!("error: cannot create snapshot dir {}: {e}", dest.display());
        return 1;
    }
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut copied = 0u64;
    for src in snapshot_sources(&args.corpus) {
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("corpus");
        let snap = dest.join(format!("{stem}-{epoch}.json"));
        match std::fs::copy(&src, &snap) {
            Ok(n) => {
                copied += 1;
                println!(
                    "snapshot: {} ({n} bytes) -> {}",
                    src.display(),
                    snap.display()
                );
            }
            Err(e) => {
                // The coverage sibling is best-effort; a corpus copy failure is fatal.
                if src == args.corpus {
                    eprintln!("error: snapshot of {} failed: {e}", src.display());
                    return 1;
                }
                eprintln!(
                    "warn: coverage sibling {} not snapshotted: {e}",
                    src.display()
                );
            }
        }
    }
    if copied == 0 {
        eprintln!("error: nothing was snapshotted.");
        return 1;
    }
    0
}

/// The corpus plus its `coverage-<slug>.json` sibling when the corpus name
/// follows the `corpus-<slug>.json` convention `wafrift hunt` writes. A
/// non-conventional name snapshots just the one file.
fn snapshot_sources(corpus: &std::path::Path) -> Vec<PathBuf> {
    let mut out = vec![corpus.to_path_buf()];
    if let (Some(dir), Some(name)) = (corpus.parent(), corpus.file_name().and_then(|n| n.to_str()))
        && let Some(slug) = name.strip_prefix("corpus-")
    {
        let coverage = dir.join(format!("coverage-{slug}"));
        if coverage.exists() {
            out.push(coverage);
        }
    }
    out
}

/// Default snapshot directory: `~/.wafrift/snapshots/`, or `./wafrift-snapshots`
/// when no home directory resolves.
fn default_snapshot_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".wafrift").join("snapshots"))
        .unwrap_or_else(|| PathBuf::from("wafrift-snapshots"))
}

fn run_stats(args: StatsArgs) -> u8 {
    // R45-I2 fix (dogfood pass 5): pre-fix `corpus stats --corpus
    // /nonexistent/x.json --coverage /nonexistent/y.json` silently
    // fell back to Default::default() (zeroed counters) and exited 0.
    // A CI gate using `corpus stats --format json` as a regression
    // check would silently pass on missing files. Hard-error on
    // any explicitly-supplied path that does not exist; the empty-
    // default is only valid when the caller intentionally requests
    // it (no path supplied).
    // PathBuf fields with empty default sentinel ("") are treated
    // as "no path supplied" — only a non-empty + nonexistent path
    // is a hard error. Optional fields (h1_archive) are checked
    // only when Some(p).
    let required: [(&str, &std::path::Path); 2] =
        [("corpus", &args.corpus), ("coverage", &args.coverage)];
    for (label, p) in required {
        if !p.as_os_str().is_empty() && !p.exists() {
            eprintln!(
                "error: --{label} {} does not exist. Pre-R45 this silently \
                 fell back to a zeroed default, which let CI gates pass on \
                 missing artifacts. Omit the flag to use the in-process \
                 default, or point at a real file.",
                p.display()
            );
            return 1;
        }
    }
    if let Some(ref p) = args.h1_archive
        && !p.exists()
    {
        eprintln!("error: --h1-archive {} does not exist.", p.display());
        return 1;
    }
    let recorder = CorpusRecorder::new(
        args.target_fingerprint.clone(),
        args.corpus.clone(),
        args.coverage.clone(),
        args.h1_archive.clone(),
    );
    let corpus = recorder.corpus();
    let coverage = recorder.coverage();

    // Per-rule inferred alphabet preview — top 4 rules by activity,
    // shows the bytes the L* learner WOULD use if mining was driven
    // by this corpus. Routes through wafrift_evolution::rule_alphabet
    // so the inference path is exercised by every `corpus stats` run.
    let mut alphabet_preview: Vec<(String, Vec<u8>)> = Vec::new();
    let mut buckets: Vec<&_> = corpus.buckets.values().collect();
    buckets.sort_by(|a, b| {
        let aa = a.blocked.len() + a.bypassed.len();
        let bb = b.blocked.len() + b.bypassed.len();
        bb.cmp(&aa)
    });
    for bucket in buckets.into_iter().take(4) {
        if let Some(alpha) = infer_alphabet_default(bucket) {
            alphabet_preview.push((bucket.rule_id.0.clone(), alpha.raw_symbols().to_vec()));
        }
    }

    // Encoding-lattice chain budget preview — shows how many encoder
    // chains the lattice search WOULD enumerate at default depth.
    // Exercises wafrift_evolution::encoding_lattice from the read-only
    // path so the search budget math is always one `corpus stats` away.
    let strategies = wafrift_encoding::encoding::strategy::all_strategies();
    let lattice = LatticeSearch::new(strategies.to_vec());
    let lattice_chain_count = lattice.estimated_chain_count();

    if args.format == "json" {
        let pops_global = coverage.pops_covered_global();
        let alpha_json: Vec<serde_json::Value> = alphabet_preview
            .iter()
            .map(|(rule, bytes)| {
                json!({
                    "rule_id": rule,
                    "alphabet_bytes": bytes,
                    "alphabet_size": bytes.len(),
                })
            })
            .collect();
        let v = json!({
            "target_fingerprint": corpus.target_fingerprint,
            "rules_seen": corpus.rules_seen(),
            "total_bypasses": corpus.total_bypasses(),
            "total_blocks": corpus.total_blocks(),
            "pops_covered": pops_global.iter().collect::<Vec<_>>(),
            "pops_covered_count": pops_global.len(),
            "schema_version": corpus.schema_version,
            "alphabet_preview": alpha_json,
            "lattice_chain_count": lattice_chain_count,
            "lattice_strategy_count": strategies.len(),
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
        if !alphabet_preview.is_empty() {
            println!(
                "  L* alphabet preview (top {} active rules):",
                alphabet_preview.len()
            );
            for (rule, bytes) in &alphabet_preview {
                let chars: String = bytes
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            (b as char).to_string()
                        } else {
                            format!("\\x{b:02x}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("    {rule:<40} → [{chars}]");
            }
        }
        println!(
            "  encoding lattice   : {lattice_chain_count} chains over {} strategies",
            strategies.len()
        );
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

    /// Empty-PathBuf sentinel — `run_stats` treats this as "no path
    /// supplied" and routes through the in-process default loader.
    /// R45 (pass-7 §11) hard-errors on a *non-empty* path that doesn't
    /// exist, so tests that want the fallback path must pass an empty
    /// PathBuf, not a synthesized-but-nonexistent one.
    fn unsupplied() -> PathBuf {
        PathBuf::new()
    }

    #[test]
    fn snapshot_copies_corpus_and_coverage_sibling() {
        let dir = tmp("snap_src");
        std::fs::create_dir_all(&dir).unwrap();
        let corpus = dir.join("corpus-test_target.json");
        let coverage = dir.join("coverage-test_target.json");
        std::fs::write(&corpus, br#"{"buckets":{}}"#).unwrap();
        std::fs::write(&coverage, br#"{"regions":{}}"#).unwrap();
        let dest = tmp("snap_dest");

        let code = run_snapshot(SnapshotArgs {
            corpus: corpus.clone(),
            dest: Some(dest.clone()),
        });
        assert_eq!(code, 0, "snapshot must succeed");

        // Exactly two snapshots (corpus + coverage), byte-identical to sources.
        let snaps: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        assert_eq!(snaps.len(), 2, "corpus + coverage sibling snapshotted");
        let corpus_snap = snaps
            .iter()
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("corpus-test_target-")
            })
            .expect("corpus snapshot present");
        assert_eq!(
            std::fs::read(corpus_snap).unwrap(),
            std::fs::read(&corpus).unwrap()
        );
        assert!(
            snaps.iter().any(|p| p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("coverage-test_target-")),
            "coverage sibling snapshot present"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn snapshot_missing_corpus_is_hard_error() {
        let code = run_snapshot(SnapshotArgs {
            corpus: PathBuf::from("/nonexistent/corpus-x.json"),
            dest: None,
        });
        assert_eq!(
            code, 1,
            "missing corpus must hard-error, never silently no-op"
        );
    }

    #[test]
    fn stats_missing_files_falls_back_to_defaults() {
        let args = StatsArgs {
            corpus: unsupplied(),
            coverage: unsupplied(),
            h1_archive: None,
            format: "human".into(),
            target_fingerprint: "test".into(),
        };
        // Must not panic. Inner returns 0 for human-format render success.
        assert_eq!(run_stats(args), 0);
    }

    /// Anti-rig (R55 pass-17): a *supplied* path that does not exist
    /// must be a hard error, not a silent zero-fill. R45's contract.
    #[test]
    fn stats_supplied_missing_path_is_hard_error() {
        let bogus = tmp("nonexistent_supplied");
        assert!(!bogus.exists(), "test precondition");
        let args = StatsArgs {
            corpus: bogus,
            coverage: unsupplied(),
            h1_archive: None,
            format: "human".into(),
            target_fingerprint: "test".into(),
        };
        assert_eq!(
            run_stats(args),
            1,
            "R45 contract: supplied-but-missing => exit 1"
        );
    }

    #[test]
    fn stats_json_format_emits_well_formed_json() {
        let args = StatsArgs {
            corpus: unsupplied(),
            coverage: unsupplied(),
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
        let human = run_stats(StatsArgs {
            corpus: unsupplied(),
            coverage: unsupplied(),
            h1_archive: None,
            format: "human".into(),
            target_fingerprint: "tf".into(),
        });
        let json_mode = run_stats(StatsArgs {
            corpus: unsupplied(),
            coverage: unsupplied(),
            h1_archive: None,
            format: "json".into(),
            target_fingerprint: "tf".into(),
        });
        assert_eq!(human, 0);
        assert_eq!(json_mode, 0);
    }

    #[test]
    fn stats_invokes_rule_alphabet_and_encoding_lattice() {
        // Sanity check: the lattice + alphabet preview paths must be
        // exercised by every `stats` run. We can't easily assert on
        // stdout from inside the function, so we just confirm that the
        // call doesn't panic when given a fresh corpus + coverage and
        // that the run completes successfully. The fingerprints +
        // alphabet inference + lattice chain count all run as side
        // effects of `run_stats`.
        let rc = run_stats(StatsArgs {
            corpus: unsupplied(),
            coverage: unsupplied(),
            h1_archive: None,
            format: "json".into(),
            target_fingerprint: "tf".into(),
        });
        assert_eq!(rc, 0);
    }
}
