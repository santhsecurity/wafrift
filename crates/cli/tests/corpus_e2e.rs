//! End-to-end tests for `wafrift corpus stats`.
//!
//! `corpus stats` is fully offline — it reads a corpus JSON file and
//! an edge-POP coverage JSON file. R45 hardened the missing-file path
//! to a hard error (anti-rig: silently loading defaults masked CI
//! regressions); tests that exercise the JSON output use real empty
//! corpus / coverage files via [`valid_empty_corpus_path`].
//!
//! Tests verify:
//! 1. `corpus --help` exits 0 and documents subcommands.
//! 2. `corpus` appears in top-level help.
//! 3. `corpus stats` with explicit nonexistent paths exits 1 (R45 anti-rig).
//! 4. `corpus stats --format json` emits valid JSON with required fields.
//! 5. `corpus stats --format json` `rules_seen` is a non-negative integer.
//! 6. `corpus stats` (human format) emits human-readable summary text.
//! 7. `corpus stats --help` exits 0.

mod common;
use common::wafrift;

fn nonexistent_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_corpus_e2e_nonexistent_{suffix}.json"));
    // Ensure the file really doesn't exist.
    let _ = std::fs::remove_file(&p);
    p.to_str().expect("path is UTF-8").to_string()
}

/// Write an empty (default-shaped) corpus JSON to a unique temp path
/// and return its absolute path. The CLI's corpus loader accepts this
/// as a valid empty corpus — exercises the JSON-output code paths
/// without rigging the R45 missing-file check.
fn valid_empty_corpus_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_corpus_e2e_empty_corpus_{suffix}.json"));
    std::fs::write(&p, "{}").expect("write empty corpus json");
    p.to_str().expect("path is UTF-8").to_string()
}

/// Write an empty edge-POP coverage JSON file and return its path.
fn valid_empty_coverage_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_corpus_e2e_empty_coverage_{suffix}.json"));
    std::fs::write(&p, "{}").expect("write empty coverage json");
    p.to_str().expect("path is UTF-8").to_string()
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn corpus_help_documents_stats_subcommand() {
    let (code, stdout, _) = wafrift(&["corpus", "--help"]);
    assert_eq!(code, 0, "corpus --help must exit 0");
    assert!(
        stdout.contains("stats"),
        "must document stats subcommand: {stdout}"
    );
}

// Surface reduction: corpus is dev/QA tooling hidden from the user-facing menu (LAW 2 —
// the command still runs, just not advertised at the top level).
#[test]
fn corpus_hidden_from_menu_but_still_runs() {
    // Must NOT appear in the top-level command listing (hidden dev tool).
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\n  corpus"),
        "corpus must be hidden from top-level help (dev/QA tooling): {stdout}"
    );

    // Must still be invokable — LAW 2 backwards compat.
    let (sub_code, sub_stdout, _) = wafrift(&["corpus", "--help"]);
    assert_eq!(
        sub_code, 0,
        "corpus --help must exit 0 (still runnable): {sub_stdout}"
    );
}

#[test]
fn corpus_stats_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["corpus", "stats", "--help"]);
    assert_eq!(code, 0, "corpus stats --help must exit 0");
}

// ── `corpus stats` ────────────────────────────────────────────────────────

/// LAW 12 anti-rig: explicitly-supplied nonexistent --corpus path is
/// a HARD ERROR (exit 1). The previous load_or_default behavior
/// silently let CI gates pass on missing artifacts, masking regressions.
#[test]
fn corpus_stats_explicit_nonexistent_corpus_exits_1_anti_rig() {
    let corpus = nonexistent_path("corpus1");
    let coverage = valid_empty_coverage_path("anti_rig_corpus");
    let (code, _stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
    ]);
    assert_eq!(code, 1, "missing --corpus must exit 1, not silently zero");
    assert!(
        stderr.contains("does not exist"),
        "stderr must explain the failure: {stderr}"
    );
}

#[test]
fn corpus_stats_explicit_nonexistent_coverage_exits_1_anti_rig() {
    let corpus = valid_empty_corpus_path("anti_rig_coverage");
    let coverage = nonexistent_path("coverage1");
    let (code, _stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
    ]);
    assert_eq!(code, 1, "missing --coverage must exit 1, not silently zero");
    assert!(
        stderr.contains("does not exist"),
        "stderr must explain the failure: {stderr}"
    );
}

/// Empty corpus + coverage files are valid input — exit 0.
#[test]
fn corpus_stats_exits_0_with_empty_files() {
    let corpus = valid_empty_corpus_path("exit0");
    let coverage = valid_empty_coverage_path("exit0");
    let (code, _stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
    ]);
    assert_eq!(
        code, 0,
        "corpus stats with empty files must exit 0; stderr: {stderr}"
    );
}

#[test]
fn corpus_stats_json_emits_valid_json() {
    let corpus = valid_empty_corpus_path("json");
    let coverage = valid_empty_coverage_path("json");
    let (code, stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "corpus stats --format json must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("corpus stats --format json must emit valid JSON");

    // Required fields from the JSON output path in corpus_cmd.rs.
    assert!(
        v["rules_seen"].is_number(),
        "rules_seen must be a number: {v}"
    );
    assert!(
        v["total_bypasses"].is_number(),
        "total_bypasses must be a number: {v}"
    );
    assert!(
        v["total_blocks"].is_number(),
        "total_blocks must be a number: {v}"
    );
    assert!(
        v["pops_covered"].is_array(),
        "pops_covered must be an array: {v}"
    );
    assert!(
        v["pops_covered_count"].is_number(),
        "pops_covered_count must be a number: {v}"
    );
    assert!(
        v["schema_version"].is_number(),
        "schema_version must be a number: {v}"
    );
    assert!(
        v["target_fingerprint"].is_string(),
        "target_fingerprint must be a string: {v}"
    );
    assert!(
        v["lattice_chain_count"].is_number(),
        "lattice_chain_count must be a number: {v}"
    );
    assert!(
        v["lattice_strategy_count"].is_number(),
        "lattice_strategy_count must be a number: {v}"
    );
    assert!(
        v["alphabet_preview"].is_array(),
        "alphabet_preview must be an array: {v}"
    );
}

#[test]
fn corpus_stats_json_rules_seen_is_nonnegative() {
    let corpus = valid_empty_corpus_path("rules_seen");
    let coverage = valid_empty_coverage_path("rules_seen");
    let (code, stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "corpus stats must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let rules_seen = v["rules_seen"].as_u64().expect("rules_seen must be u64");
    // Empty corpus → 0 rules seen.
    assert_eq!(rules_seen, 0, "empty corpus must have rules_seen=0: {v}");
}

#[test]
fn corpus_stats_json_lattice_chain_count_is_positive() {
    let corpus = valid_empty_corpus_path("lattice");
    let coverage = valid_empty_coverage_path("lattice");
    let (code, stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "corpus stats must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let chain_count = v["lattice_chain_count"].as_u64().unwrap_or(0);
    assert!(
        chain_count > 0,
        "lattice_chain_count must be > 0 (encoding lattice is never empty): {v}"
    );
}

#[test]
fn corpus_stats_human_format_emits_summary_text() {
    let corpus = valid_empty_corpus_path("human");
    let coverage = valid_empty_coverage_path("human");
    let (code, stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
    ]);
    assert_eq!(code, 0, "corpus stats must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("rules seen") || stdout.contains("wafrift corpus"),
        "human format must emit summary text: {stdout}"
    );
}

#[test]
fn corpus_stats_target_fingerprint_flag_accepted() {
    let corpus = valid_empty_corpus_path("target_fp");
    let coverage = valid_empty_coverage_path("target_fp");
    let (code, stdout, stderr) = wafrift(&[
        "corpus",
        "stats",
        "--corpus",
        &corpus,
        "--coverage",
        &coverage,
        "--target-fingerprint",
        "test-fingerprint-abc123",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "corpus stats with --target-fingerprint must exit 0; stderr: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        v["target_fingerprint"].is_string(),
        "target_fingerprint must be present: {v}"
    );
    let _ = stdout;
}
