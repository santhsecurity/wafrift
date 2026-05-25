//! End-to-end tests for `wafrift corpus stats`.
//!
//! `corpus stats` is fully offline — it reads a corpus JSON file and
//! an edge-POP coverage JSON file, both of which fall back to empty
//! defaults when missing. No HTTP, no mock server.
//!
//! Tests verify:
//! 1. `corpus --help` exits 0 and documents subcommands.
//! 2. `corpus` appears in top-level help.
//! 3. `corpus stats` exits 0 even with non-existent file paths (defaults).
//! 4. `corpus stats --format json` emits valid JSON with required fields.
//! 5. `corpus stats --format json` `rules_seen` is a non-negative integer.
//! 6. `corpus stats` (human format) emits human-readable summary text.
//! 7. `corpus stats --help` exits 0.

use std::process::Command;

fn wafrift(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wafrift"))
        .args(args)
        .output()
        .expect("spawn wafrift");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn nonexistent_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("wafrift_corpus_e2e_nonexistent_{suffix}.json"));
    // Ensure the file really doesn't exist.
    let _ = std::fs::remove_file(&p);
    p.to_str().expect("path is UTF-8").to_string()
}

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn corpus_help_documents_stats_subcommand() {
    let (code, stdout, _) = wafrift(&["corpus", "--help"]);
    assert_eq!(code, 0, "corpus --help must exit 0");
    assert!(stdout.contains("stats"), "must document stats subcommand: {stdout}");
}

#[test]
fn corpus_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("corpus"),
        "corpus must appear in top-level help: {stdout}"
    );
}

#[test]
fn corpus_stats_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["corpus", "stats", "--help"]);
    assert_eq!(code, 0, "corpus stats --help must exit 0");
}

// ── `corpus stats` ────────────────────────────────────────────────────────

#[test]
fn corpus_stats_exits_0_with_missing_files() {
    let corpus = nonexistent_path("corpus1");
    let coverage = nonexistent_path("coverage1");
    let (code, _stdout, stderr) =
        wafrift(&["corpus", "stats", "--corpus", &corpus, "--coverage", &coverage]);
    assert_eq!(
        code, 0,
        "corpus stats must exit 0 with missing files (load_or_default); stderr: {stderr}"
    );
}

#[test]
fn corpus_stats_json_emits_valid_json() {
    let corpus = nonexistent_path("corpus2");
    let coverage = nonexistent_path("coverage2");
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
    assert_eq!(code, 0, "corpus stats --format json must exit 0; stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("corpus stats --format json must emit valid JSON");

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
    let corpus = nonexistent_path("corpus3");
    let coverage = nonexistent_path("coverage3");
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
    let corpus = nonexistent_path("corpus4");
    let coverage = nonexistent_path("coverage4");
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
    let corpus = nonexistent_path("corpus5");
    let coverage = nonexistent_path("coverage5");
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
    let corpus = nonexistent_path("corpus6");
    let coverage = nonexistent_path("coverage6");
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
    assert_eq!(code, 0, "corpus stats with --target-fingerprint must exit 0; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    // The target_fingerprint field is set from the corpus (which falls back
    // to the default, not from the CLI flag when the file is missing).
    // Just confirm the command ran without error and emits the field.
    assert!(
        v["target_fingerprint"].is_string(),
        "target_fingerprint must be present: {v}"
    );
    // stdout is valid JSON; that alone proves the flag was accepted.
    let _ = stdout;
}
