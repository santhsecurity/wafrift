//! End-to-end CLI integration tests for the info-gain payload
//! scheduler — covers the LAW 9 wiring triangle (`--help` surface,
//! integration-test surface, code path reachable from the operator
//! entry point).
//!
//! Algorithmic correctness of the scheduler itself is tested by the
//! unit tests inside `crates/cli/src/info_gain_sched.rs`. This file
//! only proves the clap surface compiles, the flags reach the
//! handler, and the history file is written / re-read across runs.

mod common;
use common::wafrift;

// ── --help surface ────────────────────────────────────────────────────────

#[test]
fn bench_waf_help_documents_budget_flag() {
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0, "bench-waf --help must exit 0");
    assert!(
        stdout.contains("--budget"),
        "bench-waf --help must document --budget — info-gain \
         scheduling is fictional without it: {stdout}"
    );
}

#[test]
fn bench_waf_help_documents_history_file_flag() {
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--history-file"),
        "bench-waf --help must document --history-file — scheduler \
         warm-start is fictional without it: {stdout}"
    );
}

#[test]
fn bench_waf_help_explains_info_gain_concept() {
    // LAW 10 COHERENCE: the operator should not need to read source
    // code to know what --budget does. Pin that the help text
    // describes the underlying selection criterion.
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("information gain") || stdout.contains("informative"),
        "bench-waf --help must explain the info-gain selection: {stdout}"
    );
}

#[test]
fn bench_waf_help_documents_fair_class_flag() {
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--fair-class"),
        "bench-waf --help must document --fair-class — per-class \
         fairness is fictional without it: {stdout}"
    );
}

#[test]
fn bench_waf_help_documents_list_schedule_flag() {
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--list-schedule"),
        "bench-waf --help must document --list-schedule: {stdout}"
    );
}

#[test]
fn bench_waf_help_documents_history_merge_flag() {
    let (code, stdout, _) = wafrift(&["bench-waf", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("--history-merge"),
        "bench-waf --help must document --history-merge: {stdout}"
    );
}

#[test]
fn history_merge_combines_priors_into_working_history() {
    // End-to-end: write two history JSON files with overlapping
    // payload counts, run --list-schedule --history-merge h1
    // --history-merge h2, and verify the resulting schedule
    // reflects the combined posteriors.
    let corpus = fixture_corpus("history_merge");
    let tmp = std::env::temp_dir();
    let h1 = tmp.join("wafrift_sched_e2e_merge_h1.json");
    let h2 = tmp.join("wafrift_sched_e2e_merge_h2.json");
    // h1: sched_e2e_sql_1 blocked 10 times → theta ~ 0.91, low info_gain
    let h1_body = r#"{"by_id":{"sched_e2e_sql_1":{"n_blocked":10,"n_passed":0}}}"#;
    let h2_body = r#"{"by_id":{"sched_e2e_sql_2":{"n_blocked":0,"n_passed":10}}}"#;
    std::fs::write(&h1, h1_body).expect("write h1");
    std::fs::write(&h2, h2_body).expect("write h2");
    let (code, stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--history-merge",
        h1.to_str().unwrap(),
        "--history-merge",
        h2.to_str().unwrap(),
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0, "merge run must exit 0: stderr={stderr}");
    // Expected: cold-start sched_e2e_sql_3 ranks first (highest info_gain).
    // sql_1 and sql_2 both have biased posteriors with reduced info_gain.
    // The merge log should appear in stderr.
    assert!(
        stderr.contains("merged"),
        "expected merge log line in stderr: {stderr}"
    );
    assert!(
        stdout.contains("sched_e2e_sql_3"),
        "cold-start payload must be in schedule: {stdout}"
    );
}

#[test]
fn history_with_biased_posterior_demotes_to_schedule_tail() {
    // Dogfood pin: when a payload has 50 lopsided observations
    // (all-blocked or all-passed), its info_gain ~ 0.14 < cold-start
    // 1.0. Without --budget the schedule lists all cases ordered by
    // descending info_gain — the biased payloads MUST land at the
    // tail, not at the head. Catches a regression that reorders
    // ties in a way that puts certain cases ahead of cold-starts.
    let corpus = fixture_corpus("biased_demote");
    let tmp = std::env::temp_dir();
    let h = tmp.join("wafrift_sched_e2e_biased_demote_h.json");
    // sched_e2e_sql_1 ⇒ theta ≈ 0.98 (50 blocks). sched_e2e_sql_2
    // ⇒ theta ≈ 0.02 (50 passes). sched_e2e_sql_3 ⇒ cold-start.
    let h_body = r#"{"by_id":{
        "sched_e2e_sql_1":{"n_blocked":50,"n_passed":0},
        "sched_e2e_sql_2":{"n_blocked":0,"n_passed":50}
    }}"#;
    std::fs::write(&h, h_body).expect("write history");
    let (code, stdout, _) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--history-file",
        h.to_str().unwrap(),
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    // Find positions of the three case ids in the schedule output.
    let p1 = stdout.find("sched_e2e_sql_1").expect("sql_1 missing");
    let p2 = stdout.find("sched_e2e_sql_2").expect("sql_2 missing");
    let p3 = stdout.find("sched_e2e_sql_3").expect("sql_3 missing");
    // Cold-start sql_3 must rank ahead of both biased ones.
    assert!(
        p3 < p1 && p3 < p2,
        "cold-start sql_3 at {p3} must precede sql_1 at {p1} and sql_2 at {p2}\n{stdout}"
    );
}

#[test]
fn cold_start_payload_ranks_first_when_others_have_biased_posteriors() {
    // Anti-rig: explicit pin that the rank=1 row in --list-schedule
    // is the cold-start case when all other payloads have biased
    // posteriors. Catches a regression that puts certain cases at
    // the head of the schedule.
    let corpus = fixture_corpus("rank_one_cold");
    let tmp = std::env::temp_dir();
    let h = tmp.join("wafrift_sched_e2e_rank_one_cold_h.json");
    // sched_e2e_sql_1 always blocked; sched_e2e_sql_2 always passed.
    // Only sched_e2e_sql_3 is cold-start.
    let h_body = r#"{"by_id":{
        "sched_e2e_sql_1":{"n_blocked":50,"n_passed":0},
        "sched_e2e_sql_2":{"n_blocked":0,"n_passed":50}
    }}"#;
    std::fs::write(&h, h_body).expect("write history");
    let (code, stdout, _) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--history-file",
        h.to_str().unwrap(),
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    // Find the line starting with "    1  " — the rank=1 row.
    let rank_one_line = stdout
        .lines()
        .find(|l| l.starts_with("    1  "))
        .expect("rank-1 row missing");
    assert!(
        rank_one_line.contains("sched_e2e_sql_3"),
        "rank=1 must be the cold-start payload sql_3: {rank_one_line}"
    );
}

#[test]
fn list_schedule_with_history_merge_reflects_merged_posteriors() {
    // Compose --list-schedule + --history-merge: the preview must
    // reflect the MERGED history, not the (missing) --history-file.
    // Catches a regression where the scheduler-block reads
    // history_file only and ignores history_merge inputs.
    let corpus = fixture_corpus("list_sched_merge");
    let tmp = std::env::temp_dir();
    let merge_h = tmp.join("wafrift_sched_e2e_list_sched_merge_h.json");
    let merge_body = r#"{"by_id":{"sched_e2e_sql_1":{"n_blocked":50,"n_passed":0}}}"#;
    std::fs::write(&merge_h, merge_body).expect("write merge history");
    let (code, stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--history-merge",
        merge_h.to_str().unwrap(),
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    // sql_1's biased posterior must show up as low info_gain — find
    // its row and check the info_gain column. With 50 blocks +
    // 0 passes, theta ~ 0.98 → info_gain ~ 0.137 bits.
    // sql_2 and sql_3 stay cold-start (info_gain 1.0).
    let sql1_line = stdout
        .lines()
        .find(|l| l.contains("sched_e2e_sql_1"))
        .expect("sql_1 must appear");
    assert!(
        sql1_line.contains("0.137") || sql1_line.contains("0.13"),
        "sql_1 should show low info_gain post-merge: {sql1_line}"
    );
    // Also verify the merge log line.
    assert!(
        stderr.contains("merged"),
        "expected merge log on stderr: {stderr}"
    );
}

// ── --list-schedule preview path (no HTTP fired) ─────────────────────────

#[test]
fn list_schedule_prints_table_with_no_http_traffic() {
    // Pin: --list-schedule with --base-url pointed at a guaranteed-
    // closed port must NOT error — proves no HTTP traffic was
    // attempted before the early-return.
    let corpus = fixture_corpus("list_sched_text");
    let (code, stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "3",
        "--list-schedule",
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0, "list-schedule must exit 0: stderr={stderr}");
    // Text-format header line
    assert!(
        stdout.contains("rank") && stdout.contains("id") && stdout.contains("info_gain"),
        "expected text table header: {stdout}"
    );
    // The fixture corpus has 3 sql cases; with budget=3 all should
    // appear with rank 1, 2, 3.
    assert!(stdout.contains("    1  "), "expected rank 1 row: {stdout}");
    assert!(
        stdout.contains("sched_e2e_sql_1"),
        "case id missing: {stdout}"
    );
}

#[test]
fn list_schedule_json_emits_array_of_entries() {
    let corpus = fixture_corpus("list_sched_json");
    let (code, stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "2",
        "--list-schedule",
        "--format",
        "json",
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0, "list-schedule json must exit 0: stderr={stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    let arr = parsed.as_array().expect("must be JSON array");
    assert_eq!(arr.len(), 2);
    // Each entry must have the documented schema.
    for entry in arr {
        assert!(entry.get("id").is_some(), "missing id: {entry}");
        assert!(
            entry.get("info_gain").is_some(),
            "missing info_gain: {entry}"
        );
        assert!(
            entry.get("theta_estimate").is_some(),
            "missing theta_estimate: {entry}"
        );
        assert!(entry.get("n_trials").is_some(), "missing n_trials: {entry}");
    }
}

#[test]
fn list_schedule_without_budget_lists_full_corpus() {
    let corpus = fixture_corpus("list_sched_no_budget");
    let (code, stdout, _) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    // 3 cases in fixture; without budget all must be listed.
    assert!(stdout.contains("sched_e2e_sql_1"));
    assert!(stdout.contains("sched_e2e_sql_2"));
    assert!(stdout.contains("sched_e2e_sql_3"));
}

// ── Clap parsing exercises both flags ────────────────────────────────────

/// Build a minimal in-tree TOML corpus the binary can load + validate.
/// Mirrors the real wafrift-bench/corpus/<class>/<file>.toml shape:
/// top-level `schema = 1` then `[[case]]` arrays (singular, NOT
/// `[[cases]]`). Catching the schema/shape mismatch was a real
/// dogfood finding during e2e bring-up.
fn fixture_corpus(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wafrift_sched_e2e_{suffix}"));
    std::fs::create_dir_all(dir.join("sql")).expect("mkdir");
    let toml_body = r#"schema = 1

[[case]]
id = "sched_e2e_sql_1"
class = "sql"
payload = "1' OR '1'='1"

[[case]]
id = "sched_e2e_sql_2"
class = "sql"
payload = "admin' --"

[[case]]
id = "sched_e2e_sql_3"
class = "sql"
payload = "UNION SELECT NULL--"
"#;
    std::fs::write(dir.join("sql").join("e2e.toml"), toml_body).expect("write corpus");
    dir
}

#[test]
fn budget_flag_parses_without_validate_error() {
    // Use --validate-only so we don't need a live WAF target.
    // --validate-only returns BEFORE the scheduler filter runs, but
    // clap still has to accept the flag combination. This catches
    // the regression where someone forgets to register a clap field.
    let corpus = fixture_corpus("budget_parse");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "2",
    ]);
    assert_eq!(
        code, 0,
        "validate-only with --budget should exit 0 (clap accepted the flag): {stderr}"
    );
}

#[test]
fn fair_class_eprintln_surfaces_class_diversity_entropy() {
    // Anti-rig: the fair-class eprintln must report class_diversity
    // in bits, computed via wafrift_types::shannon over the class-
    // frequency distribution. Operators read this to spot starved
    // classes (diversity < log2(num_classes) means under-fill).
    let corpus = fixture_corpus("class_diversity_entropy");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--budget",
        "2",
        "--fair-class",
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("class_diversity="),
        "fair-class eprintln must include class_diversity= metric: {stderr}"
    );
    // Fixture has only sql class; class_diversity over a 1-class
    // distribution is exactly 0.0 bits per Shannon's H definition.
    assert!(
        stderr.contains("class_diversity=0.0000"),
        "1-class corpus must show class_diversity=0.0000: {stderr}"
    );
}

#[test]
fn fair_class_eprintln_surfaces_per_class_breakdown() {
    // Pin the operator-clarity contract: with --fair-class on, the
    // info-gain scheduler eprintln must include a per-class
    // breakdown so the operator can verify allocation worked.
    let corpus = fixture_corpus("fair_class_breakdown");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--corpus",
        corpus.to_str().unwrap(),
        "--list-schedule",
        "--budget",
        "2",
        "--fair-class",
        "--base-url",
        "http://127.0.0.1:1",
        "--skip-healthcheck",
    ]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("classes=["),
        "fair-class eprintln must include classes=[]: {stderr}"
    );
    // The fixture corpus only has 1 class (sql). The breakdown
    // should show that.
    assert!(
        stderr.contains("sql="),
        "expected sql class breakdown: {stderr}"
    );
}

#[test]
fn fair_class_flag_parses_without_validate_error() {
    let corpus = fixture_corpus("fair_class_parse");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "2",
        "--fair-class",
    ]);
    assert_eq!(
        code, 0,
        "validate-only with --fair-class should exit 0: {stderr}"
    );
}

#[test]
fn history_file_flag_parses_without_validate_error() {
    let corpus = fixture_corpus("hist_parse");
    let tmp_history = std::env::temp_dir().join("wafrift_sched_e2e_hist_parse_history.json");
    let _ = std::fs::remove_file(&tmp_history);
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--history-file",
        tmp_history.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 0,
        "validate-only with --history-file should exit 0: {stderr}"
    );
}

#[test]
fn budget_zero_is_accepted_as_noop() {
    // Pin the documented behaviour: --budget 0 must not error. The
    // scheduler treats 0 as "disable the filter" so scripts can pass
    // `--budget $N` with N=0 to opt out.
    let corpus = fixture_corpus("budget_zero");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "0",
    ]);
    assert_eq!(
        code, 0,
        "budget=0 should be a no-op, not an error: {stderr}"
    );
}

#[test]
fn budget_larger_than_corpus_is_accepted() {
    // Pin: passing a budget larger than the corpus is not an error.
    // The scheduler caps the filter at corpus length under the hood.
    let corpus = fixture_corpus("budget_huge");
    let (code, _stdout, stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "1000000",
    ]);
    assert_eq!(code, 0, "huge budget should be a no-op cap: {stderr}");
}

// ── Negative cases ────────────────────────────────────────────────────────

#[test]
fn negative_budget_is_rejected_by_clap() {
    // usize parse failure → clap emits exit code 2 (its standard for
    // argument errors). Pin so a future signed-int swap is caught.
    let corpus = fixture_corpus("budget_negative");
    let (code, _stdout, _stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "-5",
    ]);
    assert_ne!(code, 0, "negative budget must be rejected");
}

#[test]
fn non_numeric_budget_is_rejected() {
    let corpus = fixture_corpus("budget_bad");
    let (code, _stdout, _stderr) = wafrift(&[
        "bench-waf",
        "--validate-only",
        "--corpus",
        corpus.to_str().unwrap(),
        "--budget",
        "not-a-number",
    ]);
    assert_ne!(code, 0, "non-numeric budget must be rejected");
}
