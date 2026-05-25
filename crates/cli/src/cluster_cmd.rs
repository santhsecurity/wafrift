//! `wafrift cluster` — offline bypass clustering by root cause.
//!
//! Reads a `wafrift bench-waf --output bypasses.json` file and groups the
//! bypass records by three axes:
//!
//! 1. **`rule_id`** — WAF rule that *would* have blocked the raw payload
//!    (extracted from the bench result's `id` field, which encodes class and
//!    sequence number, e.g. `sql_blind_001`). If the bench JSON carries an
//!    explicit `rule_id` field per result we use that; otherwise we fall back
//!    to the `class` field (e.g. `sql`, `xss`).
//! 2. **Payload class** — the attack class from the corpus case (`sql`, `xss`,
//!    `cmdi`, …).
//! 3. **Edit-distance similarity** — within each (rule_id × class) bucket,
//!    bypasses are further sub-grouped by Levenshtein distance from a
//!    representative payload chosen as the shortest member. Two bypasses join
//!    the same sub-cluster when their normalized edit distance is ≤
//!    `--edit-threshold` (default 0.5).
//!
//! ## Input schema
//!
//! The input JSON is the `--output` blob from `bench-waf`. We read the
//! top-level `results` array. Each element has:
//!
//! ```json
//! {
//!   "id":        "sql_blind_001",
//!   "class":     "sql",
//!   "evaded": {
//!     "bypass_techniques": ["tamper/comment_strip", "..."],
//!     "variants_bypassed": 2,
//!     "variants_total": 5
//!   }
//! }
//! ```
//!
//! For clustering purposes the "bypass payload" is reconstructed from the
//! case `id` and the `bypass_techniques` list (the actual wire payload is
//! not stored in the summary JSON — only the technique names are). Sub-
//! clustering by edit distance therefore operates on the technique-list
//! joined as a string, which is a faithful proxy for payload similarity.
//!
//! ## Output
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "edit_threshold": 0.5,
//!   "total_bypasses": 12,
//!   "clusters": [
//!     {
//!       "rule_id":        "sql",
//!       "payload_class":  "sql",
//!       "representative": "tamper/comment_strip,encoding/url/double",
//!       "member_count":   3,
//!       "members": ["tamper/comment_strip,...", "..."]
//!     }
//!   ]
//! }
//! ```

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use colored::Colorize;
use serde::Serialize;
#[cfg(test)]
use serde::Deserialize;
use serde_json::Value;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ClusterArgs {
    /// Path to a `wafrift bench-waf --output <FILE>` JSON result.
    /// Pass `-` to read from stdin.
    #[arg(value_name = "FILE")]
    pub input: PathBuf,

    /// Normalized Levenshtein distance threshold (0.0–1.0).
    /// Two bypasses join the same sub-cluster when their distance is ≤ this
    /// value. 0.0 = exact match only; 1.0 = one giant cluster.
    #[arg(long, default_value_t = 0.5)]
    pub edit_threshold: f64,

    /// Output format: `text` (default) prints a human-readable tree;
    /// `json` emits the structured cluster blob.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

// ─── Internal types ───────────────────────────────────────────────────────────

/// A single bypass record extracted from the bench result.
#[derive(Debug, Clone)]
pub(crate) struct BypassRecord {
    rule_id: String,
    payload_class: String,
    /// Technique-list joined into a string — used as the edit-distance key.
    technique_sig: String,
}

/// One cluster in the output.
#[derive(Debug, Serialize)]
pub struct Cluster {
    pub rule_id: String,
    pub payload_class: String,
    /// The shortest (most readable) technique signature in the group.
    pub representative: String,
    pub member_count: usize,
    pub members: Vec<String>,
}

/// Top-level output.
#[derive(Debug, Serialize)]
struct ClusterOutput {
    schema_version: u32,
    edit_threshold: f64,
    total_bypasses: usize,
    clusters: Vec<Cluster>,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn run_cluster(args: ClusterArgs) -> ExitCode {
    // Read input.
    let raw = if args.input.as_os_str() == "-" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("{} read stdin: {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read_to_string(&args.input) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} read {}: {e}",
                    "error:".red().bold(),
                    args.input.display()
                );
                return ExitCode::from(1);
            }
        }
    };

    let json: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} parse JSON: {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };

    let records = match extract_bypass_records(&json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            return ExitCode::from(1);
        }
    };

    if records.is_empty() {
        let out = ClusterOutput {
            schema_version: 1,
            edit_threshold: args.edit_threshold,
            total_bypasses: 0,
            clusters: vec![],
        };
        print_output(&out, &args.format);
        return ExitCode::SUCCESS;
    }

    let clusters = cluster_records(&records, args.edit_threshold);
    let out = ClusterOutput {
        schema_version: 1,
        edit_threshold: args.edit_threshold,
        total_bypasses: records.len(),
        clusters,
    };

    print_output(&out, &args.format);
    ExitCode::SUCCESS
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Extract one `BypassRecord` per bypass technique entry from the bench JSON.
///
/// A bench result has one entry per corpus *case*; each case may have had
/// multiple bypasses (multiple technique variants). We explode each bypass
/// technique entry into its own `BypassRecord` so clustering operates on
/// individual bypass observations rather than per-case summaries.
fn extract_bypass_records(json: &Value) -> Result<Vec<BypassRecord>, String> {
    let results = json
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("JSON has no 'results' array — is this a bench-waf --output file?")?;

    let mut records = Vec::new();
    for result in results {
        let id = result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let class = result
            .get("class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Prefer an explicit `rule_id` field; fall back to `class`.
        let rule_id = result
            .get("rule_id")
            .and_then(|v| v.as_str())
            .unwrap_or(class)
            .to_string();

        let evaded = match result.get("evaded") {
            Some(Value::Object(m)) => m,
            _ => continue, // no evade data → case had no bypass
        };

        let bypassed = evaded
            .get("variants_bypassed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if bypassed == 0 {
            continue;
        }

        let techniques: Vec<String> = evaded
            .get("bypass_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        if techniques.is_empty() {
            // Evaded but no technique names logged — still record it with
            // the case id as the technique signature so it doesn't vanish.
            records.push(BypassRecord {
                rule_id: rule_id.clone(),
                payload_class: class.to_string(),
                technique_sig: id.to_string(),
            });
        } else {
            // Explode: one record per technique entry.
            for tech in &techniques {
                records.push(BypassRecord {
                    rule_id: rule_id.clone(),
                    payload_class: class.to_string(),
                    technique_sig: tech.clone(),
                });
            }
        }
    }

    Ok(records)
}

// ─── Clustering ──────────────────────────────────────────────────────────────

/// Group `records` into clusters using a two-level approach:
/// 1. Hard partition by `(rule_id, payload_class)`.
/// 2. Within each partition, greedy single-linkage by normalized edit distance.
pub fn cluster_records(records: &[BypassRecord], threshold: f64) -> Vec<Cluster> {
    // Group by (rule_id, payload_class).
    let mut buckets: HashMap<(String, String), Vec<String>> = HashMap::new();
    for rec in records {
        buckets
            .entry((rec.rule_id.clone(), rec.payload_class.clone()))
            .or_default()
            .push(rec.technique_sig.clone());
    }

    let mut clusters: Vec<Cluster> = Vec::new();

    // Sort bucket keys for deterministic output.
    let mut keys: Vec<(String, String)> = buckets.keys().cloned().collect();
    keys.sort();

    for key in keys {
        let sigs = buckets.remove(&key).unwrap_or_default();
        let (rule_id, payload_class) = key;

        let sub = sub_cluster(sigs, threshold);
        for members in sub {
            // Pick the shortest member as the representative.
            let representative = members
                .iter()
                .min_by_key(|s| s.len())
                .cloned()
                .unwrap_or_default();
            clusters.push(Cluster {
                rule_id: rule_id.clone(),
                payload_class: payload_class.clone(),
                member_count: members.len(),
                representative,
                members,
            });
        }
    }

    // Sort clusters: largest first, then by rule_id for stability.
    clusters.sort_by(|a, b| {
        b.member_count
            .cmp(&a.member_count)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    clusters
}

/// Greedy single-linkage clustering within one (rule_id × class) bucket.
///
/// O(n²) in the worst case — acceptable for the cluster sizes we expect from
/// a bench run (rarely > a few hundred bypasses per class).
fn sub_cluster(mut sigs: Vec<String>, threshold: f64) -> Vec<Vec<String>> {
    let mut clusters: Vec<Vec<String>> = Vec::new();

    'outer: for sig in sigs.drain(..) {
        for cluster in &mut clusters {
            let rep = &cluster[0];
            if normalized_levenshtein(rep, &sig) <= threshold {
                cluster.push(sig);
                continue 'outer;
            }
        }
        clusters.push(vec![sig]);
    }

    clusters
}

/// Normalized Levenshtein distance in `[0.0, 1.0]`.
///
/// `0.0` = identical strings; `1.0` = maximally dissimilar (edit distance
/// equals the longer string's length). Both empty → `0.0`.
pub fn normalized_levenshtein(a: &str, b: &str) -> f64 {
    if a == b {
        return 0.0;
    }
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return 0.0;
    }
    let dist = levenshtein(a, b);
    dist as f64 / max_len as f64
}

/// Classic byte-level Levenshtein distance.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<u8> = a.bytes().collect();
    let b: Vec<u8> = b.bytes().collect();
    let m = a.len();
    let n = b.len();

    // Use a rolling two-row DP to keep memory O(n).
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn print_output(out: &ClusterOutput, format: &str) {
    if format == "json" {
        match serde_json::to_string_pretty(out) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("{} serialize: {e}", "error:".red()),
        }
        return;
    }

    // Text mode.
    println!(
        "{} {} bypass(es) → {} cluster(s)  (edit_threshold={:.2})",
        "[wafrift cluster]".bright_cyan().bold(),
        out.total_bypasses.to_string().bright_white(),
        out.clusters.len().to_string().bright_white(),
        out.edit_threshold,
    );
    for (i, c) in out.clusters.iter().enumerate() {
        println!(
            "  {}. rule_id={} class={} members={} representative={}",
            i + 1,
            c.rule_id.bright_yellow(),
            c.payload_class,
            c.member_count.to_string().bright_green(),
            c.representative.dimmed(),
        );
    }
}

// ─── Deserialize helpers (test-only roundtrip types) ─────────────────────────

/// Deserializable mirror of [`ClusterOutput`] for test roundtrips.
#[cfg(test)]
#[derive(Deserialize)]
pub(crate) struct ClusterOutputDeser {
    pub schema_version: u32,
    pub edit_threshold: f64,
    pub total_bypasses: usize,
    pub clusters: Vec<ClusterDeser>,
}

/// Deserializable mirror of [`Cluster`] for test roundtrips.
#[cfg(test)]
#[derive(Deserialize)]
pub(crate) struct ClusterDeser {
    pub rule_id: String,
    pub payload_class: String,
    pub representative: String,
    pub member_count: usize,
    pub members: Vec<String>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_result(id: &str, class: &str, bypassed: u64, techs: &[&str]) -> Value {
        json!({
            "id": id,
            "class": class,
            "evaded": {
                "variants_bypassed": bypassed,
                "variants_total": bypassed + 1,
                "bypass_techniques": techs,
            }
        })
    }

    fn bench_json(results: Vec<Value>) -> Value {
        json!({ "schema_version": 1, "results": results })
    }

    // ── Test 1: empty input yields 0 clusters ─────────────────────────────

    #[test]
    fn empty_results_array() {
        let j = bench_json(vec![]);
        let records = extract_bypass_records(&j).unwrap();
        assert!(records.is_empty());
        let clusters = cluster_records(&records, 0.5);
        assert!(clusters.is_empty());
    }

    // ── Test 2: single class → all in one top-level bucket ───────────────

    #[test]
    fn single_class_corpus() {
        let j = bench_json(vec![
            make_result("sql_001", "sql", 1, &["tamper/comment"]),
            make_result("sql_002", "sql", 1, &["tamper/comment"]),
        ]);
        let records = extract_bypass_records(&j).unwrap();
        assert_eq!(records.len(), 2);
        let clusters = cluster_records(&records, 0.5);
        // Both share the identical technique sig → 1 cluster.
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].member_count, 2);
    }

    // ── Test 3: mixed rule_ids produce separate top-level clusters ────────

    #[test]
    fn mixed_rule_ids() {
        let j = bench_json(vec![
            make_result("sql_001", "sql", 1, &["tamper/comment"]),
            make_result("xss_001", "xss", 1, &["tamper/html_entity"]),
        ]);
        let records = extract_bypass_records(&j).unwrap();
        assert_eq!(records.len(), 2);
        let clusters = cluster_records(&records, 0.5);
        // Two distinct (rule_id × class) buckets → 2 clusters (each a singleton).
        assert_eq!(clusters.len(), 2);
    }

    // ── Test 4: edit-distance threshold = 0.0 → exact-match only ─────────

    #[test]
    fn edit_threshold_zero_exact_match_only() {
        let sigs = vec![
            "tamper/comment".to_string(),
            "tamper/commentX".to_string(),
        ];
        let clusters = sub_cluster(sigs, 0.0);
        // Distance is non-zero → 2 separate singletons.
        assert_eq!(clusters.len(), 2);
    }

    // ── Test 5: edit-distance threshold = 1.0 → one giant cluster ────────

    #[test]
    fn edit_threshold_one_all_together() {
        let sigs: Vec<String> = vec!["aaa", "bbb", "ccc", "zzz"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let clusters = sub_cluster(sigs, 1.0);
        // All within distance 1.0 of the first (normalized Lev ≤ 1.0 always).
        assert_eq!(clusters.len(), 1);
    }

    // ── Test 6: JSON output schema fields (round-trip via ClusterOutputDeser) ──

    #[test]
    fn json_output_schema() {
        let j = bench_json(vec![make_result("sql_001", "sql", 2, &["tamper/a", "tamper/b"])]);
        let records = extract_bypass_records(&j).unwrap();
        let clusters = cluster_records(&records, 0.5);
        let out = ClusterOutput {
            schema_version: 1,
            edit_threshold: 0.5,
            total_bypasses: records.len(),
            clusters,
        };
        let s = serde_json::to_string(&out).unwrap();
        // Deserialize via the public ClusterOutputDeser to exercise the type.
        let deser: ClusterOutputDeser = serde_json::from_str(&s).unwrap();
        assert_eq!(deser.schema_version, 1);
        assert!(!deser.clusters.is_empty());
        assert!(deser.total_bypasses > 0);
        // Verify cluster fields via ClusterDeser.
        let first: &ClusterDeser = &deser.clusters[0];
        assert!(!first.rule_id.is_empty());
        assert!(!first.payload_class.is_empty());
        assert!(first.member_count > 0);
    }

    // ── Test 7: result with zero bypasses is not counted ─────────────────

    #[test]
    fn zero_bypassed_excluded() {
        let j = bench_json(vec![
            make_result("sql_001", "sql", 0, &["tamper/a"]),
            make_result("sql_002", "sql", 1, &["tamper/b"]),
        ]);
        let records = extract_bypass_records(&j).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique_sig, "tamper/b");
    }

    // ── Test 8: edit-distance threshold sensitivity ────────────────────────

    #[test]
    fn edit_threshold_mid_sensitivity() {
        let sigs = vec![
            "tamper/comment_strip".to_string(),
            "tamper/comment_stripX".to_string(), // 1 insertion → dist=1, norm=1/21
            "encoding/url/double".to_string(),    // unrelated
        ];
        let clusters_strict = sub_cluster(sigs.clone(), 0.01); // must be 3 clusters
        let clusters_loose = sub_cluster(sigs, 0.9); // first two join, third separate
        // Strict: only exact matches (none here because all differ).
        assert_eq!(clusters_strict.len(), 3);
        // Loose: "comment_strip" and "comment_stripX" join; "encoding/url/double" stays separate.
        assert_eq!(clusters_loose.len(), 2);
    }

    // ── Test 9: normalized_levenshtein edge cases ─────────────────────────

    #[test]
    fn normalized_levenshtein_edge_cases() {
        assert_eq!(normalized_levenshtein("", ""), 0.0);
        assert_eq!(normalized_levenshtein("a", "a"), 0.0);
        let d = normalized_levenshtein("abc", "xyz");
        // All 3 chars differ: edit dist = 3, max_len = 3 → 1.0
        assert!((d - 1.0).abs() < 1e-9);
        let d2 = normalized_levenshtein("ab", "a");
        // 1 deletion: dist=1, max=2 → 0.5
        assert!((d2 - 0.5).abs() < 1e-9);
    }

    // ── Test 10: result with no evaded field is silently skipped ─────────

    #[test]
    fn no_evaded_field_skipped() {
        let j = bench_json(vec![json!({
            "id": "sql_001",
            "class": "sql",
            "raw_blocked": true,
        })]);
        let records = extract_bypass_records(&j).unwrap();
        assert!(records.is_empty());
    }
}
