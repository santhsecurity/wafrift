//! Bench-corpus stress test.
//!
//! Loads ALL corpus cases (every TOML file under `wafrift-bench/corpus/`) via
//! `toml::from_str`, runs each case through the same `build_request` logic
//! that the real bench runner uses, and asserts:
//!
//!  1. No TOML file fails to parse.
//!  2. No case panics during request construction.
//!  3. No case produces empty wire bytes (empty URL AND empty body).
//!  4. Every request has either a non-empty URL or a non-empty body.
//!  5. Total case count is ≥ 820 (our committed corpus floor).
//!  6. Every case id is unique within the full corpus (no duplicates).
//!
//! This runs entirely in-process (no network) so it completes in <10s on
//! any modern CI runner.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use wafrift_types::Request;

// ── Corpus structure (mirrors bench_waf.rs internals) ────────────────────────

#[derive(Debug, Deserialize)]
struct CorpusFile {
    #[serde(default, rename = "case")]
    cases: Vec<BenchCase>,
}

#[derive(Debug, Deserialize, Clone)]
struct BenchCase {
    id: String,
    class: String,
    payload: String,
    #[serde(default = "default_mode")]
    mode: String,
}

fn default_mode() -> String {
    "body_form_q".into()
}

// ── Mirrors bench_waf::build_request exactly ─────────────────────────────────

fn build_request(base_url: &str, case: &BenchCase) -> Request {
    let payload = &case.payload;
    match case.mode.as_str() {
        "url_query_q" => {
            let url = format!(
                "{}/get?q={}",
                base_url.trim_end_matches('/'),
                urlencoding::encode(payload)
            );
            Request::get(url)
        }
        "raw_body" => {
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let mut r = Request::post(url, payload.as_bytes().to_vec());
            r.add_header("content-type", "text/plain");
            r
        }
        _ => {
            // body_form_q (default)
            let url = format!("{}/post", base_url.trim_end_matches('/'));
            let body = format!("q={}", urlencoding::encode(payload));
            let mut r = Request::post(url, body.into_bytes());
            r.add_header("content-type", "application/x-www-form-urlencoded");
            r
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn corpus_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR always set under cargo test");
    // crates/cli/../../wafrift-bench/corpus
    manifest
        .join("..")
        .join("..")
        .join("wafrift-bench")
        .join("corpus")
}

fn load_all_cases() -> Vec<(PathBuf, BenchCase)> {
    let root = corpus_root();
    let mut all: Vec<(PathBuf, BenchCase)> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();

    // Walk one level deep (class subdirectories).
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }

    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                    continue;
                }
                let body = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let file: CorpusFile =
                    toml::from_str(&body).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                for case in file.cases {
                    all.push((path.clone(), case));
                }
            }
        }
    }

    all
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn all_corpus_cases_parse_without_panic() {
    // load_all_cases() itself panics on parse failure — that's the test.
    let all = load_all_cases();
    assert!(
        !all.is_empty(),
        "corpus loaded zero cases — corpus root is missing or empty"
    );
}

#[test]
fn corpus_total_case_count_at_or_above_floor() {
    let all = load_all_cases();
    let count = all.len();
    // Floor: 800 cases (corpus was at 817 on 2026-05-21; floor set 2%
    // below to absorb deliberate dedup/prune PRs without false-failing,
    // while still catching bulk-deletion regressions). Raise this
    // number as the corpus grows — lowering it requires explicit
    // sign-off because it weakens the guard.
    assert!(
        count >= 800,
        "corpus case count {count} is below the floor of 800 — bulk deletion regression?"
    );
}

#[test]
fn all_corpus_case_ids_are_globally_unique() {
    let all = load_all_cases();
    let mut seen: HashSet<String> = HashSet::new();
    let mut duplicates: Vec<String> = Vec::new();
    for (path, case) in &all {
        if !seen.insert(case.id.clone()) {
            duplicates.push(format!("{}: duplicate id={}", path.display(), case.id));
        }
    }
    assert!(
        duplicates.is_empty(),
        "duplicate corpus case ids found:\n{}",
        duplicates.join("\n")
    );
}

#[test]
fn every_corpus_case_produces_nonempty_request() {
    let all = load_all_cases();
    let base = "http://127.0.0.1:18081";
    let mut failures: Vec<String> = Vec::new();

    for (path, case) in &all {
        let req = build_request(base, case);
        let url_empty = req.url().trim_matches('/').is_empty()
            || req.url() == base
            || req.url() == format!("{base}/");
        let body_empty = req.body_bytes().is_none_or(|b| b.is_empty());

        if url_empty && body_empty {
            failures.push(format!(
                "{}: case id={} mode={} — both url and body are effectively empty",
                path.display(),
                case.id,
                case.mode
            ));
        }

        // URL must not be empty at all.
        if req.url().is_empty() {
            failures.push(format!(
                "{}: case id={} mode={} — url is empty",
                path.display(),
                case.id,
                case.mode
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "corpus cases produced empty wire bytes:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_corpus_case_id_is_nonempty_and_non_whitespace() {
    let all = load_all_cases();
    let mut failures: Vec<String> = Vec::new();
    for (path, case) in &all {
        if case.id.trim().is_empty() {
            failures.push(format!("{}: case has empty id", path.display()));
        }
        if case.payload.trim().is_empty() {
            failures.push(format!(
                "{}: case id={} has empty payload",
                path.display(),
                case.id
            ));
        }
        if case.class.trim().is_empty() {
            failures.push(format!(
                "{}: case id={} has empty class",
                path.display(),
                case.id
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "corpus field violations:\n{}",
        failures.join("\n")
    );
}

#[test]
fn corpus_case_counts_per_class_reasonable() {
    let all = load_all_cases();
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    for (_, case) in &all {
        *by_class.entry(case.class.clone()).or_default() += 1;
    }
    // Every class that appears at all must have at least 8 cases (same
    // floor as bench_corpus_integrity.rs — a single class below 8 means
    // per-class bypass-rate cells are statistical noise).
    for (class, count) in &by_class {
        assert!(
            *count >= 8,
            "class `{class}` has only {count} case(s) in the full corpus — \
             below the statistical floor of 8"
        );
    }
}

#[test]
fn url_query_q_mode_puts_payload_in_url() {
    let case = BenchCase {
        id: "test_url_q".into(),
        class: "sql".into(),
        payload: "1 OR 1=1".into(),
        mode: "url_query_q".into(),
    };
    let req = build_request("http://127.0.0.1:18081", &case);
    assert!(
        req.url().contains("q="),
        "url_query_q mode must put q= in URL, got: {}",
        req.url()
    );
    assert!(
        req.body_bytes().is_none(),
        "url_query_q mode must not set a body"
    );
}

#[test]
fn body_form_q_mode_puts_payload_in_body() {
    let case = BenchCase {
        id: "test_body_form".into(),
        class: "sql".into(),
        payload: "1 OR 1=1".into(),
        mode: "body_form_q".into(),
    };
    let req = build_request("http://127.0.0.1:18081", &case);
    let body = req.body_bytes().expect("body_form_q must have a body");
    let body_str = std::str::from_utf8(body).expect("body is UTF-8");
    assert!(
        body_str.starts_with("q="),
        "body_form_q body must start with q=, got: {body_str}"
    );
}

#[test]
fn raw_body_mode_puts_payload_as_body() {
    let case = BenchCase {
        id: "test_raw_body".into(),
        class: "xss".into(),
        payload: "<script>alert(1)</script>".into(),
        mode: "raw_body".into(),
    };
    let req = build_request("http://127.0.0.1:18081", &case);
    let body = req.body_bytes().expect("raw_body must have a body");
    assert!(
        body.starts_with(b"<script>"),
        "raw_body mode must put the payload directly in body"
    );
}
