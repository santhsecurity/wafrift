//! Integrity gate for the bench corpus shipped under
//! `wafrift-bench/corpus/`. The scoreboard's credibility depends on
//! every payload class being exercised on every WAF stack — and the
//! cheapest way for that to silently break is for a class subdirectory
//! to be emptied or accidentally deleted. This test fails CI the
//! moment that happens.
//!
//! Scope:
//!
//! 1. Every canonical payload class has at least one `.toml` corpus
//!    file under `wafrift-bench/corpus/<class>/`.
//! 2. Every canonical payload class contributes at least the floor
//!    case count we consider statistically meaningful for a per-class
//!    bypass-rate cell on the scoreboard (currently 8 — well below
//!    even the smallest class today, intentionally headroom).
//! 3. Every `[[case]]` entry has a non-empty `id`, `class`, and
//!    `payload` field, and the `class` matches its directory.
//!
//! Why a test and not a script: this lives alongside the bench
//! runner, runs on every `cargo test`, and is a single Rust source
//! that an outside reviewer can read in 30 seconds — versus a shell
//! script that drifts.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// The canonical payload classes the scoreboard reports on. Adding a
/// new class is a deliberate two-line edit: this slice + the renderer
/// `CANONICAL_CLASSES` list. Removing one is a deliberate edit too —
/// not a silent drift.
const REQUIRED_CLASSES: &[&str] = &[
    "sql",
    "xss",
    "cmdi",
    "ssti",
    "path",
    "ldap",
    "xxe",
    "ssrf",
    "nosql",
    "log4shell",
    "cve_pocs",
];

/// Minimum case count per class. Below this the per-class rate cell
/// on the scoreboard is statistical noise (n < ~5 produces wide
/// confidence intervals). Set conservatively low: the smallest class
/// today (xxe) ships 10 cases, so 8 has headroom for someone removing
/// a duplicate without tripping the gate.
const MIN_CASES_PER_CLASS: usize = 8;

fn corpus_root() -> PathBuf {
    // Tests run from the crate root (`crates/cli/`) — climb to the
    // workspace root so `wafrift-bench/corpus` resolves regardless of
    // which crate's tests cargo is currently running.
    let workspace = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is always set under cargo test");
    // `crates/cli` -> `crates/cli/../..` = workspace root.
    workspace.join("..").join("..").join("wafrift-bench").join("corpus")
}

#[test]
fn every_required_class_has_a_corpus_directory() {
    let root = corpus_root();
    for class in REQUIRED_CLASSES {
        let dir = root.join(class);
        assert!(
            dir.is_dir(),
            "missing corpus dir for class `{class}` at {} — the scoreboard \
             will silently drop this column",
            dir.display()
        );
    }
}

#[test]
fn every_required_class_has_at_least_one_toml_file() {
    let root = corpus_root();
    for class in REQUIRED_CLASSES {
        let dir = root.join(class);
        let toml_count = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s == "toml")
            })
            .count();
        assert!(
            toml_count >= 1,
            "class `{class}` has zero .toml corpus files — bench will skip \
             this class entirely"
        );
    }
}

#[test]
fn every_required_class_meets_minimum_case_count() {
    let counts = case_counts_per_class();
    for class in REQUIRED_CLASSES {
        let n = counts.get(*class).copied().unwrap_or(0);
        assert!(
            n >= MIN_CASES_PER_CLASS,
            "class `{class}` has only {n} case(s), below the floor of \
             {MIN_CASES_PER_CLASS} — per-class scoreboard rate would be \
             statistical noise"
        );
    }
}

#[test]
fn every_case_has_id_class_and_payload_fields() {
    let root = corpus_root();
    let mut violations: Vec<String> = Vec::new();
    for class in REQUIRED_CLASSES {
        let dir = root.join(class);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let body = match fs::read_to_string(&path) {
                Ok(b) => b,
                Err(e) => {
                    violations.push(format!("read {}: {e}", path.display()));
                    continue;
                }
            };
            // Hand-parse rather than pulling the full bench-waf
            // `CorpusFile` deserialiser into the test — the integrity
            // gate must keep working even if the bench-waf struct
            // shape evolves. We check the three load-bearing fields
            // and the class match; richer validation belongs in the
            // bench-waf parser itself (which already enforces it via
            // serde).
            let in_case_block = false;
            let mut current_id: Option<String> = None;
            let mut current_class: Option<String> = None;
            let mut current_payload: Option<String> = None;
            let flush = |id: &Option<String>,
                         cls: &Option<String>,
                         payload: &Option<String>,
                         path: &std::path::Path,
                         violations: &mut Vec<String>| {
                if id.is_none() && cls.is_none() && payload.is_none() {
                    return;
                }
                if id.as_deref().unwrap_or("").is_empty() {
                    violations.push(format!("{}: case with empty/missing id", path.display()));
                }
                if cls.as_deref().unwrap_or("").is_empty() {
                    violations.push(format!(
                        "{}: case `{}` has empty/missing class",
                        path.display(),
                        id.as_deref().unwrap_or("?")
                    ));
                }
                // `cve_pocs/` is intentionally cross-class — each case is
                // a real-world CVE PoC tagged by its actual primary
                // attack class (e.g. a Confluence SSTI CVE keeps
                // `class = "ssti"` so the scoreboard rolls it into the
                // SSTI column). The dir-must-match-class check applies
                // only to the per-class subdirectories.
                if class != &"cve_pocs" && cls.as_deref() != Some(class) {
                    violations.push(format!(
                        "{}: case `{}` class={:?} does not match its directory `{class}`",
                        path.display(),
                        id.as_deref().unwrap_or("?"),
                        cls
                    ));
                }
                if payload.as_deref().unwrap_or("").is_empty() {
                    violations.push(format!(
                        "{}: case `{}` has empty/missing payload",
                        path.display(),
                        id.as_deref().unwrap_or("?")
                    ));
                }
            };
            for raw in body.lines() {
                let line = raw.trim();
                if line == "[[case]]" {
                    flush(
                        &current_id,
                        &current_class,
                        &current_payload,
                        &path,
                        &mut violations,
                    );
                    current_id = None;
                    current_class = None;
                    current_payload = None;
                    continue;
                }
                if !in_case_block && !line.starts_with("id ")
                    && !line.starts_with("id=")
                    && !line.starts_with("class ")
                    && !line.starts_with("class=")
                    && !line.starts_with("payload ")
                    && !line.starts_with("payload=")
                {
                    // Not a field we care about; skip.
                }
                if let Some(rest) = line.strip_prefix("id") {
                    if let Some(v) = strip_eq_quoted(rest) {
                        current_id = Some(v);
                    }
                } else if let Some(rest) = line.strip_prefix("class") {
                    if let Some(v) = strip_eq_quoted(rest) {
                        current_class = Some(v);
                    }
                } else if let Some(rest) = line.strip_prefix("payload") {
                    if let Some(v) = strip_eq_quoted(rest) {
                        current_payload = Some(v);
                    }
                }
            }
            // Last case in the file.
            flush(
                &current_id,
                &current_class,
                &current_payload,
                &path,
                &mut violations,
            );
        }
    }
    assert!(
        violations.is_empty(),
        "corpus integrity violations:\n{}",
        violations.join("\n")
    );
}

/// Helper: pull `"value"` out of a line shaped like `= "value"` (with
/// optional whitespace) — sufficient for the well-formed corpus TOML
/// files; richer parsing lives in the bench-waf serde deserialiser.
fn strip_eq_quoted(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            return Some(inner[..end].to_string());
        }
    }
    None
}

fn case_counts_per_class() -> BTreeMap<&'static str, usize> {
    let root = corpus_root();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for class in REQUIRED_CLASSES {
        let dir = root.join(class);
        let mut n = 0_usize;
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                    continue;
                }
                if let Ok(body) = fs::read_to_string(&path) {
                    n += body
                        .lines()
                        .filter(|l| l.trim() == "[[case]]")
                        .count();
                }
            }
        }
        counts.insert(class, n);
    }
    counts
}

#[test]
fn corpus_total_is_in_a_sensible_range() {
    // Anti-rig: catch the case where every class was reduced to its
    // floor at once (which would pass the per-class assertion but is
    // a strong signal someone bulk-deleted real data). Today the
    // total is ~600+; a regression to <300 means something serious
    // happened.
    let total: usize = case_counts_per_class().values().sum();
    assert!(
        total >= 300,
        "corpus total {total} is below the sensible floor of 300 — bulk \
         deletion regression?"
    );
}

#[test]
fn every_corpus_toml_file_parses_via_serde() {
    // Real serde parse on every corpus file. The hand-rolled
    // line-walker tests above only check that the *fields we look at*
    // are present — they cheerfully accept files whose TOML is invalid
    // (e.g. backslash-line-continuation inside single-line basic
    // strings) because the bench runner is the thing that ultimately
    // calls `toml::from_str`. That gap shipped 17 broken files in
    // 2026-05; this test closes it. If a file can't be parsed by the
    // canonical `toml` crate, the bench harness can't load it, and we
    // want CI to fail on the PR — not the production scoreboard.
    let root = corpus_root();
    let mut violations: Vec<String> = Vec::new();
    for class in REQUIRED_CLASSES {
        let dir = root.join(class);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let body = match fs::read_to_string(&path) {
                Ok(b) => b,
                Err(e) => {
                    violations.push(format!("read {}: {e}", path.display()));
                    continue;
                }
            };
            if let Err(e) = toml::from_str::<toml::Value>(&body) {
                violations.push(format!(
                    "{}: invalid TOML — {e}",
                    path.display()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "corpus TOML parse failures (file by file):\n{}",
        violations.join("\n")
    );
}
