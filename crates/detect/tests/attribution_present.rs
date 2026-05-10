//! Regression: every shipped detect rule MUST carry a `source` field
//! and the wafw00f attribution must remain visible in the user-facing
//! README + module-level docs.
//!
//! This test runs at compile time of the detect crate's tests, so a
//! stripped-attribution change anywhere in the chain fails the suite
//! before it can land.

use std::path::PathBuf;

fn detect_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/detect")
}

#[test]
fn every_rule_file_has_a_source_field() {
    let dir = detect_rules_dir();
    let entries =
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("rules dir {dir:?} unreadable: {e}"));

    let mut missing: Vec<String> = Vec::new();
    let mut total = 0_usize;
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        total += 1;
        let body = std::fs::read_to_string(&path).expect("read toml");
        if !body.contains("source =") {
            missing.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(total >= 100, "expected ≥100 rule files, found {total}");
    assert!(
        missing.is_empty(),
        "{} rule(s) missing the `source =` attribution field: {:?}",
        missing.len(),
        missing
    );
}

#[test]
fn wafw00f_attribution_present_in_detect_readme() {
    let readme =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let body = std::fs::read_to_string(&readme).expect("read detect README");
    assert!(
        body.to_ascii_lowercase().contains("wafw00f"),
        "wafw00f attribution missing from crates/detect/README.md"
    );
    assert!(
        body.contains("BSD-3-Clause") || body.contains("BSD-3"),
        "wafw00f license note (BSD-3-Clause) missing from detect README"
    );
}

#[test]
fn most_rules_cite_a_known_upstream_source() {
    let dir = detect_rules_dir();
    let entries = std::fs::read_dir(&dir).expect("rules dir");
    let mut wafw00f = 0_usize;
    let mut identywaf = 0_usize;
    let mut wafrift_local = 0_usize;
    let mut other = 0_usize;
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        if body.contains("source = \"WAFW00F:") {
            wafw00f += 1;
        } else if body.contains("source = \"IDENTYWAF:") {
            identywaf += 1;
        } else if body.contains("source = \"wafrift:") {
            wafrift_local += 1;
        } else {
            other += 1;
        }
    }
    assert!(
        wafw00f >= 100,
        "expected at least 100 WAFW00F-cited rules, got {wafw00f}"
    );
    eprintln!(
        "rule provenance: wafw00f={wafw00f} identywaf={identywaf} wafrift_local={wafrift_local} other={other}"
    );
}
