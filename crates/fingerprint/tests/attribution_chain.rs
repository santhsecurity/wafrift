//! Regression: rules shipped for HTTP WAF fingerprinting keep `source =`
//! attribution back to wafw00f plugins, and user-facing docs cite the project.

use std::path::PathBuf;

fn detect_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../detect/rules/detect")
}

fn detect_readme() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../detect/README.md")
}

#[test]
fn corpus_rules_keep_wafw00f_source_tags() {
    let mapping = [
        ("cloudflare.toml", "WAFW00F:cloudflare"),
        ("kona.toml", "WAFW00F:kona"),
        ("awswaf.toml", "WAFW00F:awswaf"),
        ("sucuri.toml", "WAFW00F:sucuri"),
        ("incapsula.toml", "WAFW00F:incapsula"),
        ("f5bigipasm.toml", "WAFW00F:f5bigipasm"),
        ("fortigate.toml", "WAFW00F:fortigate"),
        ("barracuda.toml", "WAFW00F:barracuda"),
        ("cloudfront.toml", "WAFW00F:cloudfront"),
    ];

    let dir = detect_rules_dir();
    for (file, needle) in mapping {
        let path = dir.join(file);
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Fix: read rule file {} ({e})", path.display()));
        assert!(
            body.contains("source =") && body.contains(needle),
            "Fix: {file} must retain attribution `{needle}` for audit trail"
        );
    }
}

#[test]
fn detect_readme_preserves_wafw00f_credit_and_license() {
    let readme = detect_readme();
    let body = std::fs::read_to_string(&readme).expect("read wafrift-detect README");
    assert!(
        body.to_ascii_lowercase().contains("wafw00f"),
        "Fix: wafrift-detect README must credit wafw00f"
    );
    assert!(
        body.contains("BSD-3-Clause") || body.contains("BSD-3"),
        "Fix: wafrift-detect README must note BSD-3-Clause for wafw00f-derived rules"
    );
}
