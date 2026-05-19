//! E10/75 — doc-claim audit (the legendary differentiator).
//!
//! Every load-bearing claim the public docs make is registered in
//! `doc_claims.toml` and bound to a REAL test. This auditor enforces,
//! bidirectionally:
//!   * the `claim` text is a verbatim substring of its `source` file
//!     (a claim cannot be invented in the ledger; deleting it from the
//!     docs fails),
//!   * `proven_by` names a real `fn` in `tests/` (the proof cannot be
//!     a phantom),
//!   * the ledger only ratchets forward (no silent shrinkage; open→0).
//!
//! It also hosts the four proving tests for claims that previously had
//! no dedicated test (no-stubs, forbid-unsafe, zero-config CRS, the
//! README library example) — so the whole ledger is honestly `proven`.

use serde::Deserialize;
use std::fs;
use wafrift_types::Request;
use wafrift_wafmodel::{
    Channel, Outcome, SimRegexWaf, WafOracle, canonicalize, default_crs_ruleset,
};

#[derive(Deserialize)]
struct Ledger {
    claim: Vec<Claim>,
}
#[derive(Deserialize)]
struct Claim {
    id: String,
    claim: String,
    source: String,
    proven_by: String,
    status: String,
}

fn manifest() -> String {
    env!("CARGO_MANIFEST_DIR").to_string()
}
fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{}", manifest(), rel))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Names of every `fn` defined anywhere under `tests/`.
fn all_test_fn_names() -> std::collections::HashSet<String> {
    let dir = format!("{}/tests", manifest());
    let mut names = std::collections::HashSet::new();
    for ent in fs::read_dir(&dir).expect("tests/ dir") {
        let p = ent.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap();
        for tok in src.split("fn ").skip(1) {
            let name: String = tok
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }
    names
}

#[test]
fn every_doc_claim_is_real_and_bound_to_a_living_test() {
    let led: Ledger = toml::from_str(&read("tests/doc_claims.toml")).expect("ledger parses");

    // Ledger may only grow: a hard floor on entry count means a row
    // cannot be silently dropped to dodge the audit.
    const MIN_CLAIMS: usize = 11;
    assert!(
        led.claim.len() >= MIN_CLAIMS,
        "ledger shrank to {} (< {MIN_CLAIMS}) — a claim was dropped, not proven",
        led.claim.len()
    );

    // Legendary state: zero open claims. This number may only decrease.
    const OPEN_BASELINE: usize = 0;
    let open = led.claim.iter().filter(|c| c.status != "proven").count();
    assert_eq!(
        open, OPEN_BASELINE,
        "{open} open doc-claims (baseline {OPEN_BASELINE}) — every claim must be proven; \
         the baseline may only ratchet down to 0, never up"
    );

    let lib = read("src/lib.rs");
    let readme = read("README.md");
    let fns = all_test_fn_names();
    let mut seen_ids = std::collections::HashSet::new();

    for c in &led.claim {
        assert!(!c.id.is_empty(), "empty claim id");
        assert!(seen_ids.insert(c.id.clone()), "duplicate claim id {}", c.id);
        assert!(!c.claim.is_empty(), "[{}] empty claim text", c.id);
        assert!(
            matches!(c.status.as_str(), "proven" | "open"),
            "[{}] status must be proven|open, got {}",
            c.id,
            c.status
        );

        // The claim text must REALLY appear in its source doc.
        let hay = match c.source.as_str() {
            "src/lib.rs" => &lib,
            "README.md" => &readme,
            other => panic!("[{}] unknown source {other}", c.id),
        };
        assert!(
            hay.contains(&c.claim),
            "[{}] claim text is not a verbatim substring of {} — \
             the doc was changed or the ledger is fabricated:\n  {:?}",
            c.id,
            c.source,
            c.claim
        );

        // The proof must be a real, living test fn.
        assert!(
            fns.contains(&c.proven_by),
            "[{}] proven_by `{}` is not a test fn that exists in tests/ \
             (phantom proof)",
            c.id,
            c.proven_by
        );
    }
}

// ── The four proving tests for claims that previously had no
//    dedicated test (referenced by id in the ledger). ──

#[test]
fn no_stub_markers_in_engine_src() {
    // lib.rs claims "each module is landed complete (no stubs)".
    // Assert no stub/evasion markers anywhere in src/.
    let dir = format!("{}/src", manifest());
    let mut offenders = Vec::new();
    fn walk(d: &std::path::Path, out: &mut Vec<String>) {
        for e in fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                let s = fs::read_to_string(&p).unwrap();
                for (n, line) in s.lines().enumerate() {
                    let t = line.trim_start();
                    // Skip doc/comment lines describing the law itself.
                    if t.starts_with("//") {
                        continue;
                    }
                    if line.contains("todo!(")
                        || line.contains("unimplemented!(")
                        || line.contains("panic!(\"not implemented")
                        || line.contains("panic!(\"not yet")
                    {
                        out.push(format!("{}:{}", p.display(), n + 1));
                    }
                }
            }
        }
    }
    walk(std::path::Path::new(&dir), &mut offenders);
    assert!(
        offenders.is_empty(),
        "stub markers present (claim 'no stubs' is false): {offenders:?}"
    );
}

#[test]
fn forbid_unsafe_is_declared() {
    assert!(
        read("src/lib.rs").contains("#![forbid(unsafe_code)]"),
        "lib.rs claims #![forbid(unsafe_code)] but the attribute is absent"
    );
}

#[test]
fn default_crs_ruleset_parses_zero_config() {
    // Zero-config: the CRS ruleset is embedded (no file/network) and is
    // real — it actually blocks a canonical XSS payload.
    let mut waf = SimRegexWaf::from_toml(default_crs_ruleset())
        .expect("embedded CRS ruleset must parse with no external files");
    let req = Request::get("https://h/p?x=<script>alert(1)</script>");
    assert_eq!(
        waf.classify(&req).unwrap(),
        Outcome::Block,
        "embedded CRS must block a canonical reflected XSS (non-vacuous)"
    );
    // Precision: a benign value is not blocked.
    let benign = Request::get("https://h/p?x=hello-world");
    assert_eq!(waf.classify(&benign).unwrap(), Outcome::Pass);
}

#[test]
fn readme_library_example_runs() {
    // Exactly the README "As a library" snippet, executed:
    //   let view = canonicalize(&request);
    //   let args = view.channel(Channel::ArgValue);
    let request = Request::get("https://h/p?x=payload-xyz&y=2");
    let view = canonicalize(&request);
    let args = view.channel(Channel::ArgValue);
    assert!(
        view.total_bytes() > 0,
        "canonicalized view must be non-empty"
    );
    assert!(
        args.iter()
            .any(|a| a.windows(11).any(|w| w == b"payload-xyz")),
        "ArgValue channel must surface the query arg value (README example broken)"
    );
}
