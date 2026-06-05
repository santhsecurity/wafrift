//! Cross-document drift detector for the auth-bypass probe count.
//!
//! The count cited in prose — README, `docs/ARCHITECTURE.md`, the
//! `bypass-probe` clap help in `main.rs`, and the `bypass_probe.rs`
//! module docstring — MUST match the canonical
//! [`wafrift_encoding::auth_bypass::AUTH_BYPASS_PROBE_COUNT`].
//!
//! ## Why this exists
//!
//! The corpus was bumped 136 → 230 in code. Every hand-typed doc site
//! was updated EXCEPT `wafrift legendary`'s report prose, which kept
//! claiming a "136-probe" set (and a "150-probe sweep") in a
//! client-facing deliverable across releases. The sibling
//! `auth_bypass_probe_count_documented` test (in the encoding crate)
//! pins the *runtime* count and lists the doc sites in its failure
//! message — but it never reads them, so the prose drift slipped
//! through. This test reads each prose site and fails (naming the
//! file) the moment it stops citing the canonical number, turning a
//! silent doc lie into a red build.
//!
//! `legendary`'s report is intentionally NOT scanned here: it now
//! interpolates the const directly (see `crates/cli/src/legendary.rs`),
//! so it cannot drift and needs no prose pin.

use wafrift_encoding::auth_bypass::AUTH_BYPASS_PROBE_COUNT;

#[test]
fn prose_docs_cite_canonical_auth_bypass_count() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")); // crates/cli
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above crates/cli");

    // Hand-typed doc sites that cite the count in prose. `legendary.rs`
    // is deliberately absent — it derives the number from the const.
    let sites: [(std::path::PathBuf, &str); 4] = [
        (workspace_root.join("README.md"), "README.md"),
        (
            workspace_root.join("docs/ARCHITECTURE.md"),
            "docs/ARCHITECTURE.md",
        ),
        (manifest_dir.join("src/main.rs"), "crates/cli/src/main.rs"),
        (
            manifest_dir.join("src/bypass_probe.rs"),
            "crates/cli/src/bypass_probe.rs",
        ),
    ];

    // Canonical phrase every site must contain, e.g. "230 auth-bypass".
    // Derived from the const so bumping the count changes what this test
    // demands in lockstep — there is no second literal to keep in sync.
    let phrase = format!("{AUTH_BYPASS_PROBE_COUNT} auth-bypass");

    let mut stale = Vec::new();
    for (path, label) in &sites {
        let body = std::fs::read_to_string(path.as_path())
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if !body.contains(&phrase) {
            stale.push(*label);
        }
    }

    assert!(
        stale.is_empty(),
        "auth-bypass probe count drift: AUTH_BYPASS_PROBE_COUNT is {AUTH_BYPASS_PROBE_COUNT}, \
         but these prose sites do not cite \"{phrase}\":\n  {}\n\n\
         Update each to the canonical count. If the count changed \
         intentionally, bump AUTH_BYPASS_PROBE_COUNT and every prose \
         site together (this is the single commit where they must move \
         in lockstep).",
        stale.join("\n  ")
    );
}
