//! Drift guard: the in-crate vendored `rules/detect` copy (what
//! survives `cargo publish`) MUST be byte-identical to the workspace
//! canonical `../../rules/detect` tree (what contributors and the
//! README edit).
//!
//! Why this exists: a CloudFront signature fix was applied to the
//! canonical tree and silently had no effect, because `build.rs` was
//! embedding the *unedited* vendored copy. Two divergent sources of
//! truth for Tier-B detection data is a latent "we shipped stale
//! rules" bug. This test makes any future drift a hard CI failure
//! instead of a mystery in the field.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .expect("strip_prefix")
                    .to_string_lossy()
                    .into_owned();
                let bytes =
                    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                map.insert(rel, bytes);
            }
        }
    }
    map
}

#[test]
fn vendored_detect_rules_match_workspace_canonical() {
    // Test CWD is the crate dir (`crates/detect`).
    let in_crate = Path::new("rules/detect");
    let workspace = Path::new("../../rules/detect");

    // In a published-crate context the workspace tree is absent; the
    // vendored copy is then authoritative and there is nothing to
    // compare. The guard only has teeth in the monorepo, which is
    // exactly where drift is introduced.
    if !workspace.is_dir() {
        eprintln!("workspace rules/detect absent (published-crate layout) — drift guard skipped");
        return;
    }
    assert!(
        in_crate.is_dir(),
        "in-crate vendored rules/detect is missing — `cargo publish` would ship no rules"
    );

    let vendored = read_tree(in_crate);
    let canonical = read_tree(workspace);

    let mut problems = Vec::new();
    for name in canonical.keys() {
        match vendored.get(name) {
            None => problems.push(format!(
                "  - {name}: present in workspace, MISSING from vendored"
            )),
            Some(v) if v != &canonical[name] => {
                problems.push(format!(
                    "  - {name}: CONTENT DIFFERS between workspace and vendored"
                ));
            }
            Some(_) => {}
        }
    }
    for name in vendored.keys() {
        if !canonical.contains_key(name) {
            problems.push(format!(
                "  - {name}: present in vendored, MISSING from workspace"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "vendored crates/detect/rules/detect has drifted from canonical rules/detect — \
         build.rs may embed stale detection rules. Re-sync the trees \
         (the canonical copy is the source of truth):\n{}",
        problems.join("\n")
    );
}
