//! Regression test: shipped `docs/man/wafrift.1` must match the troff
//! the binary emits via `wafrift man`.
//!
//! We've shipped a stale manpage three times: at 0.2.1, 0.2.11, and
//! again at 0.2.12 (each time the workspace bumped without regenerating
//! the file, so the .TH title bar lied about the binary's version
//! and the SUBCOMMANDS list missed `wafrift discover` /
//! `wafrift bypass-probe` for several releases).
//!
//! The fix is single-source-of-truth: `wafrift man` is the truth,
//! `docs/man/wafrift.1` is a snapshot. This test fails if they
//! diverge — the suggested action is `cargo run --bin wafrift -- man
//! > docs/man/wafrift.1`.

use std::process::Command;

#[test]
fn shipped_manpage_matches_binary_emission() {
    let bin = env!("CARGO_BIN_EXE_wafrift");
    let output = Command::new(bin)
        .arg("man")
        .output()
        .expect("invoke wafrift man");
    assert!(
        output.status.success(),
        "wafrift man exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let emitted = String::from_utf8(output.stdout).expect("manpage is utf-8");

    // Locate the workspace root by walking up from the test binary's
    // CARGO_MANIFEST_DIR (= crates/cli) two levels.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above crates/cli");
    let shipped_path = workspace_root.join("docs/man/wafrift.1");
    let shipped = std::fs::read_to_string(&shipped_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", shipped_path.display()));

    if emitted != shipped {
        // Find the first differing line so the message points at the
        // drift instead of dumping a 100-line diff.
        let emitted_lines: Vec<&str> = emitted.lines().collect();
        let shipped_lines: Vec<&str> = shipped.lines().collect();
        let mut first_diff: Option<(usize, &str, &str)> = None;
        for (i, (a, b)) in emitted_lines.iter().zip(shipped_lines.iter()).enumerate() {
            if a != b {
                first_diff = Some((i + 1, *a, *b));
                break;
            }
        }
        let detail = match first_diff {
            Some((line, e, s)) => {
                format!("first divergence at line {line}:\n  binary:  {e}\n  shipped: {s}")
            }
            None => format!(
                "length mismatch: binary={} lines, shipped={} lines",
                emitted_lines.len(),
                shipped_lines.len()
            ),
        };
        panic!(
            "docs/man/wafrift.1 is out of sync with `wafrift man`.\n\
             Regenerate with:\n  \
             cargo run --bin wafrift --release --quiet -- man > docs/man/wafrift.1\n\n{detail}"
        );
    }
}
