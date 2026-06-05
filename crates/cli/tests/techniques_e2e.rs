//! End-to-end tests for `wafrift techniques`.
//!
//! All tests are purely offline — no HTTP, no mock server.
//! `techniques list` enumerates the technique tree;
//! `techniques explain <selector>` prints per-technique docs.
//!
//! Tests verify:
//! 1. help documents the CLI surface (list + explain subcommands).
//! 2. techniques appears in top-level help.
//! 3. `techniques list` emits a non-empty technique tree.
//! 4. The tree contains both `encoding/` and `tamper/` families.
//! 5. `techniques explain <valid>` exits 0 and documents the selector.
//! 6. `techniques explain <invalid-prefix>` exits 2 with a helpful error.
//! 7. `techniques explain <unknown-valid-prefix>` exits non-zero.
//! 8. `techniques list --help` exits 0.
//! 9. `techniques explain --help` exits 0.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn techniques_help_documents_subcommands() {
    let (code, stdout, _) = wafrift(&["techniques", "--help"]);
    assert_eq!(code, 0, "techniques --help must exit 0");
    assert!(stdout.contains("list"), "stdout: {stdout}");
    assert!(stdout.contains("explain"), "stdout: {stdout}");
}

#[test]
fn techniques_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("techniques"),
        "techniques must appear in top-level help: {stdout}"
    );
}

#[test]
fn techniques_list_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["techniques", "list", "--help"]);
    assert_eq!(code, 0, "techniques list --help must exit 0");
}

#[test]
fn techniques_explain_help_exits_0() {
    let (code, _stdout, _) = wafrift(&["techniques", "explain", "--help"]);
    assert_eq!(code, 0, "techniques explain --help must exit 0");
}

// ── `techniques list` ─────────────────────────────────────────────────────

#[test]
fn techniques_list_emits_non_empty_tree() {
    let (code, stdout, stderr) = wafrift(&["techniques", "list"]);
    assert_eq!(code, 0, "techniques list must exit 0; stderr: {stderr}");
    assert!(
        !stdout.trim().is_empty(),
        "techniques list must produce non-empty output"
    );
}

#[test]
fn techniques_list_contains_encoding_family() {
    let (code, stdout, stderr) = wafrift(&["techniques", "list"]);
    assert_eq!(code, 0, "techniques list must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("encoding"),
        "technique tree must contain 'encoding' family: {stdout}"
    );
}

#[test]
fn techniques_list_contains_tamper_family() {
    let (code, stdout, stderr) = wafrift(&["techniques", "list"]);
    assert_eq!(code, 0, "techniques list must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("tamper"),
        "technique tree must contain 'tamper' family: {stdout}"
    );
}

#[test]
fn techniques_list_contains_known_encoding_selectors() {
    let (code, stdout, stderr) = wafrift(&["techniques", "list"]);
    assert_eq!(code, 0, "techniques list must exit 0; stderr: {stderr}");
    // A few canonical selectors must be present in the catalogue.
    for selector in ["encoding/url", "encoding/base64", "encoding/html"] {
        assert!(
            stdout.contains(selector),
            "technique tree must contain '{selector}': {stdout}"
        );
    }
}

// ── `techniques explain` ──────────────────────────────────────────────────

#[test]
fn techniques_explain_valid_selector_exits_0() {
    let (code, stdout, stderr) = wafrift(&["techniques", "explain", "encoding/url/single"]);
    assert_eq!(
        code, 0,
        "techniques explain valid selector must exit 0; stderr: {stderr}"
    );
    assert!(
        !stdout.trim().is_empty(),
        "explain must produce output for a valid selector: {stderr}"
    );
    // Output must reference the selector name.
    assert!(
        stdout.contains("encoding/url"),
        "explain output must mention the selector: {stdout}"
    );
}

#[test]
fn techniques_explain_invalid_prefix_exits_2() {
    let (code, _stdout, stderr) = wafrift(&["techniques", "explain", "notaprefix/something"]);
    assert_eq!(code, 2, "invalid prefix must exit 2; stderr: {stderr}");
    assert!(
        stderr.contains("selector") || stderr.contains("tamper") || stderr.contains("encoding"),
        "error must hint at valid prefixes; stderr: {stderr}"
    );
}

#[test]
fn techniques_explain_unknown_selector_exits_nonzero() {
    // Valid prefix but unknown selector: must exit non-zero, not panic.
    let (code, _stdout, _stderr) =
        wafrift(&["techniques", "explain", "encoding/completely-unknown-xyzzy"]);
    assert_ne!(code, 0, "unknown selector must exit non-zero");
}
