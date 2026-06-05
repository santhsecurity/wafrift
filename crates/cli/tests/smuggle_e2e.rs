//! End-to-end tests for `wafrift smuggle`.
//!
//! All tests are purely offline — no HTTP, no mock server.
//! `smuggle list` enumerates variants; `smuggle dry-run` renders raw wire
//! bytes without sending anything.
//!
//! Tests verify:
//! 1. `smuggle --help` documents the subcommand surface.
//! 2. `smuggle` appears in top-level help.
//! 3. `smuggle list` enumerates all expected variant keys.
//! 4. `smuggle dry-run --variant cl-te` emits a CL.TE payload on stdout.
//! 5. `smuggle dry-run --variant te-cl` emits a TE.CL payload on stdout.
//! 6. `smuggle dry-run --variant dual-cl` emits dual Content-Length headers.
//! 7. `smuggle dry-run --format hex` emits space-separated hex octets.
//! 8. Unknown variant exits 2 with an error message.
//! 9. Missing required flags (no --host) exits non-zero.
//! 10. `smuggle list` help documents the list surface.
//! 11. `smuggle dry-run --help` documents required options.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn smuggle_help_documents_subcommands() {
    let (code, stdout, _) = wafrift(&["smuggle", "--help"]);
    assert_eq!(code, 0, "smuggle --help must exit 0");
    assert!(stdout.contains("list"), "stdout: {stdout}");
    assert!(stdout.contains("dry-run"), "stdout: {stdout}");
    assert!(stdout.contains("detect"), "stdout: {stdout}");
    assert!(stdout.contains("probe"), "stdout: {stdout}");
}

#[test]
fn smuggle_appears_in_main_help() {
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("smuggle"),
        "smuggle must appear in top-level help: {stdout}"
    );
}

#[test]
fn smuggle_list_help_documents_options() {
    let (code, stdout, _) = wafrift(&["smuggle", "list", "--help"]);
    assert_eq!(code, 0, "smuggle list --help must exit 0");
    // `list` is a simple command; at minimum --help must work.
    assert!(
        !stdout.is_empty(),
        "smuggle list --help must produce output"
    );
}

#[test]
fn smuggle_dry_run_help_documents_required_options() {
    let (code, stdout, _) = wafrift(&["smuggle", "dry-run", "--help"]);
    assert_eq!(code, 0, "smuggle dry-run --help must exit 0");
    assert!(stdout.contains("--variant"), "stdout: {stdout}");
    assert!(stdout.contains("--host"), "stdout: {stdout}");
    assert!(stdout.contains("--format"), "stdout: {stdout}");
}

// ── `smuggle list` ────────────────────────────────────────────────────────

#[test]
fn smuggle_list_enumerates_all_known_variants() {
    let (code, stdout, stderr) = wafrift(&["smuggle", "list"]);
    assert_eq!(code, 0, "smuggle list must exit 0; stderr: {stderr}");

    // All eight variant keys must appear.
    for key in [
        "detect-cl-te",
        "detect-te-cl",
        "cl-te",
        "te-cl",
        "te-te",
        "cl-0",
        "dual-cl",
        "multi-cl",
    ] {
        assert!(
            stdout.contains(key),
            "smuggle list must include variant key '{key}': {stdout}"
        );
    }
}

#[test]
fn smuggle_list_distinguishes_detection_from_exploit_tier() {
    let (code, stdout, stderr) = wafrift(&["smuggle", "list"]);
    assert_eq!(code, 0, "smuggle list must exit 0; stderr: {stderr}");

    // The catalogue must label detection-safe variants differently from exploit-grade.
    assert!(
        stdout.contains("detection") || stdout.contains("SAFE") || stdout.contains("detect"),
        "smuggle list must label detection-tier variants: {stdout}"
    );
    assert!(
        stdout.contains("EXPLOIT") || stdout.contains("exploit"),
        "smuggle list must label exploit-tier variants: {stdout}"
    );
}

// ── `smuggle dry-run` — raw format ───────────────────────────────────────

#[test]
fn smuggle_dry_run_cl_te_emits_transfer_encoding_header() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "cl-te",
        "--host",
        "example.com",
    ]);
    assert_eq!(
        code, 0,
        "smuggle dry-run cl-te must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Transfer-Encoding"),
        "CL.TE payload must contain Transfer-Encoding header: {stdout}"
    );
    assert!(
        stdout.contains("Content-Length"),
        "CL.TE payload must contain Content-Length header: {stdout}"
    );
    assert!(
        stdout.contains("example.com"),
        "payload must use the supplied --host: {stdout}"
    );
}

#[test]
fn smuggle_dry_run_te_cl_emits_transfer_encoding_header() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "te-cl",
        "--host",
        "target.internal",
    ]);
    assert_eq!(
        code, 0,
        "smuggle dry-run te-cl must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Transfer-Encoding"),
        "TE.CL payload must contain Transfer-Encoding header: {stdout}"
    );
    assert!(
        stdout.contains("Content-Length"),
        "TE.CL payload must contain Content-Length header: {stdout}"
    );
}

#[test]
fn smuggle_dry_run_dual_cl_emits_two_content_length_headers() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "dual-cl",
        "--host",
        "example.com",
    ]);
    assert_eq!(
        code, 0,
        "smuggle dry-run dual-cl must exit 0; stderr: {stderr}"
    );

    // Dual-CL: two Content-Length lines with different values.
    let cl_count = stdout.matches("Content-Length").count();
    assert!(
        cl_count >= 2,
        "dual-cl must emit at least 2 Content-Length lines, got {cl_count}: {stdout}"
    );
}

#[test]
fn smuggle_dry_run_meta_comment_contains_variant_key() {
    // The dry-run appends a `# ── meta ── variant=<key> …` comment line
    // so operators can grep the output in scripts.
    let (code, stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "cl-0",
        "--host",
        "example.com",
    ]);
    assert_eq!(
        code, 0,
        "smuggle dry-run cl-0 must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("cl-0"),
        "dry-run output must include the variant key somewhere: {stdout}"
    );
}

// ── `smuggle dry-run` — hex format ───────────────────────────────────────

#[test]
fn smuggle_dry_run_hex_format_emits_space_separated_octets() {
    let (code, stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "cl-te",
        "--host",
        "example.com",
        "--format",
        "hex",
    ]);
    assert_eq!(
        code, 0,
        "smuggle dry-run --format hex must exit 0; stderr: {stderr}"
    );

    // Hex output: lines like "50 4f 53 54 20 2f …   POST / …"
    // Every line should start with two lowercase hex chars followed by a space.
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.len() >= 2,
        "hex format must produce non-empty first line: {stdout}"
    );
    // The first two chars of the first line must be hex digits
    // ('P' = 0x50 so the line starts with "50").
    let first_two: String = first_line.chars().take(2).collect();
    assert!(
        first_two.chars().all(|c| c.is_ascii_hexdigit()),
        "hex format first line must start with hex octets (got '{first_two}'): {stdout}"
    );
}

// ── Error paths ───────────────────────────────────────────────────────────

#[test]
fn smuggle_dry_run_unknown_variant_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "not-a-real-variant",
        "--host",
        "example.com",
    ]);
    assert_eq!(code, 2, "unknown --variant must exit 2; stderr: {stderr}");
    assert!(
        stderr.contains("unknown variant") || stderr.contains("invalid value"),
        "error message must name the problem; stderr: {stderr}"
    );
}

#[test]
fn smuggle_dry_run_missing_host_exits_nonzero() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--variant",
        "cl-te",
        // no --host
    ]);
    assert_ne!(
        code, 0,
        "missing required --host must exit non-zero; stderr: {stderr}"
    );
}

#[test]
fn smuggle_dry_run_missing_variant_exits_nonzero() {
    let (code, _stdout, stderr) = wafrift(&[
        "smuggle",
        "dry-run",
        "--host",
        "example.com",
        // no --variant
    ]);
    assert_ne!(
        code, 0,
        "missing required --variant must exit non-zero; stderr: {stderr}"
    );
}
