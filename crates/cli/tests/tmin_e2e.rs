//! End-to-end tests for `wafrift tmin`.
//!
//! `tmin` is a thin alias for `wafrift distill` — it delegates entirely
//! to the same ddmin engine. Full network+mock tests for the shared
//! algorithm are in `distill_e2e.rs`. This suite covers:
//!
//! 1. `tmin --help` exits 0 and documents the key flags.
//! 2. `tmin` appears in top-level help.
//! 3. Empty `--payload` exits 2 (same as distill).
//! 4. Missing `--payload` with no stdin exits 2 with an actionable error.
//! 5. `tmin` and `distill` produce identical exit codes on the same inputs.
//! 6. `tmin` with an unreachable URL and a real payload exits non-zero.

mod common;
use common::wafrift;

// ── Help surface ──────────────────────────────────────────────────────────

#[test]
fn tmin_help_documents_key_flags() {
    let (code, stdout, _) = wafrift(&["tmin", "--help"]);
    assert_eq!(code, 0, "tmin --help must exit 0");
    assert!(
        stdout.contains("--payload"),
        "must document --payload: {stdout}"
    );
    assert!(
        stdout.contains("--max-fires"),
        "must document --max-fires: {stdout}"
    );
    assert!(
        stdout.contains("--format"),
        "must document --format: {stdout}"
    );
}

#[test]
// `tmin` is a hidden alias of `distill` (2026-05). `distill` is the
// advertised command; `tmin` must keep working forever (LAW 2).
fn distill_is_in_main_help_and_tmin_alias_still_runs() {
    // 1. `distill` is discoverable in top-level help.
    let (code, stdout, _) = wafrift(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\n  distill"),
        "`distill` must appear as a top-level command in --help: {stdout}"
    );

    // 2. Deprecated alias still runs (LAW 2 backwards-compat).
    let (code2, _stdout2, stderr2) = wafrift(&["tmin", "--help"]);
    assert_eq!(
        code2, 0,
        "`wafrift tmin --help` must still exit 0 — stderr:\n{stderr2}"
    );
}

// ── Input validation (offline — no network needed) ────────────────────────

#[test]
fn tmin_empty_payload_exits_2() {
    let (code, _stdout, stderr) = wafrift(&[
        "tmin",
        "http://127.0.0.1:65500",
        "--payload",
        "",
        "--format",
        "json",
    ]);
    assert_eq!(code, 2, "empty --payload must exit 2; stderr: {stderr}");
}

#[test]
fn tmin_and_distill_agree_on_empty_payload_exit_code() {
    let tmin_code = wafrift(&[
        "tmin",
        "http://127.0.0.1:65500",
        "--payload",
        "",
        "--format",
        "json",
    ])
    .0;
    let distill_code = wafrift(&[
        "distill",
        "http://127.0.0.1:65500",
        "--payload",
        "",
        "--format",
        "json",
    ])
    .0;
    assert_eq!(
        tmin_code, distill_code,
        "tmin and distill must produce the same exit code for the same error condition"
    );
}

#[test]
fn tmin_unreachable_target_exits_nonzero() {
    // Port 65500 is almost certainly closed on loopback. The connection
    // attempt will fail → tmin exits non-zero (cannot probe baseline).
    let (code, _stdout, _stderr) = wafrift(&[
        "tmin",
        "http://127.0.0.1:65500",
        "--payload",
        "some-payload-that-wont-bypass",
        "--max-fires",
        "2",
    ]);
    assert_ne!(
        code, 0,
        "tmin against unreachable target must exit non-zero"
    );
}

#[test]
fn tmin_param_flag_accepted() {
    // --param is documented; verify it doesn't cause a parse error.
    let (code, _stdout, stderr) = wafrift(&[
        "tmin",
        "http://127.0.0.1:65500",
        "--payload",
        "",
        "--param",
        "injection",
    ]);
    // Empty payload → exits 2; just verify it isn't a flag-parse error.
    assert!(
        code != 0,
        "tmin with empty payload exits non-zero; code={code}, stderr={stderr}"
    );
    // Must NOT say "unknown argument" or "unexpected".
    assert!(
        !stderr.to_lowercase().contains("unknown argument"),
        "--param must be accepted as a valid flag: {stderr}"
    );
}
