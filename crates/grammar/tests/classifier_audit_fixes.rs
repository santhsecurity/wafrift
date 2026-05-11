//! Regression coverage for the 2026-05-10 classifier audit findings:
//!   HIGH #1: `contains_shell_command` used substring matching, so short
//!     command names (`id`, `nc`, `sh`) matched inside ordinary words
//!     like `consider`, `validate`, `since` and pushed benign text into
//!     `CommandInjection`.
//!   MEDIUM #2: `cmd_signals` fell through to `CommandInjection` even when
//!     no separator was present — a bare `/etc/passwd` was being labelled
//!     as a shell command.
//!
//! Both tests would have failed pre-fix.

use wafrift_grammar::{PayloadType, classify};

// ── HIGH #1: substring matching of short commands ───────────────────

#[test]
fn classifier_does_not_misroute_id_inside_consider() {
    // "consider" contains "id" as a substring. Pre-fix this matched
    // contains_shell_command, then `; ` separator + "command" promoted
    // the whole thing to CommandInjection.
    assert_ne!(
        classify("; consider this option"),
        PayloadType::CommandInjection,
        "`id` inside `consider` must not trigger contains_shell_command"
    );
}

#[test]
fn classifier_does_not_misroute_id_inside_validate() {
    assert_ne!(
        classify("| validate the request"),
        PayloadType::CommandInjection,
        "`id` inside `validate` must not trigger contains_shell_command"
    );
}

#[test]
fn classifier_does_not_misroute_sh_inside_since() {
    // " sh" is a contains() pattern. "; since 1990" used to promote.
    assert_ne!(
        classify("; since 1990 the answer changed"),
        PayloadType::CommandInjection,
        "`sh` inside `since` (substring) must not trigger contains_shell_command"
    );
}

#[test]
fn classifier_does_not_misroute_nc_inside_concert() {
    assert_ne!(
        classify("; concert tickets available"),
        PayloadType::CommandInjection,
        "`nc` inside `concert` must not trigger contains_shell_command"
    );
}

#[test]
fn classifier_does_not_misroute_id_inside_android() {
    assert_ne!(
        classify("&& android version detection"),
        PayloadType::CommandInjection,
        "`id` inside `android` must not trigger contains_shell_command"
    );
}

#[test]
fn classifier_still_detects_real_id_command() {
    // Negative twin — the fix must not regress real injection detection.
    assert_eq!(
        classify("; id"),
        PayloadType::CommandInjection,
        "bare `; id` must still classify as CommandInjection"
    );
    assert_eq!(
        classify("| whoami"),
        PayloadType::CommandInjection,
        "bare `| whoami` must still classify"
    );
    assert_eq!(
        classify("&& sh -c 'curl evil'"),
        PayloadType::CommandInjection,
        "bare `sh` after `&&` must still classify"
    );
    assert_eq!(
        classify("`id`"),
        PayloadType::CommandInjection,
        "backtick id must still classify"
    );
    assert_eq!(
        classify("$(id)"),
        PayloadType::CommandInjection,
        "$(id) must still classify"
    );
}

// ── MEDIUM #2: separator-less /etc/passwd fallthrough ───────────────

#[test]
fn classifier_does_not_call_bare_etc_passwd_a_shell_command() {
    // Pre-fix: `/etc/passwd` alone produced cmd_signals=1, no separator,
    // path_traversal::detect_type was false (no `..`), so the else
    // branch returned CommandInjection. Now it falls through to the
    // type sweep and ends up Unknown or PathTraversal, never CMDi.
    assert_ne!(
        classify("filename=/etc/passwd"),
        PayloadType::CommandInjection,
        "bare /etc/passwd with no separator must not classify as CMDi"
    );
}

#[test]
fn classifier_does_not_call_bare_bin_ls_a_shell_command() {
    assert_ne!(
        classify("path=/bin/ls"),
        PayloadType::CommandInjection,
        "bare /bin/ls with no separator must not classify as CMDi"
    );
}

#[test]
fn classifier_still_detects_real_path_with_separator_as_cmdi() {
    // Negative twin — once the separator is back, it IS CMDi.
    assert_eq!(
        classify("; cat /etc/passwd"),
        PayloadType::CommandInjection,
        "; cat /etc/passwd must still classify as CMDi"
    );
    assert_eq!(
        classify("| cat /etc/shadow"),
        PayloadType::CommandInjection,
        "| cat /etc/shadow must still classify as CMDi"
    );
}

#[test]
fn classifier_does_not_panic_on_empty_or_unicode_garbage() {
    // Defence-in-depth — the byte-level whole-word scan must handle
    // edge inputs without panicking.
    let _ = classify("");
    let _ = classify("\0\0\0");
    let _ = classify("日本語のテスト");
    let _ = classify(&"a".repeat(100_000));
    let _ = classify(&"; ".repeat(10_000));
}
