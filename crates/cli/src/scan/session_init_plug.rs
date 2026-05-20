//! Scan's Step 0 — bridge `args.session_init` (an optional curl
//! file path) into a captured `SessionState` ready to feed
//! `reqwest::ClientBuilder::default_headers`.
//!
//! Lives in its own module so `scan/mod.rs` doesn't grow another
//! 35 lines of glue every time we add a phase. The phase has a
//! crisp contract: given the operator's CLI flag, return either
//! the captured state (Some), no state (None — flag wasn't set,
//! the normal path), or an `ExitCode` if the auth-phase request
//! itself failed.

use colored::Colorize;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::session_init::{SessionState, establish_from_file};

/// Run the session-init phase. Returns:
///
/// - `Ok(None)` — `--session-init` was not set; subsequent scan
///   phases proceed unauthenticated (existing default behaviour).
/// - `Ok(Some(state))` — auth-phase request succeeded; caller
///   plugs `state.headers` into `ClientBuilder::default_headers`
///   so every subsequent variant carries the cookies.
/// - `Err(ExitCode::from(1))` — auth-phase request failed; the
///   error has already been printed to stderr. Caller should
///   propagate the exit code immediately (a failed auth phase
///   means subsequent scans will be anonymous, which would
///   silently change the scan's semantics — explicit error is
///   the right move).
pub async fn run(
    session_init_path: Option<&Path>,
    insecure: bool,
    scan_text: bool,
    timeout: Duration,
) -> Result<Option<SessionState>, ExitCode> {
    let Some(path) = session_init_path else {
        return Ok(None);
    };
    if scan_text {
        println!("{}", "[0/3] Establishing session...".bold().cyan());
    }
    match establish_from_file(path, timeout, insecure).await {
        Ok(state) => {
            if scan_text {
                println!("  {} {}", "✓".green(), state.summary.bright_white());
            }
            Ok(Some(state))
        }
        Err(e) => {
            eprintln!("  {} {e}", "✗ session-init failed:".red().bold());
            Err(ExitCode::from(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_none_path_returns_ok_none_no_io() {
        // The fast path — no --session-init flag, no work.
        let result = run(None, false, false, Duration::from_secs(1)).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_missing_file_returns_err_exit_code() {
        // The error path: --session-init points at a path that
        // doesn't exist. The wrapper must error (not silently
        // proceed unauthenticated, which would change scan
        // semantics).
        let missing = std::env::temp_dir()
            .join("wafrift-scan-session-init-DOES-NOT-EXIST-9999.curl");
        let result = run(Some(&missing), false, false, Duration::from_secs(2)).await;
        match result {
            Err(_) => {} // ExitCode::from(1) — Debug not derivable on ExitCode
            Ok(_) => panic!("missing file must error"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_empty_file_returns_err_exit_code() {
        // The other error path: file exists but doesn't parse as a
        // valid curl invocation. Must surface as Err, not silently
        // proceed.
        let path = std::env::temp_dir().join(format!(
            "wafrift-scan-session-init-empty-{}.curl",
            std::process::id()
        ));
        std::fs::write(&path, "").unwrap();
        let result = run(Some(&path), false, false, Duration::from_secs(2)).await;
        match result {
            Err(_) => {}
            Ok(_) => panic!("empty file must error"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
