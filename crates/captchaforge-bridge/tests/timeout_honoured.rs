//! Integration test: `solve_in_browser` honours `solve_timeout_ms` as
//! the per-solve OVERALL budget — it bounds the browser launch AND the
//! solve phase, not just the solve phase.
//!
//! The contract under test is "the timeout is HONOURED — the call does
//! not outlive its budget" (a real timeout failure means waiting on the
//! browser launch / solver for many seconds past the budget). Before the
//! fix, the launch ran OUTSIDE the timeout: on a host with no usable
//! browser the BiDi launch probe retries for several seconds (~7s
//! observed on a browserless CI runner) and the call blew past the
//! budget even though `solve_timeout_ms` was tiny. The launch is now
//! wrapped in the same overall budget, so the deadline is real.
//!
//! `timeout_honoured_against_unresponsive_html` accepts either `Ok(_)` or
//! `Err(_)` (the test box may or may not have Firefox installed) — it
//! verifies only the wall-clock bound. `launch_hang_is_bounded_by_budget`
//! is the targeted regression for the unbounded-launch bug: it points the
//! bridge at a fake "firefox" that never speaks BiDi, so the launch would
//! hang for ~30s if the budget didn't bound it.

use std::time::{Duration, Instant};

use wafrift_captchaforge_bridge::{BridgeConfig, solve_in_browser};

const TIMEOUT_MS: u64 = 1_000;
// Slack absorbs shared-CI scheduling jitter (process spawn + tokio
// wake-up under load + the best-effort browser teardown close()). The
// launch is now bounded by TIMEOUT_MS itself, so this no longer has to
// absorb an unbounded cold-launch probe — it stays well below a true
// hang (tens of seconds).
const SLACK_MS: u64 = 4_000;

#[tokio::test]
async fn timeout_honoured_against_unresponsive_html() {
    let cfg = BridgeConfig {
        solve_timeout_ms: TIMEOUT_MS,
        headless: true,
        no_sandbox: false,
        navigate_first: false,
    };

    // An HTML page with no captcha widgets and no external resources —
    // the browser would load it instantly, the solver chain returns
    // None quickly, but if Firefox is unavailable the launch fails
    // fast too. Either way the function must not outlive the budget.
    let html = "<html><head><title>WAF challenge</title></head><body>\
                <p>Please wait while we verify your browser...</p>\
                </body></html>";

    let start = Instant::now();
    // We don't care about the outcome, only the timing.
    let _outcome = solve_in_browser(html, "https://target.example.com/", &cfg).await;
    let elapsed = start.elapsed();

    let max_allowed = Duration::from_millis(TIMEOUT_MS + SLACK_MS);
    assert!(
        elapsed <= max_allowed,
        "solve_in_browser returned after {elapsed:?}, \
         but timeout is {TIMEOUT_MS}ms + {SLACK_MS}ms slack = {max_allowed:?}"
    );
}

/// Targeted regression for the unbounded-launch bug: point `FIREFOX_PATH`
/// at a real, executable binary that exists (so the early not-found guard
/// is bypassed) but never speaks the BiDi protocol — it just sleeps far
/// longer than the budget. `launch_firefox` therefore blocks waiting for a
/// session that never arrives. With the launch bounded by the overall
/// budget, `solve_in_browser` must still return within the budget + slack;
/// before the fix it would hang for the full sleep.
#[cfg(unix)]
#[tokio::test]
async fn launch_hang_is_bounded_by_budget() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    // Write a fake "firefox" that exists and is executable but hangs.
    let dir = std::env::temp_dir().join(format!("wafrift_fake_ff_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mk tmpdir");
    let fake = dir.join("firefox");
    {
        let mut f = std::fs::File::create(&fake).expect("create fake firefox");
        // Sleep 30s — ~30× the budget. If the launch were unbounded the
        // call would block here; the overall-budget timeout must cut it.
        f.write_all(b"#!/bin/sh\nsleep 30\n")
            .expect("write fake firefox");
        let mut perm = f.metadata().expect("stat").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).expect("chmod");
    }

    let budget_ms = 1_000_u64;
    let slack_ms = 4_000_u64;
    let cfg = BridgeConfig {
        solve_timeout_ms: budget_ms,
        headless: true,
        no_sandbox: false,
        navigate_first: false,
    };

    let start = Instant::now();
    let outcome = temp_env::async_with_vars(
        [("FIREFOX_PATH", Some(fake.to_string_lossy().to_string()))],
        async { solve_in_browser("<html><body>x</body></html>", "https://t.example/", &cfg).await },
    )
    .await;
    let elapsed = start.elapsed();

    // A hung launch can never produce a solved outcome.
    assert!(
        outcome.is_err(),
        "a hung browser launch must surface as Err, got: {outcome:?}"
    );
    let max_allowed = Duration::from_millis(budget_ms + slack_ms);
    assert!(
        elapsed <= max_allowed,
        "launch hung past the budget: returned after {elapsed:?}, \
         budget {budget_ms}ms + {slack_ms}ms slack = {max_allowed:?} \
         (the launch is not bounded by solve_timeout_ms)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
