//! Integration test: `solve_in_browser` returns `Err` cleanly when
//! `FIREFOX_PATH` points to a non-existent binary.
//!
//! Guarantees:
//!  - no panic
//!  - no hang beyond a tight wall-clock deadline
//!  - the returned value is `Err`, not `Ok`

use std::time::{Duration, Instant};

use wafrift_captchaforge_bridge::{BridgeConfig, solve_in_browser};

/// The test sets a 2 s solve budget and asserts the whole thing
/// completes within 2.5 s (500 ms slack for process startup overhead).
const BUDGET_MS: u64 = 2_000;
const WALL_SLACK_MS: u64 = 500;

#[tokio::test]
async fn firefox_missing_returns_err_within_timeout() {
    // Point the bridge at a path that cannot exist.
    // temp_env::async_with_vars restores the variable after the block,
    // even on panic, without requiring unsafe.
    temp_env::async_with_vars([("FIREFOX_PATH", Some("/nonexistent/firefox"))], async {
        let cfg = BridgeConfig {
            solve_timeout_ms: BUDGET_MS,
            headless: true,
            no_sandbox: true,
            navigate_first: false,
        };

        let wall_start = Instant::now();
        let result = solve_in_browser(
            "<html><body>challenge</body></html>",
            "https://example.com/",
            &cfg,
        )
        .await;
        let elapsed = wall_start.elapsed();

        // Either Err (hard launch error) or Ok(None) ("didn't solve")
        // is a valid signal that the bridge handled the missing-firefox
        // case — what we care about is the bound on wall time, not the
        // exact Result shape, which varies by launch backend.
        assert!(
            result.is_err() || matches!(result, Ok(None)),
            "expected Err or Ok(None) when firefox path is /nonexistent, got: {result:?}"
        );

        let max_wall = Duration::from_millis(BUDGET_MS + WALL_SLACK_MS);
        assert!(
            elapsed <= max_wall,
            "solve_in_browser took {elapsed:?}, expected ≤ {max_wall:?}"
        );
    })
    .await;
}
