//! Integration test: `solve_in_browser` returns `Err` cleanly when
//! `CHROMIUM_PATH` points to a non-existent binary.
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
async fn chromium_missing_returns_err_within_timeout() {
    // Point the bridge at a path that cannot exist.
    // temp_env::async_with_vars restores the variable after the block,
    // even on panic, without requiring unsafe.
    temp_env::async_with_vars([("CHROMIUM_PATH", Some("/nonexistent/chromium"))], async {
        let cfg = BridgeConfig {
            solve_timeout_ms: BUDGET_MS,
            headless: true,
        };

        let wall_start = Instant::now();
        let result = solve_in_browser(
            "<html><body>challenge</body></html>",
            "https://example.com/",
            &cfg,
        )
        .await;
        let elapsed = wall_start.elapsed();

        assert!(
            result.is_err(),
            "expected Err when chromium path is /nonexistent, got: {result:?}"
        );

        let max_wall = Duration::from_millis(BUDGET_MS + WALL_SLACK_MS);
        assert!(
            elapsed <= max_wall,
            "solve_in_browser took {elapsed:?}, expected ≤ {max_wall:?}"
        );
    })
    .await;
}
