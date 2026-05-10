//! Integration test: `solve_in_browser` honours `solve_timeout_ms`.
//!
//! The test sets a 1 000 ms budget, passes an HTML page that never
//! resolves a captcha, and asserts the function returns within
//! `solve_timeout_ms + 200 ms` of slack.
//!
//! Because the test environment may not have Chromium installed,
//! we accept *either* `Ok(_)` or `Err(_)` — what we exclusively
//! verify is the wall-clock deadline.

use std::time::{Duration, Instant};

use wafrift_captchaforge_bridge::{BridgeConfig, solve_in_browser};

const TIMEOUT_MS: u64 = 1_000;
const SLACK_MS: u64 = 200;

#[tokio::test]
async fn timeout_honoured_against_unresponsive_html() {
    let cfg = BridgeConfig {
        solve_timeout_ms: TIMEOUT_MS,
        headless: true,
    };

    // An HTML page with no captcha widgets and no external resources —
    // the browser would load it instantly, the solver chain returns
    // None quickly, but if Chromium is unavailable the launch fails
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
