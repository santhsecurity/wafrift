//! Concrete calibration scenarios — multi-control prioritisation, the
//! status-over-body precedence, the operator `describe()` strings, and the
//! control battery's multi-class coverage. Complements the inline unit tests.

use wafrift_liveoracle::calibration::{Baseline, benign_control, calibrate, malicious_controls};
use wafrift_liveoracle::verdict::LiveVerdict;

fn b(status: u16, body: &str, control: &str) -> Baseline {
    Baseline {
        status,
        body: body.as_bytes().to_vec(),
        control: control.as_bytes().to_vec(),
    }
}

#[test]
fn calibrates_on_a_real_block_while_skipping_a_leading_reflection() {
    // The XSS control reflects (reached the app); the SQLi control is blocked.
    // Calibration must skip the reflection and learn the real block.
    let benign = b(200, "search results page footer nav", "benign_marker");
    let reflected_xss = b(
        200,
        "you searched for <script>alert(1)</script> here",
        "<script>alert(1)</script>",
    );
    let blocked_sqli = b(403, "Forbidden by policy", "1' OR '1'='1");
    let cal = calibrate(benign, vec![reflected_xss, blocked_sqli])
        .expect("the blocked SQLi control must calibrate");
    assert_eq!(cal.classify(403, b"anything"), Some(LiveVerdict::Blocked));
    assert_eq!(
        cal.classify(200, b"search results page footer nav"),
        Some(LiveVerdict::Allowed)
    );
}

#[test]
fn a_distinct_status_is_preferred_over_a_body_signal() {
    // Benign 200 vs blocked 403 — even with overlapping body text, the status
    // discriminator is chosen and classifies purely by code.
    let benign = b(200, "the application landing page content", "c");
    let blocked = b(
        403,
        "the application landing page content denied",
        "1' OR '1'='1",
    );
    let cal = calibrate(benign, vec![blocked]).expect("distinct status calibrates");
    // A 403 with a totally different body is still Blocked (status-driven).
    assert_eq!(
        cal.classify(403, b"unrelated body"),
        Some(LiveVerdict::Blocked)
    );
    assert!(
        cal.describe().to_lowercase().contains("status"),
        "describe: {}",
        cal.describe()
    );
}

#[test]
fn a_body_discriminator_describes_a_block_page() {
    let benign = b(
        200,
        "results for your query item one item two item three",
        "c",
    );
    let blocked = b(
        200,
        "access denied attack detected request id 4910 contact support",
        "1' OR '1'='1",
    );
    let cal = calibrate(benign, vec![blocked]).expect("distinct 200 bodies calibrate");
    let d = cal.describe().to_lowercase();
    assert!(
        d.contains("block page") || d.contains("body"),
        "describe: {d}"
    );
}

#[test]
fn classify_returns_none_for_an_unfamiliar_status_under_a_status_discriminator() {
    let benign = b(200, "home", "c");
    let blocked = b(403, "forbidden", "1' OR '1'='1");
    let cal = calibrate(benign, vec![blocked]).expect("status calibrates");
    // 500 is neither the learned benign (200) nor the learned block (403).
    assert_eq!(
        cal.classify(500, b"server error"),
        None,
        "an unknown status must defer"
    );
}

#[test]
fn all_reflected_controls_decline_calibration() {
    let benign = b(200, "template header footer nav body", "benign_marker");
    // Every malicious control reflects → nothing learnable → decline.
    let controls = vec![
        b(
            200,
            "echo: <script>alert(1)</script>",
            "<script>alert(1)</script>",
        ),
        b(200, "echo: 1' OR '1'='1", "1' OR '1'='1"),
        b(200, "echo: ../../etc/passwd", "../../etc/passwd"),
    ];
    assert!(
        calibrate(benign, controls).is_none(),
        "all-reflection target must decline"
    );
}

#[test]
fn the_malicious_control_battery_spans_multiple_attack_classes() {
    // A target that polices only one class must still be calibratable via another
    // — so the battery must carry XSS, SQLi, traversal, and command-injection.
    let controls = malicious_controls();
    assert!(
        controls.iter().any(|c| c.contains("<script")),
        "needs an XSS control"
    );
    assert!(
        controls.iter().any(|c| c.contains("OR '1'='1")),
        "needs a SQLi control"
    );
    assert!(
        controls.iter().any(|c| c.contains("etc/passwd")),
        "needs a traversal control"
    );
    assert!(
        controls.iter().any(|c| c.contains("cat ")),
        "needs a command-injection control"
    );
}

#[test]
fn the_benign_control_is_a_stable_harmless_token() {
    let benign = benign_control();
    assert!(!benign.is_empty());
    // No HTML/SQL metacharacters — a WAF must not plausibly block it.
    assert!(!benign.contains('<') && !benign.contains('\''));
}

#[test]
fn a_calibration_is_cloneable_and_classifies_identically() {
    let benign = b(200, "home page", "c");
    let blocked = b(403, "denied", "1' OR '1'='1");
    let cal = calibrate(benign, vec![blocked]).expect("calibrates");
    let clone = cal.clone();
    assert_eq!(cal.classify(403, b""), clone.classify(403, b""));
    assert_eq!(cal.classify(200, b""), clone.classify(200, b""));
}
