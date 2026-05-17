//! Adversarial audit of `response.rs` and `signal.rs` classification:
//!   - 429 / 451 must NOT be treated as WAF blocks
//!   - Vendor names in benign 200 bodies must NOT trigger block detection
//!   - Legacy body check must NOT false-positive on tutorial content
//!   - Double-counting of overlapping body markers must be capped
//!   - `client.rs` must back off on 429 instead of escalating evasion

use std::time::Duration;
use wafrift_transport::{BlockClass, EvasionClient, ResponseProfileDb, is_waf_block, is_waf_block_status};
use wafrift_types::EvasionConfig;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── response.rs adversarial twins ───────────────────────────────────

#[test]
fn status_429_is_not_a_waf_block() {
    assert!(
        !is_waf_block_status(429),
        "429 rate-limit must NOT be treated as a block status"
    );
    assert!(
        !is_waf_block(429, b"Too Many Requests"),
        "429 body must NOT trigger block detection"
    );
}

#[test]
fn status_451_is_not_a_waf_block() {
    assert!(
        !is_waf_block_status(451),
        "451 legal takedown must NOT be treated as a block status"
    );
    assert!(
        !is_waf_block(451, b"Unavailable For Legal Reasons"),
        "451 body must NOT trigger block detection"
    );
}

#[test]
fn benign_blog_about_cloudflare_not_blocked() {
    let body = b"<h1>How Cloudflare Works</h1><p>Cloudflare is a CDN.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 blog post mentioning Cloudflare must NOT be blocked"
    );
}

#[test]
fn benign_blog_about_akamai_not_blocked() {
    let body = b"<h1>Akamai Edge Platform Overview</h1><p>Akamai delivers content.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 blog post mentioning Akamai must NOT be blocked"
    );
}

#[test]
fn benign_blog_about_imperva_not_blocked() {
    let body = b"<h1>Imperva WAF Review</h1><p>Imperva protects applications.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 blog post mentioning Imperva must NOT be blocked"
    );
}

#[test]
fn benign_tutorial_with_firewall_not_blocked() {
    let body = b"<h1>Network Firewalls 101</h1><p>A firewall inspects packets.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 tutorial mentioning firewall must NOT be blocked"
    );
}

#[test]
fn benign_tutorial_with_forbidden_not_blocked() {
    let body = b"<h1>HTTP Status Codes</h1><p>403 Forbidden means refusal.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 tutorial mentioning Forbidden must NOT be blocked"
    );
}

#[test]
fn benign_security_check_not_blocked() {
    let body = b"<h1>Security Checklist</h1><p>Run a security check monthly.</p>";
    assert!(
        !is_waf_block(200, body),
        "benign 200 security checklist must NOT be blocked"
    );
}

// Positive twins: real block pages must still be detected

#[test]
fn real_access_denied_still_blocked() {
    assert!(
        is_waf_block(200, b"<h1>Access Denied</h1><p>Your request was blocked.</p>"),
        "real block page with 'Access Denied' must still be detected"
    );
}

#[test]
fn real_attention_required_still_blocked() {
    assert!(
        is_waf_block(200, b"Attention Required! | Cloudflare"),
        "real block page with 'Attention Required' must still be detected"
    );
}

#[test]
fn real_captcha_still_blocked() {
    assert!(
        is_waf_block(200, b"Please complete the captcha to continue"),
        "real captcha page must still be detected"
    );
}

#[test]
fn real_automated_request_still_blocked() {
    assert!(
        is_waf_block(200, b"Automated request detected and blocked"),
        "real automated-request block page must still be detected"
    );
}

// ── signal.rs adversarial twins ─────────────────────────────────────

#[test]
fn signal_451_is_pass_not_hard_block() {
    let db = ResponseProfileDb::compiled_in();
    let sig = db.classify(451, &[], b"Unavailable For Legal Reasons");
    assert_eq!(sig.classification, BlockClass::Pass);
}

#[test]
fn signal_benign_tutorial_not_soft_blocked() {
    let db = ResponseProfileDb::compiled_in();
    let body = b"<h1>HTTP Status Codes</h1><p>403 Forbidden means refusal.</p>";
    let sig = db.classify(200, &[], body);
    assert_eq!(sig.classification, BlockClass::Pass);
}

#[test]
fn signal_benign_firewall_tutorial_not_soft_blocked() {
    let db = ResponseProfileDb::compiled_in();
    let body = b"<h1>Network Firewalls</h1><p>A firewall inspects traffic.</p>";
    let sig = db.classify(200, &[], body);
    assert_eq!(sig.classification, BlockClass::Pass);
}

#[test]
fn signal_double_count_capped() {
    // F5 profile has overlapping markers: "support ID" and "Your support ID is".
    // Both match the same text. Score must cap at +3, not +6.
    let db = ResponseProfileDb::compiled_in();
    let body = b"Your support ID is 12345";
    let sig = db.classify(200, &[], body);
    assert_eq!(sig.matched_waf.as_deref(), Some("F5 BIG-IP ASM"));
    assert_eq!(sig.classification, BlockClass::SoftBlock);
}

#[test]
fn signal_rate_limit_429_from_profile() {
    let db = ResponseProfileDb::compiled_in();
    let sig = db.classify(429, &[("x-amzn-RequestId".into(), "abc".into())], b"Too many requests");
    assert_eq!(sig.classification, BlockClass::RateLimit);
    assert!(!sig.classification.is_blocked());
    assert!(sig.classification.should_backoff());
}

#[test]
fn signal_cloudflare_challenge_503_backoff() {
    let db = ResponseProfileDb::compiled_in();
    let body = b"<script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate.js\"></script>";
    let sig = db.classify(503, &[("Server".into(), "cloudflare".into())], body);
    assert_eq!(sig.classification, BlockClass::Challenge);
    assert!(!sig.classification.is_blocked());
    assert!(sig.classification.should_backoff());
}

// ── client.rs adversarial twins ─────────────────────────────────────

#[tokio::test]
async fn client_429_backoffs_instead_of_escalating() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limit exceeded"))
        .mount(&mock_server)
        .await;

    let config = EvasionConfig {
        max_attempts: 2,
        allow_private_upstream: true,
        ..Default::default()
    };
    let client = EvasionClient::with_config(config).unwrap();
    let target_url = format!("{}/api", mock_server.uri());

    let start = std::time::Instant::now();
    let result = client.get(&target_url).await.expect("request completes");
    let elapsed = start.elapsed();

    // With 2 attempts and 1-second backoff between them, total time
    // should be at least 1 second.
    assert!(
        elapsed >= Duration::from_millis(900),
        "429 must trigger backoff; elapsed was {elapsed:?}"
    );
    assert!(
        !result.was_blocked,
        "429 must NOT be classified as blocked"
    );
}

#[tokio::test]
async fn client_451_not_blocked_and_not_retried_as_evasion() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(451).set_body_string("Unavailable For Legal Reasons"))
        .mount(&mock_server)
        .await;

    let config = EvasionConfig {
        max_attempts: 3,
        allow_private_upstream: true,
        ..Default::default()
    };
    let client = EvasionClient::with_config(config).unwrap();
    let target_url = format!("{}/legal", mock_server.uri());

    let result = client.get(&target_url).await.expect("request completes");

    assert!(
        !result.was_blocked,
        "451 legal takedown must NOT be classified as blocked"
    );
    assert_eq!(result.attempts, 1, "451 must NOT trigger evasion retries");
}
