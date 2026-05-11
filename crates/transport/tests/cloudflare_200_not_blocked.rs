//! Regression test: a 200 OK response served by Cloudflare must NOT be
//! classified as blocked. Pre-fix: the profile matcher counted any
//! `Server: cloudflare` header as +2 and treated the response as
//! "soft block" because the status (200) wasn't in
//! `block_status_codes`. Result: every benign Cloudflare-fronted
//! site (example.com, anything on Pages, anything on Workers) showed
//! as "blocked 5/5" in the proxy TUI Hosts/Overview tabs.
//!
//! Fix: SoftBlock now requires a body-marker hit, not just a header
//! identification. Header-only match means "vendor identified" but
//! the request still passed.

use wafrift_transport::ResponseProfileDb;

#[test]
fn cloudflare_200_with_benign_body_classifies_as_pass() {
    let db = ResponseProfileDb::compiled_in();
    let headers = vec![
        ("Server".to_string(), "cloudflare".to_string()),
        ("CF-Cache-Status".to_string(), "HIT".to_string()),
        ("Cf-Ray".to_string(), "abc123-LHR".to_string()),
    ];
    let body = b"<html><body><h1>Example Domain</h1>\
        <p>This domain is for use in illustrative examples in documents.</p>\
        </body></html>";
    let signal = db.classify(200, &headers, body);
    assert!(
        !signal.classification.is_blocked(),
        "200 OK + Cloudflare-only headers must NOT classify as blocked, \
         got {:?}",
        signal.classification
    );
}

#[test]
fn cloudflare_403_with_block_body_classifies_as_hard_block() {
    // Positive twin: a real Cloudflare block (403 + body marker)
    // still classifies correctly.
    let db = ResponseProfileDb::compiled_in();
    let headers = vec![("Server".to_string(), "cloudflare".to_string())];
    let body = b"Attention Required! | Cloudflare\nerror code: 1020";
    let signal = db.classify(403, &headers, body);
    assert!(
        signal.classification.is_blocked(),
        "403 + Cloudflare block-page markers must classify as blocked, \
         got {:?}",
        signal.classification
    );
}

#[test]
fn cloudflare_200_with_challenge_body_still_classifies_as_challenge() {
    // The Challenge-detection path (200 + "challenge-platform" + body
    // mentioning "captcha" + "cloudflare") is separate from the
    // header-only-match path and must still fire so the engine
    // backs off + waits for the cookie instead of blasting more
    // requests at the captcha.
    let db = ResponseProfileDb::compiled_in();
    let headers = vec![("Server".to_string(), "cloudflare".to_string())];
    let body = b"<script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate.js\"></script>";
    let signal = db.classify(200, &headers, body);
    // Whether it is Challenge or SoftBlock, the engine MUST treat it
    // as not-pass — what we're guarding against is the false PASS
    // misclassification of an actual challenge page.
    let classification = &signal.classification;
    assert!(
        classification.should_backoff() || classification.is_blocked(),
        "200 + challenge-platform must trigger backoff or block, \
         got {classification:?}"
    );
}
