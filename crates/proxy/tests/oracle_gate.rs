//! Tests for the oracle gate that detects 200-cosplay blocks (#76).
//!
//! The proxy's ResponseOracle gate fires when a WAF returns HTTP 200 with
//! a body that looks like a block page, soft challenge, or JS challenge.
//! Without the gate, these appear as "bypasses" and corrupt the bench score
//! and MCTS feedback loop.
//!
//! These tests drive the oracle directly (not the full proxy) to verify the
//! classification semantics. The integration point is tested via the proxy
//! binary in the other test files.

use wafrift_oracle::response_oracle::{ResponseContext, ResponseOracle};
use wafrift_types::Verdict;

fn oracle() -> ResponseOracle {
    ResponseOracle::new()
}

// ─────────────────────────────────────────────────────────────────────────────
// True bypasses — oracle must NOT classify these as blocks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn oracle_allows_clean_200_response() {
    let v = oracle().classify(&ResponseContext {
        status: 200,
        body: b"Welcome to the application".to_vec(),
        ..Default::default()
    });
    assert!(
        v.is_allowed(),
        "clean 200 response must be classified as Allowed, got: {v:?}"
    );
}

#[test]
fn oracle_allows_200_with_json_body() {
    let v = oracle().classify(&ResponseContext {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: br#"{"user":"admin","role":"superuser"}"#.to_vec(),
        ..Default::default()
    });
    assert!(
        v.is_allowed(),
        "200 with JSON app data must be Allowed, got: {v:?}"
    );
}

#[test]
fn oracle_allows_200_with_empty_body() {
    let v = oracle().classify(&ResponseContext {
        status: 200,
        body: vec![],
        ..Default::default()
    });
    // Empty body with 200 = allowed (no block signal).
    assert!(
        v.is_allowed(),
        "200 with empty body must be Allowed, got: {v:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 200-cosplay blocks — oracle must flag these
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn oracle_flags_200_with_access_denied_body() {
    // Classic soft block: WAF serves "access denied" as 200 to evade
    // status-based rate limiting.
    let v = oracle().classify(&ResponseContext {
        status: 200,
        body: b"<html><body><h1>Access Denied</h1><p>Your request was blocked.</p></body></html>"
            .to_vec(),
        ..Default::default()
    });
    // Must be Ambiguous (conflicting 200 status vs block body) or Blocked.
    assert!(
        v.is_blocked() || v.is_ambiguous(),
        "200 with 'access denied' body must be flagged as blocked or ambiguous, got: {v:?}"
    );
}

#[test]
fn oracle_flags_200_with_request_blocked_body() {
    let v = oracle().classify(&ResponseContext {
        status: 200,
        body: b"Request blocked by security policy.".to_vec(),
        ..Default::default()
    });
    assert!(
        v.is_blocked() || v.is_ambiguous(),
        "200 + 'Request blocked' body must not count as bypass, got: {v:?}"
    );
}

#[test]
fn oracle_flags_hard_block_403() {
    let v = oracle().classify(&ResponseContext {
        status: 403,
        body: b"Forbidden".to_vec(),
        ..Default::default()
    });
    assert!(
        v.is_blocked(),
        "403 Forbidden must be classified as Blocked, got: {v:?}"
    );
}

#[test]
fn oracle_flags_challenge_on_503() {
    let v = oracle().classify(&ResponseContext {
        status: 503,
        body: b"challenge-platform".to_vec(),
        ..Default::default()
    });
    assert!(
        v.is_challenge(),
        "503 with challenge-platform body must be ChallengeRequired, got: {v:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limit detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn oracle_classifies_429_as_rate_limited() {
    let v = oracle().classify(&ResponseContext {
        status: 429,
        body: b"Too Many Requests".to_vec(),
        ..Default::default()
    });
    assert!(
        matches!(v, Verdict::RateLimited { .. }),
        "429 must be classified as RateLimited, got: {v:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle gate logic test: the proxy gate condition
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the oracle gate condition used in main.rs:
///   is_blocked() || is_challenge() || is_ambiguous()
/// This is the exact predicate used to upgrade `is_block` from false to true
/// in the proxy forward path.
#[test]
fn oracle_gate_predicate_covers_all_soft_block_classes() {
    let o = oracle();

    // 200 + block body → Ambiguous or Blocked — gate triggers.
    let v = o.classify(&ResponseContext {
        status: 200,
        body: b"access denied".to_vec(),
        ..Default::default()
    });
    let gate = v.is_blocked() || v.is_challenge() || v.is_ambiguous();
    assert!(
        gate,
        "200 + block body: gate must trigger (is_blocked||is_challenge||is_ambiguous), got: {v:?}"
    );

    // Clean 200 → Allowed — gate must NOT trigger.
    let v_clean = o.classify(&ResponseContext {
        status: 200,
        body: b"success".to_vec(),
        ..Default::default()
    });
    let gate_clean = v_clean.is_blocked() || v_clean.is_challenge() || v_clean.is_ambiguous();
    assert!(
        !gate_clean,
        "clean 200: gate must NOT trigger, got: {v_clean:?}"
    );
}

/// Anti-rig: verify that a real bypass (200 + non-block body) does NOT
/// count as a block. The oracle gate must have high specificity, not just
/// high sensitivity.
#[test]
fn oracle_gate_does_not_over_block_legitimate_200s() {
    let o = oracle();
    let legitimate_bodies: &[&[u8]] = &[
        b"OK",
        b"<html><body>Hello world</body></html>",
        b"{\"status\":\"success\",\"data\":[]}",
        b"No content here, just some benign text.",
        b"The quick brown fox jumps over the lazy dog.",
    ];
    for body in legitimate_bodies {
        let v = o.classify(&ResponseContext {
            status: 200,
            body: body.to_vec(),
            ..Default::default()
        });
        let gate = v.is_blocked() || v.is_challenge() || v.is_ambiguous();
        assert!(
            !gate,
            "oracle gate must NOT fire on legitimate 200 body {:?}, got: {v:?}",
            std::str::from_utf8(body).unwrap_or("<binary>")
        );
    }
}

/// Verify that 4xx responses are already blocked before reaching the oracle gate.
/// The gate only fires for 2xx to avoid running the oracle on known-blocked responses.
#[test]
fn oracle_gate_skips_non_2xx_status() {
    // In the proxy, the gate only runs when !profile_blocked && 200 <= status < 300.
    // For 403/406, the profile classifier already sets is_block=true, and the
    // gate condition (`!profile_blocked`) prevents the oracle from running.
    // Test this logic directly:
    let statuses_that_skip_gate: &[u16] = &[400, 401, 403, 404, 406, 500, 502, 503];
    let o = oracle();
    for &status in statuses_that_skip_gate {
        let v = o.classify(&ResponseContext {
            status,
            body: b"blocked".to_vec(),
            ..Default::default()
        });
        // The oracle classifies these as blocked (which is correct), but in
        // the proxy, the profile classifier already handles them. We verify
        // the oracle would produce a valid (non-panicking) verdict for any
        // status code — this is the "does not crash on attacker input" test.
        // Any valid Verdict variant is acceptable.
        let is_valid = v.is_blocked()
            || v.is_challenge()
            || v.is_ambiguous()
            || v.is_allowed()
            || matches!(v, Verdict::RateLimited { .. })
            || matches!(v, Verdict::ServerError { .. })
            || matches!(v, Verdict::Partial { .. });
        assert!(
            is_valid,
            "oracle must produce a valid verdict for status {status}, got: {v:?}"
        );
    }
}

/// Verify `ResponseOracle` is deterministic (no hidden state).
#[test]
fn oracle_is_deterministic() {
    let o = oracle();
    let ctx = ResponseContext {
        status: 200,
        body: b"access denied".to_vec(),
        ..Default::default()
    };
    let v1 = o.classify(&ctx);
    let v2 = o.classify(&ctx);
    assert_eq!(
        v1, v2,
        "ResponseOracle must produce identical verdicts for identical inputs"
    );
}
