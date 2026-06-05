use wafrift_transport::{EvasionClient, is_waf_block};
use wafrift_types::EvasionConfig;

#[test]
fn test_adversarial_is_waf_block_empty_input() {
    assert!(
        !is_waf_block(200, b""),
        "Empty input should not panic or cause issues"
    );
    assert!(
        is_waf_block(403, b""),
        "Empty input with block status should return true"
    );
}

#[test]
fn test_adversarial_is_waf_block_null_bytes() {
    let mut payload = vec![b'\0'; 1024];
    payload.extend_from_slice(b"access denied");
    payload.extend_from_slice(&[b'\0'; 1024]);
    assert!(
        is_waf_block(200, &payload),
        "Null bytes should not hide WAF indicator"
    );
}

#[test]
fn test_adversarial_is_waf_block_0xff_bytes() {
    let mut payload = vec![0xFF; 1024];
    payload.extend_from_slice(b"access denied");
    payload.extend_from_slice(&[0xFF; 1024]);
    assert!(
        is_waf_block(200, &payload),
        "0xFF bytes should not hide WAF indicator"
    );
}

#[test]
fn test_adversarial_is_waf_block_huge_input() {
    let mut payload = vec![b' '; 2 * 1024 * 1024];
    assert!(
        !is_waf_block(200, &payload),
        "Massive input shouldn't panic"
    );

    payload[100..113].copy_from_slice(b"access denied");
    assert!(
        is_waf_block(200, &payload),
        "Indicator at start should be found"
    );
}

#[test]
fn test_adversarial_is_waf_block_unicode_homoglyphs() {
    let payload = b"acc\xC3\xA9ss d\xC3\xA9ni\xC3\xA9d";
    assert!(
        !is_waf_block(200, payload),
        "Unicode homoglyphs might evade signature but shouldn't panic"
    );

    let valid_but_weird = "access denied \u{1F525}".as_bytes();
    assert!(
        is_waf_block(200, valid_but_weird),
        "Should handle valid UTF-8 correctly"
    );
}

#[tokio::test]
async fn test_adversarial_send_max_attempts_integer_bounds() {
    // Adversarial: u32::MAX must be rejected with a structured error
    // (not a panic, not silently clamped). The runtime cap is a
    // hardening: a runaway max_attempts would let a misconfigured
    // attack loop forever or exhaust target-side resources before the
    // operator notices. The cap message must name both the offending
    // value and the ceiling so the operator can pick a sane number.
    let config = EvasionConfig {
        max_attempts: u32::MAX,
        ..Default::default()
    };
    let err = match EvasionClient::with_config(config) {
        Ok(_) => panic!("u32::MAX max_attempts must be rejected"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("max_attempts") && msg.contains(&u32::MAX.to_string()),
        "error must name field and offending value: {msg}"
    );

    // Sanity: a sane max_attempts still constructs cleanly.
    let ok_config = EvasionConfig {
        max_attempts: 100,
        ..Default::default()
    };
    let client = EvasionClient::with_config(ok_config).unwrap();
    let host_state = client.host_state("example.com");
    assert!(host_state.is_none(), "cold-start state must be None");
}
