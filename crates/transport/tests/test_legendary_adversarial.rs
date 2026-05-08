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
    let config = EvasionConfig {
        max_attempts: u32::MAX,
        ..Default::default()
    };
    let client = EvasionClient::with_config(config).unwrap();

    let host_state = client.host_state("example.com");
    assert!(host_state.is_none());
}
