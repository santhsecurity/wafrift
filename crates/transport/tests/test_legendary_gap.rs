use wafrift_transport::is_waf_block;

#[test]
fn waf_block_scan_is_bounded_to_prefix() {
    let mut payload = vec![b' '; 5000];
    payload[4100..4107].copy_from_slice(b"captcha");

    // Implementation intentionally scans only a prefix of the body for performance.
    assert!(!is_waf_block(200, &payload));
}
