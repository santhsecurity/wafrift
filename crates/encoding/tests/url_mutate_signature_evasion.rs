//! Property tests for `UrlStrategy::PercentEncodeAggressive`: every
//! non-alphanumeric byte must be `%XX`-encoded (no RFC 3986 safe-set
//! pass-through for `-._~`).

use proptest::prelude::*;
use wafrift_encoding::url_mutate::UrlStrategy;

/// Walk `encoded` in lockstep with `input` — the aggressive encoder's
/// contract is order-preserving with 1→1 or 1→3 expansion per byte.
fn assert_aggressive_encoding(input: &[u8], encoded: &str) {
    let out = encoded.as_bytes();
    let mut i = 0;
    for &b in input {
        if b.is_ascii_alphanumeric() {
            assert_eq!(
                out.get(i),
                Some(&b),
                "alphanumeric byte {b} must pass through at index {i}"
            );
            i += 1;
        } else {
            let expected = format!("%{b:02X}");
            let slice = out.get(i..i + 3).expect("triplet present");
            assert_eq!(
                slice,
                expected.as_bytes(),
                "byte {b} must encode as {expected}"
            );
            i += 3;
        }
    }
    assert_eq!(i, out.len(), "no trailing garbage in encoded output");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_percent_encode_aggressive_contract(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let (encoded, label) = UrlStrategy::PercentEncodeAggressive.apply_bytes_with_label(&bytes);
        prop_assert_eq!(label, "url:percent_encode");
        assert_aggressive_encoding(&bytes, &encoded);
        prop_assert!(encoded.len() <= bytes.len().saturating_mul(3));
    }

    #[test]
    fn prop_url_safe_set_bytes_are_never_literal(
        safe_byte in prop::sample::select(vec![b'-', b'.', b'_', b'~'])
    ) {
        let input = [safe_byte];
        let encoded = UrlStrategy::PercentEncodeAggressive.apply_bytes(&input);
        prop_assert!(
            !encoded.as_bytes().contains(&safe_byte),
            "URL safe-set byte {safe_byte} must not appear literally; got {encoded}"
        );
        assert_aggressive_encoding(&input, &encoded);
    }

    #[test]
    fn prop_apply_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = UrlStrategy::PercentEncodeAggressive.apply_bytes(&bytes);
    }
}
