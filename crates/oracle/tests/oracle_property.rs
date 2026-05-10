//! Property tests: random bodies must not panic and verdicts must be deterministic.

mod common;

use common::{CANON_CMDI, CANON_PATH, CANON_SSRF};
use proptest::prelude::*;
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn cmdi_random_body_stable(body in prop::collection::vec(any::<u8>(), 0..8192)) {
        let s = String::from_utf8_lossy(&body);
        let oracle = CmdiOracle;
        let a = oracle.is_semantically_valid(CANON_CMDI, &s);
        let b = oracle.is_semantically_valid(CANON_CMDI, &s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn path_random_body_stable(body in prop::collection::vec(any::<u8>(), 0..8192)) {
        let s = String::from_utf8_lossy(&body);
        let oracle = PathOracle;
        let a = oracle.is_semantically_valid(CANON_PATH, &s);
        let b = oracle.is_semantically_valid(CANON_PATH, &s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn ssrf_random_body_stable(body in prop::collection::vec(any::<u8>(), 0..8192)) {
        let s = String::from_utf8_lossy(&body);
        let oracle = SsrfOracle;
        let a = oracle.is_semantically_valid(CANON_SSRF, &s);
        let b = oracle.is_semantically_valid(CANON_SSRF, &s);
        prop_assert_eq!(a, b);
    }
}
