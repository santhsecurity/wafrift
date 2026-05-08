use proptest::prelude::*;
use wafrift_transport::{is_waf_block, is_waf_block_status};

proptest! {
    #[test]
    fn prop_is_waf_block_status_never_panics(status in any::<u16>()) {
        let _ = is_waf_block_status(status);
    }

    #[test]
    fn prop_is_waf_block_never_panics(status in any::<u16>(), body in any::<Vec<u8>>()) {
        let _ = is_waf_block(status, &body);
    }
}
