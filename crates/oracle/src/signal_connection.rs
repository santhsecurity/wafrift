//! Connection-behavior signal extractor.
//!
//! Translates low-level connection events into classification signals.

use wafrift_types::{ConnectionBehavior, Signal};

/// Classify a connection event into a signal.
#[must_use]
pub fn classify_connection(behavior: ConnectionBehavior) -> Signal {
    Signal::ConnectionBehavior(behavior)
}

/// Map a boolean "connection reset" flag into a signal.
#[must_use]
pub fn tcp_reset() -> Signal {
    Signal::ConnectionBehavior(ConnectionBehavior::TcpReset)
}

/// Map a 200-OK-with-block-page scenario into a signal.
#[must_use]
pub fn ok_with_block_page() -> Signal {
    Signal::ConnectionBehavior(ConnectionBehavior::OkWithBlockPage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_reset_signal() {
        let s = tcp_reset();
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::TcpReset)
        ));
    }

    #[test]
    fn ok_block_page_signal() {
        let s = ok_with_block_page();
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::OkWithBlockPage)
        ));
    }
}
