//! Connection-behavior signal extractor.
//!
//! Translates low-level connection events into classification signals.

use wafrift_types::{ConnectionBehavior, Signal};

/// Classify a connection event into a signal.
#[must_use]
pub fn classify_connection(behavior: ConnectionBehavior) -> Signal {
    Signal::ConnectionBehavior(behavior)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_connection_tcp_reset() {
        let s = classify_connection(ConnectionBehavior::TcpReset);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::TcpReset)
        ));
    }

    #[test]
    fn classify_connection_ok_block_page() {
        let s = classify_connection(ConnectionBehavior::OkWithBlockPage);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::OkWithBlockPage)
        ));
    }

    // -- §12 full-variant coverage ------------------------------------------
    // Every ConnectionBehavior variant must round-trip through the signal
    // without loss. Each test pins that the wrapper is not accidentally
    // folding different variants into the same signal.

    #[test]
    fn classify_connection_ok_with_immediate_close() {
        let s = classify_connection(ConnectionBehavior::OkWithImmediateClose);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::OkWithImmediateClose)
        ));
    }

    #[test]
    fn classify_connection_graceful_close() {
        let s = classify_connection(ConnectionBehavior::GracefulClose);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::GracefulClose)
        ));
    }

    #[test]
    fn classify_connection_timeout() {
        let s = classify_connection(ConnectionBehavior::Timeout);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::Timeout)
        ));
    }

    #[test]
    fn classify_connection_tls_error() {
        let s = classify_connection(ConnectionBehavior::TlsError);
        assert!(matches!(
            s,
            Signal::ConnectionBehavior(ConnectionBehavior::TlsError)
        ));
    }

    #[test]
    fn all_variants_produce_distinct_signals() {
        // Sanity: no two different variants should be `==` when compared
        // as signals. Uses Debug to identify variant without PartialEq on Signal.
        let variants = [
            ConnectionBehavior::TcpReset,
            ConnectionBehavior::OkWithImmediateClose,
            ConnectionBehavior::OkWithBlockPage,
            ConnectionBehavior::GracefulClose,
            ConnectionBehavior::Timeout,
            ConnectionBehavior::TlsError,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    continue;
                }
                let s1 = format!("{:?}", classify_connection(v1.clone()));
                let s2 = format!("{:?}", classify_connection(v2.clone()));
                assert_ne!(s1, s2, "variants {i} and {j} produced identical signals");
            }
        }
    }
}
