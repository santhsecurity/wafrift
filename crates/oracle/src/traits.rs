//! Payload oracle trait — validates that evasion transforms preserve semantic meaning.
//!
//! Each injection type (SQL, XSS, SSTI, CMDI, path traversal) has different
//! structural invariants. The Oracle trait provides a uniform interface for
//! the MCTS engine to verify that a transformed payload retains its exploit
//! semantics.

/// A payload oracle that validates semantic preservation across transforms.
///
/// The MCTS engine calls `is_semantically_valid` after each transform step
/// to verify the payload hasn't been destroyed. If the oracle returns `false`,
/// the MCTS node is scored as a `Loss`.
pub trait PayloadOracle: Send + Sync {
    /// Returns `true` if `transformed` retains the exploit semantics of `original`.
    ///
    /// # Arguments
    ///
    /// * `original` — The pre-transform payload (known-good injection).
    /// * `transformed` — The post-transform payload to validate.
    ///
    /// # Contract
    ///
    /// Implementations should be conservative: return `true` only when the
    /// transformed payload is highly likely to trigger the same server-side
    /// behavior as the original. False negatives (rejecting a valid transform)
    /// are preferable to false positives (accepting a broken payload).
    fn is_semantically_valid(&self, original: &str, transformed: &str) -> bool;

    /// Human-readable name of this oracle (e.g., "SQL", "XSS").
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial oracle for testing the trait interface.
    struct EchoOracle;

    impl PayloadOracle for EchoOracle {
        fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
            !transformed.is_empty()
        }

        fn name(&self) -> &'static str {
            "echo"
        }
    }

    #[test]
    fn trait_object_works() {
        let oracle: Box<dyn PayloadOracle> = Box::new(EchoOracle);
        assert!(oracle.is_semantically_valid("test", "test"));
        assert!(!oracle.is_semantically_valid("test", ""));
        assert_eq!(oracle.name(), "echo");
    }

    #[test]
    fn trait_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn PayloadOracle>>();
    }
}
