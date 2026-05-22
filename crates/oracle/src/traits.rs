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

    // ── Property tests on a conservative reference impl ────

    /// A more realistic oracle that requires the transform to
    /// preserve a `KEY` substring.  Exercises the "conservative"
    /// validation contract.
    struct PreservesKeyOracle;

    impl PayloadOracle for PreservesKeyOracle {
        fn is_semantically_valid(&self, original: &str, transformed: &str) -> bool {
            // The original must contain the key for the oracle to
            // even be applicable; rejection on key-loss in the
            // transform is the documented contract.
            if !original.contains("KEY") {
                return false;
            }
            transformed.contains("KEY")
        }

        fn name(&self) -> &'static str {
            "preserves-key"
        }
    }

    #[test]
    fn oracle_rejects_when_key_lost_in_transform() {
        let o = PreservesKeyOracle;
        assert!(!o.is_semantically_valid("KEY: 1", "1"));
        assert!(!o.is_semantically_valid("KEY: 1", ""));
    }

    #[test]
    fn oracle_accepts_when_key_preserved_in_transform() {
        let o = PreservesKeyOracle;
        assert!(o.is_semantically_valid("KEY: 1", "KEY: 2"));
        assert!(o.is_semantically_valid("KEY: 1", "before KEY after"));
    }

    #[test]
    fn oracle_rejects_when_original_lacks_required_property() {
        // Contract: oracle returns false when original itself
        // doesn't satisfy the precondition — defensive.
        let o = PreservesKeyOracle;
        assert!(!o.is_semantically_valid("no key here", "KEY: still no"));
    }

    #[test]
    fn oracle_name_is_static_and_constant() {
        // The name should be a static reference that doesn't
        // allocate per call.
        let o1 = EchoOracle;
        let o2 = EchoOracle;
        // Same pointer / same content.
        assert_eq!(o1.name(), o2.name());
        assert_eq!(o1.name(), "echo");
    }

    #[test]
    fn oracle_trait_supports_dyn_dispatch() {
        // Build a heterogeneous oracle vec — the trait must be
        // dyn-compatible (object-safe).
        let oracles: Vec<Box<dyn PayloadOracle>> = vec![
            Box::new(EchoOracle),
            Box::new(PreservesKeyOracle),
        ];
        assert_eq!(oracles.len(), 2);
        assert_ne!(oracles[0].name(), oracles[1].name());
    }

    #[test]
    fn oracle_can_be_shared_across_threads_via_arc() {
        use std::sync::Arc;
        let o: Arc<dyn PayloadOracle> = Arc::new(EchoOracle);
        let clone = o.clone();
        // Validation produces deterministic results across
        // shared references.
        assert_eq!(
            o.is_semantically_valid("x", "y"),
            clone.is_semantically_valid("x", "y"),
        );
    }

    #[test]
    fn empty_string_transform_handled_by_echo() {
        let o = EchoOracle;
        assert!(!o.is_semantically_valid("anything", ""));
        assert!(o.is_semantically_valid("", "non-empty"));
    }

    #[test]
    fn unicode_payload_passes_through_oracle_check() {
        let o = EchoOracle;
        assert!(o.is_semantically_valid("café", "🦀"));
        assert!(!o.is_semantically_valid("any", ""));
    }
}
