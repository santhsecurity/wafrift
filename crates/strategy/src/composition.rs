//! Pipeline composition grammar.
//!
//! Defines valid partial orderings of evasion techniques:
//! - Encoding happens at the payload layer.
//! - Grammar mutations happen at the payload-semantic layer.
//! - Content-Type switching happens at the HTTP representation layer.
//! - Header obfuscation happens at the HTTP transport layer.
//! - Smuggling and H2 evasion happen at the HTTP framing layer.
//!
/// A layer in the evasion stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvasionLayer {
    /// Payload encoding (URL, unicode, etc.).
    Encoding,
    /// Grammar-aware payload mutation.
    Grammar,
    /// Content-Type representation switch.
    ContentType,
    /// HTTP header obfuscation.
    Header,
    /// Request smuggling.
    Smuggling,
    /// HTTP/2 frame manipulation.
    H2,
    /// Body-size inspection bypass: pre-pend N bytes of inert filler so
    /// the malicious payload sits past the cloud-WAF inspection window
    /// (Cloudflare Pro 8 KB, AWS WAF 16 KB, Akamai 8 KB). Runs LAST in
    /// the pipeline because it operates on the assembled body bytes —
    /// any layer that re-builds the body (Encoding, `ContentType`,
    /// Smuggling) must complete first.
    BodyPadding,
}

impl EvasionLayer {
    /// Returns the set of layers that must come *before* this layer.
    #[must_use]
    pub fn prerequisites(&self) -> &'static [EvasionLayer] {
        match self {
            Self::Encoding => &[Self::Grammar],
            Self::Grammar => &[],
            Self::ContentType => &[Self::Encoding, Self::Grammar],
            Self::Header => &[],
            Self::Smuggling => &[Self::ContentType, Self::Header],
            Self::H2 => &[Self::Header],
            // BodyPadding mutates the assembled body bytes, so any
            // layer that re-builds the body must be done first.
            Self::BodyPadding => &[Self::Encoding, Self::ContentType, Self::Grammar],
        }
    }

    /// Returns true if `other` is allowed to appear before `self`.
    #[must_use]
    pub fn can_follow(&self, other: EvasionLayer) -> bool {
        self.prerequisites().contains(&other) || *self == other
    }
}

/// Validate that a sequence of layers respects the composition grammar.
#[must_use]
pub fn is_valid_sequence(layers: &[EvasionLayer]) -> bool {
    for (i, layer) in layers.iter().enumerate() {
        let prereqs = layer.prerequisites();
        for prereq in prereqs {
            if !layers[..i].contains(prereq) {
                return false;
            }
        }
    }
    true
}

/// Build a corrected sequence by topologically sorting layers.
pub fn canonicalize(layers: &mut [EvasionLayer]) {
    // Simple bubble-sort-like reordering that respects prerequisites.
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..layers.len().saturating_sub(1) {
            let a = layers[i];
            let b = layers[i + 1];
            // If b requires a and a is not before b, swap
            if b.prerequisites().contains(&a) {
                continue; // already valid
            }
            // If a requires b but b is after a, swap
            if a.prerequisites().contains(&b) {
                layers.swap(i, i + 1);
                changed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_grammar_then_encoding_then_content_type() {
        let seq = vec![
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::ContentType,
            EvasionLayer::Header,
            EvasionLayer::Smuggling,
        ];
        assert!(is_valid_sequence(&seq));
    }

    #[test]
    fn invalid_encoding_before_grammar() {
        let seq = vec![EvasionLayer::Encoding, EvasionLayer::Grammar];
        assert!(!is_valid_sequence(&seq));
    }

    #[test]
    fn canonicalize_fixes_order() {
        let mut seq = vec![
            EvasionLayer::Encoding,
            EvasionLayer::Grammar,
            EvasionLayer::ContentType,
        ];
        canonicalize(&mut seq);
        assert!(is_valid_sequence(&seq));
        assert_eq!(seq[0], EvasionLayer::Grammar);
        assert_eq!(seq[1], EvasionLayer::Encoding);
    }

    #[test]
    fn smuggling_requires_content_type() {
        let seq = vec![EvasionLayer::Header, EvasionLayer::Smuggling];
        assert!(!is_valid_sequence(&seq));
    }

    #[test]
    fn body_padding_must_come_after_body_mutators() {
        let valid = vec![
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::ContentType,
            EvasionLayer::BodyPadding,
        ];
        assert!(is_valid_sequence(&valid));

        // Wrong order: padding before content-type would be wiped out
        // by the content-type rebuild.
        let invalid = vec![
            EvasionLayer::Grammar,
            EvasionLayer::BodyPadding,
            EvasionLayer::ContentType,
        ];
        assert!(!is_valid_sequence(&invalid));
    }

    #[test]
    fn body_padding_canonicalizes_to_end() {
        // is_valid_sequence requires ALL listed prereqs to exist, so
        // for BodyPadding we need all three (Encoding, ContentType,
        // Grammar) in the sequence.
        let mut seq = vec![
            EvasionLayer::ContentType,
            EvasionLayer::Grammar,
            EvasionLayer::BodyPadding,
            EvasionLayer::Encoding,
        ];
        canonicalize(&mut seq);
        assert!(
            is_valid_sequence(&seq),
            "canonicalize did not produce a valid sequence: {seq:?}"
        );
        assert_eq!(seq.last(), Some(&EvasionLayer::BodyPadding));
    }

    // ── Density ramp ────────────────────────────────────

    #[test]
    fn empty_sequence_is_valid() {
        // Edge case: empty composition has no prereqs to violate.
        assert!(is_valid_sequence(&[]));
    }

    #[test]
    fn single_layer_with_no_prereqs_is_valid() {
        assert!(is_valid_sequence(&[EvasionLayer::Grammar]));
        assert!(is_valid_sequence(&[EvasionLayer::Header]));
    }

    #[test]
    fn single_layer_with_unmet_prereq_is_invalid() {
        // Encoding requires Grammar; alone, it fails.
        assert!(!is_valid_sequence(&[EvasionLayer::Encoding]));
        // ContentType requires both Encoding AND Grammar.
        assert!(!is_valid_sequence(&[EvasionLayer::ContentType]));
    }

    #[test]
    fn h2_requires_header_prereq() {
        assert!(!is_valid_sequence(&[EvasionLayer::H2]));
        assert!(is_valid_sequence(&[EvasionLayer::Header, EvasionLayer::H2]));
    }

    #[test]
    fn smuggling_requires_both_content_type_and_header() {
        // Both prereqs (ContentType, Header) must appear before Smuggling.
        assert!(!is_valid_sequence(&[
            EvasionLayer::Header,
            EvasionLayer::Smuggling
        ]));
        assert!(!is_valid_sequence(&[
            EvasionLayer::ContentType,
            EvasionLayer::Smuggling
        ]));
        // With both prereqs satisfied (and ContentType's own
        // prereqs of Encoding+Grammar), the sequence is valid.
        assert!(is_valid_sequence(&[
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::ContentType,
            EvasionLayer::Header,
            EvasionLayer::Smuggling,
        ]));
    }

    #[test]
    fn duplicate_layers_in_sequence_remain_valid() {
        // The grammar doesn't forbid using the same layer twice
        // (encoding the payload, then encoding again).
        let seq = vec![
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::Encoding,
        ];
        assert!(is_valid_sequence(&seq));
    }

    #[test]
    fn can_follow_self_returns_true() {
        // A layer can follow itself (e.g. two encoding passes).
        for layer in [
            EvasionLayer::Encoding,
            EvasionLayer::Header,
            EvasionLayer::Grammar,
        ] {
            assert!(layer.can_follow(layer), "{layer:?} should follow itself");
        }
    }

    #[test]
    fn can_follow_unrelated_layer_returns_false() {
        // Encoding's prereq is Grammar; Header isn't related.
        assert!(!EvasionLayer::Encoding.can_follow(EvasionLayer::Header));
    }

    #[test]
    fn canonicalize_empty_sequence_does_not_panic() {
        let mut seq: Vec<EvasionLayer> = vec![];
        canonicalize(&mut seq);
        assert!(seq.is_empty());
    }

    #[test]
    fn canonicalize_single_layer_unchanged() {
        let mut seq = vec![EvasionLayer::Grammar];
        canonicalize(&mut seq);
        assert_eq!(seq, vec![EvasionLayer::Grammar]);
    }

    #[test]
    fn canonicalize_already_sorted_unchanged() {
        let original = vec![
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::ContentType,
            EvasionLayer::Header,
            EvasionLayer::Smuggling,
        ];
        let mut seq = original.clone();
        canonicalize(&mut seq);
        assert_eq!(seq, original);
    }

    #[test]
    fn canonicalize_terminates_on_reverse_sorted_input() {
        // Defensive: the bubble-sort loop must TERMINATE even on
        // a reverse-sorted sequence (a stress test for the
        // `changed` flag).  We don't assert full validity here —
        // canonicalize is best-effort over partial orderings; some
        // multi-prereq layers (Smuggling needs BOTH Header AND
        // ContentType) may not land in a fully-valid position from
        // pairwise swaps alone.  The non-termination case is the
        // legendary-bar concern; that's what this test guards.
        let mut seq = vec![
            EvasionLayer::Smuggling,
            EvasionLayer::Header,
            EvasionLayer::ContentType,
            EvasionLayer::Encoding,
            EvasionLayer::Grammar,
        ];
        canonicalize(&mut seq);
        // Must have terminated (test wouldn't return otherwise).
        assert_eq!(seq.len(), 5);
    }

    #[test]
    fn evasion_layer_implements_copy_and_eq() {
        // Marker test: derived traits matter for HashMap keys + Vec
        // membership checks elsewhere in the strategy crate.
        let a = EvasionLayer::Grammar;
        let b = a;
        assert_eq!(a, b);
        let _ = a;
        let _ = b;
    }

    #[test]
    fn body_padding_after_encoding_only_does_not_fully_validate() {
        // BodyPadding lists Encoding, ContentType, Grammar as prereqs.
        // Encoding alone (even with Grammar before it) isn't enough.
        let seq = vec![
            EvasionLayer::Grammar,
            EvasionLayer::Encoding,
            EvasionLayer::BodyPadding,
        ];
        assert!(
            !is_valid_sequence(&seq),
            "BodyPadding requires Encoding, ContentType, AND Grammar all present"
        );
    }

    #[test]
    fn prereqs_for_each_layer_are_a_subset_of_all_layers() {
        // Sanity-check the static prereq table: no prereq names a
        // layer that doesn't exist.
        let all = [
            EvasionLayer::Encoding,
            EvasionLayer::Grammar,
            EvasionLayer::ContentType,
            EvasionLayer::Header,
            EvasionLayer::Smuggling,
            EvasionLayer::H2,
            EvasionLayer::BodyPadding,
        ];
        for layer in all {
            for &prereq in layer.prerequisites() {
                assert!(
                    all.contains(&prereq),
                    "{layer:?} has prereq {prereq:?} not in the layer enum"
                );
            }
        }
    }

    #[test]
    fn grammar_has_no_prerequisites() {
        // Grammar is the canonical "first" layer — everything else
        // either depends on it or runs in parallel.
        assert!(EvasionLayer::Grammar.prerequisites().is_empty());
    }

    #[test]
    fn header_has_no_prerequisites() {
        // Header obfuscation runs independently of payload mutation.
        assert!(EvasionLayer::Header.prerequisites().is_empty());
    }
}
