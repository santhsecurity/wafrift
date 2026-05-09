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
    /// any layer that re-builds the body (Encoding, ContentType,
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
}
