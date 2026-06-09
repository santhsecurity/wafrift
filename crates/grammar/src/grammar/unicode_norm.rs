//! Unicode normalization-differential smuggling.
//!
//! WAFs that normalise request input to one Unicode Normal Form (NFC) before
//! applying their pattern-match rules will miss payloads expressed in a form
//! whose code-points differ from the blocked pattern — even though the
//! target application, which normalises differently (or not at all), receives
//! the semantically identical attack string.
//!
//! # Why this works
//!
//! The Unicode standard defines four Normal Forms:
//!
//! | Form | Decomposition | Composition |
//! |------|---------------|-------------|
//! | NFC  | Canonical     | Yes         |
//! | NFD  | Canonical     | No          |
//! | NFKC | Compatibility | Yes         |
//! | NFKD | Compatibility | No          |
//!
//! "Compatibility decomposition" replaces stylistic variants (fullwidth,
//! superscript, circled, etc.) with their ASCII base characters. A WAF that
//! normalises to NFC will not collapse `ａlert` (U+FF41 fullwidth 'a') to
//! `alert`, so any rule matching the literal string `alert` will not fire.
//! Meanwhile Node.js, browsers, and most back-end frameworks do apply NFKC
//! (or platform-specific normalization), so the character reaches the sink
//! as the expected ASCII.
//!
//! # Responsibility (forward-only)
//!
//! This module owns the *forward* normalization helpers the classifier and
//! bench oracle need:
//!
//! - [`detect_fullwidth`] — cheap gate: does the input already carry fullwidth
//!   Latin letters? (classifier short-circuit, `super::mutate_as`).
//! - [`nfkc_fold_ascii`] — selective NFKC fold of the fullwidth/math ranges back
//!   to ASCII, so a fullwidth payload classifies as its real attack class.
//! - [`reachable_keywords`] — oracle primitive: which known attack keywords
//!   survive the fold (gates bypass claims for normalization-mutated payloads).
//!
//! (A small fullwidth *generation* helper used to build test vectors for the
//! above lives in this module's `#[cfg(test)]` block — it has no production
//! caller, since reverse generation belongs to `nfkc_preimage`.)
//!
//! # Reverse generation lives elsewhere (NO-DUP)
//!
//! *Producing* homoglyph bypass variants — the inverse-NFKC map and the
//! style-pass / single-codepoint / alternating substitution strategies — is the
//! sole responsibility of [`super::nfkc_preimage`] (data-derived from the real
//! NFKC function, ~30 styles per letter). The four hand-rolled reverse
//! transforms that once lived here (fullwidth/math-bold/math-monospace/mixed)
//! were strictly subsumed by that engine and were removed; this module no
//! longer mints bypass payloads.
//!
//! # Scope
//!
//! These forward helpers are pure compile-time-table lookups — no dependency on
//! the `unicode-normalization` crate (that lives behind `nfkc_preimage`). The
//! goal here is *checking*/*folding* for classification, not *generating*.
//!
//! # Visibility note
//!
//! This module is `pub(crate)` — the API is internal to `wafrift-grammar`.
//! The functions (`fullwidth`, `detect_fullwidth`, `reachable_keywords`,
//! `nfkc_fold_ascii`) are callable from any module in this crate.

/// Detect whether a payload contains fullwidth Unicode letters.
///
/// Used by the classifier to short-circuit normalization detection — if the
/// input already has fullwidth characters, the WAF oracle can apply the
/// normalization heuristic even if the payload doesn't look like a known
/// attack class.
#[must_use]
pub(crate) fn detect_fullwidth(payload: &str) -> bool {
    payload.chars().any(|c| {
        // Fullwidth Latin letters: U+FF21–U+FF3A (upper), U+FF41–U+FF5A (lower)
        matches!(c, '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}')
    })
}

/// Return the set of known attack keywords that appear (as substrings) in
/// the payload after NFKC-folding the fullwidth characters.
///
/// This is the oracle primitive: if the normalised form contains a known
/// attack keyword, the payload is a real attack even though it evades the
/// WAF's NFC-based pattern match. Used by the bench oracle to gate bypass
/// claims for normalization-mutated payloads.
#[must_use]
pub(crate) fn reachable_keywords<'a>(payload: &str, keywords: &[&'a str]) -> Vec<&'a str> {
    let folded = nfkc_fold_ascii(payload);
    keywords
        .iter()
        .filter(|&&kw| {
            folded
                .to_ascii_lowercase()
                .contains(&kw.to_ascii_lowercase())
        })
        .copied()
        .collect()
}

/// Perform a lightweight ASCII-equivalent fold of fullwidth and mathematical
/// Unicode characters back to their ASCII base.
///
/// This is a selective NFKC fold for the character ranges we emit; it is NOT
/// a full Unicode NFKC normalizer (that lives in `wafrift-encoding` which
/// depends on the `unicode-normalization` crate). We don't want to pull that
/// dependency into `wafrift-grammar` — instead, this targeted fold is
/// sufficient for the oracle's keyword-detection use-case.
#[must_use]
pub(crate) fn nfkc_fold_ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            // Six mathematical / fullwidth Latin alphabets that fold
            // to ASCII via a simple base-offset. Each (start, base)
            // pair encodes "this 26-char block maps linearly to
            // base..base+26".  Linear scan over six entries beats a
            // multi-branch `if` ladder: same six comparisons, but the
            // table form survives a future block addition without
            // editing branching logic.
            const RANGES: &[(char, char, u8)] = &[
                ('\u{FF21}', '\u{FF3A}', b'A'),   // Fullwidth uppercase
                ('\u{FF41}', '\u{FF5A}', b'a'),   // Fullwidth lowercase
                ('\u{1D400}', '\u{1D419}', b'A'), // Math Bold uppercase
                ('\u{1D41A}', '\u{1D433}', b'a'), // Math Bold lowercase
                ('\u{1D670}', '\u{1D689}', b'A'), // Math Monospace uppercase
                ('\u{1D68A}', '\u{1D6A3}', b'a'), // Math Monospace lowercase
            ];
            for &(lo, hi, base) in RANGES {
                if (lo..=hi).contains(&c) {
                    let offset = c as u32 - lo as u32;
                    return char::from_u32(base as u32 + offset).unwrap_or(c);
                }
            }
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Max payload the fullwidth test-vector constructor will process — a DoS
    /// guard mirrored from the forward functions, kept here because the only
    /// users of fullwidth *generation* are these tests (reverse generation for
    /// production lives in `nfkc_preimage`).
    const MAX_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MiB

    /// Test-vector constructor: fullwidth-substitute every ASCII letter so the
    /// forward functions ([`detect_fullwidth`], [`nfkc_fold_ascii`],
    /// [`reachable_keywords`]) can be exercised on realistic fullwidth input.
    /// `None` for empty / oversized / no-op inputs.
    fn fullwidth(payload: &str) -> Option<String> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return None;
        }
        let out: String = payload
            .chars()
            .map(|c| ascii_to_fullwidth(c).unwrap_or(c))
            .collect();
        if out == payload {
            return None;
        }
        Some(out)
    }

    /// Map an ASCII letter to its Fullwidth Unicode equivalent (U+FF21 / U+FF41
    /// base offsets). Helper for [`fullwidth`].
    fn ascii_to_fullwidth(c: char) -> Option<char> {
        match c {
            'A'..='Z' => char::from_u32(c as u32 - b'A' as u32 + 0xFF21),
            'a'..='z' => char::from_u32(c as u32 - b'a' as u32 + 0xFF41),
            _ => None,
        }
    }

    // ── fullwidth transform ────────────────────────────────────────────────

    #[test]
    fn fullwidth_converts_alert() {
        let result = fullwidth("alert(1)").unwrap();
        assert!(
            result.contains('\u{FF41}'), // ａ (fullwidth a)
            "fullwidth must convert 'a': {result}"
        );
        // Must not convert the digit `1` or `(`
        assert!(result.contains('('), "parens must be preserved");
        assert!(result.contains('1'), "digits must be preserved");
    }

    #[test]
    fn fullwidth_round_trips_via_nfkc_fold() {
        let original = "alert(1)";
        let fw = fullwidth(original).unwrap();
        let folded = nfkc_fold_ascii(&fw);
        assert_eq!(
            folded.to_ascii_lowercase(),
            original.to_ascii_lowercase(),
            "NFKC fold must recover original: {fw} -> {folded}"
        );
    }

    #[test]
    fn fullwidth_returns_none_for_no_alpha() {
        // Payloads with no ASCII letters produce no-op transforms
        assert!(fullwidth("1=1").is_none());
        assert!(fullwidth("123").is_none());
        assert!(fullwidth("").is_none());
    }

    #[test]
    fn fullwidth_respects_max_payload_bytes() {
        let huge = "a".repeat(MAX_PAYLOAD_BYTES + 1);
        assert!(fullwidth(&huge).is_none());
    }

    // ── detect_fullwidth ───────────────────────────────────────────────────

    #[test]
    fn detect_fullwidth_fires_on_fullwidth_chars() {
        let fw = fullwidth("alert").unwrap();
        assert!(detect_fullwidth(&fw));
    }

    #[test]
    fn detect_fullwidth_rejects_ascii() {
        assert!(!detect_fullwidth("alert(1)"));
        assert!(!detect_fullwidth("SELECT * FROM users"));
    }

    // ── reachable_keywords ─────────────────────────────────────────────────

    #[test]
    fn reachable_keywords_finds_alert_in_fullwidth() {
        let fw = fullwidth("alert(1)").unwrap();
        let hits = reachable_keywords(&fw, &["alert", "script", "onerror"]);
        assert!(
            hits.contains(&"alert"),
            "must find 'alert' in fullwidth form: hits={hits:?}"
        );
    }

    #[test]
    fn reachable_keywords_empty_on_no_match() {
        let hits = reachable_keywords("hello world", &["alert", "select", "jndi"]);
        assert!(hits.is_empty());
    }

    #[test]
    fn reachable_keywords_case_insensitive() {
        let fw = fullwidth("ALERT").unwrap();
        let hits = reachable_keywords(&fw, &["alert"]);
        assert!(
            hits.contains(&"alert"),
            "must find keyword case-insensitively"
        );
    }

    // ── nfkc_fold_ascii ───────────────────────────────────────────────────

    #[test]
    fn nfkc_fold_ascii_identity_on_ascii() {
        let s = "Hello, World! 123";
        assert_eq!(nfkc_fold_ascii(s), s);
    }

    #[test]
    fn nfkc_fold_ascii_folds_all_supported_ranges() {
        // Spot-check one character per range
        let fw_upper = '\u{FF21}'; // Ａ
        let fw_lower = '\u{FF41}'; // ａ
        let bold_upper = '\u{1D400}'; // 𝐀
        let bold_lower = '\u{1D41A}'; // 𝐚
        let mono_upper = '\u{1D670}'; // 𝙰
        let mono_lower = '\u{1D68A}'; // 𝚊

        let s: String = [
            fw_upper, fw_lower, bold_upper, bold_lower, mono_upper, mono_lower,
        ]
        .iter()
        .collect();
        let folded = nfkc_fold_ascii(&s);
        assert_eq!(folded, "AaAaAa", "fold must produce ASCII: {folded}");
    }

    /// LAW 12 anti-rig: the size gate must accept a payload at exactly
    /// MAX_PAYLOAD_BYTES and reject at +1 to prevent DoS via huge inputs.
    #[test]
    fn fullwidth_size_gate_exact_boundary() {
        let at_limit = "a".repeat(MAX_PAYLOAD_BYTES);
        let past_limit = "a".repeat(MAX_PAYLOAD_BYTES + 1);
        // At exactly the limit: accepted (Some).
        assert!(
            fullwidth(&at_limit).is_some(),
            "payload at exactly MAX_PAYLOAD_BYTES must be accepted"
        );
        // One byte past the limit: rejected (None).
        assert!(
            fullwidth(&past_limit).is_none(),
            "payload one byte past MAX_PAYLOAD_BYTES must be rejected"
        );
    }

    /// LAW 2: MAX_PAYLOAD_BYTES is pinned to prevent silent drift
    /// that would change the rejection threshold.
    #[test]
    fn max_payload_bytes_is_pinned() {
        assert_eq!(MAX_PAYLOAD_BYTES, 1024 * 1024);
    }
}
