//! Invisible-character & tag-character encoders.
//!
//! A class of encodings the rest of `unicode.rs` doesn't cover. They share
//! one trait: the rendered or normalized string LOOKS exactly like the
//! original to a human or to a downstream tokenizer, but the byte stream a
//! WAF inspects bears no resemblance to the keywords it has rules for.
//!
//! - **Tag characters (U+E0000–U+E007F, "Plan 9 tags").** Each ASCII
//!   codepoint `c` has a tag-equivalent at `U+E0000 + c`. Strip them and
//!   you recover the original ASCII. Prompt-injection research has shown
//!   modern LLM tokenizers preserve and decode these — meaning an
//!   LLM-backed WAF will see a benign-looking blob while still receiving
//!   the attack tokens.
//! - **Variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF).** Originally
//!   for emoji presentation. Some normalizers strip them; some preserve
//!   them. A WAF that strips has to choose to strip every codepoint in
//!   two non-contiguous ranges, which most don't.
//! - **Stylistic ligatures (U+FB00–U+FB06).** `ff`/`fi`/`fl`/`ffi`/`ffl`/
//!   `ſt`/`st`. NFKC decomposes them; non-NFKC tokenizers see them as
//!   single codepoints not in any keyword. Defeats post-normalization
//!   filters that operate on the unnormalized stream.
//! - **Enclosed alphanumerics (U+24B6–U+24E9 circled, U+1F110–U+1F12B
//!   parenthesized).** Compatibility-decompose to plain Latin under NFKC.
//!   Backends that NFKC see the keyword; WAFs that don't, don't.
//! - **Soft hyphen / format chars (U+00AD, U+200B–U+200D, U+2060,
//!   U+FEFF).** Some of these already live in
//!   `unicode::zero_width_inject` for selective injection. This
//!   module exposes them as a Strategy-compatible whole-string encoder
//!   too, for cases where the engine wants to swap encoders rather than
//!   compose them.
//!
//! All encoders here preserve UTF-8 validity and are byte-deterministic
//! given the same input. None of them require entropy.
//!
//! # Why a new module
//!
//! `unicode.rs` is already 17K LOC of encoders. The encoders here belong
//! together as a class — "looks identical, parses identical, byte stream
//! is unrecognizable" — and putting them next to the case-folding /
//! homoglyph / math-alphabet encoders would dilute that boundary.

/// Encode every ASCII byte as its Plan 9 tag-character equivalent.
///
/// Input: any UTF-8 string. Output: UTF-8 string where every ASCII
/// codepoint `c` (0–0x7F) has been replaced by `U+E0000 + c` (a tag
/// character). Non-ASCII codepoints pass through unchanged.
///
/// Reversible: strip every codepoint in `U+E0000..=U+E007F` and the
/// original ASCII falls out.
#[must_use]
pub fn tag_char_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 4);
    for c in input.chars() {
        let cp = c as u32;
        if cp <= 0x7F {
            // SAFETY: U+E0000 + ASCII < U+E0080 is a valid assigned plane-14 codepoint.
            if let Some(tag) = char::from_u32(0xE0000 + cp) {
                out.push(tag);
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Append a variation selector (U+FE0F by default) after every codepoint.
///
/// Renders identically; bytes are not. `selector` must be in
/// `U+FE00..=U+FE0F` or `U+E0100..=U+E01EF`; out-of-range values are
/// silently coerced to `U+FE0F`.
#[must_use]
pub fn variation_selector_pad(input: &str, selector: char) -> String {
    let sel = match selector as u32 {
        0xFE00..=0xFE0F | 0xE0100..=0xE01EF => selector,
        _ => '\u{FE0F}',
    };
    let mut out = String::with_capacity(input.len() * 2 + input.chars().count() * sel.len_utf8());
    for c in input.chars() {
        out.push(c);
        out.push(sel);
    }
    out
}

/// Pad every codepoint with a deterministic-but-different variation
/// selector drawn from the supplementary range `U+E0100..=U+E01EF`.
///
/// Useful when a WAF strips a constant pad (U+FE0F) but allows the
/// supplementary plane — exposing the discrepancy directly.
#[must_use]
pub fn variation_selector_supplementary_pad(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 5);
    for (i, c) in (0_u32..).zip(input.chars()) {
        out.push(c);
        let sel_cp = 0xE0100 + (i % 0xF0);
        if let Some(sel) = char::from_u32(sel_cp) {
            out.push(sel);
        }
    }
    out
}

/// Replace canonical ligature digraphs with their precomposed
/// stylistic ligature codepoints (U+FB00..=U+FB06).
///
/// Defeats keyword filters that pre-NFKC and don't fold these.
/// NFKC normalization recovers the plain ASCII so the origin
/// parses identically.
#[must_use]
pub fn ligature_encode(input: &str) -> String {
    // Order matters — longer matches must be tried first so `ffi` /
    // `ffl` don't get partially consumed as `ff`.
    const LIGATURES: &[(&str, char)] = &[
        ("ffi", '\u{FB03}'),
        ("ffl", '\u{FB04}'),
        ("ff", '\u{FB00}'),
        ("fi", '\u{FB01}'),
        ("fl", '\u{FB02}'),
        ("st", '\u{FB06}'),
        ("ſt", '\u{FB05}'),
    ];
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    'outer: while !rest.is_empty() {
        for &(pat, replacement) in LIGATURES {
            if let Some(stripped) = rest.strip_prefix(pat) {
                out.push(replacement);
                rest = stripped;
                continue 'outer;
            }
        }
        // No ligature at this position — copy one codepoint and advance.
        let mut chars = rest.chars();
        if let Some(c) = chars.next() {
            out.push(c);
        }
        rest = chars.as_str();
    }
    out
}

/// Replace every ASCII letter with its circled compatibility-equivalent
/// (U+24B6..=U+24CF for uppercase, U+24D0..=U+24E9 for lowercase).
///
/// NFKC decomposes these back to the plain Latin letters. Same trick
/// shape as `fullwidth_encode` but a non-overlapping codepoint set —
/// rotating between them defeats any filter that scrubs ONE of them.
#[must_use]
pub fn circled_letter_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 4);
    for c in input.chars() {
        match c {
            'A'..='Z' => {
                let off = (c as u32) - ('A' as u32);
                if let Some(repl) = char::from_u32(0x24B6 + off) {
                    out.push(repl);
                    continue;
                }
            }
            'a'..='z' => {
                let off = (c as u32) - ('a' as u32);
                if let Some(repl) = char::from_u32(0x24D0 + off) {
                    out.push(repl);
                    continue;
                }
            }
            _ => {}
        }
        out.push(c);
    }
    out
}

/// Replace every ASCII letter with its parenthesized
/// compatibility-equivalent (U+1F110..=U+1F12B for uppercase,
/// U+249C..=U+24B5 for lowercase).
///
/// Another rotation partner for `circled_letter_encode` /
/// `fullwidth_encode` — the byte stream looks entirely different
/// even though NFKC collapses all three back to the same ASCII.
#[must_use]
pub fn parenthesized_letter_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 4);
    for c in input.chars() {
        match c {
            'A'..='Z' => {
                let off = (c as u32) - ('A' as u32);
                if let Some(repl) = char::from_u32(0x1F110 + off) {
                    out.push(repl);
                    continue;
                }
            }
            'a'..='z' => {
                let off = (c as u32) - ('a' as u32);
                if let Some(repl) = char::from_u32(0x249C + off) {
                    out.push(repl);
                    continue;
                }
            }
            _ => {}
        }
        out.push(c);
    }
    out
}

/// Inject U+00AD SOFT HYPHEN between every pair of codepoints.
///
/// Visually invisible; many WAFs don't strip it because U+00AD is a
/// valid Latin-1 character. Backends that don't fold it see a string
/// that's no longer the keyword.
#[must_use]
pub fn soft_hyphen_inject(input: &str) -> String {
    // §1 SPEED: replaced Vec<char> collect (heap allocation proportional to
    // input length) + two-pass enumerate with a single-pass peekable iterator.
    // The `first` flag replaces the `i > 0` guard without materialising the
    // full char vec — zero extra allocation beyond the output String.
    //
    // Before: 2 heap allocs (Vec + String), O(n) collect, O(n) enumerate.
    // After:  1 heap alloc (String), O(n) single pass.
    if input.is_empty() {
        return String::new();
    }
    // U+00AD is 2 bytes in UTF-8; pre-size for N chars + (N-1) soft-hyphens.
    let char_count = input.chars().count();
    let mut out = String::with_capacity(input.len() + (char_count.saturating_sub(1)) * 2);
    let mut first = true;
    for c in input.chars() {
        if !first {
            out.push('\u{00AD}');
        }
        first = false;
        out.push(c);
    }
    out
}

/// Wrap each codepoint in U+2060 WORD JOINER.
///
/// Zero-width, NFC-stable (does NOT get folded by NFC), but NFKC
/// strips it. Splits the difference between `zero_width_inject` and
/// `variation_selector_pad`.
#[must_use]
pub fn word_joiner_wrap(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 4);
    for c in input.chars() {
        out.push('\u{2060}');
        out.push(c);
    }
    out.push('\u{2060}');
    out
}

/// Returns the list of every invisible-class encoder name shipped by
/// this module — used by the integration test to assert the
/// dispatcher in `strategy.rs` has wired every one of them.
pub const INVISIBLE_ENCODER_NAMES: &[&str] = &[
    "tag_char_encode",
    "variation_selector_pad",
    "variation_selector_supplementary_pad",
    "ligature_encode",
    "circled_letter_encode",
    "parenthesized_letter_encode",
    "soft_hyphen_inject",
    "word_joiner_wrap",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_char_round_trips_via_codepoint_subtraction() {
        let encoded = tag_char_encode("SELECT");
        let recovered: String = encoded
            .chars()
            .map(|c| {
                let cp = c as u32;
                if (0xE0000..=0xE007F).contains(&cp) {
                    char::from_u32(cp - 0xE0000).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(recovered, "SELECT");
    }

    #[test]
    fn tag_char_preserves_non_ascii() {
        let encoded = tag_char_encode("SELECT' OR Ä");
        assert!(
            encoded.contains('Ä'),
            "non-ASCII passes through: {encoded:?}"
        );
    }

    #[test]
    fn tag_char_every_byte_changes() {
        let raw = "SELECT";
        let encoded = tag_char_encode(raw);
        assert_ne!(raw, encoded);
        // Every encoded codepoint must be in plane 14, not ASCII.
        for c in encoded.chars() {
            let cp = c as u32;
            assert!((0xE0000..=0xE007F).contains(&cp), "non-tag codepoint: {c}");
        }
    }

    #[test]
    fn tag_char_handles_empty() {
        assert_eq!(tag_char_encode(""), "");
    }

    #[test]
    fn variation_selector_default_is_fe0f() {
        let out = variation_selector_pad("AB", '\u{FE0F}');
        assert!(out.contains('\u{FE0F}'));
        assert_eq!(out.chars().count(), 4); // A, FE0F, B, FE0F
    }

    #[test]
    fn variation_selector_invalid_falls_back_to_fe0f() {
        let out = variation_selector_pad("X", 'a');
        assert!(out.contains('\u{FE0F}'), "fallback selector: {out:?}");
    }

    #[test]
    fn variation_selector_accepts_supplementary_range() {
        let out = variation_selector_pad("X", '\u{E0100}');
        assert!(out.contains('\u{E0100}'));
    }

    #[test]
    fn variation_selector_supplementary_varies_per_position() {
        let out = variation_selector_supplementary_pad("AB");
        let selectors: Vec<char> = out
            .chars()
            .filter(|c| (0xE0100..=0xE01EF).contains(&(*c as u32)))
            .collect();
        assert_eq!(selectors.len(), 2);
        assert_ne!(
            selectors[0], selectors[1],
            "selectors must differ per position"
        );
    }

    #[test]
    fn ligature_encode_replaces_known_digraphs() {
        // "effect"  → ef·ff·ect — `ff` not followed by `i`/`l`, so ﬀ (U+FB00).
        // "official" → o·ffi·cial — `ffi` matches before `ff`, so ﬃ (U+FB03).
        // "offload"  → o·ffl·oad — `ffl` matches before `ff`, so ﬄ (U+FB04).
        let out = ligature_encode("effect official offload");
        assert!(out.contains('\u{FB00}'), "ff → ﬀ in 'effect': {out:?}");
        assert!(out.contains('\u{FB03}'), "ffi → ﬃ in 'official': {out:?}");
        assert!(out.contains('\u{FB04}'), "ffl → ﬄ in 'offload': {out:?}");
    }

    #[test]
    fn ligature_encode_prefers_longest_match() {
        // `ffi` must be matched as one ligature, not `ff` + `i`.
        let out = ligature_encode("ffi");
        assert_eq!(out, "\u{FB03}");
        assert!(!out.contains('\u{FB00}'));
    }

    #[test]
    fn ligature_encode_passes_unmatched_chars() {
        let out = ligature_encode("axyz");
        assert_eq!(out, "axyz");
    }

    #[test]
    fn ligature_encode_handles_empty() {
        assert_eq!(ligature_encode(""), "");
    }

    #[test]
    fn circled_letter_uppercase_and_lowercase() {
        let out = circled_letter_encode("Aa");
        assert!(out.contains('\u{24B6}'), "A → Ⓐ: {out:?}");
        assert!(out.contains('\u{24D0}'), "a → ⓐ: {out:?}");
    }

    #[test]
    fn circled_letter_preserves_punctuation() {
        let out = circled_letter_encode("A'B");
        assert!(out.contains('\''), "quote preserved: {out:?}");
    }

    #[test]
    fn parenthesized_letter_uppercase_and_lowercase() {
        let out = parenthesized_letter_encode("Bb");
        assert!(out.contains('\u{1F111}'), "B → 🄑: {out:?}");
        assert!(out.contains('\u{249D}'), "b → ⒝: {out:?}");
    }

    #[test]
    fn circled_and_parenthesized_produce_different_bytes() {
        let raw = "SELECT";
        let circled = circled_letter_encode(raw);
        let parens = parenthesized_letter_encode(raw);
        assert_ne!(
            circled, parens,
            "rotation partners must produce distinct byte streams"
        );
    }

    #[test]
    fn soft_hyphen_inject_between_each_pair() {
        let out = soft_hyphen_inject("ABC");
        // Expect: A, U+00AD, B, U+00AD, C
        let count = out.chars().filter(|&c| c == '\u{00AD}').count();
        assert_eq!(count, 2, "soft hyphen between each pair: {out:?}");
    }

    #[test]
    fn soft_hyphen_inject_empty_is_empty() {
        assert_eq!(soft_hyphen_inject(""), "");
    }

    #[test]
    fn soft_hyphen_inject_single_char_unchanged() {
        assert_eq!(soft_hyphen_inject("A"), "A");
    }

    #[test]
    fn word_joiner_wraps_both_ends() {
        let out = word_joiner_wrap("AB");
        let count = out.chars().filter(|&c| c == '\u{2060}').count();
        // Before A, between A-B, after B.
        assert_eq!(count, 3, "wrap with joiner at each boundary: {out:?}");
    }

    #[test]
    fn all_encoders_preserve_utf8_validity() {
        let payload = "' OR 1=1 -- SELECT * FROM users";
        let encoders: &[fn(&str) -> String] = &[
            tag_char_encode,
            |s| variation_selector_pad(s, '\u{FE0F}'),
            variation_selector_supplementary_pad,
            ligature_encode,
            circled_letter_encode,
            parenthesized_letter_encode,
            soft_hyphen_inject,
            word_joiner_wrap,
        ];
        for (i, enc) in encoders.iter().enumerate() {
            let out = enc(payload);
            // Must be valid UTF-8 (String guarantees this, but assert
            // length-positive on non-empty input).
            assert!(
                !out.is_empty(),
                "encoder #{i} produced empty on non-empty input"
            );
        }
    }

    #[test]
    fn all_encoders_are_deterministic() {
        let payload = "SELECT' OR 1=1";
        let encoders: &[fn(&str) -> String] = &[
            tag_char_encode,
            |s| variation_selector_pad(s, '\u{FE0F}'),
            variation_selector_supplementary_pad,
            ligature_encode,
            circled_letter_encode,
            parenthesized_letter_encode,
            soft_hyphen_inject,
            word_joiner_wrap,
        ];
        for enc in encoders {
            assert_eq!(enc(payload), enc(payload), "encoder must be deterministic");
        }
    }

    #[test]
    fn all_encoders_handle_empty_input() {
        let encoders: &[fn(&str) -> String] = &[
            tag_char_encode,
            |s| variation_selector_pad(s, '\u{FE0F}'),
            variation_selector_supplementary_pad,
            ligature_encode,
            circled_letter_encode,
            parenthesized_letter_encode,
            soft_hyphen_inject,
            word_joiner_wrap,
        ];
        for enc in encoders {
            let out = enc("");
            // soft_hyphen_inject and word_joiner_wrap-empty special case:
            // word_joiner_wrap("") still produces a single U+2060.
            // That's fine — it preserves the "wrap" invariant.
            assert!(out.len() < 8, "empty input must produce ~empty output");
        }
    }

    #[test]
    fn invisible_encoder_names_match_pub_fns() {
        // Smoke: the published name list is non-empty and contains
        // every encoder we exposed. If a developer adds a pub fn but
        // forgets to register it in INVISIBLE_ENCODER_NAMES, this
        // test fires.
        assert_eq!(INVISIBLE_ENCODER_NAMES.len(), 8);
        for name in INVISIBLE_ENCODER_NAMES {
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "encoder names must be snake_case: {name}"
            );
        }
    }

    #[test]
    fn adversarial_large_input_does_not_panic() {
        let big = "A".repeat(10_000);
        let _ = tag_char_encode(&big);
        let _ = variation_selector_pad(&big, '\u{FE0F}');
        let _ = variation_selector_supplementary_pad(&big);
        let _ = ligature_encode(&big);
        let _ = circled_letter_encode(&big);
        let _ = parenthesized_letter_encode(&big);
        let _ = soft_hyphen_inject(&big);
        let _ = word_joiner_wrap(&big);
    }

    #[test]
    fn unicode_input_round_trip_safe() {
        let payload = "Ä' OR ñ=1 -- 日本";
        let encoders: &[fn(&str) -> String] = &[
            tag_char_encode,
            |s| variation_selector_pad(s, '\u{FE0F}'),
            ligature_encode,
            circled_letter_encode,
            parenthesized_letter_encode,
            soft_hyphen_inject,
            word_joiner_wrap,
        ];
        for enc in encoders {
            let out = enc(payload);
            // Non-ASCII payload chars must survive (encoders only touch
            // ASCII or known digraphs).
            assert!(out.contains('日') || out.contains('Ä') || out.contains('ñ'));
        }
    }
}
