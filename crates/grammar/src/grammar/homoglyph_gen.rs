//! Shared variant generator for the homoglyph/normalization-differential
//! engines ([`super::nfkc_preimage`], [`super::bestfit`]).
//!
//! Both engines exploit the same WAF↔origin gap — a WAF matches literal ASCII
//! tokens, an origin transform (`f`) collapses a family of codepoints back to
//! ASCII — and differ ONLY in (a) the inverse map `ASCII → preimage codepoints`
//! and (b) the origin transform `f` used for the soundness gate. This module
//! owns the three substitution strategies and the `f(variant) == payload`
//! soundness invariant so neither engine duplicates them.

use std::collections::{HashMap, HashSet};

/// Distinct "style passes" attempted — each picks preimages at a rotating
/// index, yielding visually distinct, fully-substituted variants.
const STYLE_PASSES: usize = 16;

/// Hard cap on payload length processed (DoS guard — fanout is per character).
const MAX_PAYLOAD_BYTES: usize = 4096;

/// Generate up to `max` substitution variants of `payload` using `preimage`
/// (`ASCII char → codepoints that the origin transform maps back to it`) and
/// `normalize` (the origin transform — the soundness oracle). Every returned
/// string `v` satisfies `normalize(v) == payload && v != payload`, is unique,
/// and shares few literal bytes with the attack.
///
/// Strategies: (A) full style passes, (C) minimal single-position perturbation
/// — the stealthiest evasion, breaking a literal token with one substitution —
/// and (B) alternating fold.
pub(crate) fn generate<F>(
    payload: &str,
    max: usize,
    preimage: &HashMap<char, Vec<char>>,
    normalize: F,
) -> Vec<String>
where
    F: Fn(&str) -> String,
{
    if payload.is_empty() || max == 0 || payload.len() > MAX_PAYLOAD_BYTES {
        return Vec::new();
    }
    let chars: Vec<char> = payload.chars().collect();
    let foldable: HashSet<usize> = chars
        .iter()
        .enumerate()
        .filter(|(_, c)| preimage.get(c).is_some_and(|v| !v.is_empty()))
        .map(|(i, _)| i)
        .collect();
    if foldable.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Strategy A — style passes: pick preimage index k (mod each char's count).
    for k in 0..STYLE_PASSES.min(max.saturating_mul(2)) {
        let s: String = chars
            .iter()
            .map(|&c| match preimage.get(&c) {
                Some(pre) if !pre.is_empty() => pre[k % pre.len()],
                _ => c,
            })
            .collect();
        accept(payload, s, &normalize, &mut out, &mut seen);
        if out.len() >= max {
            out.truncate(max);
            return out;
        }
    }

    // Strategy C — minimal perturbation: fold exactly ONE position at a time.
    let mut ordered: Vec<usize> = foldable.iter().copied().collect();
    ordered.sort_unstable();
    for &pos in &ordered {
        if out.len() >= max {
            out.truncate(max);
            return out;
        }
        let s: String = chars
            .iter()
            .enumerate()
            .map(|(i, &c)| {
                if i == pos {
                    preimage
                        .get(&c)
                        .and_then(|p| p.first())
                        .copied()
                        .unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();
        accept(payload, s, &normalize, &mut out, &mut seen);
    }

    // Strategy B — alternating fold (defeats "too many non-ASCII" heuristics).
    let alt: String = chars
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if foldable.contains(&i) && i % 2 == 0 {
                preimage
                    .get(&c)
                    .and_then(|p| p.first())
                    .copied()
                    .unwrap_or(c)
            } else {
                c
            }
        })
        .collect();
    accept(payload, alt, &normalize, &mut out, &mut seen);

    out.truncate(max);
    out
}

/// Soundness gate: push `candidate` iff `normalize(candidate) == payload`,
/// it differs from `payload`, and it is new. Nothing escapes that does not
/// reconstruct the exact attack under the origin transform.
fn accept<F: Fn(&str) -> String>(
    payload: &str,
    candidate: String,
    normalize: &F,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if candidate != payload && normalize(&candidate) == payload && seen.insert(candidate.clone()) {
        out.push(candidate);
    }
}

/// Percent-encode only the non-ASCII (homoglyph-carrying) UTF-8 bytes of `s` as
/// `%XX`, leaving the ASCII structure intact.
pub(crate) fn percent_encode_homoglyphs(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len() * 2);
    let mut buf = [0u8; 4];
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            for &b in ch.encode_utf8(&mut buf).as_bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Layered variants: each normalization variant *additionally* percent-encoded.
///
/// This composes two differential layers. A WAF that normalizes (NFKC/best-fit)
/// but does NOT url-decode first sees inert `%XX` literals and matches nothing;
/// a WAF that url-decodes but does NOT normalize sees the homoglyph and matches
/// nothing; only an origin that url-decodes **then** normalizes reconstructs the
/// attack. Sound by construction: the inner [`generate`] already gated
/// `normalize(v) == payload`, and url-decoding the composed form recovers `v`
/// byte-for-byte, so `normalize(urldecode(composed)) == payload`.
pub(crate) fn generate_composed<F>(
    payload: &str,
    max: usize,
    preimage: &HashMap<char, Vec<char>>,
    normalize: F,
) -> Vec<String>
where
    F: Fn(&str) -> String,
{
    let mut seen: HashSet<String> = HashSet::new();
    generate(payload, max, preimage, normalize)
        .into_iter()
        .map(|v| percent_encode_homoglyphs(&v))
        .filter(|c| c.as_str() != payload && seen.insert(c.clone()))
        .take(max)
        .collect()
}
