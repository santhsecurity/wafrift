//! E3/23 — algebraic laws of the CRS `t:` transforms, at 10k.
//!
//! Honest contract: assert ONLY laws that genuinely hold. The two
//! *decoders* (`UrlDecodeUni`, `HtmlEntityDecode`) are deliberately NOT
//! claimed idempotent — `%2525 → %25 → %` and re-forming entities are
//! exactly why the normalization-mismatch bypass class exists; a test
//! asserting their idempotence would be a lie. We pin that
//! non-idempotence explicitly (a concrete witness) so it can never be
//! "tidied" into a false law.

use proptest::prelude::*;
use wafrift_wafmodel::normalize::Transform;

fn pc() -> u32 {
    std::env::var("WAFMODEL_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

const T: Transform = Transform::Lowercase;

/// Must mirror the engine's whitespace set EXACTLY: `RemoveWhitespace`
/// filters on `u8::is_ascii_whitespace()`, which is space/tab/LF/FF/CR
/// and (by the Rust std definition) does NOT include 0x0B vertical tab.
/// Asserting any other set would be asserting a false law.
fn is_ascii_ws(b: u8) -> bool {
    b.is_ascii_whitespace()
}

/// Genuinely idempotent transforms (pure per-byte / fixpoint reducers).
const IDEMPOTENT: [Transform; 4] = [
    Transform::Lowercase,
    Transform::RemoveNulls,
    Transform::RemoveWhitespace,
    Transform::CompressWhitespace,
];
/// Transforms that never *grow* the input.
const NON_GROWING: [Transform; 5] = [
    Transform::UrlDecodeUni,
    Transform::HtmlEntityDecode,
    Transform::RemoveNulls,
    Transform::RemoveWhitespace,
    Transform::CompressWhitespace,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    #[test]
    fn every_transform_law_holds(x in proptest::collection::vec(any::<u8>(), 0..64)) {
        // Totality: applying any transform to arbitrary bytes never
        // panics (exercised by construction here).
        for t in [
            Transform::UrlDecodeUni, Transform::HtmlEntityDecode,
            Transform::Lowercase, Transform::RemoveNulls,
            Transform::CompressWhitespace, Transform::RemoveWhitespace,
        ] {
            let _ = t.apply(&x);
        }

        // Idempotence — only for the transforms that truly satisfy it.
        for t in IDEMPOTENT {
            let once = t.apply(&x);
            prop_assert_eq!(t.apply(&once), once.clone(),
                "{:?} is not idempotent", t);
        }

        // Length: non-growing set never increases length; Lowercase
        // exactly preserves it.
        for t in NON_GROWING {
            prop_assert!(t.apply(&x).len() <= x.len(), "{:?} grew input", t);
        }
        prop_assert_eq!(T.apply(&x).len(), x.len(), "Lowercase changed length");

        // Lowercase: A–Z → a–z, every other byte byte-identical.
        let lo = T.apply(&x);
        for (i, &b) in x.iter().enumerate() {
            let want = if b.is_ascii_uppercase() { b + 32 } else { b };
            prop_assert_eq!(lo[i], want, "Lowercase wrong at {}", i);
        }

        // RemoveNulls removes exactly 0x00 and is a subsequence of x.
        let rn = Transform::RemoveNulls.apply(&x);
        prop_assert!(!rn.contains(&0), "RemoveNulls left a NUL");
        prop_assert_eq!(rn, x.iter().copied().filter(|&b| b != 0).collect::<Vec<_>>());

        // RemoveWhitespace removes exactly ASCII whitespace.
        let rw = Transform::RemoveWhitespace.apply(&x);
        prop_assert!(!rw.iter().any(|&b| is_ascii_ws(b)), "RemoveWhitespace left ws");
        prop_assert_eq!(rw, x.iter().copied().filter(|&b| !is_ascii_ws(b)).collect::<Vec<_>>());

        // Commutativity of independent per-byte ops.
        let a = Transform::RemoveNulls.apply(&Transform::Lowercase.apply(&x));
        let b = Transform::Lowercase.apply(&Transform::RemoveNulls.apply(&x));
        prop_assert_eq!(a, b, "Lowercase and RemoveNulls must commute");
        let c = Transform::RemoveNulls.apply(&Transform::RemoveWhitespace.apply(&x));
        let d = Transform::RemoveWhitespace.apply(&Transform::RemoveNulls.apply(&x));
        prop_assert_eq!(c, d, "RemoveNulls and RemoveWhitespace must commute");
    }
}

#[test]
fn decoders_are_not_idempotent_pinned_precision_twin() {
    // The negative twin: the two decoders are PROVABLY not idempotent.
    // %2525 -> %25 (one pass) -> % (second pass).
    let url = b"%2525";
    let p1 = Transform::UrlDecodeUni.apply(url);
    let p2 = Transform::UrlDecodeUni.apply(&p1);
    assert_eq!(p1, b"%25", "first url-decode pass");
    assert_eq!(p2, b"%", "second pass decodes again — NOT idempotent");
    assert_ne!(p1, p2, "UrlDecodeUni must NOT be idempotent (mismatch class)");

    // &amp;lt; -> &lt; (one pass) -> < (second pass).
    let ent = b"&amp;lt;";
    let e1 = Transform::HtmlEntityDecode.apply(ent);
    let e2 = Transform::HtmlEntityDecode.apply(&e1);
    assert_ne!(
        e1, e2,
        "HtmlEntityDecode must NOT be idempotent (re-forming entities \
         are the mismatch class): {e1:?} vs {e2:?}"
    );
    assert_eq!(e2, b"<", "double entity-decode reaches the live byte");
}
