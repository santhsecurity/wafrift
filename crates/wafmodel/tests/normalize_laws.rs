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
    assert_ne!(
        p1, p2,
        "UrlDecodeUni must NOT be idempotent (mismatch class)"
    );

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

// ── E5 ratchet (normalize.rs): the byte-exact DECODING of
// `url_decode_uni` / `html_entity_decode` / `compress_ws` had no test
// (the prior laws only checked length/idempotence/membership), so
// `cargo-mutants` left 36 survivors in the decoder arithmetic. These
// decoders ARE the WAF's normalization — if their bytes are wrong every
// mismatch-bypass conclusion is built on sand. Independent reference
// reimplementations (in the test, never mutated) are the oracle; the
// engine must match them byte-for-byte over an exhaustive + edge +
// random corpus. ──

fn hx(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Independent ModSecurity-`urlDecodeUni` reference (single pass;
/// `%uXXXX` narrows to the low byte; an invalid escape is a literal
/// `%` and scanning continues).
fn ref_url_decode_uni(input: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 5 < input.len()
                && (input[i + 1] | 0x20) == b'u'
                && let (Some(a), Some(b), Some(c), Some(d)) = (
                    hx(input[i + 2]),
                    hx(input[i + 3]),
                    hx(input[i + 4]),
                    hx(input[i + 5]),
                )
            {
                let cp =
                    (u32::from(a) << 12) | (u32::from(b) << 8) | (u32::from(c) << 4) | u32::from(d);
                o.push((cp & 0xff) as u8);
                i += 6;
                continue;
            }
            if i + 2 < input.len()
                && let (Some(h), Some(l)) = (hx(input[i + 1]), hx(input[i + 2]))
            {
                o.push((h << 4) | l);
                i += 3;
                continue;
            }
            o.push(b'%');
            i += 1;
        } else {
            o.push(input[i]);
            i += 1;
        }
    }
    o
}

fn ref_compress_ws(x: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    let mut w = false;
    for &b in x {
        if b.is_ascii_whitespace() {
            if !w {
                o.push(b' ');
                w = true;
            }
        } else {
            o.push(b);
            w = false;
        }
    }
    o
}

#[test]
fn url_decode_uni_is_byte_exact_exhaustive_and_edge() {
    let d = |s: &[u8]| Transform::UrlDecodeUni.apply(s);

    // Every byte via %XX, upper- AND lower-case hex (i+2 bound, the
    // `(h<<4)|l` assembly, and the hexval indices are all pinned).
    for b in 0u8..=255 {
        let up = format!("%{b:02X}");
        let lo = format!("%{b:02x}");
        assert_eq!(d(up.as_bytes()), vec![b], "%{b:02X}");
        assert_eq!(d(lo.as_bytes()), vec![b], "%{b:02x}");
        assert_eq!(d(up.as_bytes()), ref_url_decode_uni(up.as_bytes()));
    }

    // %uXXXX narrows to the low 8 bits (ModSecurity) — pins the
    // i+5 bound, the case-insensitive `|0x20 == 'u'` test, the four
    // hexval indices, the `<<12|<<8|<<4` assembly, the `&0xff`
    // narrowing and the `i += 6` advance.
    for (seq, want) in [
        (&b"%u003C"[..], 0x3c),
        (b"%uFF41", 0x41),
        (b"%U0041", 0x41), // upper-case U accepted (|0x20)
        (b"%uabcd", 0xcd),
        (b"%u0000", 0x00),
        (b"%uFFFF", 0xff),
    ] {
        assert_eq!(
            d(seq),
            vec![want as u8],
            "{:?}",
            String::from_utf8_lossy(seq)
        );
        assert_eq!(d(seq), ref_url_decode_uni(seq));
    }

    // Invalid / truncated escapes are literal, scanning continues.
    for (seq, want) in [
        (&b"%"[..], &b"%"[..]),
        (b"%G0", b"%G0"),
        (b"%2", b"%2"),
        (b"%u", b"%u"),
        (b"%u12", b"%u12"),
        // `%u` + exactly 3 hex with NOTHING after: i+5 == len. The
        // correct `i + 5 < len` bound rejects it (literal); a `<= len`
        // mutation would index input[i+5] == input[len] (OOB panic).
        (b"%uABC", b"%uABC"),
        (b"%uZZZZ", b"%uZZZZ"),
        (b"a%41b", b"aAb"),
        (b"%41%42", b"AB"),
        (b"%%41", b"%A"),
        (b"100%done", b"100%done"),
    ] {
        assert_eq!(d(seq), want.to_vec(), "{:?}", String::from_utf8_lossy(seq));
        assert_eq!(d(seq), ref_url_decode_uni(seq));
    }
}

#[test]
fn html_entity_decode_is_byte_exact() {
    let d = |s: &[u8]| Transform::HtmlEntityDecode.apply(s);
    for (seq, want) in [
        (&b"&#60;"[..], &b"<"[..]), // decimal
        (b"&#x3C;", b"<"),          // hex lower x
        (b"&#X3c;", b"<"),          // hex upper X (|0x20)
        (b"&lt;", b"<"),            // named
        (b"&LT;", b"<"),            // named, case-insensitive
        (b"&amp;", b"&"),
        (b"&lt", b"<"),                        // trailing ; optional
        (b"&#999;", &[(999u32 & 0xff) as u8]), // saturating, low byte
        // Numeric digits running to END OF INPUT (no `;`): the scan
        // index reaches j == rest.len(). Correct `j < rest.len()`
        // stops and decodes; `j <= rest.len()` would OOB-index
        // rest[rest.len()] (panic) — pins that boundary.
        (b"&#12", &[12u8]),
        (b"&#x1f", &[0x1fu8]),
        (b"&#;", b"&#;"),             // empty number ⇒ literal
        (b"&unknown;", b"&unknown;"), // unknown ⇒ literal
        (b"x&gt;y", b"x>y"),
        (b"&amp;lt;", b"&lt;"), // single pass only
    ] {
        assert_eq!(d(seq), want.to_vec(), "{:?}", String::from_utf8_lossy(seq));
    }
}

#[test]
fn compress_ws_collapses_runs_exactly() {
    let d = |s: &[u8]| Transform::CompressWhitespace.apply(s);
    for s in [
        &b"a   b"[..],
        b"\t\n\r x \x0c y",
        b"   leading",
        b"trailing   ",
        b"no_ws",
        b"",
        b" ",
        b"a\tb\nc",
    ] {
        assert_eq!(d(s), ref_compress_ws(s), "{:?}", String::from_utf8_lossy(s));
    }
    // Concretely: every maximal whitespace run becomes exactly one
    // 0x20 (kills `compress_ws -> vec![]` and the `if !in_ws` deletion).
    assert_eq!(d(b"a \t\n b"), b"a b");
    assert_eq!(d(b"  x  "), b" x ");
    assert!(!d(b"a b").is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    /// The engine decoders equal the independent references on random
    /// byte strings biased toward `%`/`&`/whitespace structure — any
    /// arithmetic mutation in the decoders diverges here.
    #[test]
    fn decoders_match_independent_references(
        raw in proptest::collection::vec(
            proptest::sample::select(
                &[b'%', b'u', b'&', b'#', b';', b'<', b'>', b'A', b'a',
                  b'0', b'9', b'F', b'f', b'Z', b' ', b'\t', b'\n', 0u8, 0xff][..]),
            0..48),
    ) {
        prop_assert_eq!(
            Transform::UrlDecodeUni.apply(&raw),
            ref_url_decode_uni(&raw),
            "url_decode_uni diverged from reference"
        );
        prop_assert_eq!(
            Transform::CompressWhitespace.apply(&raw),
            ref_compress_ws(&raw),
            "compress_ws diverged from reference"
        );
    }
}
