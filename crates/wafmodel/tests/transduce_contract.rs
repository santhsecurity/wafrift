//! Truth contract for the pipeline transducers, and a transducer-level
//! demonstration that the normalization-mismatch bypass class *emerges
//! from composition* (the foundation the P2 solver stands on) — with
//! the inert twin staying inert (anti-rig).

use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{Pipeline, Stage, json_unescape, url_decode_once};

#[test]
fn url_decode_is_single_pass_and_lenient() {
    assert_eq!(url_decode_once(b"%3Cscript%3E", false), b"<script>");
    // One pass peels exactly one layer: %25→% , so %253C → %3C.
    assert_eq!(url_decode_once(b"%253Cscript%253E", false), b"%3Cscript%3E");
    // Invalid escapes are literal, scanning continues (real-server
    // behaviour, and the reason the mismatch class exists).
    assert_eq!(url_decode_once(b"%zz%3", false), b"%zz%3");
    assert_eq!(url_decode_once(b"a%", false), b"a%");
    // `+` only becomes space in form mode.
    assert_eq!(url_decode_once(b"a+b", false), b"a+b");
    assert_eq!(url_decode_once(b"a+b", true), b"a b");
}

#[test]
fn json_unescape_handles_unicode_and_surrogates() {
    // The framework JSON decode the WAF does NOT perform: `<`
    // becomes a literal `<` only after the body parser runs.
    assert_eq!(json_unescape(br"<script>"), b"<script>");
    assert_eq!(json_unescape(br#"\"quote\\slash\/"#), b"\"quote\\slash/");
    assert_eq!(json_unescape(br"line\nbreak"), b"line\nbreak");
    // UTF-16 surrogate pair 😀 -> U+1F600 = F0 9F 98 80.
    assert_eq!(
        json_unescape(br"\uD83D\uDE00"),
        vec![0xF0, 0x9F, 0x98, 0x80]
    );
    // Unknown escape is left literal (lenient).
    assert_eq!(json_unescape(br"a\xb"), b"a\\xb");
    // BMP codepoint é -> U+00E9 = C3 A9.
    assert_eq!(
        json_unescape(br"caf\u00e9"),
        vec![b'c', b'a', b'f', 0xC3, 0xA9]
    );
}

#[test]
fn double_decode_differs_from_single_decode() {
    let x = b"%253Cscript%253E";
    let once = Stage::UrlDecode {
        plus_is_space: false,
    }
    .apply(x);
    let twice = Stage::DoubleUrlDecode.apply(x);
    assert_eq!(once, b"%3Cscript%3E");
    assert_eq!(twice, b"<script>");
    assert_ne!(once, twice, "the asymmetry IS the bypass");
}

#[test]
fn normalization_mismatch_bypass_emerges_from_composition() {
    // x is crafted to be inert to the WAF but live at the sink — but
    // we do NOT hand-code that; we *compose stage transducers* and
    // observe the mismatch fall out. This is exactly what the P2
    // solver searches for automatically.
    let x = b"%253Cscript%253Ealert(1)%253C/script%253E";

    // WAF view: CRS urlDecodeUni is a SINGLE pass.
    let waf_view = Stage::CrsView(vec![Transform::UrlDecodeUni, Transform::Lowercase]).apply(x);
    assert!(
        !String::from_utf8_lossy(&waf_view).contains("<script"),
        "WAF view must be inert: {:?}",
        String::from_utf8_lossy(&waf_view)
    );

    // Sink view: a stack that URL-decodes twice (proxy + app).
    let sink_view = Pipeline(vec![Stage::DoubleUrlDecode]).apply(x);
    assert_eq!(
        sink_view, b"<script>alert(1)</script>",
        "sink must reconstruct the live attack"
    );

    // Anti-rig twin: a sink that decodes only ONCE keeps it inert —
    // the bypass is a property of the *mismatch*, not the payload.
    let single_sink = Pipeline(vec![Stage::UrlDecode {
        plus_is_space: false,
    }])
    .apply(x);
    assert!(
        !String::from_utf8_lossy(&single_sink).contains("<script>"),
        "single-decode sink must NOT reconstruct the attack (no false bypass)"
    );
}

#[test]
fn pipeline_is_left_fold_and_total() {
    // JSON body → unescape → then framework URL-decode of the result.
    let p = Pipeline(vec![
        Stage::JsonUnescape,
        Stage::UrlDecode {
            plus_is_space: false,
        },
    ]);
    assert_eq!(p.apply(br"%3Cx"), b"<x"); // %='%', '3C' → %3C → '<'
    // Empty pipeline is identity; never panics on arbitrary bytes.
    assert_eq!(
        Pipeline(vec![]).apply(&[0, 255, 13, 10]),
        vec![0, 255, 13, 10]
    );
}

// ── E3/22: structural-encode → stage-decode is identity for 10k
// random ASCII payloads, for every reversible stage. ──
mod roundtrip_props {
    use proptest::prelude::*;
    use wafrift_wafmodel::Stage;

    fn pc() -> u32 {
        std::env::var("WAFMODEL_PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000)
    }

    fn pct_all(s: &[u8]) -> Vec<u8> {
        s.iter()
            .flat_map(|b| format!("%{b:02X}").into_bytes())
            .collect()
    }
    fn json_all(s: &[u8]) -> Vec<u8> {
        s.iter()
            .flat_map(|b| format!("\\u{b:04x}").into_bytes())
            .collect()
    }
    fn ent_all(s: &[u8]) -> Vec<u8> {
        s.iter()
            .flat_map(|b| format!("&#x{b:x};").into_bytes())
            .collect()
    }
    /// Inject a NUL after every byte (input is NUL-free 0x20..0x7f).
    fn nul_all(s: &[u8]) -> Vec<u8> {
        s.iter().flat_map(|b| [*b, 0u8]).collect()
    }
    /// Overlong-encode every ASCII byte as its non-canonical 2-byte form.
    fn overlong_all(s: &[u8]) -> Vec<u8> {
        s.iter()
            .flat_map(|b| [0xC0 | (b >> 6), 0x80 | (b & 0x3F)])
            .collect()
    }
    /// Base64-encode the whole value (a whole-value transform).
    fn b64_all(s: &[u8]) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s).into_bytes()
    }
    /// Hex-encode the whole value (a whole-value transform).
    fn hex_all(s: &[u8]) -> Vec<u8> {
        hex::encode(s).into_bytes()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(pc()))]

        #[test]
        fn every_reversible_stage_round_trips(p in proptest::collection::vec(0x20u8..0x7f, 0..40)) {
            // URL single decode reverses full %XX encode.
            prop_assert_eq!(
                Stage::UrlDecode { plus_is_space: false }.apply(&pct_all(&p)),
                p.clone()
            );
            // Double-URL decode reverses double %XX encode.
            prop_assert_eq!(Stage::DoubleUrlDecode.apply(&pct_all(&pct_all(&p))), p.clone());
            // JSON unescape reverses \uXXXX encode.
            prop_assert_eq!(Stage::JsonUnescape.apply(&json_all(&p)), p.clone());
            // HTML-entity decode reverses &#xHH; encode.
            prop_assert_eq!(Stage::HtmlEntityDecode.apply(&ent_all(&p)), p.clone());
            // NUL-strip reverses NUL injection.
            prop_assert_eq!(Stage::StripNulls.apply(&nul_all(&p)), p.clone());
            // Overlong UTF-8 decode reverses overlong encoding.
            prop_assert_eq!(Stage::OverlongUtf8Decode.apply(&overlong_all(&p)), p.clone());
            // Base64 decode reverses whole-value base64 encode.
            prop_assert_eq!(Stage::Base64Decode.apply(&b64_all(&p)), p.clone());
            // Hex decode reverses whole-value hex encode.
            prop_assert_eq!(Stage::HexDecode.apply(&hex_all(&p)), p.clone());
            // Identity is identity; every stage is total (no panic) on
            // arbitrary bytes — exercised by construction above. The two text
            // normalizers (NFKC/best-fit) round-trip in their own engine
            // soundness proptests and the solver's all-stage anti-drift guard.
            prop_assert_eq!(Stage::Identity.apply(&p), p);
        }
    }
}
