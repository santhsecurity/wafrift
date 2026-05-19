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
