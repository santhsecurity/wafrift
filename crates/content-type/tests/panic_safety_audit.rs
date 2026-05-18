//! Deep robustness audit for the content-type transforms.
//!
//! `parse_form_body` and `generate_variants_from_body` consume **raw
//! attacker request bodies** byte-for-byte; `xml_safe_name`,
//! `unique_boundary`, `multipart_enhanced::generate_variants` and
//! `generate_variants` transform attacker-supplied parameter names and
//! filenames. These are squarely on the hostile-input path
//! (`wafrift scan --strategies content-type`, the proxy's Content-Type
//! confusion engine). A panic, a mid-codepoint slice, or an output that
//! balloons super-linearly here takes the whole evasion pass down.
//!
//! Contracts asserted (corpus + proptest):
//!   1. No panic on any bytes / any string.
//!   2. Bounded output: total serialized variant bytes stay within
//!      `input_len * 256 + 1 MiB` (catches accidental blow-up DoS).
//!   3. `xml_safe_name` always returns a syntactically valid XML Name
//!      (NameStartChar + NameChar*), never empty, for ANY input — that
//!      is the function's entire reason to exist.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wafrift_content_type::{
    generate_variants, generate_variants_from_body, multipart_enhanced, parse_form_body,
    unique_boundary, xml_safe_name,
};

fn adversarial_bytes() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", vec![]),
        ("single_amp", b"&".to_vec()),
        ("single_eq", b"=".to_vec()),
        ("eq_amp_storm", b"=&=&=&==&&=".repeat(512)),
        ("no_delims", b"abcdefghij".repeat(4096)),
        ("nul_bytes", vec![0u8; 8192]),
        ("high_bytes", vec![0xFFu8; 8192]),
        ("invalid_utf8_1", vec![0x80]),
        ("invalid_utf8_2", vec![0xC0, 0xAF]),
        ("invalid_utf8_3", vec![0xED, 0xA0, 0x80]),
        ("invalid_utf8_4", vec![0xF0, 0x80, 0x80, 0x80]),
        ("truncated_mb", vec![b'a', b'=', 0xE2, 0x82]), // half a €
        ("crlf_inject", b"a=b\r\nSet-Cookie: x=y\r\n\r\n".to_vec()),
        ("pct_storm", b"%2525%00%ff%".repeat(1024)),
        ("multipart_ish", b"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n".to_vec()),
        ("json_ish", b"{\"a\":[1,2,{\"b\":\"\xff\"}]}".to_vec()),
        ("xml_ish", b"<?xml version=\"1.0\"?><r>&ent;<![CDATA[\xff]]></r>".to_vec()),
        ("huge_value", {
            let mut v = b"k=".to_vec();
            v.extend(std::iter::repeat_n(b'A', 300_000));
            v
        }),
        ("many_params", {
            let mut v = Vec::new();
            for i in 0..5000 {
                v.extend(format!("p{i}=v{i}&").bytes());
            }
            v
        }),
    ]
}

fn adversarial_strings() -> Vec<String> {
    let mut v: Vec<String> = [
        "",
        " ",
        "\u{0}",
        "\u{0}\u{1}\u{2}",
        "1abc",          // digit start — invalid XML NameStartChar
        "-bad",          // hyphen start
        ".bad",          // dot start
        "xml-reserved",  // "xml" prefix is reserved
        "a b\tc\n",      // whitespace
        "café",
        "日本語",
        "𝕏𝕐𝕑",
        "a\u{301}",      // combining
        "\u{200B}",      // zero-width only
        "<script>",
        "a&b=c\"d'e",
        "\u{FFFD}",
        "../../etc/passwd",
        "shell.php\u{0}.jpg",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    v.push("x".repeat(100_000));
    v
}

/// Real serialized size of the variants — the actual bytes that would
/// go on the wire (`Content-Type` header + body), NOT `{:?}` Debug
/// (which renders a `Vec<u8>` body as `[72, 84, ...]`, ~5× inflated and
/// a meaningless metric for a DoS-ceiling assertion).
fn variant_bytes(v: &[wafrift_content_type::ContentTypeVariant]) -> usize {
    v.iter()
        .map(|x| x.content_type.len() + x.body.len())
        .sum()
}

/// `generate_variants` re-emits the full param set per variant but the
/// expandable input is hard-capped (`MAX_VARIANT_INPUT_BYTES`), so the
/// output is bounded by an absolute constant *regardless of input
/// size*. This ceiling holds for a 10-byte body and a 10 MB body alike
/// — that is the entire point of the cap.
const ABSOLUTE_VARIANT_CEILING: usize = 8 * 1024 * 1024;

#[test]
fn content_type_transforms_survive_adversarial_corpus() {
    let mut failures: Vec<String> = Vec::new();

    let mut guard = |name: &str, f: &mut dyn FnMut()| {
        if catch_unwind(AssertUnwindSafe(|| f())).is_err() {
            failures.push(format!("PANIC: {name}"));
        }
    };

    for (label, bytes) in adversarial_bytes() {
        let b = bytes.clone();
        guard(&format!("parse_form_body[{label}]"), &mut || {
            let _ = parse_form_body(&b);
        });

        let b = bytes.clone();
        guard(&format!("generate_variants_from_body[{label}]"), &mut || {
            let out = generate_variants_from_body(&b);
            let got = variant_bytes(&out);
            assert!(
                got <= ABSOLUTE_VARIANT_CEILING,
                "generate_variants_from_body[{label}] expanded to {got} bytes > absolute ceiling {ABSOLUTE_VARIANT_CEILING} (input was {} bytes — output must NOT scale with input)",
                b.len()
            );
        });

        // Round-trip: parsed params back through generate_variants.
        let parsed = std::panic::catch_unwind(AssertUnwindSafe(|| parse_form_body(&bytes)))
            .unwrap_or_default();
        guard(&format!("generate_variants[{label}]"), &mut || {
            let _ = generate_variants(&parsed);
        });
    }

    for s in adversarial_strings() {
        let label: String = s.chars().take(16).collect();
        guard(&format!("xml_safe_name[{label:?}]"), &mut || {
            let name = xml_safe_name(&s);
            assert!(
                is_valid_xml_name(&name),
                "xml_safe_name({s:?}) = {name:?} is not a valid XML Name"
            );
        });
        guard(&format!("multipart_enhanced[{label:?}]"), &mut || {
            let _ = multipart_enhanced::generate_variants(&s);
        });
        guard(&format!("unique_boundary[{label:?}]"), &mut || {
            let _ = unique_boundary(&[s.as_str(), s.as_str(), "boundary"]);
        });
    }

    // unique_boundary's actual contract: the multipart delimiter
    // `--{boundary}` must NOT occur as a substring of any supplied
    // value (otherwise an attacker who controls a field value can
    // forge a part boundary). Feed it values that *do* embed a
    // plausible delimiter so the collision-avoidance path is exercised,
    // not just the trivial case.
    let crafted = format!("prefix--{}suffix", "----WafriftBoundarydeadbeef");
    let avoid = [
        crafted.as_str(),
        "------WebKitFormBoundary",
        "",
        "🦀boundary",
        "plain field value",
    ];
    let b = unique_boundary(&avoid);
    let needle = format!("--{b}");
    assert!(
        !avoid.iter().any(|v| v.contains(&needle)),
        "unique_boundary returned {b:?} whose delimiter {needle:?} appears in an input value"
    );
    assert!(!b.is_empty(), "unique_boundary returned an empty boundary");

    assert!(
        failures.is_empty(),
        "content-type robustness audit found {} defect(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Minimal XML 1.0 Name validator (NameStartChar NameChar*) — enough to
/// prove `xml_safe_name`'s output can be dropped into an element/attr
/// position without producing malformed XML.
fn is_valid_xml_name(s: &str) -> bool {
    fn is_start(c: char) -> bool {
        c == ':'
            || c == '_'
            || c.is_ascii_alphabetic()
            || ('\u{C0}'..='\u{D6}').contains(&c)
            || ('\u{D8}'..='\u{F6}').contains(&c)
            || ('\u{F8}'..='\u{2FF}').contains(&c)
            || ('\u{370}'..='\u{37D}').contains(&c)
            || ('\u{37F}'..='\u{1FFF}').contains(&c)
            || ('\u{200C}'..='\u{200D}').contains(&c)
            || ('\u{2070}'..='\u{218F}').contains(&c)
            || ('\u{2C00}'..='\u{2FEF}').contains(&c)
            || ('\u{3001}'..='\u{D7FF}').contains(&c)
            || ('\u{F900}'..='\u{FDCF}').contains(&c)
            || ('\u{FDF0}'..='\u{FFFD}').contains(&c)
            || ('\u{10000}'..='\u{EFFFF}').contains(&c)
    }
    fn is_part(c: char) -> bool {
        is_start(c)
            || c == '-'
            || c == '.'
            || c.is_ascii_digit()
            || c == '\u{B7}'
            || ('\u{0300}'..='\u{036F}').contains(&c)
            || ('\u{203F}'..='\u{2040}').contains(&c)
    }
    let mut chars = s.chars();
    match chars.next() {
        None => false, // empty Name is invalid
        Some(c) if !is_start(c) => false,
        _ => chars.all(is_part),
    }
}

// ───────────────────── pinned regressions (handwritten) ─────────────────────

/// `xml_safe_name` used `char::is_alphanumeric()`, which accepts
/// Unicode category `No` (e.g. `²` U+00B2) — *not* a valid XML
/// `NameChar`. `xml_safe_name("0²")` returned `"_²"`, an element name
/// that makes the generated XML evasion variant malformed and useless.
#[test]
fn regression_xml_safe_name_rejects_non_namechar_unicode() {
    for bad in ["0²", "²", "a²b", "x\u{00B9}\u{00BC}", "𝟙²³"] {
        let got = xml_safe_name(bad);
        assert!(
            is_valid_xml_name(&got),
            "xml_safe_name({bad:?}) = {got:?} is not a valid XML Name"
        );
    }
    // Valid Unicode names must still pass through unmangled.
    assert_eq!(xml_safe_name("日本語"), "日本語");
    assert_eq!(xml_safe_name("validName"), "validName");
    // Reserved "xml" prefix is shifted out.
    assert!(!xml_safe_name("xmlThing").to_lowercase().starts_with("xml"));
}

/// `generate_variants` re-emits every param per variant. Output MUST be
/// bounded by an absolute constant no matter how huge the input — a
/// 4 MB body must not become ~50 MB (the proxy calls this per request).
#[test]
fn regression_generate_variants_output_is_input_independent() {
    let tiny = b"a=1&b=2".to_vec();
    let huge = {
        let mut v = Vec::with_capacity(4 * 1024 * 1024);
        while v.len() < 4 * 1024 * 1024 {
            v.extend_from_slice(b"param=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&");
        }
        v
    };
    // A body exactly at the expand cap, and one 64× past it.
    let at_cap = {
        let mut v = Vec::new();
        while v.len() < 64 * 1024 {
            v.extend_from_slice(b"param=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&");
        }
        v
    };
    let tiny_out = variant_bytes(&generate_variants_from_body(&tiny));
    let at_cap_out = variant_bytes(&generate_variants_from_body(&at_cap));
    let huge_out = variant_bytes(&generate_variants_from_body(&huge));

    assert!(
        huge_out <= ABSOLUTE_VARIANT_CEILING,
        "4 MB body produced {huge_out} bytes of variants > ceiling {ABSOLUTE_VARIANT_CEILING}"
    );
    assert!(
        tiny_out < at_cap_out,
        "sanity: a 2-param body should produce less than a 64 KiB one (tiny={tiny_out}, at_cap={at_cap_out})"
    );
    // The decisive contract: growing the input 64× beyond the cap
    // (64 KiB → 4 MiB) must NOT grow the output — both are clamped to
    // the same `MAX_VARIANT_INPUT_BYTES` of expandable params, so the
    // outputs are within a few percent. Pre-cap this ratio was ~64×.
    let (lo, hi) = (at_cap_out.min(huge_out), at_cap_out.max(huge_out));
    assert!(
        hi <= lo + lo / 10 + 4096,
        "output scaled with input past the cap: at_cap={at_cap_out}, huge={huge_out} \
         (64× more input must not meaningfully grow output)"
    );
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1200))]

        #[test]
        fn arbitrary_body_bytes_panic_free(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let parsed = parse_form_body(&bytes);
            let _ = generate_variants(&parsed);
            let out = generate_variants_from_body(&bytes);
            prop_assert!(
                variant_bytes(&out) <= ABSOLUTE_VARIANT_CEILING,
                "expansion {} > absolute ceiling {ABSOLUTE_VARIANT_CEILING}",
                variant_bytes(&out)
            );
        }

        #[test]
        fn arbitrary_name_yields_valid_xml_name(s in ".{0,512}") {
            let name = xml_safe_name(&s);
            prop_assert!(
                is_valid_xml_name(&name),
                "xml_safe_name({s:?}) = {name:?} invalid"
            );
        }

        #[test]
        fn arbitrary_filename_panic_free(s in ".{0,1024}") {
            let _ = multipart_enhanced::generate_variants(&s);
            let _ = unique_boundary(&[s.as_str()]);
        }
    }
}
