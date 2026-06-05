//! Source Map v3 decoder.
//!
//! Shipped JavaScript is minified, but production builds frequently ship a
//! companion `*.map` (referenced by a `//# sourceMappingURL=` comment). A v3
//! source map carries — often verbatim in `sourcesContent` — the **original,
//! unminified** module sources, plus a `mappings` string that maps every
//! minified position back to an original `(source, line, column)`.
//!
//! For the sanitizer decompiler the prize is `sourcesContent`: it hands back the
//! readable sanitizer source the site's authors thought they had hidden behind
//! minification. This module parses the map, recovers those sources, and (when
//! `sourcesContent` is absent) decodes the `mappings` so positions can still be
//! correlated.
//!
//! ## Wire format (Source Map Revision 3)
//!
//! A JSON object: `version` (must be 3), `sources` (original file paths),
//! optional `sourcesContent` (parallel to `sources`), `names`, and `mappings` —
//! a string of `;`-separated lines, each a `,`-separated list of **Base64-VLQ**
//! segments. Each segment is 1, 4, or 5 signed VLQ-encoded fields, all stored as
//! *deltas* from the previous segment:
//!
//! ```text
//!   [ genColumn, sourceIndex, sourceLine, sourceColumn, nameIndex? ]
//! ```
//!
//! `genColumn` resets each line; the other four accumulate across the whole map.

use serde::Deserialize;

/// Errors decoding a source map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceMapError {
    /// The JSON did not parse.
    Json(String),
    /// `version` was not 3.
    UnsupportedVersion(i64),
    /// A `mappings` segment contained a character outside the Base64 alphabet.
    BadBase64Char(char),
    /// A VLQ value was truncated (continuation bit set on the final digit).
    TruncatedVlq,
    /// A VLQ value overflowed an `i64` (more than 63 magnitude bits).
    VlqOverflow,
    /// A segment had an illegal field count (not 1, 4, or 5).
    BadSegmentArity(usize),
}

impl std::fmt::Display for SourceMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "source map JSON parse error: {e}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported source map version {v} (only v3 is supported)")
            }
            Self::BadBase64Char(c) => write!(f, "illegal Base64-VLQ character {c:?} in mappings"),
            Self::TruncatedVlq => write!(f, "truncated Base64-VLQ value (continuation bit on final digit)"),
            Self::VlqOverflow => write!(f, "Base64-VLQ value overflows i64"),
            Self::BadSegmentArity(n) => write!(f, "source-map segment has {n} fields (must be 1, 4, or 5)"),
        }
    }
}

impl std::error::Error for SourceMapError {}

/// The Base64 alphabet used by source-map VLQ (RFC 4648 standard, no padding).
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Bits of payload per Base64 digit before the continuation flag.
const VLQ_SHIFT: u32 = 5;
/// Continuation flag bit within a Base64 digit.
const VLQ_CONTINUATION: u32 = 1 << VLQ_SHIFT;
/// Mask for the payload bits of a Base64 digit.
const VLQ_MASK: u32 = VLQ_CONTINUATION - 1;

/// Map a Base64 character to its 6-bit value, or `None` if out of alphabet.
fn b64_value(c: char) -> Option<u32> {
    let b = u8::try_from(c).ok()?;
    B64_ALPHABET.iter().position(|&x| x == b).map(|p| p as u32)
}

/// Encode a single signed integer as Base64-VLQ (used in tests and any caller
/// that needs to round-trip; the encoder is the differential check for the
/// decoder).
#[must_use]
pub fn encode_vlq(value: i64) -> String {
    // Move the sign into bit 0 (the source-map VLQ convention).
    let mut vlq: u64 = if value < 0 {
        ((value.unsigned_abs()) << 1) | 1
    } else {
        (value as u64) << 1
    };
    let mut out = String::new();
    loop {
        let mut digit = (vlq as u32) & VLQ_MASK;
        vlq >>= VLQ_SHIFT;
        if vlq > 0 {
            digit |= VLQ_CONTINUATION;
        }
        out.push(B64_ALPHABET[digit as usize] as char);
        if vlq == 0 {
            break;
        }
    }
    out
}

/// Decode one Base64-VLQ value starting at `chars[pos]`, returning the value and
/// the number of characters consumed.
fn decode_vlq(chars: &[char], pos: usize) -> Result<(i64, usize), SourceMapError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = pos;
    loop {
        let c = chars.get(i).copied().ok_or(SourceMapError::TruncatedVlq)?;
        let digit = b64_value(c).ok_or(SourceMapError::BadBase64Char(c))?;
        let continuation = digit & VLQ_CONTINUATION != 0;
        let payload = u64::from(digit & VLQ_MASK);
        // Guard overflow of the u64 accumulator. `payload` is < 2^5, occupying
        // bits [shift, shift+5); `shift` advances by 5, so it never equals 63 —
        // the boundary is `shift == 60` with `payload >= 16` (which would set
        // bit 64), plus any `shift >= 64`. Written this way it cannot itself
        // shift-overflow (the `1 << (64 - shift)` term only runs for shift in
        // 60..64, so the shift amount is 1..=4). A hostile/corrupt map thus
        // yields a clean `VlqOverflow` instead of a silently truncated value.
        if shift >= 64 || (shift + VLQ_SHIFT > 64 && payload >= (1u64 << (64 - shift))) {
            return Err(SourceMapError::VlqOverflow);
        }
        result |= payload << shift;
        shift += VLQ_SHIFT;
        i += 1;
        if !continuation {
            break;
        }
    }
    let consumed = i - pos;
    // Recover the sign from bit 0.
    let negative = result & 1 == 1;
    let magnitude = (result >> 1) as i64;
    Ok((if negative { -magnitude } else { magnitude }, consumed))
}

/// One decoded mapping segment, with **absolute** (delta-accumulated) fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// 0-based column in the generated (minified) file.
    pub generated_column: i64,
    /// Index into [`SourceMap::sources`], if the segment names a source.
    pub source_index: Option<i64>,
    /// 0-based original line.
    pub original_line: Option<i64>,
    /// 0-based original column.
    pub original_column: Option<i64>,
    /// Index into [`SourceMap::names`], if the segment names a symbol.
    pub name_index: Option<i64>,
}

/// A parsed Source Map v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMap {
    /// Optional generated file name.
    pub file: Option<String>,
    /// Optional path prepended to every entry in `sources`.
    pub source_root: Option<String>,
    /// Original source paths.
    pub sources: Vec<String>,
    /// Original source contents, parallel to `sources` (entries may be absent).
    pub sources_content: Vec<Option<String>>,
    /// Symbol names referenced by segments.
    pub names: Vec<String>,
    /// The raw, undecoded `mappings` string.
    pub mappings: String,
}

/// Raw JSON shape (mirrors the v3 spec field names).
#[derive(Deserialize)]
struct RawMap {
    version: i64,
    #[serde(default)]
    file: Option<String>,
    #[serde(rename = "sourceRoot", default)]
    source_root: Option<String>,
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    mappings: String,
}

/// A recovered original source: its (root-resolved) path and, when the map
/// embedded it, the original unminified content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    /// Source path with `sourceRoot` applied.
    pub path: String,
    /// Original content, if `sourcesContent` carried it.
    pub content: Option<String>,
}

impl SourceMap {
    /// Parse a Source Map v3 from its JSON text. Fails closed on a non-3
    /// `version` or malformed JSON — a map we cannot trust is never silently
    /// treated as empty.
    pub fn parse(json: &str) -> Result<Self, SourceMapError> {
        let raw: RawMap =
            serde_json::from_str(json).map_err(|e| SourceMapError::Json(e.to_string()))?;
        if raw.version != 3 {
            return Err(SourceMapError::UnsupportedVersion(raw.version));
        }
        // `sources` entries may be null per spec; normalise to "" so indices
        // still line up with `sourcesContent`.
        let sources: Vec<String> = raw
            .sources
            .into_iter()
            .map(|s| s.unwrap_or_default())
            .collect();
        Ok(Self {
            file: raw.file,
            source_root: raw.source_root,
            sources,
            sources_content: raw.sources_content,
            names: raw.names,
            mappings: raw.mappings,
        })
    }

    /// Recover every original source: its `sourceRoot`-resolved path and the
    /// embedded content when present. This is the decompiler's headline output —
    /// the readable module sources the minifier was supposed to obscure.
    #[must_use]
    pub fn recovered_sources(&self) -> Vec<RecoveredSource> {
        let root = self.source_root.as_deref().unwrap_or("");
        self.sources
            .iter()
            .enumerate()
            .map(|(i, src)| {
                let path = if root.is_empty() {
                    src.clone()
                } else if root.ends_with('/') {
                    format!("{root}{src}")
                } else {
                    format!("{root}/{src}")
                };
                RecoveredSource {
                    path,
                    content: self.sources_content.get(i).cloned().flatten(),
                }
            })
            .collect()
    }

    /// Concatenate every recovered source that carried embedded content — the
    /// single haystack the sanitizer extractor scans.
    #[must_use]
    pub fn recovered_content(&self) -> String {
        self.recovered_sources()
            .into_iter()
            .filter_map(|s| s.content)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Decode the `mappings` string into per-line absolute segments. `mappings`
    /// stores deltas; this accumulates them so each [`Segment`] carries absolute
    /// positions. The outer `Vec` is indexed by generated line.
    pub fn decode_mappings(&self) -> Result<Vec<Vec<Segment>>, SourceMapError> {
        // The four non-genColumn fields accumulate across the WHOLE map; only
        // genColumn resets per line (RFC: "the generated column ... reset[s] ...
        // for each new line").
        let mut source_index: i64 = 0;
        let mut original_line: i64 = 0;
        let mut original_column: i64 = 0;
        let mut name_index: i64 = 0;

        let mut lines = Vec::new();
        for line in self.mappings.split(';') {
            let mut generated_column: i64 = 0;
            let mut segments = Vec::new();
            for seg in line.split(',') {
                if seg.is_empty() {
                    continue;
                }
                let chars: Vec<char> = seg.chars().collect();
                let mut fields = Vec::with_capacity(5);
                let mut pos = 0;
                while pos < chars.len() {
                    let (v, n) = decode_vlq(&chars, pos)?;
                    fields.push(v);
                    pos += n;
                }
                let segment = match fields.len() {
                    1 => {
                        generated_column += fields[0];
                        Segment {
                            generated_column,
                            source_index: None,
                            original_line: None,
                            original_column: None,
                            name_index: None,
                        }
                    }
                    4 | 5 => {
                        generated_column += fields[0];
                        source_index += fields[1];
                        original_line += fields[2];
                        original_column += fields[3];
                        let name = if fields.len() == 5 {
                            name_index += fields[4];
                            Some(name_index)
                        } else {
                            None
                        };
                        Segment {
                            generated_column,
                            source_index: Some(source_index),
                            original_line: Some(original_line),
                            original_column: Some(original_column),
                            name_index: name,
                        }
                    }
                    n => return Err(SourceMapError::BadSegmentArity(n)),
                };
                segments.push(segment);
            }
            lines.push(segments);
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── VLQ codec ─────────────────────────────────────────────────────────

    fn decode_one(s: &str) -> i64 {
        let chars: Vec<char> = s.chars().collect();
        decode_vlq(&chars, 0).expect("decode").0
    }

    #[test]
    fn vlq_known_values() {
        // Spec examples: 0→"A", 1→"C", -1→"D", 16→"gB", 123→"2H".
        assert_eq!(encode_vlq(0), "A");
        assert_eq!(encode_vlq(1), "C");
        assert_eq!(encode_vlq(-1), "D");
        assert_eq!(encode_vlq(16), "gB");
        assert_eq!(decode_one("A"), 0);
        assert_eq!(decode_one("C"), 1);
        assert_eq!(decode_one("D"), -1);
        assert_eq!(decode_one("gB"), 16);
    }

    #[test]
    fn vlq_decode_reports_chars_consumed() {
        // "ACDgB" = [0, 1, -1, 16] back to back.
        let chars: Vec<char> = "ACDgB".chars().collect();
        let (v0, n0) = decode_vlq(&chars, 0).unwrap();
        assert_eq!((v0, n0), (0, 1));
        let (v1, n1) = decode_vlq(&chars, n0).unwrap();
        assert_eq!((v1, n1), (1, 1));
        let (v2, n2) = decode_vlq(&chars, n0 + n1).unwrap();
        assert_eq!((v2, n2), (-1, 1));
        let (v3, n3) = decode_vlq(&chars, n0 + n1 + n2).unwrap();
        assert_eq!((v3, n3), (16, 2));
    }

    #[test]
    fn vlq_bad_char_is_rejected() {
        let chars: Vec<char> = "!".chars().collect();
        assert_eq!(decode_vlq(&chars, 0), Err(SourceMapError::BadBase64Char('!')));
    }

    #[test]
    fn vlq_truncated_continuation_is_rejected() {
        // 'g' = 32 = continuation bit set, with nothing following.
        let chars: Vec<char> = "g".chars().collect();
        assert_eq!(decode_vlq(&chars, 0), Err(SourceMapError::TruncatedVlq));
    }

    #[test]
    fn vlq_overflow_at_the_shift_60_boundary_is_rejected_not_truncated() {
        // 12 continuation digits with payload 0 ('g' = idx 32 = continuation,
        // payload 0) advance `shift` to 60. A 13th digit with payload >= 16
        // would set bit 64 of the u64 accumulator. 'Q' = idx 16 = no
        // continuation, payload 16 → must be a clean VlqOverflow, NOT a silently
        // truncated value (the bug the old dead `shift == 63` guard missed).
        let chars: Vec<char> = "ggggggggggggQ".chars().collect();
        assert_eq!(chars.len(), 13);
        assert_eq!(decode_vlq(&chars, 0), Err(SourceMapError::VlqOverflow));
    }

    #[test]
    fn vlq_just_under_the_overflow_boundary_still_decodes() {
        // Same 12-digit run to shift=60, but a 13th payload of 15 ('P' = idx 15)
        // fits (bits 60..63) — it must decode, not error. Proves the guard is a
        // tight boundary, not an over-eager reject.
        let chars: Vec<char> = "ggggggggggggP".chars().collect();
        let (_v, consumed) = decode_vlq(&chars, 0).expect("payload 15 at shift 60 fits u64");
        assert_eq!(consumed, 13);
    }

    #[test]
    fn vlq_long_continuation_run_past_64_bits_is_rejected() {
        // 13 continuation digits drive shift to 65; the next read trips the
        // `shift >= 64` arm. Must error, never panic on the shift.
        let chars: Vec<char> = "gggggggggggggA".chars().collect();
        assert_eq!(decode_vlq(&chars, 0), Err(SourceMapError::VlqOverflow));
    }

    // ── SourceMap parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_rejects_non_v3() {
        let json = r#"{"version":2,"sources":[],"mappings":""}"#;
        assert_eq!(SourceMap::parse(json), Err(SourceMapError::UnsupportedVersion(2)));
    }

    #[test]
    fn parse_rejects_malformed_json() {
        assert!(matches!(
            SourceMap::parse("{not json"),
            Err(SourceMapError::Json(_))
        ));
    }

    #[test]
    fn recovered_sources_returns_embedded_content() {
        let json = r#"{
            "version":3,
            "sources":["src/sanitize.js"],
            "sourcesContent":["export function clean(s){return s.replace(/<script>/gi,'');}"],
            "names":[],
            "mappings":""
        }"#;
        let map = SourceMap::parse(json).unwrap();
        let recovered = map.recovered_sources();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].path, "src/sanitize.js");
        assert!(recovered[0].content.as_deref().unwrap().contains("replace(/<script>/gi"));
    }

    #[test]
    fn recovered_sources_applies_source_root() {
        let json = r#"{
            "version":3,
            "sourceRoot":"webpack://app",
            "sources":["sanitize.js","util.js"],
            "sourcesContent":["a","b"],
            "names":[],"mappings":""
        }"#;
        let map = SourceMap::parse(json).unwrap();
        let r = map.recovered_sources();
        assert_eq!(r[0].path, "webpack://app/sanitize.js");
        assert_eq!(r[1].path, "webpack://app/util.js");
    }

    #[test]
    fn recovered_content_joins_only_present_sources() {
        let json = r#"{
            "version":3,
            "sources":["a.js","b.js","c.js"],
            "sourcesContent":["AAA",null,"CCC"],
            "names":[],"mappings":""
        }"#;
        let map = SourceMap::parse(json).unwrap();
        let content = map.recovered_content();
        assert!(content.contains("AAA"));
        assert!(content.contains("CCC"));
        // The null (missing) source contributes nothing — no empty "null" text.
        assert!(!content.contains("null"));
    }

    #[test]
    fn missing_sources_content_yields_none_not_error() {
        let json = r#"{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}"#;
        let map = SourceMap::parse(json).unwrap();
        assert_eq!(map.recovered_sources()[0].content, None);
    }

    // ── mappings decoding ─────────────────────────────────────────────────

    #[test]
    fn decode_single_segment_mapping() {
        // "AAAA" = one segment [0,0,0,0]: genCol 0, source 0, line 0, col 0.
        let json = r#"{"version":3,"sources":["a.js"],"names":[],"mappings":"AAAA"}"#;
        let map = SourceMap::parse(json).unwrap();
        let lines = map.decode_mappings().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), 1);
        let s = lines[0][0];
        assert_eq!(s.generated_column, 0);
        assert_eq!(s.source_index, Some(0));
        assert_eq!(s.original_line, Some(0));
        assert_eq!(s.original_column, Some(0));
        assert_eq!(s.name_index, None);
    }

    #[test]
    fn decode_accumulates_deltas_across_segments_and_lines() {
        // Hand-built two-line map. Line 1: "AAAA,CAAC" → segs at genCol 0 and 1,
        // second has original_column delta +1. Line 2: "ACAA" → line delta...
        // Build it with the encoder so the test is self-consistent.
        let seg = |g: i64, s: i64, l: i64, c: i64| {
            format!(
                "{}{}{}{}",
                encode_vlq(g),
                encode_vlq(s),
                encode_vlq(l),
                encode_vlq(c)
            )
        };
        // Line 0: seg(genCol+0, src+0, line+0, col+0), seg(genCol+5, src+0, line+0, col+3)
        // Line 1: seg(genCol+2, src+0, line+1, col+0)
        let mappings = format!("{},{};{}", seg(0, 0, 0, 0), seg(5, 0, 0, 3), seg(2, 0, 1, 0));
        let json = format!(
            r#"{{"version":3,"sources":["a.js"],"names":[],"mappings":"{mappings}"}}"#
        );
        let map = SourceMap::parse(&json).unwrap();
        let lines = map.decode_mappings().unwrap();
        assert_eq!(lines.len(), 2);
        // Line 0, segment 1: genCol resets per line then +0 → 0, then +5 → 5.
        assert_eq!(lines[0][0].generated_column, 0);
        assert_eq!(lines[0][1].generated_column, 5);
        assert_eq!(lines[0][1].original_column, Some(3));
        // Line 1: genCol resets to 0 then +2 → 2; original_line accumulated to 1.
        assert_eq!(lines[1][0].generated_column, 2);
        assert_eq!(lines[1][0].original_line, Some(1));
    }

    #[test]
    fn decode_five_field_segment_carries_name_index() {
        let seg5 = format!(
            "{}{}{}{}{}",
            encode_vlq(0),
            encode_vlq(0),
            encode_vlq(0),
            encode_vlq(0),
            encode_vlq(2)
        );
        let json = format!(
            r#"{{"version":3,"sources":["a.js"],"names":["x","y","clean"],"mappings":"{seg5}"}}"#
        );
        let map = SourceMap::parse(&json).unwrap();
        let lines = map.decode_mappings().unwrap();
        assert_eq!(lines[0][0].name_index, Some(2));
        assert_eq!(map.names[2], "clean");
    }

    #[test]
    fn decode_empty_mappings_line_is_kept_as_empty_segment_list() {
        // ";;" → three lines, all empty (common for blank generated lines).
        let json = r#"{"version":3,"sources":["a.js"],"names":[],"mappings":";;"}"#;
        let map = SourceMap::parse(json).unwrap();
        let lines = map.decode_mappings().unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(Vec::is_empty));
    }

    #[test]
    fn decode_rejects_bad_segment_arity() {
        // A 2-field segment is illegal (must be 1, 4, or 5).
        let two = format!("{}{}", encode_vlq(0), encode_vlq(1));
        let json = format!(r#"{{"version":3,"sources":["a.js"],"names":[],"mappings":"{two}"}}"#);
        let map = SourceMap::parse(&json).unwrap();
        assert_eq!(map.decode_mappings(), Err(SourceMapError::BadSegmentArity(2)));
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5000))]

        /// Every i64 in the source-map field range round-trips through the VLQ
        /// codec, and the decoder reports consuming exactly the encoded length.
        #[test]
        fn prop_vlq_roundtrips(v in -(1i64 << 53)..(1i64 << 53)) {
            let enc = encode_vlq(v);
            let chars: Vec<char> = enc.chars().collect();
            let (decoded, consumed) = decode_vlq(&chars, 0).expect("decode");
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(consumed, chars.len());
        }

        /// A run of VLQ values concatenated decodes back to the same sequence —
        /// the property a real `mappings` segment relies on.
        #[test]
        fn prop_vlq_sequence_roundtrips(vals in proptest::collection::vec(-100000i64..100000, 0..8)) {
            let mut s = String::new();
            for &v in &vals {
                s.push_str(&encode_vlq(v));
            }
            let chars: Vec<char> = s.chars().collect();
            let mut pos = 0;
            let mut got = Vec::new();
            while pos < chars.len() {
                let (v, n) = decode_vlq(&chars, pos).expect("decode");
                got.push(v);
                pos += n;
            }
            prop_assert_eq!(got, vals);
        }

        /// `decode_vlq` over an arbitrary Base64 run never panics — it returns a
        /// value or a typed error (overflow / truncation / bad char). Direct fuzz
        /// of the decoder's overflow guard, including the `shift == 60` boundary
        /// and the `shift >= 64` long-run case that valid-JSON fuzzing can't reach.
        #[test]
        fn prop_decode_vlq_never_panics(s in "[A-Za-z0-9+/]{1,40}") {
            let chars: Vec<char> = s.chars().collect();
            let _ = decode_vlq(&chars, 0);
        }

        /// Any value the decoder accepts re-encodes and re-decodes to itself — the
        /// codec is a faithful inverse on its entire accepted domain.
        #[test]
        fn prop_decoded_value_reencodes_stably(s in "[A-Za-z0-9+/]{1,13}") {
            let chars: Vec<char> = s.chars().collect();
            if let Ok((v, _)) = decode_vlq(&chars, 0) {
                let re: Vec<char> = encode_vlq(v).chars().collect();
                let (v2, _) = decode_vlq(&re, 0).expect("a re-encoded accepted value must decode");
                prop_assert_eq!(v, v2);
            }
        }

        /// Parsing never panics on arbitrary JSON-ish input — it returns a typed
        /// error or a value, but never crashes the decompiler.
        #[test]
        fn prop_parse_never_panics(s in ".{0,200}") {
            let _ = SourceMap::parse(&s);
        }
    }
}
