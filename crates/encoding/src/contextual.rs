use crate::encoding::strategy::MAX_PAYLOAD_SIZE;
use crate::encoding::Strategy;
use wafrift_types::injection_context::{ContextualEncodeError, InjectionContext};

pub fn encode_in_context(
    payload: &[u8],
    strategy: Strategy,
    context: InjectionContext,
) -> Result<String, ContextualEncodeError> {
    // §7 DEDUP: context-specific limits reference the canonical
    // `MAX_PAYLOAD_SIZE` (8 MiB) instead of repeating the bare literal.
    // The pre-fix had two independent `8 * 1024 * 1024` entries; both
    // now track the shared constant so a single edit adjusts them all.
    let max_size = match context {
        InjectionContext::JsonString => MAX_PAYLOAD_SIZE / 2, // 4 MiB
        InjectionContext::JsonNumber => 1024,
        InjectionContext::XmlAttribute => MAX_PAYLOAD_SIZE / 8, // 1 MiB
        InjectionContext::XmlCdata => MAX_PAYLOAD_SIZE,
        InjectionContext::HeaderValue => 8 * 1024,
        InjectionContext::CookieValue => 4 * 1024,
        InjectionContext::MultipartFileName => 256,
        _ => MAX_PAYLOAD_SIZE,
    };

    if payload.len() > max_size {
        return Err(ContextualEncodeError::PayloadTooLarge {
            context,
            size: payload.len(),
            max: max_size,
        });
    }

    let base = match crate::encoding::encode(payload, strategy) {
        Ok(s) => s,
        Err(e) => {
            return Err(match e {
                crate::error::EncodeError::InvalidUtf8 => {
                    ContextualEncodeError::InvalidUtf8 { offset: 0 }
                }
                crate::error::EncodeError::PayloadTooLarge { max, actual } => {
                    ContextualEncodeError::PayloadTooLarge {
                        context,
                        size: actual,
                        max,
                    }
                }
                crate::error::EncodeError::LayeredOutputTooLarge { max, actual } => {
                    ContextualEncodeError::PayloadTooLarge {
                        context,
                        size: actual,
                        max,
                    }
                }
                crate::error::EncodeError::InvalidContext {
                    strategy: s,
                    context: _,
                } => ContextualEncodeError::ContextIncompatible {
                    strategy: s.into(),
                    context,
                    reason: "strategy invalid for context".into(),
                },
                crate::error::EncodeError::InvalidConfig(msg) => {
                    ContextualEncodeError::ContextIncompatible {
                        strategy: "config".into(),
                        context,
                        reason: msg,
                    }
                }
            });
        }
    };

    escape_for_context(&base, context)
}

pub fn escape_for_context(
    input: &str,
    context: InjectionContext,
) -> Result<String, ContextualEncodeError> {
    let escaped = match context {
        InjectionContext::JsonString => {
            let mut s = String::with_capacity(input.len() + 10);
            for c in input.chars() {
                match c {
                    '\\' => s.push_str("\\\\"),
                    '"' => s.push_str("\\\""),
                    '\n' => s.push_str("\\n"),
                    '\r' => s.push_str("\\r"),
                    '\t' => s.push_str("\\t"),
                    '\x00'..='\x1f' => s.push_str(&format!("\\u{:04x}", c as u32)),
                    // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR
                    // are valid in JSON strings per RFC 8259 but are line
                    // terminators in legacy ECMAScript / JSONP / eval
                    // contexts. Pre-fix a payload-controlled value with
                    // U+2028 inlined into <script>JSON</script> would
                    // close the string literal and inject script. Escape
                    // both for defence-in-depth even when shipping pure
                    // JSON over the wire.
                    '\u{2028}' => s.push_str("\\u2028"),
                    '\u{2029}' => s.push_str("\\u2029"),
                    _ => s.push(c),
                }
            }
            s
        }
        InjectionContext::JsonNumber => {
            if input.chars().any(|c| {
                !c.is_ascii_digit() && c != '.' && c != '-' && c != 'e' && c != 'E' && c != '+'
            }) {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "not a valid JSON number".into(),
                });
            }
            input.to_string()
        }
        InjectionContext::XmlAttribute => {
            if input.contains('\x00') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "null byte in xml attribute".into(),
                });
            }
            // XML allows single-quoted attributes; pre-fix only escaped
            // `&"<>` and a payload with `'` would break out of an
            // `<elem attr='...'>` form. Add &apos; escape.
            input
                .replace('&', "&amp;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        }
        InjectionContext::XmlCdata => {
            if input.contains("]]>") {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "CDATA cannot contain ]]>".into(),
                });
            }
            input.to_string()
        }
        InjectionContext::XmlText => input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
        InjectionContext::HtmlAttribute => input
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('<', "&lt;"),
        InjectionContext::HtmlText => input.replace('&', "&amp;").replace('<', "&lt;"),
        InjectionContext::UrlQuery => urlencoding::encode(input).to_string(),
        InjectionContext::UrlPath => urlencoding::encode(input).to_string().replace("%2F", "/"),
        InjectionContext::UrlFragment => urlencoding::encode(input).to_string(),
        InjectionContext::HeaderValue => {
            if input.contains('\r') || input.contains('\n') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "CR/LF in header value".into(),
                });
            }
            if input.contains('\x00') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "null byte in header value".into(),
                });
            }
            input.to_string()
        }
        InjectionContext::CookieValue => input
            // RFC 6265 §4.1.1 cookie-octet excludes space, ",", '"', `\\`
            // in addition to ; = CTLs. Pre-fix the missing chars caused
            // Chrome / Firefox / curl to truncate the cookie at the
            // offending byte — making bypass probes silently lie about
            // the value that actually reached the server.
            .replace(';', "%3B")
            .replace('=', "%3D")
            .replace(' ', "%20")
            .replace(',', "%2C")
            .replace('"', "%22")
            .replace('\\', "%5C")
            .replace('\x00', "%00")
            .replace('\r', "%0D")
            .replace('\n', "%0A"),
        InjectionContext::MultipartField => {
            if input.contains('\r') || input.contains('\n') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "CR/LF would break multipart structure".into(),
                });
            }
            input.to_string()
        }
        InjectionContext::MultipartFileName => {
            if input.contains('"') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "quote in filename".into(),
                });
            }
            if input.contains('\r') || input.contains('\n') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "escape".into(),
                    context,
                    reason: "CR/LF in filename".into(),
                });
            }
            input.to_string()
        }
        InjectionContext::PlainBody => input.to_string(),
        _ => input.to_string(),
    };
    validate_in_context(&escaped, context)?;
    Ok(escaped)
}

pub fn validate_in_context(
    payload: &str,
    context: InjectionContext,
) -> Result<(), ContextualEncodeError> {
    match context {
        InjectionContext::JsonString => {
            let mut chars = payload.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '"' {
                    return Err(ContextualEncodeError::ContextIncompatible {
                        strategy: "validate".into(),
                        context,
                        reason: "unescaped double quote in JSON string".into(),
                    });
                }
                if c == '\\' {
                    let escaped = chars.next();
                    match escaped {
                        Some('\\' | '"' | 'n' | 'r' | 't' | 'b' | 'f' | '/') => {}
                        Some('u') => {
                            // Validate exactly 4 hex digits after \u
                            for _ in 0..4 {
                                match chars.next() {
                                    Some(c) if c.is_ascii_hexdigit() => {}
                                    _ => {
                                        return Err(ContextualEncodeError::ContextIncompatible {
                                            strategy: "validate".into(),
                                            context,
                                            reason: "invalid Unicode escape in JSON string".into(),
                                        });
                                    }
                                }
                            }
                        }
                        Some(other) => {
                            return Err(ContextualEncodeError::ContextIncompatible {
                                strategy: "validate".into(),
                                context,
                                reason: format!("invalid JSON escape sequence: \\{other}"),
                            });
                        }
                        None => {
                            return Err(ContextualEncodeError::ContextIncompatible {
                                strategy: "validate".into(),
                                context,
                                reason: "trailing backslash in JSON string".into(),
                            });
                        }
                    }
                }
            }
        }
        InjectionContext::XmlAttribute => {
            // F137: pre-fix the `&` branch did `chars.by_ref().take(6).collect()`
            // which UNCONDITIONALLY consumed the next 6 chars regardless of
            // whether an entity matched. Those 6 chars were never validated,
            // so a payload like `&lt;<script>` slipped past — the validator
            // saw `&`, ate `lt;<sc` to "check" for a known entity, recognised
            // `lt;`, and then never inspected the `<` it had already swallowed.
            // Switch to a lookahead via `chars.clone()` (cheap — `Chars` is a
            // slice cursor) and advance only as far as a matched entity.
            let mut chars = payload.chars();
            const ENTITIES: &[&str] = &["quot;", "apos;", "amp;", "lt;", "gt;"];
            while let Some(c) = chars.next() {
                if c == '"' {
                    return Err(ContextualEncodeError::ContextIncompatible {
                        strategy: "validate".into(),
                        context,
                        reason: "unescaped double quote in XML attribute".into(),
                    });
                }
                // Single-quoted XML attributes (attr='...') are equally valid in
                // XML 1.0 §3.1. An unescaped `'` inside such an attribute breaks
                // out of the value just as `"` does in a double-quoted attribute.
                if c == '\'' {
                    return Err(ContextualEncodeError::ContextIncompatible {
                        strategy: "validate".into(),
                        context,
                        reason: "unescaped single quote in XML attribute".into(),
                    });
                }
                if c == '<' {
                    return Err(ContextualEncodeError::ContextIncompatible {
                        strategy: "validate".into(),
                        context,
                        reason: "unescaped `<` in XML attribute".into(),
                    });
                }
                if c == '&' {
                    let lookahead: String = chars.clone().take(6).collect();
                    if let Some(matched) =
                        ENTITIES.iter().find(|e| lookahead.starts_with(*e))
                    {
                        // Consume exactly the entity body (name + `;`). The
                        // rest of the payload stays in `chars` for the next
                        // iteration so every other byte is still validated.
                        for _ in 0..matched.len() {
                            chars.next();
                        }
                    }
                    // Lenient on unknown `&`: leave `chars` untouched and
                    // keep scanning. An `&` alone is technically valid XML
                    // text per XML 1.0 §2.4 only when not followed by an
                    // entity-like shape; we don't reject it here so the
                    // existing permissive contract holds.
                }
            }
        }
        // Contexts below have no validation rules yet. Adding an explicit
        // arm for each ensures the compiler warns us when a new variant is
        // added so we can decide whether it needs validation.
        InjectionContext::PlainBody => {
            // Plain body accepts any byte sequence; nothing to validate.
        }
        InjectionContext::XmlCdata if payload.contains("]]>") => {
            return Err(ContextualEncodeError::ContextIncompatible {
                strategy: "validate".into(),
                context,
                reason: "CDATA payload contains `]]>` (unterminated section)".into(),
            });
        }
        InjectionContext::XmlText => {
            if payload.contains('<') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "validate".into(),
                    context,
                    reason: "XML text payload contains unescaped `<`".into(),
                });
            }
            reject_unescaped_ampersand(payload, context)?;
        }
        InjectionContext::HtmlAttribute => {
            if payload.contains('<') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "validate".into(),
                    context,
                    reason: "HTML attribute contains unescaped `<` — would close the attribute"
                        .into(),
                });
            }
            if payload.contains('"') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "validate".into(),
                    context,
                    reason: "HTML attribute contains unescaped `\"` — attribute breakout".into(),
                });
            }
            if payload.contains('\'') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "validate".into(),
                    context,
                    reason: "HTML attribute contains unescaped `'` — single-quoted attr breakout"
                        .into(),
                });
            }
            reject_unescaped_ampersand(payload, context)?;
        }
        InjectionContext::HtmlText => {
            if payload.contains('<') {
                return Err(ContextualEncodeError::ContextIncompatible {
                    strategy: "validate".into(),
                    context,
                    reason: "HTML text contains unescaped `<` — would start a tag".into(),
                });
            }
            reject_unescaped_ampersand(payload, context)?;
        }
        InjectionContext::UrlQuery | InjectionContext::UrlPath | InjectionContext::UrlFragment => {
            // URL components are validated by percent-encoding step later;
            // raw payload can contain any bytes here.
        }
        InjectionContext::HeaderValue => {
            // Header values are validated by the header obfuscation layer;
            // CRLF injection is guarded at the transport level.
        }
        InjectionContext::CookieValue => {
            // Cookie values accept most printable ASCII; validation is
            // handled by the cookie encoding layer.
        }
        InjectionContext::MultipartField | InjectionContext::MultipartFileName => {
            // Multipart boundaries are managed by the form encoder;
            // individual field values have no additional constraints.
        }
        // InjectionContext is #[non_exhaustive]; future variants default to
        // no validation until explicit rules are added.
        _ => {}
    }
    Ok(())
}

/// Returns Err if `payload` contains an `&` that is NOT the start of a
/// well-formed entity reference (`&name;`, `&#nnn;`, or `&#xHHH;`).
///
/// This is the cheap cousin of an HTML5 entity validator — it doesn't
/// know which named entities are real (`&copy;` vs `&xyz;`), but it
/// does enforce the lexical shape so a stray `&` cannot ride through
/// `validate_in_context` for HTML/XML contexts.
fn reject_unescaped_ampersand(
    payload: &str,
    context: InjectionContext,
) -> Result<(), ContextualEncodeError> {
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            i += 1;
            continue;
        }
        // Walk forward to find the terminating `;` within a bounded
        // window — real entities are short (max ~12 chars including
        // the `;`). If we don't find one, the `&` is unescaped.
        let mut j = i + 1;
        let max = (i + 12).min(bytes.len());
        let mut saw_semicolon = false;
        let mut valid_shape = true;
        let first = bytes.get(j).copied();
        if first == Some(b'#') {
            j += 1;
            let hex = bytes.get(j).copied() == Some(b'x') || bytes.get(j).copied() == Some(b'X');
            if hex {
                j += 1;
            }
            let mut digit_count = 0;
            while j < max {
                let b = bytes[j];
                if b == b';' {
                    saw_semicolon = true;
                    j += 1;
                    break;
                }
                let ok = if hex {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                };
                if !ok {
                    valid_shape = false;
                    break;
                }
                digit_count += 1;
                j += 1;
            }
            if digit_count == 0 {
                valid_shape = false;
            }
        } else if let Some(b) = first {
            if b.is_ascii_alphabetic() {
                while j < max {
                    let b = bytes[j];
                    if b == b';' {
                        saw_semicolon = true;
                        j += 1;
                        break;
                    }
                    if !b.is_ascii_alphanumeric() {
                        valid_shape = false;
                        break;
                    }
                    j += 1;
                }
            } else {
                valid_shape = false;
            }
        } else {
            valid_shape = false;
        }
        if !valid_shape || !saw_semicolon {
            return Err(ContextualEncodeError::ContextIncompatible {
                strategy: "validate".into(),
                context,
                reason: format!("unescaped `&` at byte {i} (no entity reference follows)"),
            });
        }
        i = j;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Strategy;

    #[test]
    fn encode_error_mapping_payload_too_large() {
        // PayloadTooLarge from encode maps to PayloadTooLarge contextual error
        // We can't easily trigger this from encode(), but we verify the error path
        // by checking that InvalidUtf8 is only returned for actual UTF-8 errors
        let result = encode_in_context(
            b"\x80",
            Strategy::CaseAlternation,
            InjectionContext::PlainBody,
        );
        // \x80 alone is invalid UTF-8, so encode should return InvalidUtf8
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid") || err.to_string().contains("UTF-8"),
            "error should mention invalid UTF-8, got: {err}"
        );
    }

    #[test]
    fn json_string_validates_unescaped_quote() {
        let err = validate_in_context("hello\"world", InjectionContext::JsonString).unwrap_err();
        assert!(err.to_string().contains("unescaped double quote"));
    }

    #[test]
    fn json_string_validates_valid_escapes() {
        assert!(validate_in_context("hello\\nworld", InjectionContext::JsonString).is_ok());
        assert!(validate_in_context("hello\\tworld", InjectionContext::JsonString).is_ok());
        assert!(validate_in_context("hello\\\\world", InjectionContext::JsonString).is_ok());
        assert!(validate_in_context("hello\\\"world", InjectionContext::JsonString).is_ok());
    }

    #[test]
    fn json_string_validates_unicode_escape() {
        // Valid \u00e4
        assert!(validate_in_context("\\u00e4", InjectionContext::JsonString).is_ok());
        // Invalid \u00g4 (non-hex)
        let err = validate_in_context("\\u00g4", InjectionContext::JsonString).unwrap_err();
        assert!(err.to_string().contains("invalid Unicode escape"));
        // Too short \u00
        let err = validate_in_context("\\u00", InjectionContext::JsonString).unwrap_err();
        assert!(err.to_string().contains("invalid Unicode escape"));
    }

    #[test]
    fn json_string_validates_invalid_escape() {
        let err = validate_in_context("\\x", InjectionContext::JsonString).unwrap_err();
        assert!(err.to_string().contains("invalid JSON escape"));
    }

    #[test]
    fn json_string_validates_trailing_backslash() {
        let err = validate_in_context("hello\\", InjectionContext::JsonString).unwrap_err();
        assert!(err.to_string().contains("trailing backslash"));
    }

    #[test]
    fn xml_attribute_validates_unescaped_quote() {
        let err = validate_in_context("hello\"world", InjectionContext::XmlAttribute).unwrap_err();
        assert!(err.to_string().contains("unescaped double quote"));
    }

    #[test]
    fn xml_attribute_allows_escaped_quote() {
        // &quot; should be allowed (the validator doesn't fully validate entities,
        // but it shouldn't error on well-formed entity references)
        assert!(validate_in_context("hello&quot;world", InjectionContext::XmlAttribute).is_ok());
    }

    #[test]
    fn xml_attribute_validates_unescaped_single_quote() {
        // A single-quoted XML attribute (attr='...') breaks out on an unescaped `'`.
        // Previously the validator only checked `"`, so `' onclick='alert(1)` passed
        // as "valid" despite being an injection vector.
        let err = validate_in_context("foo' onclick='alert(1)", InjectionContext::XmlAttribute)
            .unwrap_err();
        assert!(
            err.to_string().contains("single quote"),
            "error must mention single quote, got: {err}"
        );
    }

    #[test]
    fn xml_attribute_validator_does_not_swallow_chars_after_entity() {
        // F137 regression: pre-fix `&lt;<script>` passed validation
        // because the validator consumed 6 chars after every `&` to
        // peek at the entity name. After matching `lt;` it had already
        // eaten the next 2 chars (`<s`) and never validated them — so
        // the unescaped `<` rode straight through. Post-fix the
        // validator clones the cursor for lookahead and advances only
        // by the matched entity length, so the trailing `<` is caught.
        let err = validate_in_context("&lt;<script>", InjectionContext::XmlAttribute)
            .expect_err("unescaped `<` after &lt; MUST reject");
        assert!(
            err.to_string().contains('<') || err.to_string().contains("unescaped"),
            "error should mention the unescaped `<`, got: {err}"
        );
    }

    #[test]
    fn xml_attribute_validator_catches_quote_after_short_entity() {
        // Same F137 hazard, different exploit: `&amp;"` — after `&amp;`
        // (4 chars), the pre-fix code consumed 2 chars beyond (the `"`
        // and one more), bypassing the unescaped-quote check.
        let err = validate_in_context("&amp;\"breakout", InjectionContext::XmlAttribute)
            .expect_err("unescaped `\"` after &amp; MUST reject");
        assert!(
            err.to_string().contains("double quote"),
            "error should mention double quote, got: {err}"
        );
    }

    #[test]
    fn xml_attribute_validator_allows_multiple_entities_in_a_row() {
        // The fix must not over-correct: a payload of nothing-but-
        // entities still passes.
        assert!(
            validate_in_context(
                "&amp;&lt;&gt;&quot;&apos;",
                InjectionContext::XmlAttribute,
            )
            .is_ok(),
            "chain of well-formed entities must pass validation"
        );
    }

    #[test]
    fn xml_attribute_escape_encodes_single_quote() {
        // escape_for_context must produce &apos; for `'` so that the escaped
        // output then passes validate_in_context.
        let escaped =
            escape_for_context("don't break my attribute", InjectionContext::XmlAttribute)
                .unwrap();
        assert!(
            escaped.contains("&apos;"),
            "expected &apos; in escaped output, got: {escaped}"
        );
        // The round-trip must also pass validation.
        validate_in_context(&escaped, InjectionContext::XmlAttribute)
            .expect("escaped output must pass validation");
    }

    #[test]
    fn xml_attribute_allows_escaped_apos() {
        // &apos; is a well-formed entity reference and must not trigger the
        // single-quote validator.
        assert!(
            validate_in_context("don&apos;t", InjectionContext::XmlAttribute).is_ok(),
            "&apos; must be accepted by the XmlAttribute validator"
        );
    }

    #[test]
    fn header_value_validates_crlf() {
        let err = encode_in_context(
            b"hello\r\nworld",
            Strategy::CaseAlternation,
            InjectionContext::HeaderValue,
        )
        .unwrap_err();
        assert!(err.to_string().contains("CR/LF"));
    }

    #[test]
    fn cookie_value_escapes_crlf() {
        let out = encode_in_context(
            b"hello\r\nworld",
            Strategy::CaseAlternation,
            InjectionContext::CookieValue,
        )
        .unwrap();
        assert!(out.contains("%0D") && out.contains("%0A"));
    }

    #[test]
    fn multipart_field_validates_crlf() {
        let err = encode_in_context(
            b"hello\r\nworld",
            Strategy::CaseAlternation,
            InjectionContext::MultipartField,
        )
        .unwrap_err();
        assert!(err.to_string().contains("CR/LF"));
    }

    #[test]
    fn html_attribute_escapes_ampersand() {
        let out = encode_in_context(
            b"a&b",
            Strategy::CaseAlternation,
            InjectionContext::HtmlAttribute,
        )
        .unwrap();
        assert!(out.contains("&amp;"));
    }

    #[test]
    fn url_query_escapes_space() {
        let out = encode_in_context(
            b"hello world",
            Strategy::CaseAlternation,
            InjectionContext::UrlQuery,
        )
        .unwrap();
        assert!(!out.contains(' '));
    }

    #[test]
    fn url_path_preserves_slash() {
        let out = encode_in_context(
            b"/api/v1",
            Strategy::CaseAlternation,
            InjectionContext::UrlPath,
        )
        .unwrap();
        assert!(out.contains('/'));
    }

    #[test]
    fn plain_body_no_structural_escaping() {
        // PlainBody doesn't add structural escaping, but the strategy still mutates
        let out = encode_in_context(
            b"<script>",
            Strategy::CaseAlternation,
            InjectionContext::PlainBody,
        )
        .unwrap();
        assert_eq!(out, "<ScRiPt>");
    }

    #[test]
    fn max_size_enforced() {
        let big = vec![b'a'; 8 * 1024 * 1024 + 1];
        let err = encode_in_context(&big, Strategy::CaseAlternation, InjectionContext::PlainBody)
            .unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn xml_cdata_rejects_termination_sequence() {
        let err = encode_in_context(
            b"hello]]>world",
            Strategy::CaseAlternation,
            InjectionContext::XmlCdata,
        )
        .unwrap_err();
        assert!(err.to_string().contains("CDATA"));
    }

    #[test]
    fn multipart_filename_rejects_quote() {
        let err = encode_in_context(
            b"file\"name.txt",
            Strategy::CaseAlternation,
            InjectionContext::MultipartFileName,
        )
        .unwrap_err();
        assert!(err.to_string().contains("quote"));
    }

    #[test]
    fn json_number_rejects_non_numeric() {
        let err = encode_in_context(
            b"abc",
            Strategy::CaseAlternation,
            InjectionContext::JsonNumber,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a valid JSON number"));
    }

    #[test]
    fn empty_payload_valid_in_all_contexts() {
        for ctx in [
            InjectionContext::PlainBody,
            InjectionContext::JsonString,
            InjectionContext::XmlAttribute,
            InjectionContext::HeaderValue,
            InjectionContext::CookieValue,
        ] {
            assert!(
                encode_in_context(b"", Strategy::UrlEncode, ctx).is_ok(),
                "empty payload should be valid in {ctx:?}"
            );
        }
    }

    // ── New tests added 2026-05-24 ─────────────────────────────────────────

    #[test]
    fn xml_attribute_single_quote_payloads_all_rejected() {
        // 10 distinct single-quote-bearing payloads — each must either error
        // OR produce output that passes validate_in_context (escape succeeded).
        // The fix was to escape ' as &apos; so validate accepts it.
        let payloads = [
            "don't",
            "a' onclick='alert(1)",
            "' OR 1=1",
            "test' attribute='injected",
            "hello'world",
            "foo' onmouseover='evil",
            "x' style='color:red",
            "value'extra",
            "a'b'c",
            "' union select",
        ];
        for payload in &payloads {
            let escaped = escape_for_context(payload, InjectionContext::XmlAttribute);
            match escaped {
                Ok(s) => {
                    // If escaping succeeded, validation must also succeed.
                    validate_in_context(&s, InjectionContext::XmlAttribute)
                        .unwrap_or_else(|e| panic!(
                            "escape_for_context produced invalid output for {payload:?}: {e}\n  escaped: {s}"
                        ));
                    // The escaped form must NOT contain a bare single quote.
                    assert!(
                        !s.contains('\''),
                        "bare single quote survived in escaped output for {payload:?}: {s}"
                    );
                }
                Err(_) => {
                    // Rejecting is also valid — as long as the bare payload doesn't
                    // silently pass validation.
                    let _ = validate_in_context(payload, InjectionContext::XmlAttribute);
                    // We just require no panic. The point is the input can't bypass.
                }
            }
        }
    }

    #[test]
    fn escape_for_context_xml_attribute_round_trip() {
        // Payloads that can be expressed in an XML attribute must survive
        // a round-trip: escape → validate succeeds.
        let payloads = [
            "hello world",
            "test & value",
            "\"quoted\"",
            "less < than",
            "greater > than",
        ];
        for payload in &payloads {
            let escaped = escape_for_context(payload, InjectionContext::XmlAttribute)
                .unwrap_or_else(|e| panic!("escape_for_context failed for {payload:?}: {e}"));
            validate_in_context(&escaped, InjectionContext::XmlAttribute)
                .unwrap_or_else(|e| panic!(
                    "round-trip validation failed for {payload:?}: {e}\n  escaped: {escaped}"
                ));
        }
    }

    #[test]
    fn url_encode_twice_is_deterministic() {
        // URL-encoding is NOT idempotent (% chars get re-encoded), but it IS a
        // pure deterministic function: applying it twice always produces the
        // same result as applying it twice on a second call.
        let payload = "' OR 1=1--";
        let run1_once = encode_in_context(payload.as_bytes(), Strategy::UrlEncode, InjectionContext::UrlQuery).unwrap();
        let run1_twice = encode_in_context(run1_once.as_bytes(), Strategy::UrlEncode, InjectionContext::UrlQuery).unwrap();
        let run2_once = encode_in_context(payload.as_bytes(), Strategy::UrlEncode, InjectionContext::UrlQuery).unwrap();
        let run2_twice = encode_in_context(run2_once.as_bytes(), Strategy::UrlEncode, InjectionContext::UrlQuery).unwrap();
        assert_eq!(run1_twice, run2_twice, "URL-encode applied twice must be deterministic across calls");
        // double-encoded result must differ from single-encoded (% is re-encoded to %25)
        assert_ne!(run1_once, run1_twice, "URL-encode applied twice must produce a different (double-encoded) result");
    }

    #[test]
    fn url_encode_decode_round_trip() {
        // encode(payload, UrlEncode) then url-decode must reproduce the original.
        let original = "' OR 1=1--";
        let encoded = crate::encoding::encode(original.as_bytes(), Strategy::UrlEncode).unwrap();
        let decoded = urlencoding::decode(&encoded).unwrap();
        assert_eq!(decoded, original, "URL encode → decode round-trip must equal original");
    }

    #[test]
    fn unicode_boundary_4byte_utf8_no_panic() {
        // 4-byte UTF-8 characters must not panic in any encoder.
        let payload = "😀𝄞🚀"; // all supplementary-plane chars
        for strategy in crate::encoding::all_strategies() {
            let _ = crate::encoding::encode(payload.as_bytes(), *strategy);
        }
    }

    #[test]
    fn unicode_boundary_bom_no_panic() {
        // BOM (U+FEFF) must not panic in any encoder.
        let payload = "\u{FEFF}SELECT * FROM users";
        for strategy in crate::encoding::all_strategies() {
            let _ = crate::encoding::encode(payload.as_bytes(), *strategy);
        }
    }

    #[test]
    fn json_string_escape_u2028_and_u2029() {
        // U+2028 and U+2029 must be escaped to  /  to prevent
        // line-terminator injection in JSONP/eval contexts.
        let payload = "\u{2028}hello\u{2029}world";
        let escaped = escape_for_context(payload, InjectionContext::JsonString).unwrap();
        assert!(
            escaped.contains("\\u2028"),
            "U+2028 must be escaped to \\u2028, got: {escaped}"
        );
        assert!(
            escaped.contains("\\u2029"),
            "U+2029 must be escaped to \\u2029, got: {escaped}"
        );
        // Escaped result must also pass validation.
        validate_in_context(&escaped, InjectionContext::JsonString).unwrap();
    }

    #[test]
    fn cookie_value_all_special_chars_encoded() {
        let payload = "val;ue=sp ace,\"q\"\\back\x00nul\r\n";
        let out = escape_for_context(payload, InjectionContext::CookieValue).unwrap();
        // Must not contain raw special chars.
        assert!(!out.contains(';'), "semicolon must be encoded");
        assert!(!out.contains('='), "equals must be encoded");
        assert!(!out.contains(' '), "space must be encoded");
        assert!(!out.contains(','), "comma must be encoded");
        assert!(!out.contains('"'), "double-quote must be encoded");
        assert!(!out.contains('\\'), "backslash must be encoded");
        assert!(!out.contains('\x00'), "null must be encoded");
        assert!(!out.contains('\r'), "CR must be encoded");
        assert!(!out.contains('\n'), "LF must be encoded");
    }

    #[test]
    fn header_value_null_byte_rejected() {
        // NULL byte in a header value must be rejected.
        let err = escape_for_context("hello\x00world", InjectionContext::HeaderValue).unwrap_err();
        assert!(
            err.to_string().contains("null"),
            "error must mention null byte, got: {err}"
        );
    }

    #[test]
    fn xml_attribute_null_byte_rejected() {
        // NULL byte in an XML attribute must be rejected.
        let err = escape_for_context("hello\x00world", InjectionContext::XmlAttribute).unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
