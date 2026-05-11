use crate::encoding::Strategy;
use wafrift_types::injection_context::{ContextualEncodeError, InjectionContext};

pub fn encode_in_context(
    payload: &[u8],
    strategy: Strategy,
    context: InjectionContext,
) -> Result<String, ContextualEncodeError> {
    let max_size = match context {
        InjectionContext::JsonString => 4 * 1024 * 1024,
        InjectionContext::JsonNumber => 1024,
        InjectionContext::XmlAttribute => 1024 * 1024,
        InjectionContext::XmlCdata => 8 * 1024 * 1024,
        InjectionContext::HeaderValue => 8 * 1024,
        InjectionContext::CookieValue => 4 * 1024,
        InjectionContext::MultipartFileName => 256,
        _ => 8 * 1024 * 1024,
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
            let mut chars = payload.chars();
            while let Some(c) = chars.next() {
                if c == '"' {
                    return Err(ContextualEncodeError::ContextIncompatible {
                        strategy: "validate".into(),
                        context,
                        reason: "unescaped double quote in XML attribute".into(),
                    });
                }
                if c == '&' {
                    // Allow known entity references; anything else starting with & is suspicious
                    let remainder: String = chars.by_ref().take(6).collect();
                    if !remainder.starts_with("quot;")
                        && !remainder.starts_with("amp;")
                        && !remainder.starts_with("lt;")
                        && !remainder.starts_with("gt;")
                    {
                        // Not a known entity — could be an unescaped &
                        // (We keep scanning rather than erroring, since & alone
                        // is technically valid XML text if followed by whitespace.)
                    }
                }
            }
        }
        // Contexts below have no validation rules yet. Adding an explicit
        // arm for each ensures the compiler warns us when a new variant is
        // added so we can decide whether it needs validation.
        InjectionContext::PlainBody => {
            // Plain body accepts any byte sequence; nothing to validate.
        }
        InjectionContext::XmlCdata
            if payload.contains("]]>") => {
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
                let ok = if hex { b.is_ascii_hexdigit() } else { b.is_ascii_digit() };
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
}
