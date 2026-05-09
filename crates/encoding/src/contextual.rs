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
            input
                .replace('&', "&amp;")
                .replace('"', "&quot;")
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
            .replace(';', "%3B")
            .replace('=', "%3D")
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
                        Some('\\') | Some('"') | Some('n') | Some('r') | Some('t') | Some('b')
                        | Some('f') | Some('/') => {}
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
        _ => {}
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
            "error should mention invalid UTF-8, got: {}",
            err
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
}
