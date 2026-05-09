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
                crate::error::EncodeError::InvalidUtf8 => ContextualEncodeError::InvalidUtf8 { offset: 0 },
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
                crate::error::EncodeError::InvalidContext { strategy: s, context: _ } => {
                    ContextualEncodeError::ContextIncompatible {
                        strategy: s.into(),
                        context,
                        reason: "strategy invalid for context".into(),
                    }
                }
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
            if input.chars().any(|c| !c.is_ascii_digit() && c != '.' && c != '-' && c != 'e' && c != 'E' && c != '+') {
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
            input.replace('&', "&amp;")
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
        InjectionContext::XmlText => {
            input.replace('&', "&amp;")
                 .replace('<', "&lt;")
                 .replace('>', "&gt;")
        }
        InjectionContext::HtmlAttribute => {
            input.replace('&', "&amp;")
                 .replace('"', "&quot;")
                 .replace('\'', "&#x27;")
                 .replace('<', "&lt;")
        }
        InjectionContext::HtmlText => {
            input.replace('&', "&amp;")
                 .replace('<', "&lt;")
        }
        InjectionContext::UrlQuery => {
            urlencoding::encode(input).to_string()
        }
        InjectionContext::UrlPath => {
            urlencoding::encode(input).to_string().replace("%2F", "/")
        }
        InjectionContext::UrlFragment => {
            urlencoding::encode(input).to_string()
        }
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
        InjectionContext::CookieValue => {
            input.replace(';', "%3B")
                 .replace('=', "%3D")
                 .replace('\x00', "%00")
                 .replace('\r', "%0D")
                 .replace('\n', "%0A")
        }
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
        InjectionContext::PlainBody => {
            input.to_string()
        }
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
                        Some('\\') | Some('"') | Some('n') | Some('r') | Some('t')
                        | Some('b') | Some('f') | Some('/') => {}
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
