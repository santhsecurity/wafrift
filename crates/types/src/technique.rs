//! Evasion technique identifiers.
//!
//! Each variant names a specific category of WAF bypass that was applied.
//! Strategy code inspects these to track which techniques work against a
//! particular WAF, enabling the evolution engine's feedback loop.

use std::fmt;

use serde::{Deserialize, Serialize};

/// An evasion technique that was applied.
///
/// Each variant represents a specific category of WAF bypass. Strategy
/// code can inspect these to track which techniques work and which don't.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Technique {
    /// Payload re-encoded using a specific strategy (URL, double-URL, etc.).
    PayloadEncoding(String),
    /// Content-Type switched to a different format (JSON, XML, multipart).
    ContentTypeSwitch(String),
    /// Multipart boundary manipulated to confuse parsers.
    BoundaryManipulation,
    /// JSON keys/values unicode-escaped.
    JsonUnicodeEscape,
    /// TLS fingerprint rotated to a specific browser profile.
    TlsFingerprint(String),
    /// User-Agent and browser headers rotated.
    UserAgentRotation,
    /// HTTP/2 settings tuned to mimic a browser.
    Http2Settings,
    /// Grammar-aware payload mutation (SQL/XSS/CMD semantic transform).
    GrammarMutation(String),
    /// Header obfuscation (case mixing, tab separators, line folding).
    HeaderObfuscation(String),
    /// HTTP request smuggling (CL.TE, TE.CL, TE.TE).
    RequestSmuggling(String),
    /// HTTP/2 frame-level evasion technique.
    H2Evasion(String),
    /// WAF rule differential analysis probe.
    DifferentialProbe,
    /// Body-size inspection bypass: pad the request body with `usize`
    /// bytes of inert junk before the real payload so cloud WAFs that
    /// only inspect the first 8 KB (Cloudflare Pro) or 16 KB (AWS WAF)
    /// see only padding and forward the real payload unmodified.
    BodyPadding(usize),
}

impl Technique {
    /// Parse a pool / stats key produced by the [`Display`](std::fmt::Display) impl (used by `HostState` and the proxy).
    #[must_use]
    pub fn from_pool_key(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix("encoding:") {
            return Some(Self::PayloadEncoding(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("content-type:") {
            return Some(Self::ContentTypeSwitch(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("tls:") {
            return Some(Self::TlsFingerprint(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("grammar:") {
            return Some(Self::GrammarMutation(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("header:") {
            return Some(Self::HeaderObfuscation(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("smuggling:") {
            return Some(Self::RequestSmuggling(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("h2:") {
            return Some(Self::H2Evasion(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("body-padding:") {
            return rest.parse::<usize>().ok().map(Self::BodyPadding);
        }
        match s {
            "boundary-manipulation" => Some(Self::BoundaryManipulation),
            "json-unicode-escape" => Some(Self::JsonUnicodeEscape),
            "user-agent-rotation" => Some(Self::UserAgentRotation),
            "http2-settings" => Some(Self::Http2Settings),
            "differential-probe" => Some(Self::DifferentialProbe),
            _ => None,
        }
    }
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadEncoding(s) => write!(f, "encoding:{s}"),
            Self::ContentTypeSwitch(s) => write!(f, "content-type:{s}"),
            Self::BoundaryManipulation => f.write_str("boundary-manipulation"),
            Self::JsonUnicodeEscape => f.write_str("json-unicode-escape"),
            Self::TlsFingerprint(s) => write!(f, "tls:{s}"),
            Self::UserAgentRotation => f.write_str("user-agent-rotation"),
            Self::Http2Settings => f.write_str("http2-settings"),
            Self::GrammarMutation(s) => write!(f, "grammar:{s}"),
            Self::HeaderObfuscation(s) => write!(f, "header:{s}"),
            Self::RequestSmuggling(s) => write!(f, "smuggling:{s}"),
            Self::H2Evasion(s) => write!(f, "h2:{s}"),
            Self::DifferentialProbe => f.write_str("differential-probe"),
            Self::BodyPadding(n) => write!(f, "body-padding:{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_display() {
        let t = Technique::PayloadEncoding("UrlEncode".into());
        assert_eq!(t.to_string(), "encoding:UrlEncode");
        assert_eq!(
            Technique::from_pool_key("encoding:UrlEncode"),
            Some(t.clone())
        );
        assert_eq!(
            Technique::GrammarMutation("sql_tautology".into()).to_string(),
            "grammar:sql_tautology"
        );
        assert_eq!(
            Technique::RequestSmuggling("CL.TE".into()).to_string(),
            "smuggling:CL.TE"
        );
    }

    #[test]
    fn body_padding_roundtrip() {
        let t = Technique::BodyPadding(16384);
        assert_eq!(t.to_string(), "body-padding:16384");
        assert_eq!(Technique::from_pool_key("body-padding:16384"), Some(t));
        assert_eq!(Technique::from_pool_key("body-padding:not-a-number"), None);
    }

    #[test]
    fn technique_serde_roundtrip() {
        let tech = Technique::ContentTypeSwitch("multipart".into());
        let json = serde_json::to_string(&tech).expect("serialize");
        let deserialized: Technique = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tech, deserialized);
    }
}
