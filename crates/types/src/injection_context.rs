use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InjectionContext {
    JsonString,
    JsonNumber,
    XmlAttribute,
    XmlCdata,
    XmlText,
    HtmlAttribute,
    HtmlText,
    UrlQuery,
    UrlPath,
    UrlFragment,
    HeaderValue,
    CookieValue,
    MultipartField,
    MultipartFileName,
    PlainBody,
}

impl Default for InjectionContext {
    fn default() -> Self {
        Self::PlainBody
    }
}

#[derive(Debug, Error, Serialize, Deserialize, Clone, PartialEq)]
pub enum ContextualEncodeError {
    #[error("strategy {strategy:?} produced output incompatible with context {context:?}: {reason}")]
    ContextIncompatible {
        strategy: String,
        context: InjectionContext,
        reason: String,
    },
    #[error("payload contains invalid UTF-8 at byte offset {offset}")]
    InvalidUtf8 { offset: usize },
    #[error("payload too large for context {context:?}: {size} bytes exceeds max {max}")]
    PayloadTooLarge {
        context: InjectionContext,
        size: usize,
        max: usize,
    },
    #[error("contextual escaping failed: {0}")]
    EscapeFailed(String),
}
