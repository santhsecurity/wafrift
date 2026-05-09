//! Error types for wafrift — shared across all crates.
//!
//! A single error enum covers all evasion failures. Each variant carries
//! a descriptive, lowercase, actionable message string.



/// Errors that can occur during evasion operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WafRiftError {
    /// The request is malformed or missing required fields.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The payload could not be encoded with the selected strategy.
    #[error("encoding failed: {0}")]
    EncodingFailed(String),
    /// The grammar mutation engine could not process the payload type.
    #[error("grammar error: {0}")]
    GrammarError(String),
    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),
}

impl WafRiftError {
    /// Create an invalid request error.
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::InvalidRequest(msg.into())
    }

    /// Create an encoding-failed error.
    pub fn encoding_failed(msg: impl Into<String>) -> Self {
        Self::EncodingFailed(msg.into())
    }

    /// Create a grammar error.
    pub fn grammar_error(msg: impl Into<String>) -> Self {
        Self::GrammarError(msg.into())
    }

    /// Create an internal error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, WafRiftError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_request() {
        let err = WafRiftError::invalid_request("missing url");
        assert_eq!(err.to_string(), "invalid request: missing url");
    }

    #[test]
    fn error_display_encoding_failed() {
        let err = WafRiftError::encoding_failed("unsupported charset");
        assert_eq!(err.to_string(), "encoding failed: unsupported charset");
    }

    #[test]
    fn error_display_grammar() {
        let err = WafRiftError::grammar_error("unrecognized payload type");
        assert_eq!(err.to_string(), "grammar error: unrecognized payload type");
    }

    #[test]
    fn error_display_internal() {
        let err = WafRiftError::internal("state corruption");
        assert_eq!(err.to_string(), "internal error: state corruption");
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(WafRiftError::invalid_request("test"));
        assert!(err.to_string().contains("invalid request"));
    }
}
