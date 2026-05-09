//! Error types for wafrift-encoding.

/// Errors that can occur during encoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The input payload exceeds the maximum allowed size.
    #[error("payload too large: {actual} bytes (max {max} bytes)")]
    PayloadTooLarge { max: usize, actual: usize },
    /// The accumulated layered output exceeds the maximum allowed size.
    #[error("layered output too large: {actual} bytes (max {max} bytes)")]
    LayeredOutputTooLarge { max: usize, actual: usize },
    /// The payload contains invalid UTF-8 where valid UTF-8 is required.
    #[error("payload contains invalid UTF-8")]
    InvalidUtf8,
    /// The requested strategy is not applicable in the given context.
    #[error("strategy {strategy} is not valid in context {context}")]
    InvalidContext {
        strategy: &'static str,
        context: String,
    },
    /// An internal configuration or I/O error occurred.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}
