//! Error types for wafrift-encoding.

/// Errors that can occur during encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// The input payload exceeds the maximum allowed size.
    PayloadTooLarge { max: usize, actual: usize },
    /// The accumulated layered output exceeds the maximum allowed size.
    LayeredOutputTooLarge { max: usize, actual: usize },
    /// The payload contains invalid UTF-8 where valid UTF-8 is required.
    InvalidUtf8,
    /// The requested strategy is not applicable in the given context.
    InvalidContext {
        strategy: &'static str,
        context: String,
    },
    /// An internal configuration or I/O error occurred.
    InvalidConfig(String),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { max, actual } => {
                write!(f, "payload too large: {actual} bytes (max {max} bytes)")
            }
            Self::LayeredOutputTooLarge { max, actual } => {
                write!(
                    f,
                    "layered output too large: {actual} bytes (max {max} bytes)"
                )
            }
            Self::InvalidUtf8 => f.write_str("payload contains invalid UTF-8"),
            Self::InvalidContext { strategy, context } => {
                write!(f, "strategy {strategy} is not valid in context {context}")
            }
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for EncodeError {}
