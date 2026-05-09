use async_trait::async_trait;
use thiserror::Error;
use wafrift_types::oob::{OobCanary, OobInteraction};

#[derive(Debug, Error)]
pub enum OobError {
    #[error("Provider unavailable: {url} - {status}")]
    ProviderUnavailable { url: String, status: u16 },
    #[error("Registration failed: {reason}")]
    RegistrationFailed { reason: String },
    #[error("Poll failed: {reason}")]
    PollFailed { reason: String },
    #[error("Timeout")]
    Timeout,
    #[error("Invalid payload type: {payload_type}")]
    InvalidPayloadType { payload_type: String },
}

#[async_trait]
pub trait OobProviderTrait: Send + Sync + std::fmt::Debug {
    async fn register(&self) -> Result<OobCanary, OobError>;
    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError>;
}
