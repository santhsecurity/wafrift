pub mod grpc_web;
pub mod messagepack;
pub mod protobuf;

use thiserror::Error;
use wafrift_types::format::BodyFormat;
use wafrift_types::injection_context::InjectionContext;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Unsupported format: {format:?}")]
    UnsupportedFormat { format: BodyFormat },
    #[error("Serialization failed: {reason}")]
    SerializationFailed { reason: String },
    #[error("Context incompatible: {format:?} for {context:?}")]
    ContextIncompatible {
        format: BodyFormat,
        context: InjectionContext,
    },
    #[error("Payload too large: {size} > {max}")]
    PayloadTooLarge { size: usize, max: usize },
}

pub fn serialize(
    payload: &str,
    format: BodyFormat,
    _context: InjectionContext,
) -> Result<Vec<u8>, FormatError> {
    match format {
        BodyFormat::Raw => Ok(payload.as_bytes().to_vec()),
        BodyFormat::Protobuf => Ok(protobuf::serialize(payload)),
        BodyFormat::MessagePack => Ok(messagepack::serialize(payload)),
        BodyFormat::GrpcWeb => Ok(grpc_web::serialize(payload)),
        _ => Err(FormatError::UnsupportedFormat { format }),
    }
}

pub fn deserialize(bytes: &[u8], format: BodyFormat) -> Result<String, FormatError> {
    match format {
        BodyFormat::Raw => Ok(String::from_utf8_lossy(bytes).into_owned()),
        BodyFormat::Protobuf => Ok(protobuf::deserialize(bytes)),
        BodyFormat::MessagePack => Ok(messagepack::deserialize(bytes)),
        BodyFormat::GrpcWeb => Ok(grpc_web::deserialize(bytes)),
        _ => Err(FormatError::UnsupportedFormat { format }),
    }
}
