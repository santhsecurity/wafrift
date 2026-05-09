use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BodyFormat {
    Json,
    Xml,
    Multipart,
    Protobuf,
    MessagePack,
    GrpcWeb,
    Raw,
}
