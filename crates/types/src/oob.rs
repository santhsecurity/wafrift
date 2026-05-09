use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobConfig {
    pub provider: OobProvider,
    pub poll_interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OobProvider {
    Interactsh { server: String },
    BurpCollaborator { url: String },
    CustomDns { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OobCanary {
    pub id: Uuid,
    pub expected_dns: String,
    pub expected_http_path: String,
    #[serde(skip)]
    pub created_at: Option<Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OobInteraction {
    DnsQuery {
        query: String,
        source_ip: String,
    },
    HttpRequest {
        path: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OobConfirmation {
    Confirmed,
    Timeout,
    Error,
}
