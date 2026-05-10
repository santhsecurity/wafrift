//! Active probing: HTTP response header classification and TCP banner grabs.

mod config;
mod error;
mod http;
mod rules;
mod tcp;

pub use config::ActiveProbeConfig;
pub use error::ReconProbeError;
pub use http::{probe_http_headers, probe_http_headers_with_rules};
pub use rules::HeaderRules;
pub use tcp::{TcpServiceClass, probe_tcp_banner};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// High-level bucket for a matched fingerprint rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TagFamily {
    Waf,
    Cdn,
    Framework,
}

/// One successful rule hit (e.g. WAF family + stable id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StackTag {
    pub family: TagFamily,
    pub id: String,
}

/// Canonical snapshot of an HTTP header probe (stable `serde_json` key order via [`BTreeMap`]).
///
/// Hop-by-hop and clock-driven headers that would make repeated probes non-comparable
/// (notably `date`, which Hyper adds automatically) are intentionally omitted from
/// [`HttpHeaderProbeSnapshot::headers`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeaderProbeSnapshot {
    pub status: u16,
    /// Response header names normalized to lowercase ASCII.
    pub headers: BTreeMap<String, String>,
    pub tags: Vec<StackTag>,
}

impl HttpHeaderProbeSnapshot {
    /// Serialize to JSON bytes with stable header and tag ordering.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails (should not for this type).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Parsed first-line TCP banner plus coarse service classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpBannerSnapshot {
    /// First line of the peer greeting (trimmed, lossy UTF-8).
    pub line: String,
    pub service: TcpServiceClass,
}

impl TcpBannerSnapshot {
    /// Serialize to JSON bytes for byte-for-byte comparisons across probes.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}
