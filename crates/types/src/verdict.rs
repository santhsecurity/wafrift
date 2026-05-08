//! WAF response verdict taxonomy.
//!
//! This module defines the typed classification of HTTP responses
//! from a WAF-protected target. Verdicts are consumed by the strategy
//! engine to decide which evasion pipeline to try next.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A classification signal that contributed to a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    /// HTTP status code observation.
    StatusCode { code: u16, expected: u16 },
    /// Body contained a known block-page marker.
    BodyMarker(String),
    /// Body contained a known success marker.
    SuccessMarker(String),
    /// Response time anomaly relative to baseline.
    ResponseTimeAnomaly { baseline_ms: u64, actual_ms: u64 },
    /// Connection behavior anomaly.
    ConnectionBehavior(ConnectionBehavior),
    /// HTTP/2 GOAWAY frame observed.
    H2Goaway(String),
    /// Baseline fingerprint drift detected.
    FingerprintDrift(String),
    /// Challenge platform identifier detected in body.
    ChallengePlatform(String),
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StatusCode { code, expected } => {
                write!(f, "status {code} (expected {expected})")
            }
            Self::BodyMarker(m) => write!(f, "body marker: {m}"),
            Self::SuccessMarker(m) => write!(f, "success marker: {m}"),
            Self::ResponseTimeAnomaly {
                baseline_ms,
                actual_ms,
            } => {
                write!(f, "response time {actual_ms}ms (baseline {baseline_ms}ms)")
            }
            Self::ConnectionBehavior(c) => write!(f, "connection: {c}"),
            Self::H2Goaway(reason) => write!(f, "h2 goaway: {reason}"),
            Self::FingerprintDrift(d) => write!(f, "fingerprint drift: {d}"),
            Self::ChallengePlatform(p) => write!(f, "challenge platform: {p}"),
        }
    }
}

/// Connection behavior anomalies that influence verdict classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionBehavior {
    /// TCP connection was reset (RST) before or during response.
    TcpReset,
    /// Server returned 200 OK but immediately closed the connection.
    OkWithImmediateClose,
    /// Server returned 200 OK with a block-page body.
    OkWithBlockPage,
    /// Standard graceful close after full response.
    GracefulClose,
    /// Connection timeout.
    Timeout,
    /// TLS alert or handshake failure.
    TlsError,
}

impl fmt::Display for ConnectionBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpReset => f.write_str("TCP reset"),
            Self::OkWithImmediateClose => f.write_str("200 OK with immediate close"),
            Self::OkWithBlockPage => f.write_str("200 OK with block page"),
            Self::GracefulClose => f.write_str("graceful close"),
            Self::Timeout => f.write_str("timeout"),
            Self::TlsError => f.write_str("TLS error"),
        }
    }
}

/// Extracted block reason from a WAF response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockReason {
    /// A specific WAF rule ID was triggered.
    RuleId(String),
    /// A category of rule was triggered (e.g., "SQLi", "XSS").
    RuleCategory(String),
    /// Vendor-specific block reason string.
    VendorReason(String),
    /// IP reputation block.
    IpReputation,
    /// Geographic block.
    GeoBlock,
    /// Custom block page matched.
    CustomBlockPage(String),
    /// Unknown / not extractable.
    Unknown,
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleId(id) => write!(f, "rule {id}"),
            Self::RuleCategory(c) => write!(f, "category {c}"),
            Self::VendorReason(r) => write!(f, "vendor: {r}"),
            Self::IpReputation => f.write_str("IP reputation"),
            Self::GeoBlock => f.write_str("geo block"),
            Self::CustomBlockPage(p) => write!(f, "block page: {p}"),
            Self::Unknown => f.write_str("unknown reason"),
        }
    }
}

/// WAF response verdict — the output of the response oracle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    /// Request was blocked by the WAF.
    Blocked {
        /// Optional extracted reason for the block.
        reason: Option<BlockReason>,
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// Request was allowed through.
    Allowed {
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// Rate limit was applied (429 or 503 with rate-limit headers).
    RateLimited {
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// A challenge (CAPTCHA, JS challenge) was returned.
    /// Strategy should use a challenge solver or pick a different bypass.
    ChallengeRequired {
        /// Challenge platform detected (e.g., "cloudflare-challenge", "recaptcha").
        platform: Option<String>,
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// Server error (5xx) not attributable to the WAF.
    ServerError {
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// Soft block — partial body redaction or modified response.
    Partial {
        /// Why the response was considered partial.
        reason: Option<BlockReason>,
        /// Signals that led to this verdict.
        signals: Vec<Signal>,
    },
    /// Conflicting signals — multiple plausible verdicts.
    Ambiguous {
        /// Competing verdicts and their supporting signals.
        competing: Vec<(Verdict, Vec<Signal>)>,
        /// Human-readable explanation of the conflict.
        explanation: String,
    },
}

impl Verdict {
    /// Create a simple `Blocked` verdict with no reason.
    #[must_use]
    pub fn blocked(signals: Vec<Signal>) -> Self {
        Self::Blocked {
            reason: None,
            signals,
        }
    }

    /// Create a `Blocked` verdict with a specific reason.
    #[must_use]
    pub fn blocked_with_reason(reason: BlockReason, signals: Vec<Signal>) -> Self {
        Self::Blocked {
            reason: Some(reason),
            signals,
        }
    }

    /// Create an `Allowed` verdict.
    #[must_use]
    pub fn allowed(signals: Vec<Signal>) -> Self {
        Self::Allowed { signals }
    }

    /// Create a `RateLimited` verdict.
    #[must_use]
    pub fn rate_limited(signals: Vec<Signal>) -> Self {
        Self::RateLimited { signals }
    }

    /// Create a `ChallengeRequired` verdict.
    #[must_use]
    pub fn challenge_required(platform: Option<String>, signals: Vec<Signal>) -> Self {
        Self::ChallengeRequired { platform, signals }
    }

    /// Create a `ServerError` verdict.
    #[must_use]
    pub fn server_error(signals: Vec<Signal>) -> Self {
        Self::ServerError { signals }
    }

    /// Create a `Partial` verdict.
    #[must_use]
    pub fn partial(reason: Option<BlockReason>, signals: Vec<Signal>) -> Self {
        Self::Partial { reason, signals }
    }

    /// Returns true if this verdict represents a hard block.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// Returns true if this verdict requires a challenge solver.
    #[must_use]
    pub fn is_challenge(&self) -> bool {
        matches!(self, Self::ChallengeRequired { .. })
    }

    /// Returns true if this verdict is ambiguous.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }

    /// Returns true if the request was allowed (or at least not blocked).
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Get all signals attached to this verdict.
    #[must_use]
    pub fn signals(&self) -> Vec<Signal> {
        match self {
            Self::Blocked { signals, .. }
            | Self::Allowed { signals }
            | Self::RateLimited { signals }
            | Self::ChallengeRequired { signals, .. }
            | Self::ServerError { signals }
            | Self::Partial { signals, .. } => signals.clone(),
            Self::Ambiguous { competing, .. } => {
                competing.iter().flat_map(|(v, _)| v.signals()).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_blocked_creation() {
        let v = Verdict::blocked(vec![Signal::StatusCode {
            code: 403,
            expected: 200,
        }]);
        assert!(v.is_blocked());
        assert!(!v.is_allowed());
    }

    #[test]
    fn verdict_challenge_creation() {
        let v = Verdict::challenge_required(
            Some("cloudflare".into()),
            vec![Signal::ChallengePlatform("cloudflare".into())],
        );
        assert!(v.is_challenge());
        assert!(!v.is_blocked());
    }

    #[test]
    fn verdict_ambiguous_signals_flatten() {
        let v = Verdict::Ambiguous {
            competing: vec![
                (
                    Verdict::blocked(vec![Signal::BodyMarker("denied".into())]),
                    vec![Signal::BodyMarker("denied".into())],
                ),
                (
                    Verdict::allowed(vec![Signal::SuccessMarker("ok".into())]),
                    vec![Signal::SuccessMarker("ok".into())],
                ),
            ],
            explanation: "conflict".into(),
        };
        let signals = v.signals();
        assert_eq!(signals.len(), 2);
        assert!(signals.contains(&Signal::BodyMarker("denied".into())));
        assert!(signals.contains(&Signal::SuccessMarker("ok".into())));
    }

    #[test]
    fn block_reason_display() {
        assert_eq!(BlockReason::RuleId("1001".into()).to_string(), "rule 1001");
        assert_eq!(BlockReason::IpReputation.to_string(), "IP reputation");
    }
}
