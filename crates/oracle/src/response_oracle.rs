//! WAF response oracle.
//!
//! Classifies HTTP responses into [`Verdict`](wafrift_types::Verdict) values using multiple
//! signals: status code, body markers, response time, connection
//! behavior, and HTTP/2 GOAWAY frames.

use crate::calibration::CalibrationSession;
use crate::signal_body_marker::{extract_block_reason, extract_body_signals};
use crate::signal_connection::classify_connection;
use crate::signal_h2_goaway::classify_h2_goaway;
use crate::signal_response_time::classify_response_time;
use crate::signal_status_code::classify_status_code;
use wafrift_types::{BlockReason, ConnectionBehavior, Signal, Verdict};

/// Input context for response classification.
#[derive(Debug, Clone, Default)]
pub struct ResponseContext {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Response time in milliseconds.
    pub response_time_ms: u64,
    /// Connection behavior anomaly.
    pub connection_behavior: Option<ConnectionBehavior>,
    /// HTTP/2 GOAWAY reason (if any).
    pub h2_goaway: Option<String>,
    /// Whether the body is gzip-compressed.
    pub is_gzipped: bool,
}

/// A response oracle that classifies HTTP responses.
#[derive(Debug, Clone, Default)]
pub struct ResponseOracle {
    /// Optional per-target calibration session.
    pub calibration: Option<CalibrationSession>,
}

impl ResponseOracle {
    /// Create a new response oracle with no calibration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a calibration session.
    pub fn with_calibration(mut self, calibration: CalibrationSession) -> Self {
        self.calibration = Some(calibration);
        self
    }

    /// Classify a response into a [`Verdict`].
    ///
    /// This method is **deterministic**: given identical `ctx` and
    /// `calibration`, it always returns the same verdict.
    pub fn classify(&self, ctx: &ResponseContext) -> Verdict {
        let mut signals = Vec::new();
        let mut competing = Vec::new();

        // ── Status code ──
        let (status_verdict, status_signal) = classify_status_code(ctx.status);
        signals.push(status_signal);

        // ── Body markers ──
        let body_signals = extract_body_signals(&ctx.body, ctx.is_gzipped);
        signals.extend(body_signals.clone());

        // ── Response headers ──
        let header_signals = crate::signal_headers::classify_headers(&ctx.headers);
        signals.extend(header_signals);

        // ── Response time ──
        // Prefer measured benign latency; otherwise default 200ms.
        let baseline_ms = self
            .calibration
            .as_ref()
            .map_or(200, |c| c.benign_latency_ms.unwrap_or(200));
        if let Some(s) = classify_response_time(baseline_ms, ctx.response_time_ms) {
            signals.push(s);
        }

        // ── Connection behavior ──
        if let Some(ref behavior) = ctx.connection_behavior {
            signals.push(classify_connection(behavior.clone()));
        }

        // ── H2 GOAWAY ──
        if let Some(ref reason) = ctx.h2_goaway
            && let Some(s) = classify_h2_goaway(reason)
        {
            signals.push(s);
        }

        // ── Calibration drift ──
        if let Some(ref cal) = self.calibration
            && cal.is_complete()
        {
            let benign_drift = cal.drift_from_benign(ctx.status, ctx.body.len());
            let blocked_drift = cal.drift_from_blocked(ctx.status, ctx.body.len());

            match (benign_drift, blocked_drift) {
                (Some(b), Some(bl)) => {
                    if b.is_closer_than(&bl) {
                        signals.push(Signal::FingerprintDrift("closer to benign baseline".into()));
                    } else if bl.is_closer_than(&b) {
                        signals.push(Signal::FingerprintDrift(
                            "closer to blocked baseline".into(),
                        ));
                    } else {
                        signals.push(Signal::FingerprintDrift(
                            "equidistant from baselines".into(),
                        ));
                    }
                }
                (Some(_), None) => {
                    signals.push(Signal::FingerprintDrift("closer to benign baseline".into()));
                }
                (None, Some(_)) => {
                    signals.push(Signal::FingerprintDrift(
                        "closer to blocked baseline".into(),
                    ));
                }
                _ => {}
            }
        }

        // ── Resolve challenge vs block vs rate-limit from body ──
        let has_challenge = signals.iter().any(|s| {
            matches!(s, Signal::ChallengePlatform(_))
                || matches!(s, Signal::BodyMarker(m) if m.contains("challenge"))
        });
        let has_rate_limit = signals
            .iter()
            .any(|s| matches!(s, Signal::BodyMarker(m) if m.contains("rate-limit")));
        let has_block_marker = body_signals
            .iter()
            .any(|s| matches!(s, Signal::BodyMarker(_)));
        let has_success_marker = body_signals
            .iter()
            .any(|s| matches!(s, Signal::SuccessMarker(_)));

        // If status says allowed but body has block markers, that's a conflict.
        if status_verdict.is_allowed() && has_block_marker {
            competing.push((
                status_verdict.clone(),
                signals
                    .iter()
                    .filter(|s| matches!(s, Signal::StatusCode { .. }))
                    .cloned()
                    .collect(),
            ));
            let reason = extract_block_reason(&ctx.body, ctx.is_gzipped);
            competing.push((
                Verdict::blocked_with_reason(
                    reason.unwrap_or(BlockReason::Unknown),
                    body_signals.clone(),
                ),
                body_signals.clone(),
            ));
        }

        // If status says blocked but body has success markers, that's a conflict.
        if status_verdict.is_blocked() && has_success_marker {
            competing.push((
                status_verdict.clone(),
                signals
                    .iter()
                    .filter(|s| matches!(s, Signal::StatusCode { .. }))
                    .cloned()
                    .collect(),
            ));
            competing.push((
                Verdict::allowed(
                    body_signals
                        .iter()
                        .filter(|s| matches!(s, Signal::SuccessMarker(_)))
                        .cloned()
                        .collect(),
                ),
                body_signals
                    .iter()
                    .filter(|s| matches!(s, Signal::SuccessMarker(_)))
                    .cloned()
                    .collect(),
            ));
        }

        // If 503 with challenge markers → ChallengeRequired
        if ctx.status == 503 && has_challenge {
            let platform = signals.iter().find_map(|s| match s {
                Signal::ChallengePlatform(p) => Some(p.clone()),
                _ => None,
            });
            return Verdict::challenge_required(platform, signals);
        }

        // If 429 or has rate-limit markers → RateLimited
        if ctx.status == 429 || has_rate_limit {
            return Verdict::rate_limited(signals);
        }

        // If conflicting signals were collected, return Ambiguous.
        if !competing.is_empty() {
            return Verdict::Ambiguous {
                competing,
                explanation: format!("status {} conflicts with body markers", ctx.status),
            };
        }

        // Default: attach the full collected signal set (status, body, calibration, …).
        match status_verdict {
            Verdict::Blocked { .. } => {
                let reason = extract_block_reason(&ctx.body, ctx.is_gzipped);
                Verdict::Blocked { reason, signals }
            }
            Verdict::Partial { .. } => {
                let reason = extract_block_reason(&ctx.body, ctx.is_gzipped);
                Verdict::Partial { reason, signals }
            }
            Verdict::Allowed { .. } => Verdict::allowed(signals),
            Verdict::RateLimited { .. } => Verdict::rate_limited(signals),
            Verdict::ServerError { .. } => Verdict::server_error(signals),
            Verdict::ChallengeRequired { platform, .. } => {
                Verdict::challenge_required(platform, signals)
            }
            Verdict::Ambiguous { .. } => status_verdict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_allowed() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"welcome".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_allowed());
    }

    #[test]
    fn classify_blocked() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            body: b"access denied".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_blocked());
    }

    #[test]
    fn classify_challenge() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 503,
            body: b"challenge-platform".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_challenge());
    }

    #[test]
    fn classify_ambiguous() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"access denied".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_ambiguous());
    }

    #[test]
    fn deterministic_classify() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            body: b"blocked".to_vec(),
            ..Default::default()
        };
        let v1 = oracle.classify(&ctx);
        let v2 = oracle.classify(&ctx);
        assert_eq!(v1, v2);
    }

    #[test]
    fn adversarial_empty_body() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            body: vec![],
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_blocked());
    }

    #[test]
    fn adversarial_body_with_both_markers() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"access denied but login successful".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_ambiguous());
    }

    #[test]
    fn adversarial_200_with_rst() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"ok".to_vec(),
            connection_behavior: Some(ConnectionBehavior::TcpReset),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        // 200 with RST should still be allowed by status, but connection signal is present
        assert!(v.is_allowed());
        let signals = v.signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::ConnectionBehavior(ConnectionBehavior::TcpReset)))
        );
    }

    #[test]
    fn adversarial_gzipped_block_page() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"access denied").unwrap();
        let gzipped = encoder.finish().unwrap();

        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            body: gzipped,
            is_gzipped: true,
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_blocked());
        let signals = v.signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m == "access denied"))
        );
    }

    #[test]
    fn calibration_drift_used() {
        let mut cal = CalibrationSession::default();
        cal.record_benign(200, &[], b"x".repeat(100).as_slice());
        cal.record_blocked(403, &[], b"y".repeat(200).as_slice());

        let oracle = ResponseOracle::new().with_calibration(cal);
        let ctx = ResponseContext {
            status: 200,
            body: b"x".repeat(100),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_allowed());
        let signals = v.signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::FingerprintDrift(_)))
        );
    }

    #[test]
    fn calibration_latency_used_for_response_time_signal() {
        let mut cal = CalibrationSession::default();
        cal.record_benign_with_latency(200, &[], b"ok", 50);
        cal.record_blocked(403, &[], b"blocked");

        let oracle = ResponseOracle::new().with_calibration(cal);
        let ctx = ResponseContext {
            status: 200,
            response_time_ms: 500,
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        let signals = v.signals();
        assert!(signals.iter().any(|s| matches!(
            s,
            Signal::ResponseTimeAnomaly {
                baseline_ms: 50,
                actual_ms: 500
            }
        )));
    }
}
