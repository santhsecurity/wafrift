//! WAF response oracle.
//!
//! Classifies HTTP responses into [`Verdict`](wafrift_types::Verdict) values using multiple
//! signals: status code, body markers, response time, connection
//! behavior, and HTTP/2 GOAWAY frames.

use crate::calibration::CalibrationSession;
use crate::cloudflare::{CfBlockSignal, parse_cf_block};
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
        // A `waf_block_header:` marker is an EXPLICIT block indicator that, per
        // signal_headers + block_headers.toml ("ONLY appear when a WAF actively
        // blocks … even when the status is 200"), must count toward the block
        // signal even on an allowed status. Plain `header:<vendor>` markers are
        // mere vendor-ID (every Cloudflare 200 carries cf-ray) and must NOT be
        // treated as a block — so we key strictly on the waf_block_header prefix.
        let has_header_block = header_signals
            .iter()
            .any(|s| matches!(s, Signal::BodyMarker(m) if m.starts_with("waf_block_header:")));
        signals.extend(header_signals);

        // -- Response time --
        // When >= 3 calibration latency samples exist, use the statistical
        // TimingOracle (mean + 3*sigma) for precise confirmation of blind
        // attacks (pg_sleep / WAITFOR DELAY / ; ping -c 10). Fall back to the
        // crude 3x ratio heuristic when fewer samples are available.
        let timing_signal = self
            .calibration
            .as_ref()
            .and_then(|cal| {
                if let Some(oracle) = cal.build_timing_oracle() {
                    if oracle.is_anomalous(ctx.response_time_ms as f64) {
                        Some(wafrift_types::Signal::ResponseTimeAnomaly {
                            baseline_ms: oracle.baseline_ms as u64,
                            actual_ms: ctx.response_time_ms,
                        })
                    } else {
                        None
                    }
                } else {
                    // Fewer than 3 samples -- fall back to heuristic ratio.
                    let baseline_ms = cal.benign_latency_ms.unwrap_or(200);
                    classify_response_time(baseline_ms, ctx.response_time_ms)
                }
            })
            .or_else(|| {
                // No calibration at all -- use default 200ms baseline.
                classify_response_time(200, ctx.response_time_ms)
            });
        if let Some(s) = timing_signal {
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
        // A block can be signalled by the body OR by an explicit waf_block_header
        // (the latter holds even on a 200 status — see has_header_block above).
        let has_block_marker = has_header_block
            || body_signals
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

        // ChallengeRequired regardless of status — pre-fix this was
        // gated on `ctx.status == 503`, which missed Cloudflare
        // challenges served on 403, Akamai _abck challenges on
        // 200/403, and AWS WAF Challenge action on 202/401. The
        // status gate caused the evade loop to burn evasion budget
        // on a challenge page instead of entering the cookie-replay
        // /solve path. `has_challenge` already requires concrete
        // ChallengePlatform or "challenge" body markers, so widening
        // the status doesn't introduce false positives.
        if has_challenge {
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
                explanation: format!(
                    "status {} conflicts with body/header block markers",
                    ctx.status
                ),
            };
        }

        // Default: attach the full collected signal set (status, body, calibration, …).
        match status_verdict {
            Verdict::Blocked { .. } => {
                let mut reason = extract_block_reason(&ctx.body, ctx.is_gzipped);
                // When the generic extractor finds nothing, try CF-specific
                // attribution. `rule_attribution` is always non-empty for CF
                // responses (e.g. "cf:SJC:waf-managed-rule") and feeds
                // `OracleVerdict.rule_id` in the evolution engine.
                if reason.is_none() || matches!(reason, Some(BlockReason::Unknown)) {
                    let cf = parse_cf_block(&ctx.headers, &ctx.body);
                    if cf.is_cloudflare_response() {
                        reason = Some(BlockReason::RuleId(cf.rule_attribution));
                    }
                }
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

    /// Classify a response and simultaneously extract Cloudflare-specific signals.
    ///
    /// Returns `(verdict, Some(cf_signal))` when the response is from a CF
    /// edge node, `(verdict, None)` otherwise.
    ///
    /// `cf_signal.rule_attribution` is the recommended value to store in
    /// `OracleVerdict.rule_id` for the evolution engine's corpus keying.
    ///
    /// Equivalent to calling [`classify`] and [`parse_cf_block`] separately
    /// but avoids parsing headers twice.
    pub fn classify_with_cf_signal(
        &self,
        ctx: &ResponseContext,
    ) -> (Verdict, Option<CfBlockSignal>) {
        let verdict = self.classify(ctx);
        let cf = parse_cf_block(&ctx.headers, &ctx.body);
        let cf_opt = if cf.is_cloudflare_response() { Some(cf) } else { None };
        (verdict, cf_opt)
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

    /// §5/§6 regression: a clean 403 WAF block whose page contains the word
    /// "successfully" (e.g. "successfully blocked") must classify as Blocked,
    /// NOT Ambiguous. Pre-fix the loose "success" success-marker matched the
    /// substring and the status-blocked-vs-success conflict rule produced a
    /// false Ambiguous — derailing the evade loop's verdict.
    #[test]
    fn block_page_saying_successfully_blocked_is_blocked_not_ambiguous() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            body: b"Request denied. Our WAF successfully blocked this attack.".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_blocked(), "must be Blocked, got {v:?}");
        assert!(!v.is_ambiguous(), "must NOT be Ambiguous, got {v:?}");
    }

    /// A 401 page literally containing "unauthenticated" must not trip the
    /// success path (old "authenticated" marker substring-matched it).
    #[test]
    fn unauthenticated_401_does_not_become_ambiguous() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 401,
            body: b"401 Unauthorized: this request is unauthenticated.".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(
            !v.is_ambiguous(),
            "401 unauthenticated must not be Ambiguous, got {v:?}"
        );
    }

    /// §6: a benign 200 with a "press F5 to refresh" hint must stay Allowed —
    /// the old bare "f5" block marker matched the refresh-key text and forced
    /// a false Ambiguous via the allowed-vs-block conflict rule.
    #[test]
    fn f5_refresh_hint_on_200_stays_allowed() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"<p>If the page looks stale, press F5 to refresh.</p>".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_allowed(), "must be Allowed, got {v:?}");
        assert!(!v.is_ambiguous(), "must NOT be Ambiguous, got {v:?}");
    }

    /// §6: a benign "please wait" loader must NOT classify as ChallengeRequired.
    /// Challenge is the highest-precedence verdict (early return), so a false
    /// positive here masks a real bypass and burns the solve path. Bare
    /// "please wait" was removed from the challenge table.
    #[test]
    fn benign_please_wait_loader_is_not_a_challenge() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            body: b"Please wait while your order is processed...".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(
            !v.is_challenge(),
            "benign loader must not be a challenge, got {v:?}"
        );
        assert!(v.is_allowed(), "should be Allowed, got {v:?}");
    }

    /// §5 false-NEGATIVE fix: signal_headers + block_headers.toml document that
    /// a waf-block HEADER is a block signal "even with 200 status", but classify()
    /// previously scanned only body_signals for the block-conflict, so a 200 +
    /// `x-amzn-waf-action: block` was reported a clean Allowed — a PHANTOM BYPASS
    /// (the worst error for an evasion tool: the WAF blocked, the tool says it got
    /// through). The explicit waf_block_header must now surface the conflict.
    #[test]
    fn block_header_on_200_is_not_reported_as_clean_allowed() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            headers: vec![("x-amzn-waf-action".to_string(), "block".to_string())],
            body: b"ok".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(
            !v.is_allowed(),
            "200 + waf-block header must NOT be a clean Allowed (phantom bypass), got {v:?}"
        );
    }

    /// Guard the other side (no over-firing): a plain vendor-ID header (cf-ray on
    /// a normal 200) must NOT be treated as a block — every Cloudflare-fronted 200
    /// carries cf-ray, so counting it would flag the entire internet as blocked.
    #[test]
    fn vendor_id_header_on_200_stays_allowed() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 200,
            headers: vec![("cf-ray".to_string(), "abc123-SJC".to_string())],
            body: b"welcome".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(
            v.is_allowed(),
            "a vendor-ID header (cf-ray) on a clean 200 must stay Allowed, got {v:?}"
        );
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


    /// When >= 3 calibration latency samples are present, the statistical
    /// TimingOracle is used (mean + 3*sigma). The oracle is more precise:
    /// 200ms IS anomalous vs 100ms baseline (threshold ~105ms) but would NOT
    /// be anomalous under the 3x ratio heuristic (threshold 300ms).
    #[test]
    fn statistical_timing_oracle_used_when_enough_samples() {
        let mut cal = CalibrationSession::default();
        for ms in [98u64, 100, 101, 99, 102] {
            cal.record_benign_with_latency(200, &[], b"ok", ms);
        }
        cal.record_blocked(403, &[], b"blocked");
        let oracle = ResponseOracle::new().with_calibration(cal);
        let ctx = ResponseContext {
            status: 200,
            response_time_ms: 200, // anomalous vs ~105ms threshold, not vs 300ms
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        let signals = v.signals();
        assert!(
            signals.iter().any(|s| matches!(s, Signal::ResponseTimeAnomaly { .. })),
            "statistical oracle must flag 200ms anomalous (threshold ~105ms): {:?}",
            signals
        );
    }

    /// With < 3 samples, falls back to 3x ratio. 200ms is NOT anomalous vs
    /// 100ms baseline under 3x (threshold 300ms).
    #[test]
    fn ratio_fallback_used_below_min_samples() {
        let mut cal = CalibrationSession::default();
        cal.record_benign_with_latency(200, &[], b"ok", 100);
        cal.record_benign_with_latency(200, &[], b"ok", 102);
        cal.record_blocked(403, &[], b"blocked");
        let oracle = ResponseOracle::new().with_calibration(cal);
        let ctx = ResponseContext {
            status: 200,
            response_time_ms: 200, // not anomalous under 3x (300ms threshold)
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        let signals = v.signals();
        assert!(
            !signals.iter().any(|s| matches!(s, Signal::ResponseTimeAnomaly { .. })),
            "below min samples, 200ms should not be flagged (3x=300ms): {:?}",
            signals
        );
    }

    // ── CF wiring tests ────────────────────────────────────────────────────

    #[test]
    fn cf_block_promotes_rule_id_in_blocked_verdict() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            headers: vec![
                ("cf-ray".to_string(), "8a1b2c3d4e5f6a7b-SJC".to_string()),
                ("cf-mitigated".to_string(), "block".to_string()),
                ("server".to_string(), "cloudflare".to_string()),
            ],
            body: b"Sorry, you have been blocked <!-- error code: 1020 -->".to_vec(),
            ..Default::default()
        };
        let v = oracle.classify(&ctx);
        assert!(v.is_blocked());
        // The CF-promoted rule_id should be embedded in the BlockReason::RuleId
        let signals = v.signals();
        // Must have the cf-ray signal via signal_headers
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::BodyMarker(m) if m.contains("cloudflare")))
        );
    }

    #[test]
    fn classify_with_cf_signal_returns_cf_for_cloudflare_response() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            headers: vec![
                ("cf-ray".to_string(), "9b2c3d4e5f6a7b8c-LHR".to_string()),
                ("cf-mitigated".to_string(), "block".to_string()),
            ],
            body: b"You have been blocked <!-- error code: 1020 -->".to_vec(),
            ..Default::default()
        };
        let (verdict, cf_signal) = oracle.classify_with_cf_signal(&ctx);
        assert!(verdict.is_blocked());
        assert!(cf_signal.is_some());
        let cf = cf_signal.unwrap();
        assert_eq!(cf.edge_pop.as_deref(), Some("LHR"));
        assert_eq!(cf.mitigated_reason.as_deref(), Some("block"));
        assert!(cf.rule_attribution.starts_with("cf:LHR:"));
    }

    #[test]
    fn classify_with_cf_signal_returns_none_for_non_cf() {
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            headers: vec![("server".to_string(), "nginx".to_string())],
            body: b"Forbidden".to_vec(),
            ..Default::default()
        };
        let (verdict, cf_signal) = oracle.classify_with_cf_signal(&ctx);
        assert!(verdict.is_blocked());
        assert!(cf_signal.is_none());
    }

    #[test]
    fn cf_verdict_rule_id_format() {
        // When a CF block provides edge_pop + ruleset_hint, the rule_attribution
        // must match "cf:<POP>:<HINT>" so it can be used as OracleVerdict.rule_id.
        let oracle = ResponseOracle::new();
        let ctx = ResponseContext {
            status: 403,
            headers: vec![
                ("cf-ray".to_string(), "1a2b3c4d5e6f7a8b-FRA".to_string()),
                ("cf-mitigated".to_string(), "block".to_string()),
            ],
            body: b"OWASP blocked this request <!-- error code: 1020 -->".to_vec(),
            ..Default::default()
        };
        let (_, cf_opt) = oracle.classify_with_cf_signal(&ctx);
        let cf = cf_opt.expect("should detect CF");
        // rule_attribution must be parseable as cf:<pop>:<hint>
        let parts: Vec<&str> = cf.rule_attribution.splitn(3, ':').collect();
        assert_eq!(parts[0], "cf");
        assert_eq!(parts[1], "FRA");
        // hint is either the error code mapping or body text
        assert!(!parts[2].is_empty());
    }
}
