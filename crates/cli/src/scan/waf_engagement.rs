//! WAF engagement assessment — distinguish real bypasses from unguarded parameters.
//!
//! A high `bypass_rate_pct` against a query parameter the WAF never inspects
//! (identical benign vs attack responses) is a **measurement artifact**, not a
//! finding. This module fingerprints responses and classifies whether the
//! injection point is actually guarded before downstream phases count bypasses.

use colored::Colorize;
use wafrift_evolution::intelligence::IntelligenceLoop;
use wafrift_types::hash::fnv1a_64;

use super::baseline::BaselineOutcome;
use super::scan_url_with_param;

/// Benign value injected when probing whether `param` affects the response.
pub(crate) const BENIGN_PROBE_VALUE: &str = "wafrift_benign_probe0";

/// Stable fingerprint of an HTTP response for engagement comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseFingerprint {
    pub status: u16,
    pub body_len: usize,
    pub body_digest: u64,
}

impl ResponseFingerprint {
    #[must_use]
    pub(crate) fn from_parts(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body_len: body.len(),
            body_digest: fnv1a_64(body),
        }
    }

    /// Same status and body hash — WAF/edge treated attack like benign.
    #[must_use]
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.status == other.status && self.body_digest == other.body_digest
    }
}

/// Whether the WAF appears to inspect this injection point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WafEngagementLevel {
    /// Raw attack payload was blocked — evasion targets an active rule set.
    Active,
    /// Baseline passed but differential probes show selective blocking.
    Selective,
    /// No block signal; attack fingerprint matches benign probe.
    Unguarded,
    /// Parameter changes the response but nothing was blocked (reflection / routing).
    ParamLiveNoWaf,
    /// Baseline transport failed — engagement unknown.
    Unknown,
}

impl WafEngagementLevel {
    #[must_use]
    pub(crate) fn counts_meaningful_bypass(self) -> bool {
        matches!(self, Self::Active | Self::Selective)
    }

    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Selective => "selective",
            Self::Unguarded => "unguarded",
            Self::ParamLiveNoWaf => "param_live_no_waf",
            Self::Unknown => "unknown",
        }
    }
}

/// Result of the post-baseline / post-differential engagement check.
#[derive(Debug, Clone)]
pub(crate) struct WafEngagementReport {
    pub level: WafEngagementLevel,
    pub reason: String,
    pub attack_fingerprint: Option<ResponseFingerprint>,
    pub benign_fingerprint: Option<ResponseFingerprint>,
    pub differential_blocked: usize,
    pub differential_total: usize,
}

impl WafEngagementReport {
    #[must_use]
    pub(crate) fn counts_meaningful_bypass(&self) -> bool {
        self.level.counts_meaningful_bypass()
    }

    #[must_use]
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "level": self.level.as_str(),
            "reason": self.reason,
            "differential_blocked": self.differential_blocked,
            "differential_total": self.differential_total,
            "attack_fingerprint": self.attack_fingerprint.map(fp_json),
            "benign_fingerprint": self.benign_fingerprint.map(fp_json),
        })
    }
}

fn fp_json(fp: ResponseFingerprint) -> serde_json::Value {
    serde_json::json!({
        "status": fp.status,
        "body_len": fp.body_len,
        "body_digest": format!("{:016x}", fp.body_digest),
    })
}

/// GET `param=BENIGN_PROBE_VALUE` and fingerprint the response.
pub(crate) async fn probe_benign(
    http: &reqwest::Client,
    target: &str,
    param: &str,
) -> Option<ResponseFingerprint> {
    let url = scan_url_with_param(target, param, &urlencoding::encode(BENIGN_PROBE_VALUE));
    let resp = http.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .ok()?;
    Some(ResponseFingerprint::from_parts(status, &body))
}

/// Classify WAF engagement from baseline, benign probe, and differential results.
#[must_use]
pub(crate) fn assess(
    baseline: &BaselineOutcome,
    attack_fp: Option<ResponseFingerprint>,
    benign_fp: Option<ResponseFingerprint>,
    intel_loop: &IntelligenceLoop,
) -> WafEngagementReport {
    let diff = intel_loop.differential_results();
    let differential_blocked = diff.total_blocked;
    let differential_total = diff.total_probes;

    if !baseline.transport_ok {
        return WafEngagementReport {
            level: WafEngagementLevel::Unknown,
            reason: "baseline transport failed — cannot assess WAF engagement on this parameter"
                .to_string(),
            attack_fingerprint: attack_fp,
            benign_fingerprint: benign_fp,
            differential_blocked,
            differential_total,
        };
    }

    if baseline.blocked {
        return WafEngagementReport {
            level: WafEngagementLevel::Active,
            reason: "raw attack payload was blocked — WAF is inspecting this injection point"
                .to_string(),
            attack_fingerprint: attack_fp,
            benign_fingerprint: benign_fp,
            differential_blocked,
            differential_total,
        };
    }

    if differential_blocked > 0 {
        return WafEngagementReport {
            level: WafEngagementLevel::Selective,
            reason: format!(
                "differential probes blocked {differential_blocked}/{differential_total} patterns — \
                 WAF selectively inspects this parameter"
            ),
            attack_fingerprint: attack_fp,
            benign_fingerprint: benign_fp,
            differential_blocked,
            differential_total,
        };
    }

    if let (Some(attack), Some(benign)) = (attack_fp, benign_fp) {
        if attack.matches(&benign) {
            return WafEngagementReport {
                level: WafEngagementLevel::Unguarded,
                reason: "benign and attack responses are identical (status + body) — \
                          this parameter is not WAF-inspected; pass-through is not a bypass"
                    .to_string(),
                attack_fingerprint: Some(attack),
                benign_fingerprint: Some(benign),
                differential_blocked,
                differential_total,
            };
        }
        return WafEngagementReport {
            level: WafEngagementLevel::ParamLiveNoWaf,
            reason: "parameter changes the response but no probe was blocked — \
                      not a WAF bypass measurement (retest on API/form fields)"
                .to_string(),
            attack_fingerprint: Some(attack),
            benign_fingerprint: Some(benign),
            differential_blocked,
            differential_total,
        };
    }

    WafEngagementReport {
        level: WafEngagementLevel::Unguarded,
        reason:
            "no block signal and fingerprints unavailable — treating as unguarded (conservative)"
                .to_string(),
        attack_fingerprint: attack_fp,
        benign_fingerprint: benign_fp,
        differential_blocked,
        differential_total,
    }
}

pub(crate) fn render_engagement_warning(report: &WafEngagementReport, scan_text: bool) {
    if report.counts_meaningful_bypass() || !scan_text {
        return;
    }
    eprintln!(
        "\n  {} {}",
        "⚠ WAF engagement:".yellow().bold(),
        report.reason.yellow()
    );
    eprintln!(
        "  {} {}",
        "→".bright_black(),
        "Pass-through variants are NOT counted as WAF bypasses. \
         Use --raw-request on real form/API fields, or --full-scan-unguarded to fire anyway."
            .bright_black()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_evolution::intelligence::IntelligenceLoop;

    fn baseline_ok(blocked: bool) -> BaselineOutcome {
        BaselineOutcome {
            status: 200,
            blocked,
            transport_ok: true,
            fingerprint: None,
        }
    }

    fn fp(status: u16, body: &[u8]) -> ResponseFingerprint {
        ResponseFingerprint::from_parts(status, body)
    }

    #[test]
    fn active_when_baseline_blocked() {
        let r = assess(
            &baseline_ok(true),
            Some(fp(403, b"blocked")),
            Some(fp(200, b"ok")),
            &IntelligenceLoop::new(1),
        );
        assert_eq!(r.level, WafEngagementLevel::Active);
        assert!(r.counts_meaningful_bypass());
    }

    #[test]
    fn selective_when_differential_blocked() {
        let mut il = IntelligenceLoop::new(1);
        for p in il.generate_quick_probes() {
            il.record_probe(&p, true);
        }
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, b"attack")),
            Some(fp(200, b"benign")),
            &il,
        );
        assert_eq!(r.level, WafEngagementLevel::Selective);
        assert!(r.counts_meaningful_bypass());
    }

    #[test]
    fn unguarded_when_fingerprints_match() {
        let body = b"same page";
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, body)),
            Some(fp(200, body)),
            &IntelligenceLoop::new(1),
        );
        assert_eq!(r.level, WafEngagementLevel::Unguarded);
        assert!(!r.counts_meaningful_bypass());
    }

    #[test]
    fn param_live_when_fingerprints_differ_no_blocks() {
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, b"attack page")),
            Some(fp(200, b"benign page")),
            &IntelligenceLoop::new(1),
        );
        assert_eq!(r.level, WafEngagementLevel::ParamLiveNoWaf);
        assert!(!r.counts_meaningful_bypass());
    }

    #[test]
    fn fingerprint_matches_is_symmetric() {
        let a = fp(200, b"hello");
        let b = fp(200, b"hello");
        assert!(a.matches(&b));
        assert!(!a.matches(&fp(200, b"world")));
        assert!(!a.matches(&fp(404, b"hello")));
    }

    #[test]
    fn fingerprint_same_body_different_len_impossible_but_digest_differs() {
        // Body length is part of fingerprint storage; digest is over bytes.
        let a = fp(200, b"aa");
        let b = fp(200, b"aaa");
        assert_ne!(a.body_digest, b.body_digest);
        assert!(!a.matches(&b));
    }

    #[test]
    fn unknown_when_baseline_transport_failed() {
        let baseline = BaselineOutcome {
            status: 0,
            blocked: false,
            transport_ok: false,
            fingerprint: None,
        };
        let r = assess(&baseline, None, None, &IntelligenceLoop::new(1));
        assert_eq!(r.level, WafEngagementLevel::Unknown);
        assert!(!r.counts_meaningful_bypass());
        assert!(r.reason.contains("transport"));
    }

    #[test]
    fn active_takes_priority_over_selective_differential() {
        let mut il = IntelligenceLoop::new(1);
        for p in il.generate_quick_probes() {
            il.record_probe(&p, true);
        }
        let r = assess(
            &baseline_ok(true),
            Some(fp(403, b"blocked")),
            Some(fp(200, b"ok")),
            &il,
        );
        assert_eq!(r.level, WafEngagementLevel::Active);
    }

    #[test]
    fn selective_requires_baseline_pass_and_diff_blocks() {
        let mut il = IntelligenceLoop::new(1);
        let probes = il.generate_quick_probes();
        assert!(
            !probes.is_empty(),
            "quick probes must exist for selective test"
        );
        il.record_probe(&probes[0], true);
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, b"x")),
            Some(fp(200, b"y")),
            &il,
        );
        assert_eq!(r.level, WafEngagementLevel::Selective);
        assert!(r.differential_blocked >= 1);
    }

    #[test]
    fn unguarded_when_fingerprints_missing_conservative() {
        let r = assess(
            &baseline_ok(false),
            None,
            Some(fp(200, b"only benign")),
            &IntelligenceLoop::new(1),
        );
        assert_eq!(r.level, WafEngagementLevel::Unguarded);
        assert!(!r.counts_meaningful_bypass());
    }

    #[test]
    fn to_json_includes_level_and_fingerprints() {
        let body = b"same";
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, body)),
            Some(fp(200, body)),
            &IntelligenceLoop::new(1),
        );
        let j = r.to_json();
        assert_eq!(j["level"], "unguarded");
        assert!(j["reason"].is_string());
        assert!(j["attack_fingerprint"]["body_digest"].is_string());
        assert!(j["benign_fingerprint"]["body_digest"].is_string());
    }

    #[test]
    fn engagement_level_as_str_roundtrip() {
        assert_eq!(WafEngagementLevel::Active.as_str(), "active");
        assert_eq!(WafEngagementLevel::Selective.as_str(), "selective");
        assert_eq!(WafEngagementLevel::Unguarded.as_str(), "unguarded");
        assert_eq!(
            WafEngagementLevel::ParamLiveNoWaf.as_str(),
            "param_live_no_waf"
        );
        assert_eq!(WafEngagementLevel::Unknown.as_str(), "unknown");
    }

    #[test]
    fn counts_meaningful_bypass_only_active_and_selective() {
        assert!(WafEngagementLevel::Active.counts_meaningful_bypass());
        assert!(WafEngagementLevel::Selective.counts_meaningful_bypass());
        assert!(!WafEngagementLevel::Unguarded.counts_meaningful_bypass());
        assert!(!WafEngagementLevel::ParamLiveNoWaf.counts_meaningful_bypass());
        assert!(!WafEngagementLevel::Unknown.counts_meaningful_bypass());
    }

    #[test]
    fn from_parts_uses_fnv_digest() {
        let fp1 = ResponseFingerprint::from_parts(200, b"payload");
        let fp2 = ResponseFingerprint::from_parts(200, b"payload");
        let fp3 = ResponseFingerprint::from_parts(200, b"other");
        assert_eq!(fp1, fp2);
        assert_ne!(fp1.body_digest, fp3.body_digest);
    }

    #[test]
    fn benign_probe_constant_is_stable() {
        assert_eq!(BENIGN_PROBE_VALUE, "wafrift_benign_probe0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_benign_fingerprints_mock_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = b"benign-mock-body";
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let body = body.to_vec();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let client = reqwest::Client::builder().build().unwrap();
        let fp = probe_benign(&client, &format!("http://{addr}/"), "q")
            .await
            .expect("probe must return fingerprint");
        assert_eq!(fp.status, 200);
        assert_eq!(fp.body_len, body.len());
        assert_eq!(fp, ResponseFingerprint::from_parts(200, body));
    }

    #[test]
    fn render_engagement_warning_noop_when_meaningful() {
        let r = WafEngagementReport {
            level: WafEngagementLevel::Active,
            reason: String::new(),
            attack_fingerprint: None,
            benign_fingerprint: None,
            differential_blocked: 0,
            differential_total: 0,
        };
        // Must not panic; text mode off is also fine.
        render_engagement_warning(&r, false);
    }

    #[test]
    fn render_engagement_warning_noop_in_json_mode_for_unguarded() {
        let r = assess(
            &baseline_ok(false),
            Some(fp(200, b"x")),
            Some(fp(200, b"x")),
            &IntelligenceLoop::new(1),
        );
        render_engagement_warning(&r, false);
    }
}
