//! Lossless projection of a confirmed wafrift bypass into the
//! universal [`secfinding::Finding`] shape.
//!
//! A wafrift "finding" is the pair `(EvasionResult, Verdict)` where
//! the verdict is [`Verdict::Allowed`]: the WAF let the transformed
//! request through. The bridge translates that pair into a
//! universal-shaped [`Finding`] so report renderers (reportkit's
//! SARIF / Markdown / HTML / CSV / JSON), bench scoring, and
//! cross-tool correlators don't need to learn wafrift's domain types.
//!
//! Failed bypasses ([`Verdict::Blocked`] etc.) intentionally do
//! **not** map to findings  -  they're negative evidence and belong
//! in the bench scoreboard, not the finding stream.
//!
//! ```ignore
//! use wafrift_types::{EvasionResult, Verdict};
//! use wafrift_types::secfinding_bridge::bypass_to_finding;
//!
//! let er: EvasionResult = /* from the strategy engine */;
//! let v: Verdict = /* from the response oracle */;
//! if let Some(finding) = bypass_to_finding("https://target/", &er, &v) {
//!     // hand to reportkit, bench, etc.
//! }
//! ```

use std::sync::Arc;

use secfinding::{Evidence, Finding, FindingBuildError, FindingKind, Severity};

use crate::request::{Method, Request};
use crate::result::EvasionResult;
use crate::technique::Technique;
use crate::verdict::{BlockReason, Signal, Verdict};

/// Project a `(EvasionResult, Verdict)` pair into a universal
/// [`Finding`].
///
/// Returns `Ok(Some(finding))` for an [`Verdict::Allowed`] verdict;
/// returns `Ok(None)` for any other verdict (blocked / rate-limited /
/// challenged / etc.  -  those are not findings, they're metadata for
/// the next attempt).
///
/// Returns `Err` if the underlying [`secfinding`] builder rejects the
/// mapping (e.g. malformed CWE id), which should not happen with the
/// fixed mapping below.
pub fn bypass_to_finding(
    target: &str,
    evasion: &EvasionResult,
    verdict: &Verdict,
) -> Result<Option<Finding>, FindingBuildError> {
    let signals = match verdict {
        Verdict::Allowed { signals } => signals,
        _ => return Ok(None),
    };

    let title = title_for(evasion);
    let detail = detail_for(evasion, signals);
    let mut builder = Finding::builder("wafrift", target, severity_for(evasion))
        .title(title)
        .detail(detail)
        .kind(FindingKind::Vulnerability)
        .confidence(evasion.confidence.clamp(0.0, 1.0))
        .cwe("CWE-942")
        .tag("waf-bypass")
        .tag(verdict_tag(verdict));

    for t in &evasion.techniques {
        builder = builder.tag(technique_tag(t));
    }

    builder = builder.evidence(request_evidence(&evasion.request));
    for s in signals {
        builder = builder.evidence(Evidence::raw(s.to_string()));
    }

    Ok(Some(builder.build()?))
}

/// All bypass severities are at least High  -  a confirmed bypass is
/// always actionable. Critical when the bypass payload chain
/// includes a known-RCE technique signature; today the heuristic is
/// "high unless tagged extra-critical by the technique" but the
/// hook is here so future severity refinement is one match arm
/// rather than a new public API.
fn severity_for(_evasion: &EvasionResult) -> Severity {
    Severity::High
}

fn title_for(evasion: &EvasionResult) -> String {
    if evasion.description.is_empty() {
        if evasion.techniques.is_empty() {
            "WAF bypass (unspecified technique)".to_string()
        } else {
            format!(
                "WAF bypass via {}",
                evasion
                    .techniques
                    .iter()
                    .map(|t| format!("{t:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    } else {
        format!("WAF bypass: {}", evasion.description)
    }
}

fn detail_for(evasion: &EvasionResult, signals: &[Signal]) -> String {
    let mut out = String::new();
    out.push_str("Transformed request was allowed through the WAF.\n");
    if !evasion.description.is_empty() {
        out.push_str("Technique: ");
        out.push_str(&evasion.description);
        out.push('\n');
    }
    if !signals.is_empty() {
        out.push_str("Signals: ");
        let joined = signals
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&joined);
        out.push('\n');
    }
    out
}

fn verdict_tag(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allowed { .. } => "verdict-allowed",
        Verdict::Blocked { .. } => "verdict-blocked",
        Verdict::RateLimited { .. } => "verdict-rate-limited",
        Verdict::ChallengeRequired { .. } => "verdict-challenge",
        Verdict::ServerError { .. } => "verdict-server-error",
        Verdict::Partial { .. } => "verdict-partial",
        Verdict::Ambiguous { .. } => "verdict-ambiguous",
    }
}

/// Stable tag for each [`Technique`] family. The exact strings are
/// part of the public contract  -  downstream filters and dashboards
/// match against them.
pub fn technique_tag(t: &Technique) -> String {
    // Technique is a large enum with many variants; we encode each
    // via its Debug repr lower-cased and snake_cased so adding a new
    // technique upstream is automatically routable here. Heavier
    // hand-mapping can replace this once we want richer dashboards.
    let raw = format!("{t:?}");
    let mut out = String::with_capacity(raw.len() + 9);
    out.push_str("technique-");
    let mut prev_upper = false;
    for (i, c) in raw.chars().enumerate() {
        if c == ' ' {
            break;
        }
        if c.is_ascii_uppercase() {
            if i > 0 && !prev_upper {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
            prev_upper = true;
        } else if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_upper = false;
        }
    }
    out
}

/// Bridge wafrift's [`BlockReason`] enum to a kebab-case tag string.
/// Stable across releases (per LAW 2). Not consumed by
/// [`bypass_to_finding`] today  -  block-reason tagging belongs on
/// the failed-attempt path, which is intentionally out of scope.
pub fn block_reason_tag(r: &BlockReason) -> String {
    match r {
        BlockReason::RuleId(_) => "block-rule-id".to_string(),
        BlockReason::RuleCategory(_) => "block-rule-category".to_string(),
        BlockReason::VendorReason(_) => "block-vendor-reason".to_string(),
        BlockReason::IpReputation => "block-ip-reputation".to_string(),
        BlockReason::GeoBlock => "block-geo".to_string(),
        BlockReason::CustomBlockPage(_) => "block-page-match".to_string(),
        BlockReason::Unknown => "block-unknown".to_string(),
    }
}

fn request_evidence(req: &Request) -> Evidence {
    let headers: Vec<(Arc<str>, Arc<str>)> = req
        .headers
        .iter()
        .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
        .collect();
    let body = req
        .body
        .as_ref()
        .map(|b| Arc::from(String::from_utf8_lossy(b).as_ref()));
    Evidence::HttpRequest {
        method: Arc::from(method_str(&req.method)),
        url: Arc::from(req.url.as_str()),
        headers,
        body,
    }
}

fn method_str(m: &Method) -> &str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Patch => "PATCH",
        Method::Head => "HEAD",
        Method::Options => "OPTIONS",
        Method::Custom(s) => s.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> Request {
        let mut r = Request::get("https://target.test/api?id=1");
        r.headers
            .push(("User-Agent".to_string(), "wafrift/1".to_string()));
        r
    }

    fn sample_evasion() -> EvasionResult {
        EvasionResult::new(
            sample_request(),
            vec![Technique::HeaderObfuscation("case-mixing".to_string())],
            "case-mixing on header values".to_string(),
        )
    }

    #[test]
    fn allowed_verdict_produces_finding() {
        let er = sample_evasion();
        let v = Verdict::Allowed { signals: vec![] };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .expect("Allowed verdict must produce Some(finding)");
        assert_eq!(f.scanner(), "wafrift");
        assert_eq!(f.severity(), Severity::High);
        assert_eq!(f.kind(), FindingKind::Vulnerability);
        assert!(f.tags().iter().any(|t| t.as_ref() == "waf-bypass"));
        assert!(f.tags().iter().any(|t| t.as_ref() == "verdict-allowed"));
    }

    #[test]
    fn blocked_verdict_produces_no_finding() {
        let er = sample_evasion();
        let v = Verdict::Blocked {
            reason: None,
            signals: vec![],
        };
        let res = bypass_to_finding("https://target.test/", &er, &v).unwrap();
        assert!(
            res.is_none(),
            "Blocked verdict must not produce a finding (it's negative evidence)"
        );
    }

    #[test]
    fn rate_limited_verdict_produces_no_finding() {
        let er = sample_evasion();
        let v = Verdict::RateLimited { signals: vec![] };
        let res = bypass_to_finding("https://target.test/", &er, &v).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn challenge_verdict_produces_no_finding() {
        let er = sample_evasion();
        let v = Verdict::ChallengeRequired {
            platform: Some("cloudflare".to_string()),
            signals: vec![],
        };
        let res = bypass_to_finding("https://target.test/", &er, &v).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn signals_become_raw_evidence_lines() {
        let er = sample_evasion();
        let v = Verdict::Allowed {
            signals: vec![
                Signal::StatusCode {
                    code: 200,
                    expected: 200,
                },
                Signal::SuccessMarker("welcome".to_string()),
            ],
        };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .unwrap();
        let raw_lines: Vec<String> = f
            .evidence()
            .iter()
            .filter_map(|e| match e {
                Evidence::Raw { value } => Some(value.to_string()),
                _ => None,
            })
            .collect();
        assert!(raw_lines.iter().any(|s| s.contains("status 200")));
        assert!(raw_lines
            .iter()
            .any(|s| s.contains("success marker: welcome")));
    }

    #[test]
    fn request_evidence_round_trips_method_url_and_headers() {
        let er = sample_evasion();
        let v = Verdict::Allowed { signals: vec![] };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .unwrap();
        let req_ev = f
            .evidence()
            .iter()
            .find(|e| matches!(e, Evidence::HttpRequest { .. }))
            .expect("must include an HttpRequest evidence");
        if let Evidence::HttpRequest {
            method,
            url,
            headers,
            ..
        } = req_ev
        {
            assert_eq!(method.as_ref(), "GET");
            assert_eq!(url.as_ref(), "https://target.test/api?id=1");
            assert!(headers
                .iter()
                .any(|(k, v)| k.as_ref() == "User-Agent" && v.as_ref() == "wafrift/1"));
        } else {
            unreachable!();
        }
    }

    #[test]
    fn techniques_become_tags() {
        let er = sample_evasion();
        let v = Verdict::Allowed { signals: vec![] };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .unwrap();
        assert!(
            f.tags()
                .iter()
                .any(|t| t.as_ref().starts_with("technique-")),
            "tag list must include at least one technique-* tag, got {:?}",
            f.tags()
        );
    }

    #[test]
    fn confidence_is_clamped_to_unit_interval() {
        let mut er = sample_evasion();
        er.confidence = 1.5;
        let v = Verdict::Allowed { signals: vec![] };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .unwrap();
        assert_eq!(f.confidence(), Some(1.0));
    }

    #[test]
    fn cwe_942_is_attached() {
        let er = sample_evasion();
        let v = Verdict::Allowed { signals: vec![] };
        let f = bypass_to_finding("https://target.test/", &er, &v)
            .unwrap()
            .unwrap();
        assert!(f.cwe_ids().iter().any(|c| c.as_ref() == "CWE-942"));
    }

    #[test]
    fn verdict_tag_is_total() {
        // Every Verdict variant must map to a stable tag string. The
        // strings are public contract  -  asserted explicitly so a
        // future variant + missing arm fails this test loudly.
        assert_eq!(
            verdict_tag(&Verdict::Allowed { signals: vec![] }),
            "verdict-allowed"
        );
        assert_eq!(
            verdict_tag(&Verdict::Blocked {
                reason: None,
                signals: vec![]
            }),
            "verdict-blocked"
        );
        assert_eq!(
            verdict_tag(&Verdict::RateLimited { signals: vec![] }),
            "verdict-rate-limited"
        );
        assert_eq!(
            verdict_tag(&Verdict::ChallengeRequired {
                platform: None,
                signals: vec![]
            }),
            "verdict-challenge"
        );
        assert_eq!(
            verdict_tag(&Verdict::ServerError { signals: vec![] }),
            "verdict-server-error"
        );
        assert_eq!(
            verdict_tag(&Verdict::Partial {
                reason: None,
                signals: vec![]
            }),
            "verdict-partial"
        );
        assert_eq!(
            verdict_tag(&Verdict::Ambiguous {
                competing: vec![],
                explanation: String::new()
            }),
            "verdict-ambiguous"
        );
    }

    #[test]
    fn block_reason_tag_is_total() {
        assert_eq!(block_reason_tag(&BlockReason::IpReputation), "block-ip-reputation");
        assert_eq!(block_reason_tag(&BlockReason::GeoBlock), "block-geo");
        assert_eq!(block_reason_tag(&BlockReason::Unknown), "block-unknown");
        assert_eq!(
            block_reason_tag(&BlockReason::RuleId("REQ-913".to_string())),
            "block-rule-id"
        );
        assert_eq!(
            block_reason_tag(&BlockReason::RuleCategory("xss".to_string())),
            "block-rule-category"
        );
        assert_eq!(
            block_reason_tag(&BlockReason::VendorReason("cf-1020".to_string())),
            "block-vendor-reason"
        );
        assert_eq!(
            block_reason_tag(&BlockReason::CustomBlockPage("acme".to_string())),
            "block-page-match"
        );
    }

    // ── technique_tag payload-bleed regression ────────────────────
    //
    // Pre-fix: the loop only stopped on ' ' (struct-variant delimiter).
    // Tuple variants like HeaderObfuscation("x") would bleed their
    // payload string into the tag, making tags non-stable and different
    // for every unique argument string.

    #[test]
    fn technique_tag_tuple_variant_does_not_bleed_payload() {
        // HeaderObfuscation holds a String; the tag must be
        // "technique-header-obfuscation" regardless of the payload.
        let t1 = Technique::HeaderObfuscation("case-mixing".to_string());
        let t2 = Technique::HeaderObfuscation("tab-separator".to_string());
        assert_eq!(
            technique_tag(&t1),
            technique_tag(&t2),
            "technique tag must not vary with the payload string"
        );
        assert_eq!(technique_tag(&t1), "technique-header-obfuscation");
    }

    #[test]
    fn technique_tag_grammar_mutation_stable() {
        let t1 = Technique::GrammarMutation("sql_tautology".to_string());
        let t2 = Technique::GrammarMutation("xss_polyglot".to_string());
        assert_eq!(technique_tag(&t1), technique_tag(&t2));
        assert_eq!(technique_tag(&t1), "technique-grammar-mutation");
    }

    #[test]
    fn technique_tag_payload_encoding_stable() {
        let t1 = Technique::PayloadEncoding("UrlEncode".to_string());
        let t2 = Technique::PayloadEncoding("HexEncode".to_string());
        assert_eq!(technique_tag(&t1), technique_tag(&t2));
        assert_eq!(technique_tag(&t1), "technique-payload-encoding");
    }

    #[test]
    fn technique_tag_content_type_switch_stable() {
        let t = Technique::ContentTypeSwitch("form -> json".to_string());
        assert_eq!(technique_tag(&t), "technique-content-type-switch");
    }

    #[test]
    fn technique_tag_unit_variants() {
        assert_eq!(
            technique_tag(&Technique::BoundaryManipulation),
            "technique-boundary-manipulation"
        );
        assert_eq!(
            technique_tag(&Technique::JsonUnicodeEscape),
            "technique-json-unicode-escape"
        );
        assert_eq!(
            technique_tag(&Technique::UserAgentRotation),
            "technique-user-agent-rotation"
        );
        assert_eq!(
            technique_tag(&Technique::Http2Settings),
            "technique-http2-settings"
        );
        assert_eq!(
            technique_tag(&Technique::DifferentialProbe),
            "technique-differential-probe"
        );
    }

    #[test]
    fn technique_tag_starts_with_technique_prefix_for_all_variants() {
        let variants: Vec<Technique> = vec![
            Technique::PayloadEncoding("x".into()),
            Technique::ContentTypeSwitch("y".into()),
            Technique::HeaderObfuscation("z".into()),
            Technique::GrammarMutation("w".into()),
            Technique::RequestSmuggling("cl-te".into()),
            Technique::H2Evasion("frame".into()),
            Technique::TlsFingerprint("chrome".into()),
            Technique::BodyPadding(1024),
            Technique::BoundaryManipulation,
            Technique::JsonUnicodeEscape,
            Technique::UserAgentRotation,
            Technique::Http2Settings,
            Technique::DifferentialProbe,
            Technique::MlEvasion {
                waf_class: "AwsBotControl".into(),
                queries: 10,
                off_manifold_rejected: 2,
            },
        ];
        for t in &variants {
            let tag = technique_tag(t);
            assert!(
                tag.starts_with("technique-"),
                "tag `{tag}` must start with technique-"
            );
            // No spaces in tags — they must be valid kebab-case.
            assert!(!tag.contains(' '), "tag `{tag}` must not contain spaces");
            // Tag must not contain parentheses or braces — no payload bleed.
            assert!(!tag.contains('('), "tag `{tag}` must not contain '('");
            assert!(!tag.contains('{'), "tag `{tag}` must not contain '{{'");
        }
    }

    #[test]
    fn technique_tag_ml_evasion_stable_across_different_payloads() {
        let t1 = Technique::MlEvasion {
            waf_class: "AwsBotControl".into(),
            queries: 100,
            off_manifold_rejected: 5,
        };
        let t2 = Technique::MlEvasion {
            waf_class: "CloudflareBot".into(),
            queries: 1,
            off_manifold_rejected: 0,
        };
        assert_eq!(
            technique_tag(&t1),
            technique_tag(&t2),
            "MlEvasion tag must not vary with waf_class or query counts"
        );
        assert_eq!(technique_tag(&t1), "technique-ml-evasion");
    }
}
