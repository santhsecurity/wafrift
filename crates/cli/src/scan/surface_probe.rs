//! HTML surface harvest + engagement preflight — find injection points the WAF
//! actually inspects instead of burning budget on decorative query params.
//!
//! When the operator scans `https://target/?q=payload` but the real sinks live
//! in `POST /api/upload` or `register.php` form fields, this module harvests
//! candidates from the landing HTML and ranks them with the same fingerprint
//! logic as [`super::waf_engagement`].

use scanclient::urlutil;
use serde::Serialize;
use wafrift_evolution::intelligence::IntelligenceLoop;
use wafrift_transport::is_waf_block;

use super::baseline;
use super::scan_url_with_param;
use super::waf_engagement::{self, WafEngagementLevel, WafEngagementReport};

/// One injectable surface extracted from HTML or common path heuristics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SurfaceCandidate {
    pub url: String,
    pub param: String,
    pub method: &'static str,
    pub source: &'static str,
}

/// Quick engagement read on a candidate surface (baseline + benign only).
#[derive(Debug, Clone)]
pub(crate) struct SurfacePreflight {
    pub candidate: SurfaceCandidate,
    pub report: WafEngagementReport,
    pub score: u8,
}

impl SurfacePreflight {
    #[must_use]
    pub fn counts_meaningful_bypass(&self) -> bool {
        self.report.counts_meaningful_bypass()
    }
}

// NOTE (§11 UTILIZATION / §7 DEDUP): the aggregate `SurfaceProbeReport`
// + `PrimarySurfaceSummary` types were removed — they had zero consumers.
// Scan emits surface results through the live `SurfacePreflightJson` path
// (`escalated_to_json` in scan::mod), so the aggregate was never-wired
// redundant scaffolding, not a shipped output shape.

/// One injectable surface, JSON-serialized for scan's `--format json` output.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SurfacePreflightJson {
    pub url: String,
    pub param: String,
    pub method: String,
    pub source: String,
    pub engagement_level: String,
    pub score: u8,
    pub reason: String,
}

#[must_use]
pub(crate) fn engagement_score(level: WafEngagementLevel) -> u8 {
    match level {
        WafEngagementLevel::Active => 4,
        WafEngagementLevel::Selective => 3,
        WafEngagementLevel::ParamLiveNoWaf => 2,
        WafEngagementLevel::Unguarded => 1,
        WafEngagementLevel::Unknown => 0,
    }
}

/// Extract form fields and common API paths from HTML (regex — no DOM dep).
///
/// Regexes are compiled ONCE via `LazyLock` (regex compilation is far
/// costlier than matching). Pre-fix this function called `Regex::new`
/// six times on every invocation — and `harvest_from_html` runs per
/// crawled page during a recon sweep, so a link-rich target paid the
/// compile cost N times over. The standalone-input pattern was also a
/// byte-identical duplicate of the in-form input pattern; both now share
/// the single `INPUT_NAME_RE` static (§7 dedup).
#[must_use]
pub(crate) fn harvest_from_html(base_url: &str, html: &str) -> Vec<SurfaceCandidate> {
    use std::sync::LazyLock;
    static FORM_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?is)(<form\b[^>]*>)(.*?)</form>"#)
            .expect("form harvest regex compiles")
    });
    static FORM_ACTION_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)\baction\s*=\s*["']([^"']*)["']"#).expect("form action regex")
    });
    static FORM_METHOD_GET_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)\bmethod\s*=\s*["']?get["']?"#).expect("form method regex")
    });
    // Shared by the in-form scan AND the standalone-input (SPA partial)
    // scan — the two patterns were identical, so one static serves both.
    static INPUT_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)<input\b[^>]*\bname\s*=\s*["']([^"']+)["']"#).expect("input regex")
    });
    static PATH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"(?i)(?:href|src|action)\s*=\s*["']([^"']*(?:api|login|register|auth|upload|search|graphql)[^"']*)["']"#,
        )
        .expect("path regex")
    });

    let mut out: Vec<SurfaceCandidate> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    let base = base_url.trim_end_matches('/');

    // <form action="..." ...> with <input name="...">
    let form_re = &*FORM_RE;
    let form_action_re = &*FORM_ACTION_RE;
    let form_method_get_re = &*FORM_METHOD_GET_RE;
    let input_re = &*INPUT_NAME_RE;

    for caps in form_re.captures_iter(html) {
        let form_open = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = form_action_re
            .captures(form_open)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        let method = if form_method_get_re.is_match(form_open) {
            "GET"
        } else {
            "POST"
        };
        let url = resolve_url(base, action);
        for input_cap in input_re.captures_iter(body) {
            let name = input_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if name.is_empty() || is_boring_param(name) {
                continue;
            }
            let key = (url.clone(), name.to_string());
            if seen.insert(key) {
                out.push(SurfaceCandidate {
                    url: url.clone(),
                    param: name.to_string(),
                    method,
                    source: "html_form",
                });
            }
        }
    }

    // Standalone inputs outside forms (SPA partials). Same pattern as the
    // in-form input scan (INPUT_NAME_RE), run against the whole document.
    let loose_input = &*INPUT_NAME_RE;
    for caps in loose_input.captures_iter(html) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || is_boring_param(name) {
            continue;
        }
        let key = (base.to_string(), name.to_string());
        if seen.insert(key) {
            out.push(SurfaceCandidate {
                url: base.to_string(),
                param: name.to_string(),
                method: "GET",
                source: "html_input",
            });
        }
    }

    // Paths in href/src/action and inline scripts.
    let path_re = &*PATH_RE;
    for caps in path_re.captures_iter(html) {
        let path = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let url = resolve_url(base, path);
        for param in [
            "q", "id", "search", "query", "key", "file", "username", "email",
        ] {
            let key = (url.clone(), param.to_string());
            if seen.insert(key) {
                out.push(SurfaceCandidate {
                    url: url.clone(),
                    param: param.to_string(),
                    method: "GET",
                    source: "html_path_heuristic",
                });
            }
        }
    }

    // Well-known PHP/API filenames when linked in page text.
    for path in [
        "/login.php",
        "/register.php",
        "/authenticate.php",
        "/api/v1/upload",
        "/api/1/upload",
        "/search",
    ] {
        let url = format!("{base}{path}");
        for param in ["username", "email", "q", "key", "file"] {
            let key = (url.clone(), param.to_string());
            if seen.insert(key) {
                out.push(SurfaceCandidate {
                    url: url.clone(),
                    param: param.to_string(),
                    method: if path.contains("api") || path.ends_with(".php") {
                        "POST"
                    } else {
                        "GET"
                    },
                    source: "common_path",
                });
            }
        }
    }

    out
}

fn is_boring_param(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "csrf"
            | "_token"
            | "token"
            | "submit"
            | "remember_me"
            | "remember"
            | "captcha"
            | "cf-turnstile-response"
            | "g-recaptcha-response"
    )
}

fn resolve_url(base: &str, action: &str) -> String {
    if action.is_empty() {
        return base.to_string();
    }
    urlutil::resolve_url(base, action)
}

async fn preflight_get(
    http: &reqwest::Client,
    url: &str,
    param: &str,
    payload: &str,
) -> Option<(
    baseline::BaselineOutcome,
    Option<waf_engagement::ResponseFingerprint>,
    Option<waf_engagement::ResponseFingerprint>,
    IntelligenceLoop,
)> {
    let baseline_outcome = baseline::run(http, url, param, payload, false).await;
    if !baseline_outcome.transport_ok {
        return None;
    }
    let benign_fp = waf_engagement::probe_benign(http, url, param).await;
    let attack_fp = baseline_outcome.fingerprint;
    let mut il = IntelligenceLoop::new(3);
    for probe in il.generate_quick_probes().into_iter().take(3) {
        let probe_payload = format!("{:?}", probe.tests);
        let probe_url = scan_url_with_param(url, param, &urlencoding::encode(&probe_payload));
        let blocked = match http.get(&probe_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = crate::safe_body::read_bounded(
                    resp,
                    crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                )
                .await
                .unwrap_or_default();
                is_waf_block(status, &body)
            }
            Err(_) => false,
        };
        il.record_probe(&probe, blocked);
    }
    Some((baseline_outcome, attack_fp, benign_fp, il))
}

async fn preflight_post_form(
    http: &reqwest::Client,
    url: &str,
    param: &str,
    payload: &str,
) -> Option<(
    baseline::BaselineOutcome,
    Option<waf_engagement::ResponseFingerprint>,
    Option<waf_engagement::ResponseFingerprint>,
    IntelligenceLoop,
)> {
    let attack_body = [(param, payload)];
    let baseline_outcome = match http.post(url).form(&attack_body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body =
                crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
                    .await
                    .unwrap_or_default();
            let blocked = is_waf_block(status, &body);
            let fingerprint = Some(waf_engagement::ResponseFingerprint::from_parts(
                status, &body,
            ));
            baseline::BaselineOutcome {
                status,
                blocked,
                transport_ok: true,
                fingerprint,
            }
        }
        Err(_) => {
            return None;
        }
    };
    let benign_body = [(param, waf_engagement::BENIGN_PROBE_VALUE)];
    let benign_fp = match http.post(url).form(&benign_body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body =
                crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
                    .await
                    .unwrap_or_default();
            Some(waf_engagement::ResponseFingerprint::from_parts(
                status, &body,
            ))
        }
        Err(_) => None,
    };
    let attack_fp = baseline_outcome.fingerprint;
    let mut il = IntelligenceLoop::new(3);
    for probe in il.generate_quick_probes().into_iter().take(3) {
        let probe_payload = format!("{:?}", probe.tests);
        let probe_body = [(param, probe_payload.as_str())];
        let blocked = match http.post(url).form(&probe_body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = crate::safe_body::read_bounded(
                    resp,
                    crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
                )
                .await
                .unwrap_or_default();
                is_waf_block(status, &body)
            }
            Err(_) => false,
        };
        il.record_probe(&probe, blocked);
    }
    Some((baseline_outcome, attack_fp, benign_fp, il))
}

/// Run minimal engagement preflight on one surface (GET query or POST form).
pub(crate) async fn preflight_surface(
    http: &reqwest::Client,
    candidate: &SurfaceCandidate,
    payload: &str,
) -> Option<SurfacePreflight> {
    let pre = match candidate.method {
        "GET" => preflight_get(http, &candidate.url, &candidate.param, payload).await,
        "POST" => preflight_post_form(http, &candidate.url, &candidate.param, payload).await,
        _ => None,
    }?;
    let (baseline_outcome, attack_fp, benign_fp, il) = pre;
    let report = waf_engagement::assess(&baseline_outcome, attack_fp, benign_fp, &il);
    let score = engagement_score(report.level);
    Some(SurfacePreflight {
        candidate: candidate.clone(),
        report,
        score,
    })
}

/// Harvest + preflight up to `cap` alternatives; return ranked list (best first).
pub(crate) async fn probe_alternatives(
    http: &reqwest::Client,
    base_url: &str,
    payload: &str,
    cap: usize,
) -> Vec<SurfacePreflight> {
    let html = match http.get(base_url).send().await {
        Ok(resp) => {
            crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
                .await
                .unwrap_or_default()
        }
        Err(_) => return Vec::new(),
    };
    let html_str = String::from_utf8_lossy(&html);
    let candidates = harvest_from_html(base_url, html_str.as_ref());
    let mut results = Vec::new();
    for c in candidates.into_iter().take(cap) {
        if let Some(pf) = preflight_surface(http, &c, payload).await {
            results.push(pf);
        }
    }
    results.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.candidate.url.cmp(&b.candidate.url))
    });
    results
}

#[must_use]
pub(crate) fn best_meaningful<'a>(alts: &'a [SurfacePreflight]) -> Option<&'a SurfacePreflight> {
    alts.iter().find(|p| p.counts_meaningful_bypass())
}

pub(crate) fn to_json_preflight(p: &SurfacePreflight) -> SurfacePreflightJson {
    SurfacePreflightJson {
        url: p.candidate.url.clone(),
        param: p.candidate.param.clone(),
        method: p.candidate.method.to_string(),
        source: p.candidate.source.to_string(),
        engagement_level: p.report.level.as_str().to_string(),
        score: p.score,
        reason: p.report.reason.clone(),
    }
}

pub(crate) fn build_recommendations(
    primary_level: WafEngagementLevel,
    alts: &[SurfacePreflight],
    escalated: bool,
) -> Vec<String> {
    let mut r = Vec::new();
    if escalated {
        r.push(
            "Scan auto-escalated to a higher-signal injection surface — see escalated_to."
                .to_string(),
        );
        return r;
    }
    match primary_level {
        WafEngagementLevel::Active | WafEngagementLevel::Selective => {
            r.push(
                "Primary injection point shows WAF engagement — evasion results are meaningful."
                    .to_string(),
            );
        }
        WafEngagementLevel::Unguarded => {
            r.push(
                "Primary parameter is not WAF-inspected (identical benign/attack responses). \
                 Use --auto-escalate or scan --raw-request on a form/API field."
                    .to_string(),
            );
        }
        WafEngagementLevel::ParamLiveNoWaf => {
            r.push(
                "Parameter affects the response but nothing was blocked — retest on API POST \
                 bodies or authenticated form fields."
                    .to_string(),
            );
        }
        WafEngagementLevel::Unknown => {
            r.push("Could not assess WAF engagement — fix connectivity and re-run.".to_string());
        }
    }
    if let Some(best) = alts.first() {
        if best.counts_meaningful_bypass() {
            r.push(format!(
                "Best alternative surface: {} param={} ({}, score={}) — rerun with --auto-escalate",
                best.candidate.url,
                best.candidate.param,
                best.report.level.as_str(),
                best.score
            ));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvest_finds_form_fields() {
        let html = r#"
        <form action="/register.php" method="POST">
          <input name="username" type="text">
          <input name="password" type="password">
          <input name="csrf" type="hidden" value="x">
        </form>
        "#;
        let surfaces = harvest_from_html("https://example.com", html);
        let params: Vec<&str> = surfaces.iter().map(|s| s.param.as_str()).collect();
        assert!(params.contains(&"username"));
        assert!(params.contains(&"password"));
        assert!(!params.contains(&"csrf"));
        assert!(surfaces.iter().any(|s| s.url.contains("register.php")));
    }

    #[test]
    fn harvest_dedupes_same_param_on_url() {
        let html = r#"<input name="email"><input name="email">"#;
        let surfaces = harvest_from_html("https://x.com", html);
        assert_eq!(
            surfaces
                .iter()
                .filter(|s| s.param == "email" && s.source == "html_input")
                .count(),
            1,
            "duplicate loose inputs dedupe; common_path heuristics may add more email sinks"
        );
    }

    #[test]
    fn engagement_score_orders_active_above_unguarded() {
        assert!(
            engagement_score(WafEngagementLevel::Active)
                > engagement_score(WafEngagementLevel::Unguarded)
        );
        assert!(
            engagement_score(WafEngagementLevel::Selective)
                > engagement_score(WafEngagementLevel::ParamLiveNoWaf)
        );
    }

    #[test]
    fn resolve_url_relative_path() {
        assert_eq!(
            resolve_url("https://upld.me", "/login.php"),
            "https://upld.me/login.php"
        );
    }

    #[test]
    fn resolve_url_empty_action_stays_on_current_surface() {
        assert_eq!(
            resolve_url("https://upld.me/account/settings", ""),
            "https://upld.me/account/settings"
        );
    }

    #[test]
    fn resolve_url_absolute_action_is_not_merged_into_base() {
        assert_eq!(
            resolve_url(
                "https://upld.me/account/settings",
                "https://auth.example.com/login"
            ),
            "https://auth.example.com/login"
        );
    }

    #[test]
    fn build_recommendations_mentions_auto_escalate_when_unguarded() {
        let recs = build_recommendations(WafEngagementLevel::Unguarded, &[], false);
        assert!(recs.iter().any(|r| r.contains("auto-escalate")));
    }
}
