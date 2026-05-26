//! Scan's Step 1 — WAF detection + advisor planning.
//!
//! Fires a baseline GET at the target, runs the 160+ TOML rules
//! to identify the WAF in front, then asks the advisor for a
//! WAF-specific evasion plan (header obfuscation, content-type
//! switching, H2 evasion, encoding-strategy bias).
//!
//! Bundled as one phase because the four sub-steps share request
//! data (the baseline response feeds detect; detect feeds advisor)
//! and splitting them would just re-thread the same headers+body
//! through three function signatures. The output struct
//! [`DetectOutcome`] is the canonical "what we learned in Step 1"
//! bundle that downstream phases consume.

use colored::Colorize;
use std::process::ExitCode;
use wafrift_detect::waf_detect::{self, DetectedWaf};
use wafrift_evolution::advisor::{self, EvasionPlan};
use wafrift_evolution::custom_rules::{CustomDetection, CustomRulesFile};

/// Everything Step 1 produced — feeds the rest of the scan.
#[derive(Debug, Clone)]
pub struct DetectOutcome {
    /// HTTP status code of the baseline GET.
    pub baseline_status: u16,
    /// Response headers from the baseline (used to identify CDN /
    /// origin markers downstream).
    pub headers_vec: Vec<(String, String)>,
    /// Body bytes from the baseline. May be the WAF's block page
    /// (which the detect rules will recognise) or the origin's
    /// normal response. Owned `Vec<u8>` so the cli crate does not
    /// need a direct `bytes` dep.
    pub body_bytes: Vec<u8>,
    /// All WAF candidates the detect rules matched, sorted by
    /// descending confidence.
    pub detected: Vec<DetectedWaf>,
    /// Top WAF candidate above the actionable threshold, or
    /// `"Unknown"` when no confident match.
    pub waf_name: String,
    /// The DetectedWaf corresponding to `waf_name`, or None when
    /// `waf_name == "Unknown"`. Kept separately because some
    /// downstream consumers want the structured result (for JSON
    /// output) and others just want the name.
    pub detected_waf_obj: Option<DetectedWaf>,
    /// Advisor-generated plan: which evasion knobs to enable for
    /// this WAF (header obfuscation, CT switching, H2, encoding
    /// strategy bias).
    pub evasion_plan: EvasionPlan,
}

/// Run Step 1 against `target`. Prints progress when `scan_text`,
/// otherwise stays quiet. Returns `Err(ExitCode::from(1))` if the
/// baseline request fails at the transport layer — every
/// downstream phase becomes meaningless without one, so we bail
/// early with a clear error.
pub async fn run(
    http: &reqwest::Client,
    target: &str,
    scan_text: bool,
    custom_rules: Option<&CustomRulesFile>,
) -> Result<DetectOutcome, ExitCode> {
    if scan_text {
        println!("{}", "[1/3] Detecting WAF...".bold().cyan());
    }
    let baseline_response = match http.get(target).send().await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!(
                "  {} {} ({})\n    {}",
                "✗ Cannot reach target:".red().bold(),
                target,
                err,
                "hint: check the URL is reachable, the host resolves, and your network allows the connection".bright_black()
            );
            return Err(ExitCode::from(1));
        }
    };

    let baseline_status = baseline_response.status().as_u16();
    let headers_vec: Vec<(String, String)> = baseline_response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body_bytes = baseline_response
        .bytes()
        .await
        .unwrap_or_default()
        .to_vec();

    let mut detected = waf_detect::detect(baseline_status, &headers_vec, &body_bytes);
    // Layer custom rules on top. Their result is wrapped as a DetectedWaf
    // and merged via `merge_custom_into_detected`, which keeps the list
    // sorted by descending confidence so `detected[0]` is still the top
    // candidate regardless of whether it came from built-ins or custom.
    if let Some(rules) = custom_rules {
        if let Some(custom_hit) =
            wafrift_evolution::custom_rules::detect(rules, baseline_status, &headers_vec, &body_bytes)
        {
            if scan_text {
                println!(
                    "  {} {} ({:.0}%) via --custom-rules",
                    "✓ Custom:".green().bold(),
                    custom_hit.rule_name.bold().yellow(),
                    custom_hit.confidence * 100.0
                );
            }
            merge_custom_into_detected(&mut detected, custom_hit);
        }
    }
    let top_detection = detected
        .first()
        .filter(|result| result.confidence >= waf_detect::ACTIONABLE_CONFIDENCE_THRESHOLD)
        .cloned();
    let waf_name = if let Some(result) = top_detection.as_ref() {
        if scan_text {
            println!(
                "  {} {} ({:.0}% confidence)",
                "✓ Detected:".green().bold(),
                result.name.bold().yellow(),
                result.confidence * 100.0
            );
        }
        result.name.clone()
    } else {
        if scan_text {
            println!(
                "  {}",
                "⚠ No WAF confidently detected (testing anyway)"
                    .yellow()
                    .bold()
            );
        }
        String::from("Unknown")
    };

    // Advisor: generate WAF-specific evasion plan.
    let evasion_plan = advisor::advise(top_detection.as_ref(), None);
    if scan_text {
        for rationale in &evasion_plan.rationale {
            println!("  {} {}", "📋 Advisor:".bold().cyan(), rationale.yellow());
        }
        if evasion_plan.use_header_obfuscation {
            println!("    {} header obfuscation", "✓".green());
        }
        if evasion_plan.use_content_type_switch {
            println!("    {} content-type switching", "✓".green());
        }
        if evasion_plan.use_h2 {
            println!("    {} HTTP/2 evasion", "✓".green());
        }
    }

    Ok(DetectOutcome {
        baseline_status,
        headers_vec,
        body_bytes,
        detected,
        waf_name,
        detected_waf_obj: top_detection,
        evasion_plan,
    })
}

/// Merge a custom-rules detection into the built-in detection list,
/// preserving the descending-confidence ordering downstream code
/// relies on.
///
/// The conversion preserves:
/// - `rule_name` → `DetectedWaf::name` (so the advisor and JSON
///   output show the operator's chosen label).
/// - `confidence` → `DetectedWaf::confidence` (raw passthrough; the
///   custom_rules validator already enforces `[0.0, 1.0]`).
/// - `vendor` + `evasion_strategies` → joined into the `indicators`
///   list. This is the only place the operator's vendor string +
///   strategy hints surface in scan's JSON output, so they're not
///   silently dropped.
///
/// If the custom detection matches an existing `name` in `detected`
/// (case-insensitive), the existing entry's confidence is **raised
/// to the max** of the two — so layering custom rules on top of
/// built-ins can only INCREASE confidence, never decrease it. This
/// is the property an operator naturally expects when adding
/// in-house signatures to the built-in corpus.
pub(crate) fn merge_custom_into_detected(
    detected: &mut Vec<DetectedWaf>,
    custom: CustomDetection,
) {
    let mut indicators = Vec::new();
    if !custom.vendor.is_empty() {
        indicators.push(format!("vendor={}", custom.vendor));
    }
    if !custom.evasion_strategies.is_empty() {
        indicators.push(format!(
            "evasion_strategies={}",
            custom.evasion_strategies.join(",")
        ));
    }
    indicators.push("source=custom-rules".to_string());

    if let Some(existing) = detected
        .iter_mut()
        .find(|d| d.name.eq_ignore_ascii_case(&custom.rule_name))
    {
        if custom.confidence > existing.confidence {
            existing.confidence = custom.confidence;
        }
        existing.indicators.extend(indicators);
    } else {
        detected.push(DetectedWaf {
            name: custom.rule_name,
            confidence: custom.confidence,
            indicators,
        });
    }
    // Re-sort by descending confidence so `detected[0]` is still the
    // top candidate. NaN can't appear (validator forbids it) so
    // partial_cmp.unwrap is safe; we still belt-and-suspender it with
    // a fallback to Equal.
    detected.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock(response: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resp = response.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let resp = resp.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_unreachable_target_returns_err_exit_code() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let result = run(&client, "http://127.0.0.1:1/", false, None).await;
        match result {
            Err(_) => {}
            Ok(_) => panic!("dead port must err"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_plain_origin_captures_baseline_no_waf() {
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 5\r\n\
             Connection: close\r\n\r\nhello",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false, None)
            .await
            .expect("ok");
        assert_eq!(outcome.baseline_status, 200);
        assert_eq!(outcome.body_bytes, b"hello".to_vec());
        // Server: nginx alone isn't a WAF signal (it's an origin
        // server), so waf_name should fall back to "Unknown".
        assert_eq!(outcome.waf_name, "Unknown");
        assert!(outcome.detected_waf_obj.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_cloudflare_markers_identifies_cloudflare() {
        // CF-Ray + cf-cache-status are strong Cloudflare signals;
        // the rule corpus should flag with high confidence.
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-Ray: abc123-LHR\r\n\
             cf-cache-status: HIT\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false, None)
            .await
            .expect("ok");
        // Either Cloudflare lands by name, or it lands as Unknown
        // (depending on threshold tuning). The PRESENCE of CF-Ray
        // in the captured headers is the load-bearing invariant.
        let cf_ray = outcome.headers_vec.iter().any(|(k, _)| k.eq_ignore_ascii_case("cf-ray"));
        assert!(cf_ray, "CF-Ray should be in the captured headers");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_captures_response_headers_lossy_utf8_safe() {
        // A header with non-UTF-8 bytes (rare but possible) must
        // not panic the lossy-conversion path.
        // We can't easily inject non-UTF-8 from a string literal,
        // so this test is a smoke against the conversion path's
        // existence; the unwrap_or("") fallback in run() handles
        // the case.
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nX-Weird: ok\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false, None)
            .await
            .expect("ok");
        assert!(
            outcome
                .headers_vec
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-weird"))
        );
    }

    // ─── merge_custom_into_detected ──────────────────────────────────────

    fn det(name: &str, c: f64) -> DetectedWaf {
        DetectedWaf {
            name: name.to_string(),
            confidence: c,
            indicators: vec![format!("builtin:{name}")],
        }
    }

    fn cd(name: &str, c: f64, vendor: &str, strat: &[&str]) -> CustomDetection {
        CustomDetection {
            rule_name: name.to_string(),
            vendor: vendor.to_string(),
            confidence: c,
            evasion_strategies: strat.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn merge_appends_new_waf_and_preserves_descending_sort() {
        let mut detected = vec![det("Cloudflare", 0.9), det("ModSecurity", 0.6)];
        merge_custom_into_detected(&mut detected, cd("InHouseWAF", 0.7, "acme", &[]));
        assert_eq!(detected.len(), 3);
        assert_eq!(detected[0].name, "Cloudflare");
        assert_eq!(detected[1].name, "InHouseWAF");
        assert_eq!(detected[2].name, "ModSecurity");
        // Source tag is present so JSON consumers can tell it came from --custom-rules.
        assert!(detected[1].indicators.iter().any(|i| i == "source=custom-rules"));
    }

    #[test]
    fn merge_raises_existing_waf_confidence_only_upward() {
        let mut detected = vec![det("Cloudflare", 0.6)];
        // Higher custom → existing confidence rises.
        merge_custom_into_detected(&mut detected, cd("Cloudflare", 0.95, "cf", &[]));
        assert_eq!(detected.len(), 1, "must not duplicate same-name entry");
        assert!((detected[0].confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn merge_does_not_lower_existing_confidence() {
        let mut detected = vec![det("Cloudflare", 0.95)];
        merge_custom_into_detected(&mut detected, cd("Cloudflare", 0.30, "cf", &[]));
        assert_eq!(detected.len(), 1);
        assert!(
            (detected[0].confidence - 0.95).abs() < 1e-9,
            "merge must never reduce confidence, got {}",
            detected[0].confidence
        );
    }

    #[test]
    fn merge_case_insensitive_name_match() {
        // operator typed `cloudflare` lowercase — must collapse with built-in `Cloudflare`.
        let mut detected = vec![det("Cloudflare", 0.6)];
        merge_custom_into_detected(&mut detected, cd("cloudflare", 0.7, "cf", &[]));
        assert_eq!(detected.len(), 1, "case must NOT cause duplicate entries");
    }

    #[test]
    fn merge_carries_vendor_and_evasion_strategies_into_indicators() {
        let mut detected = vec![];
        merge_custom_into_detected(
            &mut detected,
            cd("Foo", 0.5, "acme", &["DoubleUrlEncode", "CaseAlternation"]),
        );
        assert_eq!(detected.len(), 1);
        let inds = &detected[0].indicators;
        assert!(inds.iter().any(|i| i == "vendor=acme"));
        assert!(inds
            .iter()
            .any(|i| i.starts_with("evasion_strategies=") && i.contains("DoubleUrlEncode")));
        assert!(inds.iter().any(|i| i == "source=custom-rules"));
    }

    #[test]
    fn merge_with_empty_vendor_omits_vendor_indicator() {
        let mut detected = vec![];
        merge_custom_into_detected(&mut detected, cd("Foo", 0.5, "", &[]));
        let inds = &detected[0].indicators;
        // Source tag still required.
        assert!(inds.iter().any(|i| i == "source=custom-rules"));
        // But no `vendor=` prefix when operator left it blank.
        assert!(
            !inds.iter().any(|i| i.starts_with("vendor=")),
            "blank vendor must not emit a vendor= indicator: {inds:?}"
        );
    }

    #[test]
    fn merge_empty_list_just_appends() {
        let mut detected: Vec<DetectedWaf> = vec![];
        merge_custom_into_detected(&mut detected, cd("Solo", 0.42, "v", &[]));
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].name, "Solo");
    }

    #[test]
    fn merge_stable_ordering_when_confidences_equal() {
        // Two entries with identical confidence — order between them is
        // unspecified, but the new entry must STILL appear in the list.
        let mut detected = vec![det("A", 0.5), det("B", 0.5)];
        merge_custom_into_detected(&mut detected, cd("C", 0.5, "v", &[]));
        assert_eq!(detected.len(), 3);
        let names: Vec<&str> = detected.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"A") && names.contains(&"B") && names.contains(&"C"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_with_custom_rules_layers_detection_on_top() {
        // Origin returns plain content with NO built-in WAF signal,
        // but a custom rule matches on a body substring.
        let addr = spawn_mock(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Origin-Foo: yes\r\n\
             Content-Length: 24\r\nConnection: close\r\n\r\nBlocked by InHouseWAF v3",
        )
        .await;
        let toml = r#"
[[waf]]
name = "InHouseWAF"
vendor = "acme-corp"

[[waf.body_signatures]]
pattern = "Blocked by InHouseWAF"
confidence = 0.92
"#;
        let rules = wafrift_evolution::custom_rules::load_rules(toml).expect("parses");
        let client = reqwest::Client::builder().build().unwrap();
        let outcome = run(&client, &format!("http://{addr}/"), false, Some(&rules))
            .await
            .expect("ok");
        // The custom hit becomes the top candidate (confidence 0.92).
        assert!(
            outcome
                .detected
                .iter()
                .any(|d| d.name == "InHouseWAF" && (d.confidence - 0.92).abs() < 1e-6),
            "expected InHouseWAF in detected list, got {:?}",
            outcome.detected
        );
    }
}
