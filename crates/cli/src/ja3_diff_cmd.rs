//! `wafrift ja3-diff` — per-browser-profile TLS-fingerprint differential
//! scanner. Gated behind the `tls-impersonate` cargo feature so default
//! builds skip the BoringSSL/rquest compile cost.
//!
//! ## The innovation
//!
//! Modern WAFs (Cloudflare, Akamai Bot Manager, Fastly Sigsci, Imperva
//! Advanced Bot Protection) JA3/JA4-fingerprint the inbound TLS
//! `ClientHello` BEFORE inspecting any HTTP content. A `reqwest`/
//! `rustls` client has a recognizably "not a browser" fingerprint, so
//! the connection is blocked or shunted to a JS challenge before any
//! payload mutation has a chance to run.
//!
//! `ja3-diff` is the discovery tool for exactly this gating: it sends
//! the same probe (identical method/path/headers/body) through N
//! different browser-emulating TLS clients (Chrome 120/131, Firefox
//! 133, Safari 17.5/18, Edge 131, OkHttp 5) plus a reqwest baseline,
//! then surfaces any profile whose status / body-length DIVERGES from
//! the baseline. Divergence is direct evidence the WAF in front of
//! the target is fingerprinting at the TLS layer.
//!
//! ## Why this is a wafrift moat
//!
//! Sqlmap, Nuclei, ffuf, Burp, Caido — none of them ship a TLS-
//! fingerprint differential scanner as a first-class subcommand. Most
//! rely on a single TLS backend (Go's crypto/tls, Java's JSSE) which
//! is itself a fingerprint a WAF can block. wafrift's `ja3-diff`
//! both detects the gating AND points the operator at the right
//! `--tls-impersonate <profile>` to run subsequent scans through the
//! proxy with.
//!
//! ## Limitations
//!
//! - StealthClient refuses bogon targets (RFC1918 / loopback /
//!   link-local) — same SSRF gate as the proxy. Test against your
//!   real public infrastructure or your authorized cloud target.
//! - Per-probe cost is roughly N+1 TLS handshakes (no connection
//!   reuse across profiles), so default profile set is small.
//! - JA3 hashing itself is not computed here — `wafrift_fingerprint::
//!   tls_fingerprint::compute_ja3_string` is the reference if the
//!   operator wants the raw JA3 of each profile in a report.

#![cfg(feature = "tls-impersonate")]

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use serde::Serialize;
use serde_json::json;

use wafrift_transport::stealth::{ImpersonateProfile, StealthClient, supported_profiles};

#[derive(Args, Debug)]
pub(crate) struct Ja3DiffArgs {
    /// Target URL. Must be a non-bogon address (the stealth client
    /// refuses 127.0.0.1, RFC1918, link-local, CGN, Teredo, IMDS —
    /// same SSRF gate the proxy uses).
    pub url: String,

    /// Comma-separated list of browser profiles to probe.
    /// Default: the full supported set. Each profile is one
    /// `--tls-impersonate <profile>` value the proxy understands —
    /// when ja3-diff flags one as a bypass, you can immediately run
    /// `wafrift-proxy --tls-impersonate <best>` to route your scan
    /// through the winning fingerprint.
    #[arg(long, value_delimiter = ',')]
    pub profiles: Vec<String>,

    /// Inter-probe delay (ms) — honour rate limits.
    #[arg(long, default_value_t = 100)]
    pub delay_ms: u64,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// Maximum upstream response body size (bytes). Bodies larger
    /// than this are truncated, not errored — truncated content is
    /// still useful for diff classification.
    #[arg(long, default_value_t = 64 * 1024)]
    pub max_body_bytes: usize,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Result of one profile's probe.
#[derive(Debug, Clone, Serialize)]
struct ProbeOutcome {
    profile: String,
    /// `None` when the probe couldn't be sent at all (bogon refused,
    /// DNS failure, TLS handshake error). The error string is in
    /// `error` so the operator sees WHY each profile is missing.
    status: Option<u16>,
    body_len: Option<usize>,
    latency_ms: Option<u128>,
    error: Option<String>,
    /// Severity vs the most-common (baseline) outcome. `"high"` when
    /// status flipped; `"medium"` when status held but body length
    /// shifted >20%; `"none"` for the baseline cohort and matching
    /// profiles.
    severity: &'static str,
}

/// Entry point for the `wafrift ja3-diff` subcommand.
pub(crate) fn run_ja3_diff(mut args: Ja3DiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    // §7 DEDUPLICATION: delegate to the canonical runtime helper.
    crate::helpers::block_on_with_runtime(run_async(args))
}

async fn run_async(args: Ja3DiffArgs) -> ExitCode {
    let want_json = args.format == "json";

    // Resolve the profile set. Default = every supported profile.
    let profile_names: Vec<String> = if args.profiles.is_empty() {
        supported_profiles().into_iter().map(String::from).collect()
    } else {
        args.profiles.clone()
    };
    if profile_names.is_empty() {
        eprintln!(
            "{} no profiles to probe — `supported_profiles()` returned empty",
            "ja3-diff error:".red().bold()
        );
        return ExitCode::from(1);
    }

    // Parse each name → profile up front so a typo fails fast,
    // before we open any sockets.
    let mut profiles: Vec<(String, ImpersonateProfile)> = Vec::new();
    for name in &profile_names {
        match ImpersonateProfile::parse(name) {
            Ok(p) => profiles.push((name.clone(), p)),
            Err(e) => {
                eprintln!("{} {e}", "ja3-diff error:".red().bold());
                return ExitCode::from(2);
            }
        }
    }

    if !want_json {
        eprintln!(
            "[wafrift ja3-diff] probing {} profile(s) → {}",
            profiles.len(),
            args.url
        );
    }

    let mut outcomes: Vec<ProbeOutcome> = Vec::with_capacity(profiles.len());
    let delay = Duration::from_millis(args.delay_ms);
    for (i, (name, profile)) in profiles.iter().enumerate() {
        if i > 0 && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        outcomes.push(probe_one(name, *profile, &args).await);
    }

    // Classify divergence: bucket profiles by (status, body_len) and
    // tag any profile whose bucket has fewer members than the largest
    // bucket — the largest bucket is "what most browsers see"
    // (baseline), and minorities are evidence of TLS-layer gating.
    classify_severity(&mut outcomes);

    let total = outcomes.len();
    let high = outcomes.iter().filter(|o| o.severity == "high").count();
    let medium = outcomes.iter().filter(|o| o.severity == "medium").count();
    let errored = outcomes.iter().filter(|o| o.error.is_some()).count();

    if want_json {
        let blob = json!({
            "url": args.url,
            "profiles_probed": total,
            "errored": errored,
            "high": high,
            "medium": medium,
            "results": outcomes,
        });
        match serde_json::to_string_pretty(&blob) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!(
                    "{} failed to serialise output: {e}",
                    "ja3-diff error:".red().bold()
                );
                return ExitCode::from(1);
            }
        }
    } else {
        println!();
        println!(
            "  {} {} probe(s) · {} high, {} medium · {} error(s)",
            "[wafrift ja3-diff summary]".bright_cyan().bold(),
            total.to_string().bold().yellow(),
            high.to_string().bright_red().bold(),
            medium.to_string().yellow(),
            errored.to_string().bright_red(),
        );
        for o in &outcomes {
            print_outcome_text(o);
        }
        if high > 0 {
            println!();
            println!(
                "  {} the WAF appears to fingerprint the TLS ClientHello. \
                 Run `wafrift-proxy --tls-impersonate <profile>` with one of the \
                 non-high-severity profiles above to route subsequent scans through \
                 the matching browser TLS.",
                "next:".bright_cyan().bold()
            );
        }
    }

    if errored == total {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

async fn probe_one(name: &str, profile: ImpersonateProfile, args: &Ja3DiffArgs) -> ProbeOutcome {
    let client = match StealthClient::with_timeout(profile, Duration::from_secs(args.timeout_secs))
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome {
                profile: name.into(),
                status: None,
                body_len: None,
                latency_ms: None,
                error: Some(format!("client build: {e}")),
                severity: "none",
            };
        }
    };
    let started = std::time::Instant::now();
    let result = client
        .send("GET", &args.url, &[], None, args.max_body_bytes)
        .await;
    let latency = started.elapsed();
    match result {
        Ok(resp) => ProbeOutcome {
            profile: name.into(),
            status: Some(resp.status),
            body_len: Some(resp.body.len()),
            latency_ms: Some(latency.as_millis()),
            error: None,
            severity: "none",
        },
        Err(e) => ProbeOutcome {
            profile: name.into(),
            status: None,
            body_len: None,
            latency_ms: Some(latency.as_millis()),
            error: Some(format!("{e}")),
            severity: "none",
        },
    }
}

fn classify_severity(outcomes: &mut [ProbeOutcome]) {
    use std::collections::BTreeMap;
    // Group only the successful outcomes by (status, body_len).
    let mut buckets: BTreeMap<(u16, usize), Vec<usize>> = BTreeMap::new();
    for (i, o) in outcomes.iter().enumerate() {
        if let (Some(s), Some(l)) = (o.status, o.body_len) {
            buckets.entry((s, l)).or_default().push(i);
        }
    }
    // Largest bucket is the baseline. Smaller buckets are
    // candidates for divergence.
    let baseline_key = buckets.iter().max_by_key(|(_, v)| v.len()).map(|(k, _)| *k);
    let Some((baseline_status, baseline_body_len)) = baseline_key else {
        // No successful probes — all errored; leave severity as-is.
        return;
    };
    for o in outcomes.iter_mut() {
        let Some(status) = o.status else { continue };
        let Some(body_len) = o.body_len else { continue };
        if status == baseline_status && body_len == baseline_body_len {
            o.severity = "none";
            continue;
        }
        if status / 100 != baseline_status / 100 {
            // 200 ↔ 4xx flip — TLS-layer gating, the headline signal.
            o.severity = "high";
        } else {
            // Same status class, different body — could be a JS
            // challenge page swapped in, or just dynamic content.
            // Threshold at 20% to mirror the parser-diff family.
            //
            // R64 pass-21 §7 DEDUP: delegate to
            // `parser_diff_common::body_delta_pct` instead of
            // re-implementing the formula. Pre-fix this site
            // used `.abs()` (unsigned), while the canonical
            // function is signed — wrap with .abs() at the
            // call site to keep the existing "fire on growth OR
            // shrinkage" behaviour, but the formula now comes
            // from one canonical home. If `respdiff` ever swaps
            // its delta semantics (e.g., similarity score),
            // this site automatically tracks the change.
            let delta =
                crate::parser_diff_common::body_delta_pct(baseline_body_len, body_len).abs();
            o.severity = if delta > 20.0 { "medium" } else { "none" };
        }
    }
}

fn print_outcome_text(o: &ProbeOutcome) {
    let badge = crate::parser_diff_common::severity_badge(o.severity);
    print!("  [{badge:>6}] {:<12} ", o.profile.bold());
    if let Some(e) = &o.error {
        println!("{} {}", "error:".bright_red(), e.bright_red());
    } else {
        let lat = o.latency_ms.map_or("?".into(), |m| format!("{m}ms"));
        let status = o.status.map_or("?".into(), |s| s.to_string());
        let body_len = o.body_len.map_or("?".into(), |l| format!("{l}B"));
        println!(
            "HTTP {} · {} body · {}",
            status.yellow(),
            body_len.bright_white(),
            lat.bright_black()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_no_outcomes_does_not_panic() {
        let mut outcomes: Vec<ProbeOutcome> = Vec::new();
        classify_severity(&mut outcomes);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn classify_all_errored_leaves_severity_none() {
        let mut outcomes = vec![
            ProbeOutcome {
                profile: "chrome131".into(),
                status: None,
                body_len: None,
                latency_ms: Some(0),
                error: Some("boom".into()),
                severity: "none",
            },
            ProbeOutcome {
                profile: "firefox133".into(),
                status: None,
                body_len: None,
                latency_ms: Some(0),
                error: Some("boom".into()),
                severity: "none",
            },
        ];
        classify_severity(&mut outcomes);
        for o in &outcomes {
            assert_eq!(o.severity, "none", "errored probes stay none");
        }
    }

    #[test]
    fn classify_one_status_flip_is_high_others_none() {
        // Baseline cohort: 3 profiles all get HTTP 200 + 1024 bytes.
        // The fourth gets HTTP 403 — TLS-layer gating headline.
        let mk = |name: &str, status: u16, body: usize| ProbeOutcome {
            profile: name.into(),
            status: Some(status),
            body_len: Some(body),
            latency_ms: Some(50),
            error: None,
            severity: "none",
        };
        let mut outcomes = vec![
            mk("chrome131", 200, 1024),
            mk("chrome120", 200, 1024),
            mk("firefox133", 200, 1024),
            mk("okhttp5", 403, 256),
        ];
        classify_severity(&mut outcomes);
        assert_eq!(outcomes[0].severity, "none");
        assert_eq!(outcomes[1].severity, "none");
        assert_eq!(outcomes[2].severity, "none");
        assert_eq!(
            outcomes[3].severity, "high",
            "200→403 flip must be high severity"
        );
    }

    #[test]
    fn classify_body_shift_within_status_class_is_medium() {
        // All 200, but one profile gets a body length that's 50% smaller —
        // could be a JS challenge swapped in for that fingerprint.
        let mk = |name: &str, body: usize| ProbeOutcome {
            profile: name.into(),
            status: Some(200),
            body_len: Some(body),
            latency_ms: Some(50),
            error: None,
            severity: "none",
        };
        let mut outcomes = vec![
            mk("chrome131", 1024),
            mk("chrome120", 1024),
            mk("firefox133", 1024),
            mk("okhttp5", 512), // 50% smaller
        ];
        classify_severity(&mut outcomes);
        assert_eq!(outcomes[3].severity, "medium");
    }

    #[test]
    fn classify_body_shift_under_threshold_stays_none() {
        let mk = |name: &str, body: usize| ProbeOutcome {
            profile: name.into(),
            status: Some(200),
            body_len: Some(body),
            latency_ms: Some(50),
            error: None,
            severity: "none",
        };
        let mut outcomes = vec![
            mk("chrome131", 1000),
            mk("chrome120", 1000),
            mk("firefox133", 1000),
            mk("okhttp5", 1100), // 10% larger — under 20% threshold
        ];
        classify_severity(&mut outcomes);
        assert_eq!(
            outcomes[3].severity, "none",
            "<20% body delta should not flag as medium"
        );
    }

    #[test]
    fn classify_zero_baseline_body_with_non_empty_probe_is_medium() {
        let mk = |name: &str, body: usize| ProbeOutcome {
            profile: name.into(),
            status: Some(200),
            body_len: Some(body),
            latency_ms: Some(50),
            error: None,
            severity: "none",
        };
        let mut outcomes = vec![mk("chrome131", 0), mk("chrome120", 0), mk("okhttp5", 1024)];
        classify_severity(&mut outcomes);
        // okhttp5 gets a different body length from the zero-baseline
        // cohort. Goes through the 100% delta branch and registers as
        // medium. Pin the behaviour so the divide-by-zero guard doesn't
        // silently regress.
        assert_eq!(outcomes[2].severity, "medium");
    }
}
