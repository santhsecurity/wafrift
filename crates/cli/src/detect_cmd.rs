//! `wafrift detect` — WAF / CDN / origin-infrastructure fingerprinting.
//!
//! Two input modes:
//! - `--url <URL>` fetches the target once and runs the rule corpus
//!   against the live response (status + headers + body capped at
//!   64 KiB).
//! - `--status` / `--headers` / `--body` accepts the same triple from
//!   a prior `curl -i` capture so the operator doesn't need to expose
//!   the CLI to the target a second time.
//!
//! Outputs the highest-confidence WAF candidate (text mode) or the
//! full structured detect result + infra markers (`--quiet` /
//! `--format json`). When no WAF crosses the confidence threshold,
//! `infra_markers` surfaces the CDN / origin banners so the report is
//! never an unhelpful bare "no WAF found."
//!
//! `fetch_for_detect`, `infra_markers`, and `DetectFetch` are
//! intentionally `pub(crate)` so the higher-level demo command
//! (`crate::legendary::run_legendary`) composes the same primitives
//! that ship under `wafrift detect` — no risk of the demo drifting
//! from the real command's behaviour.

use colored::Colorize;
use serde_json::json;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_detect::waf_detect;

use crate::helpers::parse_headers;

#[derive(clap::Args, Debug)]
pub struct DetectArgs {
    /// Fetch the target URL directly and run detection on the live
    /// response — no manual `curl` + `--status`/`--headers` round-trip.
    /// `wafrift detect --url https://target.com`. Mutually exclusive
    /// with `--status`/`--headers`.
    #[arg(long, conflicts_with_all = ["status", "headers"])]
    pub url: Option<String>,

    /// HTTP status code (100–599). Required unless `--url` is given.
    #[arg(long, value_parser = parse_http_status, required_unless_present = "url")]
    pub status: Option<u16>,

    /// Repeated "key: value" header arguments. Required unless `--url`
    /// is given.
    #[arg(long, required_unless_present = "url")]
    pub headers: Vec<String>,

    /// Response body fragment.
    #[arg(long, default_value = "")]
    pub body: String,

    /// With `--url`: per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// With `--url`: disable TLS certificate verification (lab targets).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
}

/// clap value-parser for an HTTP status code. RFC 9110 status codes are
/// three digits in the range 100–599; anything else (`0`, `99`, `999`,
/// `1000`) is a typo or an attempt to smuggle a nonsense value past
/// detection and is rejected at parse time rather than silently scored.
pub fn parse_http_status(s: &str) -> Result<u16, String> {
    let n: u16 = s
        .parse()
        .map_err(|_| format!("`{s}` is not a number; HTTP status codes are 100–599"))?;
    if (100..=599).contains(&n) {
        Ok(n)
    } else {
        Err(format!(
            "HTTP status code {n} is out of range — valid codes are 100–599"
        ))
    }
}

/// `(status, response headers, body)` from a detect fetch, or an error
/// string. Aliased so the nested generic isn't a `type_complexity`
/// lint at every use site.
pub(crate) type DetectFetch = Result<(u16, Vec<(String, String)>, Vec<u8>), String>;

/// Single-shot GET against a target for fingerprinting. Sends a
/// realistic browser UA so the edge behaves normally (some CDNs serve
/// a different page or skip a JS challenge when they see "rustls" or
/// a bare reqwest UA, which would skew detection). Returns
/// `(status, headers, body)` with the body capped at 64 KiB — WAF/CDN
/// banners and block pages are always in the head.
pub(crate) fn fetch_for_detect(url: &str, timeout_secs: u64, insecure: bool) -> DetectFetch {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.clamp(1, 120)))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        );
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start tokio runtime: {e}"))?;
    rt.block_on(async move {
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("<binary>").to_string(),
                )
            })
            .collect();
        // Cap the body read: don't let a hostile/huge response OOM the CLI.
        let bytes = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;
        let body = bytes[..bytes.len().min(64 * 1024)].to_vec();
        Ok((status, headers, body))
    })
}

/// Infrastructure markers worth surfacing even when no WAF crosses the
/// confidence threshold — so `detect` on an nginx/CDN-fronted host
/// (e.g. meta.discourse.org) reports *what is in front of the origin*
/// instead of a bare, useless "No WAF confidently detected."
pub(crate) fn infra_markers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const KEYS: &[&str] = &[
        "server",
        "via",
        "x-cache",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "cf-ray",
        "cf-cache-status",
        "x-akamai-transformed",
        "x-sucuri-id",
        "x-sucuri-cache",
        "x-cdn",
        "x-served-by",
        "x-powered-by",
        "fastly-debug-digest",
        "x-fastly-request-id",
        "x-iinfo",
        "x-cdn-provider",
    ];
    headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_ascii_lowercase();
            KEYS.contains(&lk.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    // Two input modes: live `--url` fetch, or the manual
    // `--status`/`--headers`/`--body` triple. clap's
    // `required_unless_present`/`conflicts_with_all` guarantees exactly
    // one mode is selected.
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
        if let Some(ref url) = args.url {
            match fetch_for_detect(url, args.timeout_secs, args.insecure) {
                Ok((s, h, b)) => {
                    if !quiet {
                        eprintln!(
                            "{} GET {url} → HTTP {s} ({} headers, {} body bytes)",
                            "probe:".bright_black(),
                            h.len(),
                            b.len()
                        );
                    }
                    (s, h, b)
                }
                Err(e) => {
                    eprintln!("{} {e}", "Probe error:".red().bold());
                    return ExitCode::from(1);
                }
            }
        } else {
            let headers = match parse_headers(&args.headers) {
                Ok(headers) => headers,
                Err(message) => {
                    eprintln!("{} {}", "Header parse error:".red().bold(), message);
                    return ExitCode::from(2);
                }
            };
            // clap enforces `--status` present in this branch.
            let status = args
                .status
                .unwrap_or_else(|| unreachable!("clap requires --status unless --url is present"));
            (status, headers, args.body.clone().into_bytes())
        };

    let detected = waf_detect::detect(status, &headers, &body);
    if quiet {
        let results: Vec<_> = detected
            .iter()
            .map(|r| {
                json!({
                    "name": r.name,
                    "confidence": r.confidence,
                    "indicators": r.indicators,
                })
            })
            .collect();
        let infra: Vec<_> = infra_markers(&headers)
            .into_iter()
            .map(|(k, v)| json!({ "header": k, "value": v }))
            .collect();
        println!(
            "{}",
            json!({ "status": status, "detected": results, "infrastructure": infra })
        );
        ExitCode::SUCCESS
    } else if let Some(result) = detected.first() {
        println!("{} {}", "Detected WAF:".bold().green(), result.name.bold());
        println!(
            "{} {:.0}%",
            "Confidence:".bold().cyan(),
            (result.confidence * 100.0).round()
        );
        println!("{}", "Indicators:".bold().cyan());
        for indicator in &result.indicators {
            println!("  {} {}", "-".bright_black(), indicator.yellow());
        }
        ExitCode::SUCCESS
    } else {
        println!("{}", "No WAF confidently detected.".yellow().bold());
        let infra = infra_markers(&headers);
        if infra.is_empty() {
            println!(
                "  {}",
                "(no CDN/edge/origin markers in the response headers either)".bright_black()
            );
        } else {
            println!(
                "{}",
                "Infrastructure in front of / serving the origin:"
                    .bold()
                    .cyan()
            );
            for (k, v) in &infra {
                println!(
                    "  {} {}: {}",
                    "-".bright_black(),
                    k.yellow(),
                    v.bright_white()
                );
            }
            println!(
                "  {}",
                "These are CDN/proxy/origin banners, not a WAF verdict — \
                 a WAF may still be present in monitor-only mode."
                    .bright_black()
            );
        }
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_status_accepts_canonical_codes() {
        assert_eq!(parse_http_status("200"), Ok(200));
        assert_eq!(parse_http_status("403"), Ok(403));
        assert_eq!(parse_http_status("100"), Ok(100));
        assert_eq!(parse_http_status("599"), Ok(599));
    }

    #[test]
    fn parse_http_status_rejects_out_of_range() {
        assert!(parse_http_status("0").is_err());
        assert!(parse_http_status("99").is_err());
        assert!(parse_http_status("600").is_err());
        assert!(parse_http_status("999").is_err());
    }

    #[test]
    fn parse_http_status_rejects_non_numeric() {
        assert!(parse_http_status("abc").is_err());
        assert!(parse_http_status("").is_err());
        assert!(parse_http_status("2xx").is_err());
    }

    #[test]
    fn infra_markers_extracts_cdn_and_edge_banners() {
        let headers = vec![
            ("Server".into(), "cloudflare".into()),
            ("CF-Ray".into(), "abc123-LHR".into()),
            ("Content-Type".into(), "text/html".into()),
            ("X-Cache".into(), "HIT from front-edge-1".into()),
        ];
        let m = infra_markers(&headers);
        assert!(m.iter().any(|(k, _)| k == "Server"));
        assert!(m.iter().any(|(k, _)| k == "X-Cache"));
        // CF-Ray is in the allowlist but case-insensitively — verify
        // that the extractor picks it up regardless of header case.
        assert!(m.iter().any(|(k, _)| k.eq_ignore_ascii_case("cf-ray")));
        // Content-Type is not in the infra allowlist (it's a general
        // response header, not a fingerprint anchor) — must be dropped.
        assert!(!m.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")));
    }
}
