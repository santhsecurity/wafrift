//! `wafrift bypass-probe` — differential bypass scanner for a single
//! protected URL.
//!
//! Algorithm (ported from gossan's `bypass403::probe`, generalised
//! against wafrift's much larger probe library):
//!
//! 1. Establish a baseline by GET-ing the user-supplied URL once.
//! 2. Fire each probe family in turn:
//!    - 136 auth-bypass header probes from `wafrift_encoding::auth_bypass`
//!      (X-Original-URL, X-Rewrite-URL, X-Forwarded-For loopback,
//!      method-override, scheme-trust, host-trust)
//!    - All path-routing-disagreement variants from
//!      `wafrift_grammar::grammar::path_traversal::mutate` (ProxyShell
//!      `?@`, semicolon path-param, double-encoded slash, IIS null
//!      truncation, fullwidth dot, ...)
//!    - HTTP method overrides at the wire level (GET → POST/PUT/
//!      DELETE/PATCH/HEAD/PROPFIND).
//! 3. For every probe, classify the response vs the baseline:
//!    - status changed (esp 403 → 200 / 302)
//!    - body length changed >10% (smaller body == access denied page;
//!      larger body == content was returned)
//!    - new redirect target
//! 4. Report each divergence as a finding with an exact reproduce-it
//!    `curl` command. Findings are sorted by interestingness.
//!
//! This is the workflow that turns wafrift from "WAF evasion engine"
//! into "Tsai-class vuln finder": you point it at `/admin` (or any
//! resource the WAF gates) and it tells you which of the 152+ tricks
//! actually changes the response — i.e. which routing/auth bypass is
//! real on this stack.

use clap::Args;
use reqwest::{Client, Method};
use std::str::FromStr;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct BypassProbeArgs {
    /// Target URL to probe. Must already return 401/403 (or any status
    /// the user wants to bypass) for the probe set to be meaningful.
    /// When `--paths-file` is set this is the base URL (scheme://host)
    /// and the file supplies the path list.
    pub url: String,

    /// Path one URL path per line. Each path is appended to `<url>` and
    /// probed with the full bypass set. Useful for sweeping a known
    /// admin surface (`/admin /actuator /.env /wp-admin ...`). When
    /// unset, only the single `url` arg is probed.
    #[arg(long)]
    pub paths_file: Option<String>,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Inter-request delay in milliseconds. 0 = fire as fast as
    /// possible (may trip rate limits).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Maximum concurrent in-flight probes. Higher = faster but more
    /// likely to trip rate limits. With `--delay-ms > 0` the delay
    /// applies between batches (so effective rate is concurrency /
    /// delay).
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Disable TLS certificate verification (self-signed test stacks).
    #[arg(long)]
    pub insecure: bool,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Skip the auth-bypass-header probe family.
    #[arg(long)]
    pub skip_headers: bool,

    /// Skip the path-routing-disagreement probe family.
    #[arg(long)]
    pub skip_paths: bool,

    /// Skip the HTTP-method-override probe family.
    #[arg(long)]
    pub skip_methods: bool,

    /// Minimum body-length difference (in percent) to flag a probe as
    /// a divergence even when status code is unchanged. Lower = noisier,
    /// higher = miss small content changes.
    #[arg(long, default_value_t = 10.0)]
    pub body_diff_threshold_pct: f64,

    /// Skip results below this severity (LOW < MEDIUM < HIGH).
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high"])]
    pub min_severity: String,

    /// Quiet — emit only machine-parseable JSON.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Classification of how a probe response diverged from the baseline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Divergence {
    /// Probe family name (`headers`, `paths`, `methods`).
    pub family: String,
    /// Short label naming the specific probe within the family.
    pub label: String,
    /// Human-readable description of the probe.
    pub description: String,
    /// Baseline HTTP status code (for reference).
    pub baseline_status: u16,
    /// Probe response HTTP status code.
    pub probe_status: u16,
    /// Body length delta in percent vs baseline (positive = larger).
    pub body_delta_pct: f64,
    /// Reproduce-it shell command (curl).
    pub curl_cmd: String,
    /// Severity guess based on the divergence pattern.
    pub severity: &'static str,
}

/// Entry point for `wafrift bypass-probe`.
///
/// # Errors
/// Returns `Err` if the target URL can't be parsed, the HTTP client
/// can't be built, or the baseline request fails outright (no
/// connectivity).
pub fn run_bypass_probe(args: BypassProbeArgs) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: BypassProbeArgs) -> Result<(), String> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(args.timeout_secs))
        .redirect(reqwest::redirect::Policy::none()); // see redirects, don't follow them
    if args.insecure {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    let client = builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let urls = build_url_list(&args)?;
    let concurrency = args.concurrency.max(1);
    let min_severity_rank = severity_rank(&args.min_severity);

    let mut all_results: Vec<UrlReport> = Vec::with_capacity(urls.len());
    for url in &urls {
        match probe_one_url(&client, url, &args, concurrency).await {
            Ok(mut report) => {
                report
                    .divergences
                    .retain(|d| severity_rank(d.severity) >= min_severity_rank);
                all_results.push(report);
            }
            Err(e) => {
                eprintln!("error probing {url}: {e}");
                if urls.len() == 1 {
                    return Err(e);
                }
                // multi-URL mode: keep going with the rest
            }
        }
    }

    if args.format == "json" {
        let out = serde_json::json!({ "results": all_results });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for report in &all_results {
            print_report_text(report);
        }
        let total = all_results
            .iter()
            .map(|r| r.divergences.len())
            .sum::<usize>();
        if all_results.len() > 1 {
            println!();
            println!(
                "=== summary: {} URL(s) probed, {total} divergence(s) at or above {} severity ===",
                all_results.len(),
                args.min_severity.to_uppercase()
            );
        }
    }
    Ok(())
}

/// Per-URL result for JSON output and text rendering.
#[derive(Debug, Clone, serde::Serialize)]
struct UrlReport {
    target: String,
    baseline_status: u16,
    baseline_body_len: usize,
    divergences: Vec<Divergence>,
}

/// Build the final probe-target list from `args.url` + optional
/// `--paths-file`. The single-URL case yields one entry; the paths-
/// file case yields one URL per non-blank, non-`#` line.
fn build_url_list(args: &BypassProbeArgs) -> Result<Vec<String>, String> {
    let Some(ref pf) = args.paths_file else {
        return Ok(vec![args.url.clone()]);
    };
    let body = std::fs::read_to_string(pf).map_err(|e| format!("read {pf}: {e}"))?;
    let base = args.url.trim_end_matches('/');
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let url = if line.starts_with("http://") || line.starts_with("https://") {
            line.to_string()
        } else if line.starts_with('/') {
            format!("{base}{line}")
        } else {
            format!("{base}/{line}")
        };
        out.push(url);
    }
    if out.is_empty() {
        return Err(format!(
            "{pf} contained no non-empty / non-comment lines — nothing to probe"
        ));
    }
    Ok(out)
}

/// Probe a single URL through the full bypass set. Concurrency is
/// bounded by `concurrency` (a `Semaphore` is acquired before each
/// probe and released as soon as the response lands).
async fn probe_one_url(
    client: &Client,
    url: &str,
    args: &BypassProbeArgs,
    concurrency: usize,
) -> Result<UrlReport, String> {
    let parsed_path = parse_path_from_url(url);

    // Baseline. Even with concurrency we always do this first
    // sequentially — the rest of the run depends on it.
    let baseline = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("baseline GET {url} failed: {e}")),
    };
    let baseline_status = baseline.status().as_u16();
    let baseline_body = baseline.bytes().await.unwrap_or_default();
    let baseline_len = baseline_body.len();

    if !args.quiet {
        eprintln!("baseline: GET {url} → HTTP {baseline_status}, {baseline_len} bytes");
    }

    // Build the full probe list as `(family, ProbeKind)` so we can
    // run them all through a single bounded-concurrency loop. Order
    // doesn't matter for correctness; results are sorted at the end.
    let mut work: Vec<ProbeJob> = Vec::new();

    if !args.skip_headers {
        for p in wafrift_encoding::auth_bypass::auth_bypass_probes(&parsed_path) {
            work.push(ProbeJob::Header(p));
        }
    }
    if !args.skip_paths {
        let synthetic = if wafrift_grammar::grammar::path_traversal::detect_type(&parsed_path) {
            parsed_path.clone()
        } else {
            format!("../../{}", parsed_path.trim_start_matches('/'))
        };
        for v in wafrift_grammar::grammar::path_traversal::mutate(&synthetic) {
            work.push(ProbeJob::Path(v));
        }
    }
    if !args.skip_methods {
        for m in [
            "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "PROPFIND",
        ] {
            work.push(ProbeJob::Method(m.to_string()));
        }
    }

    if !args.quiet {
        eprintln!(
            "firing {} probes (concurrency={concurrency}, delay={}ms)",
            work.len(),
            args.delay_ms
        );
    }

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let delay_ms = args.delay_ms;
    let body_thresh = args.body_diff_threshold_pct;
    let url_owned = url.to_string();
    let base_origin = url.split('/').take(3).collect::<Vec<_>>().join("/");

    let mut handles = Vec::with_capacity(work.len());
    for job in work {
        let sem_c = sem.clone();
        let client_c = client.clone();
        let url_c = url_owned.clone();
        let base_origin_c = base_origin.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire_owned().await.ok()?;
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            run_probe_job(
                &client_c,
                &url_c,
                &base_origin_c,
                job,
                baseline_status,
                baseline_len,
                body_thresh,
            )
            .await
        }));
    }

    let mut divergences = Vec::new();
    for h in handles {
        if let Ok(Some(div)) = h.await {
            divergences.push(div);
        }
    }

    divergences.sort_by(|a, b| {
        let a_status_change = a.probe_status != a.baseline_status;
        let b_status_change = b.probe_status != b.baseline_status;
        b_status_change
            .cmp(&a_status_change)
            .then_with(|| severity_rank(b.severity).cmp(&severity_rank(a.severity)))
            .then_with(|| b.body_delta_pct.abs().total_cmp(&a.body_delta_pct.abs()))
    });

    Ok(UrlReport {
        target: url.to_string(),
        baseline_status,
        baseline_body_len: baseline_len,
        divergences,
    })
}

#[derive(Debug)]
enum ProbeJob {
    Header(wafrift_encoding::auth_bypass::AuthBypassProbe),
    Path(String),
    Method(String),
}

async fn run_probe_job(
    client: &Client,
    url: &str,
    base_origin: &str,
    job: ProbeJob,
    baseline_status: u16,
    baseline_len: usize,
    body_thresh: f64,
) -> Option<Divergence> {
    match job {
        ProbeJob::Header(probe) => {
            let resp = client
                .get(url)
                .header(probe.header.clone(), probe.value.clone())
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            classify(
                "headers",
                probe.label,
                &format!(
                    "{} (header `{}: {}`)",
                    probe.description, probe.header, probe.value
                ),
                baseline_status,
                baseline_len,
                status,
                body.len(),
                body_thresh,
                || format!("curl -s -H '{}: {}' '{url}'", probe.header, probe.value),
            )
        }
        ProbeJob::Path(v) => {
            let probe_url = if v.starts_with("http://") || v.starts_with("https://") {
                v.clone()
            } else if v.starts_with('/') {
                format!("{base_origin}{v}")
            } else {
                format!("{base_origin}/{v}")
            };
            let resp = client.get(&probe_url).send().await.ok()?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            classify(
                "paths",
                "path-routing",
                &format!("path-routing variant `{v}`"),
                baseline_status,
                baseline_len,
                status,
                body.len(),
                body_thresh,
                || format!("curl -s '{probe_url}'"),
            )
        }
        ProbeJob::Method(m) => {
            let method = Method::from_str(&m).ok()?;
            let resp = client.request(method, url).send().await.ok()?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();
            classify(
                "methods",
                &m,
                &format!("HTTP {m} method override"),
                baseline_status,
                baseline_len,
                status,
                body.len(),
                body_thresh,
                || format!("curl -s -X {m} '{url}'"),
            )
        }
    }
}

fn print_report_text(r: &UrlReport) {
    println!();
    println!("=== bypass-probe results: {} ===", r.target);
    println!(
        "baseline:  HTTP {} ({} bytes)",
        r.baseline_status, r.baseline_body_len
    );
    if r.divergences.is_empty() {
        println!("no divergences — every probe matched the baseline.");
    } else {
        println!(
            "{} divergences (sorted by interestingness):",
            r.divergences.len()
        );
        println!();
        for d in &r.divergences {
            println!(
                "[{}] {}  HTTP {}→{}  body Δ {:+.1}%",
                d.severity, d.family, d.baseline_status, d.probe_status, d.body_delta_pct
            );
            println!("    {}", d.description);
            println!("    repro: {}", d.curl_cmd);
            println!();
        }
    }
}

/// Numeric rank for severity strings — used for sorting and for
/// `--min-severity` filtering. Unknown strings rank as 0 (always
/// included).
fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Decide whether a probe's response is meaningfully different from
/// the baseline, and if so build a `Divergence` describing it.
#[allow(clippy::too_many_arguments)]
fn classify(
    family: &'static str,
    label: &str,
    description: &str,
    baseline_status: u16,
    baseline_len: usize,
    probe_status: u16,
    probe_len: usize,
    body_threshold_pct: f64,
    curl_fn: impl FnOnce() -> String,
) -> Option<Divergence> {
    let status_changed = probe_status != baseline_status;
    let body_delta = if baseline_len == 0 {
        if probe_len == 0 { 0.0 } else { 100.0 }
    } else {
        ((probe_len as f64 - baseline_len as f64) / baseline_len as f64) * 100.0
    };
    let body_changed = body_delta.abs() >= body_threshold_pct;

    if !status_changed && !body_changed {
        return None;
    }

    // Severity heuristic:
    //   - HIGH: was 401/403, now 200/302. Real access bypass.
    //   - MEDIUM: status flipped some other way, or body grew significantly.
    //   - LOW: body shrank or method-override returned the same status.
    let severity = if matches!(baseline_status, 401 | 403)
        && matches!(probe_status, 200 | 201 | 202 | 204 | 301 | 302)
    {
        "HIGH"
    } else if (status_changed && (200..400).contains(&probe_status))
        || (body_changed && body_delta > 0.0)
    {
        "MEDIUM"
    } else {
        "LOW"
    };

    Some(Divergence {
        family: family.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        baseline_status,
        probe_status,
        body_delta_pct: body_delta,
        curl_cmd: curl_fn(),
        severity,
    })
}

/// Pull the path component out of a URL for the auth-bypass probe set.
fn parse_path_from_url(url: &str) -> String {
    if let Some(after_scheme) = url.split_once("://") {
        let rest = after_scheme.1;
        if let Some(slash) = rest.find('/') {
            return rest[slash..].to_string();
        }
        return "/".to_string();
    }
    if url.starts_with('/') {
        return url.to_string();
    }
    "/".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_path_from_full_url() {
        assert_eq!(parse_path_from_url("https://example.com/admin"), "/admin");
        assert_eq!(parse_path_from_url("http://x:8080/a/b?q=1"), "/a/b?q=1");
        assert_eq!(parse_path_from_url("https://example.com/"), "/");
        assert_eq!(parse_path_from_url("https://example.com"), "/");
    }

    #[test]
    fn classify_status_unchanged_below_threshold_returns_none() {
        let d = classify(
            "headers",
            "x",
            "y",
            200,
            1000,
            200,
            1050, // 5% delta
            10.0,
            || "curl".to_string(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn classify_403_to_200_is_high_severity() {
        let d = classify("headers", "x", "y", 403, 500, 200, 500, 10.0, || {
            "curl".to_string()
        })
        .expect("must fire");
        assert_eq!(d.severity, "HIGH");
    }

    #[test]
    fn classify_body_growth_flags_medium() {
        let d = classify(
            "paths",
            "x",
            "y",
            403,
            100,
            403,
            500, // 400% growth, status unchanged
            10.0,
            || "curl".to_string(),
        )
        .expect("must fire");
        assert_eq!(d.severity, "MEDIUM");
    }

    #[test]
    fn classify_baseline_zero_body_then_content_returns_100pct() {
        let d = classify("paths", "x", "y", 403, 0, 403, 500, 10.0, || {
            "curl".to_string()
        })
        .expect("must fire");
        assert!((d.body_delta_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn classify_unchanged_returns_none() {
        let d = classify("methods", "POST", "test", 403, 500, 403, 500, 10.0, || {
            "curl".to_string()
        });
        assert!(d.is_none());
    }
}
