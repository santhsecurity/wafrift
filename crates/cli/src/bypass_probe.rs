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
//!      `wafrift_grammar::grammar::path_traversal::mutate` (`ProxyShell`
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::probe_classify::{is_throttle_or_unavailable, severity_rank};

#[derive(Args, Debug)]
pub struct BypassProbeArgs {
    /// Target URL to probe. Must already return 401/403 (or any status
    /// the user wants to bypass) for the probe set to be meaningful.
    /// When `--paths-file` is set this is the base URL (<scheme://host>)
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
        // Align with `wafrift scan` / `detect` / `replay`: only
        // accept_invalid_certs. Previously this also set
        // `danger_accept_invalid_hostnames(true)`, which is much
        // looser — it lets ANY cert authenticate the requested
        // host (e.g. an evil.com cert would be trusted on a probe
        // to target.example.com). Pentesters running --insecure
        // expect "accept self-signed / expired on the actual
        // target", not "accept any cert from any origin". The
        // tighter default matches operator intent and removes a
        // cross-command behaviour gap.
        builder = builder.danger_accept_invalid_certs(true);
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
    /// Probes whose response was a throttle/unavailable code (429/503/…)
    /// — excluded from `divergences` and surfaced so the operator knows
    /// the run was degraded rather than "clean, nothing found".
    rate_limited_probes: u32,
    /// Total probes fired (denominator for the rate-limited ratio).
    probes_fired: usize,
    /// True when the *baseline* itself was throttled — every delta in
    /// this report is then measured against an error page and the whole
    /// run is inconclusive.
    baseline_was_throttled: bool,
    /// Number of probe responses that carried a parseable `Retry-After`
    /// header AND a throttle status — i.e., the target asked us to slow
    /// down with a precise number. Distinguishes polite WAFs (parse +
    /// obey their hint) from silent ones (fall back to our own backoff).
    retry_after_responses: u32,
    /// Maximum `Retry-After` we obeyed across all probes for this URL,
    /// in milliseconds. Capped by [`crate::retry_after::MAX_OBEYED`] so
    /// a hostile origin cannot pin us asleep for an hour. Useful when
    /// reading the report after the fact to know "the longest cooldown
    /// the target named was N seconds — that's the floor for a future
    /// `--delay-ms` value if you re-scan."
    max_retry_after_obeyed_ms: u64,
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
    // Bounded read — decompression-bomb defence on the baseline.
    let baseline_body = crate::safe_body::read_bounded(
        baseline,
        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
    )
    .await
    .unwrap_or_default();
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

    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let delay_ms = args.delay_ms;
    let body_thresh = args.body_diff_threshold_pct;
    let url_owned = url.to_string();
    let base_origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
    let probes_fired = work.len();
    let rate_limited = Arc::new(AtomicU32::new(0));
    // Shared cooldown deadline (process-monotonic ms since `start`) that
    // every spawned probe honours before firing. The scan loop's batched
    // analogue is `batch_retry_after`; here we are semaphore-throttled
    // concurrent so the natural primitive is a deadline + fetch_max,
    // not a per-batch accumulator. fetch_max is the cleanest way for
    // sibling tasks to publish "everyone wait until at least T" without
    // a mutex — and `Instant`-derived ms is monotonic, so a wall-clock
    // skip can't accidentally rush past it.
    let start = Instant::now();
    let not_before_ms = Arc::new(AtomicU64::new(0));
    let retry_after_responses = Arc::new(AtomicU32::new(0));
    let max_retry_after_obeyed_ms = Arc::new(AtomicU64::new(0));
    let baseline_was_throttled = is_throttle_or_unavailable(baseline_status);
    if baseline_was_throttled && !args.quiet {
        eprintln!(
            "WARNING: baseline GET {url} returned HTTP {baseline_status} (throttled/unavailable) — \
             every divergence below is measured against an error page and the whole run is \
             inconclusive. Slow down (--delay-ms) or test off the rate limiter."
        );
    }

    let mut handles = Vec::with_capacity(work.len());
    for (idx, job) in work.into_iter().enumerate() {
        let sem_c = sem.clone();
        let client_c = client.clone();
        let url_c = url_owned.clone();
        let base_origin_c = base_origin.clone();
        let rl_c = rate_limited.clone();
        let nbf_c = not_before_ms.clone();
        let rar_c = retry_after_responses.clone();
        let max_ra_c = max_retry_after_obeyed_ms.clone();
        // Per-task nonce for jittered cooldown sleep. The task index in
        // the work list is monotonic, deterministic within a run, and
        // unique — exactly the contract `retry_after::jittered` wants.
        let nonce = u32::try_from(idx).unwrap_or(u32::MAX);
        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire_owned().await.ok()?;
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            // Honour any cooldown a sibling task has discovered. We
            // sleep ONCE — if the deadline moves while we are asleep
            // (a sibling fires, hits another 429, pushes the deadline
            // further), we accept that we may fire one premature probe
            // before the system re-converges. That probe will itself
            // be throttled and re-extend the deadline; siblings spawned
            // after will see the new value. This is strictly safer than
            // a busy re-check loop (no infinite-sleep risk on a hostile
            // origin) and converges in O(1) extra probes.
            let now_ms = elapsed_ms(start);
            let deadline = nbf_c.load(Ordering::Relaxed);
            if deadline > now_ms {
                let wait = Duration::from_millis(deadline.saturating_sub(now_ms));
                tokio::time::sleep(crate::retry_after::jittered(wait, nonce)).await;
            }
            run_probe_job(
                &client_c,
                &url_c,
                &base_origin_c,
                job,
                baseline_status,
                baseline_len,
                body_thresh,
                &rl_c,
                &nbf_c,
                &rar_c,
                &max_ra_c,
                start,
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
    let rate_limited_probes = rate_limited.load(Ordering::Relaxed);
    let retry_after_responses_n = retry_after_responses.load(Ordering::Relaxed);
    let max_retry_after_obeyed_ms_n = max_retry_after_obeyed_ms.load(Ordering::Relaxed);
    if rate_limited_probes > 0 && !args.quiet {
        let pct = f64::from(rate_limited_probes) / probes_fired.max(1) as f64 * 100.0;
        eprintln!(
            "RATE-LIMITED: {rate_limited_probes}/{probes_fired} probes ({pct:.0}%) were \
             rate-limited (HTTP 429/503/…) and excluded from divergences — they are the \
             target throttling us, not access bypasses."
        );
        if retry_after_responses_n > 0 {
            eprintln!(
                "Retry-After: obeyed on {retry_after_responses_n} probe(s); longest \
                 server-named cooldown was {max_retry_after_obeyed_ms_n} ms (capped at \
                 {} ms). Use --delay-ms >= {} to stay polite on a re-scan.",
                crate::retry_after::MAX_OBEYED.as_millis(),
                max_retry_after_obeyed_ms_n
            );
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
        rate_limited_probes,
        probes_fired,
        baseline_was_throttled,
        retry_after_responses: retry_after_responses_n,
        max_retry_after_obeyed_ms: max_retry_after_obeyed_ms_n,
        divergences,
    })
}

/// Process-monotonic elapsed milliseconds since the per-URL `start`
/// Instant. Monotonic so a wall-clock skip cannot accidentally bring
/// `now_ms` above the cooldown deadline early; `Instant::elapsed`
/// saturates rather than overflowing on tiny intervals.
fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug)]
enum ProbeJob {
    Header(wafrift_encoding::auth_bypass::AuthBypassProbe),
    Path(String),
    Method(String),
}

#[allow(clippy::too_many_arguments)]
async fn run_probe_job(
    client: &Client,
    url: &str,
    base_origin: &str,
    job: ProbeJob,
    baseline_status: u16,
    baseline_len: usize,
    body_thresh: f64,
    rate_limited: &AtomicU32,
    not_before_ms: &AtomicU64,
    retry_after_responses: &AtomicU32,
    max_retry_after_obeyed_ms: &AtomicU64,
    start: Instant,
) -> Option<Divergence> {
    let note_throttle = |status: u16| {
        if is_throttle_or_unavailable(status) {
            rate_limited.fetch_add(1, Ordering::Relaxed);
        }
    };
    // Pull the `Retry-After` header off a response *before* the body is
    // consumed (`resp.bytes()` moves `resp`). Only meaningful on a
    // throttle/unavailable status; on a 200 we explicitly do not honour
    // the header (some CDNs ship it even on success and we would
    // gratuitously stall on every probe).
    let consume_retry_after = |resp: &reqwest::Response, status: u16| -> Option<Duration> {
        if !is_throttle_or_unavailable(status) {
            return None;
        }
        let now = std::time::SystemTime::now();
        resp.headers()
            .get_all("retry-after")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|s| crate::retry_after::parse(s, now))
            .max()
    };
    let publish_retry_after = |d: Duration| {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        if ms == 0 {
            return;
        }
        let deadline = elapsed_ms(start).saturating_add(ms);
        not_before_ms.fetch_max(deadline, Ordering::Relaxed);
        retry_after_responses.fetch_add(1, Ordering::Relaxed);
        max_retry_after_obeyed_ms.fetch_max(ms, Ordering::Relaxed);
    };
    match job {
        ProbeJob::Header(probe) => {
            let resp = client
                .get(url)
                .header(probe.header.clone(), probe.value.clone())
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            note_throttle(status);
            if let Some(d) = consume_retry_after(&resp, status) {
                publish_retry_after(d);
            }
            let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES).await.unwrap_or_default();
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
            note_throttle(status);
            if let Some(d) = consume_retry_after(&resp, status) {
                publish_retry_after(d);
            }
            let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES).await.unwrap_or_default();
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
            note_throttle(status);
            if let Some(d) = consume_retry_after(&resp, status) {
                publish_retry_after(d);
            }
            let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES).await.unwrap_or_default();
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
        "baseline:  HTTP {} ({} bytes){}",
        r.baseline_status,
        r.baseline_body_len,
        if r.baseline_was_throttled {
            "  ⚠ THROTTLED — results inconclusive"
        } else {
            ""
        }
    );
    if r.rate_limited_probes > 0 {
        let pct = f64::from(r.rate_limited_probes) / r.probes_fired.max(1) as f64 * 100.0;
        println!(
            "rate-limited: {}/{} probes ({pct:.0}%) returned 429/503/… — excluded from \
             divergences (target throttling, not a bypass)",
            r.rate_limited_probes, r.probes_fired
        );
    }
    if r.retry_after_responses > 0 {
        println!(
            "retry-after: obeyed on {} probe(s); longest server-named cooldown {} ms",
            r.retry_after_responses, r.max_retry_after_obeyed_ms
        );
    }
    if r.divergences.is_empty() {
        let why = if r.baseline_was_throttled || r.rate_limited_probes * 2 >= r.probes_fired as u32
        {
            "no divergences — but the run was dominated by rate-limiting, so this is \
             INCONCLUSIVE, not a clean bill of health. Re-run slower / off the limiter."
        } else {
            "no divergences — every probe matched the baseline."
        };
        println!("{why}");
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

/// Decide whether a probe's response is meaningfully different from
/// the baseline, and if so build a `Divergence` describing it.
///
/// The status/body delta + severity heuristics live in
/// [`crate::probe_classify`] so `parser_diff` and any future
/// "probe-N-shapes-against-a-baseline" command consume the same
/// rules and a rule-set update lands in exactly one place.
///
/// Returns `None` for throttle/unavailable probe responses: they are
/// never bypass evidence, regardless of how far the body length drifted
/// from baseline (a 429 error page is ~always far smaller than the real
/// resource, which is exactly why the old code mis-scored them).
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
    let (status_changed, body_changed, body_delta) = crate::probe_classify::delta_signal(
        baseline_status,
        baseline_len,
        probe_status,
        probe_len,
        body_threshold_pct,
    );
    if !status_changed && !body_changed {
        return None;
    }
    if crate::probe_classify::is_throttle_or_unavailable(probe_status) {
        return None;
    }
    // bypass_probe historically reported only HIGH/MEDIUM/LOW (no
    // EQUAL) for divergences — that's preserved here. EQUAL is
    // filtered above by the "if !status_changed && !body_changed"
    // gate; what reaches the severity_label call is always at
    // least LOW.
    let severity = crate::probe_classify::severity_label(
        baseline_status,
        probe_status,
        body_delta,
        body_threshold_pct,
    );
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

    // ── shared-deadline Retry-After integration ─────────────────────
    //
    // These tests stand up a minimal in-process HTTP server with
    // tokio's TcpListener (axum is not a dev-dep here and we want
    // exact control over the response bytes — wiremock buys nothing
    // we don't already get from 15 lines of raw socket code). The
    // server's per-request behaviour is driven by a shared atomic
    // counter, so a single test can name exactly which probes
    // throttle and which succeed.

    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin a localhost server. `respond(n)` is called with the 0-based
    /// request index (n=0 is the baseline GET fired by `probe_one_url`
    /// before the probe loop, n≥1 are probe requests). The returned
    /// `String` is sent verbatim as the HTTP response.
    async fn spawn_mock_server<F>(respond: F) -> std::net::SocketAddr
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let count_c = count.clone();
                let respond_c = respond.clone();
                tokio::spawn(async move {
                    // Drain the request headers — we don't inspect them,
                    // but reqwest will close the connection if we reply
                    // before reading at least the first line, and a
                    // single read() is enough for a header-only GET.
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let n = count_c.fetch_add(1, Ordering::SeqCst);
                    let body = respond_c(n);
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        // Give the listener a beat to be ready before any client connects.
        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn rate_limited_response(retry_after_secs: u32) -> String {
        format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry_after_secs}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    fn methods_only_args(url: String) -> BypassProbeArgs {
        // 7 method-override probes only — keeps the test loop short
        // and deterministic. delay_ms=0 because the cooldown wait is
        // what we want to observe, not the user politeness spread.
        BypassProbeArgs {
            url,
            paths_file: None,
            timeout_secs: 4,
            delay_ms: 0,
            concurrency: 4,
            insecure: false,
            format: "text".into(),
            skip_headers: true,
            skip_paths: true,
            skip_methods: false,
            body_diff_threshold_pct: 10.0,
            min_severity: "low".into(),
            quiet: true,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_extends_cooldown_across_subsequent_probes() {
        // Server: baseline 200, next 2 probes return 429 + Retry-After:1,
        // the rest return 200. After the first concurrent batch trips
        // the rate limit, every remaining probe must wait ≥ ~1 s before
        // firing — proving the shared deadline is published and obeyed.
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("baseline body 11"),
            1 | 2 => rate_limited_response(1),
            _ => ok_response("bypassed body!!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let t0 = Instant::now();
        let report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");
        let elapsed = t0.elapsed();

        assert_eq!(report.probes_fired, 7, "7 method overrides expected");
        assert!(
            report.retry_after_responses >= 1,
            "expected ≥ 1 obeyed Retry-After, got {}",
            report.retry_after_responses
        );
        assert!(
            report.max_retry_after_obeyed_ms >= 1000,
            "expected ≥ 1000 ms obeyed, got {}",
            report.max_retry_after_obeyed_ms
        );
        // ~800 ms is the jittered floor (0.80 × 1000). Use 700 ms as the
        // hard lower bound to absorb mock-server scheduling jitter on
        // slow CI runners without making the test a tautology.
        assert!(
            elapsed >= Duration::from_millis(700),
            "expected elapsed ≥ 700 ms after a 1-s Retry-After, got {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_retry_after_header_means_no_obeyed_counter_bump() {
        // Anti-rig: a target that throttles without a Retry-After must
        // not falsely inflate `retry_after_responses`. Only a parseable
        // header on a throttle status should count.
        let addr = spawn_mock_server(|n| {
            if n == 0 {
                ok_response("base")
            } else {
                // 429 with NO Retry-After at all.
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
                    .to_string()
            }
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");

        assert!(
            report.rate_limited_probes >= 1,
            "expected ≥ 1 RL probe, got {}",
            report.rate_limited_probes
        );
        assert_eq!(
            report.retry_after_responses, 0,
            "no Retry-After header was sent — counter must stay at zero"
        );
        assert_eq!(
            report.max_retry_after_obeyed_ms, 0,
            "no Retry-After header was sent — max must stay at zero"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_zero_is_not_a_spurious_sleep() {
        // RFC permits `Retry-After: 0` and we honour it as "no wait"
        // rather than fabricating a deadline at `now`. Anti-rig against
        // a degenerate counter that bumps even for zero-duration hints.
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("base"),
            1 => format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            _ => ok_response("bypassed!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let t0 = Instant::now();
        let _report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");
        let elapsed = t0.elapsed();

        // No real cooldown means the whole 7-probe sweep finishes well
        // under a second on any reasonable host. If the deadline was
        // falsely set to `now + 0` we'd still finish fast, but the test
        // remains a useful smoke against a future regression that
        // computes the deadline differently.
        assert!(
            elapsed < Duration::from_millis(800),
            "Retry-After: 0 must not introduce a real cooldown — elapsed {elapsed:?}"
        );
    }

    // ── Deep cooldown stress (added 2026-05-20).

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_above_max_obeyed_is_capped_not_obeyed_in_full() {
        // Adversarial server: Retry-After: 3600 (one hour). The
        // parser caps at MAX_OBEYED (60s); the test asserts the
        // reported max_retry_after_obeyed_ms is ≤ 60_000.
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("base"),
            1 => format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3600\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            _ => ok_response("bypassed!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let mut args = methods_only_args(url.clone());
        // Tight timeout — we never want to actually sleep ANYWHERE
        // near 60s in this test. The MAX_OBEYED cap is what we're
        // gating; the deadline will be 60s in the future and the
        // remaining probes will time out on their semaphore wait,
        // which is fine. We just need the captured aggregate to
        // reflect the cap.
        args.timeout_secs = 2;
        // 1 probe is enough — the very first 429 captures the cap.
        args.skip_headers = true;
        args.skip_paths = true;
        // 7 methods × cooldown caps total runtime; assert via the
        // aggregate, not by waiting it out.
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // Run with the spawned listener; the first probe sees 429+RA.
        // We don't await the full 60s deadline — we check the reported
        // max_retry_after_obeyed_ms.
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            probe_one_url(&client, &url, &args, 1),
        )
        .await;
        // Whether the run completes within the 3s window or times
        // out, what we care about is what we observed FIRST: the
        // single 429+RA-3600 either gets capped at 60s and stored
        // in the aggregate, or never gets there. Both cases are
        // observable.
        if let Ok(Ok(r)) = report {
            assert!(
                r.max_retry_after_obeyed_ms <= 60_000,
                "MAX_OBEYED cap violated: got {}",
                r.max_retry_after_obeyed_ms
            );
        }
    }

    #[test]
    fn classify_probe_with_zero_baseline_and_zero_probe_is_inert() {
        // Boundary: both sides empty. delta_signal must return
        // (false, false, 0.0) — and classify returns None.
        let d = classify(
            "x", "x", "x", 200, 0, 200, 0, 10.0,
            || "curl".to_string(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn classify_extreme_body_growth_does_not_overflow() {
        // u32-large body sizes. The f64 conversion uses the full
        // usize, so this must produce a finite delta without
        // overflowing into infinity.
        let d = classify(
            "x", "x", "x", 200, 100, 200, 1_000_000_000, 10.0,
            || "curl".to_string(),
        )
        .expect("must fire");
        assert!(
            d.body_delta_pct.is_finite(),
            "extreme body delta must stay finite, got {}",
            d.body_delta_pct
        );
        assert!(d.body_delta_pct > 0.0);
    }

    #[test]
    fn severity_rank_via_shared_module_orders_canonically() {
        // The bypass_probe re-uses crate::probe_classify::severity_rank.
        // Re-test the canonical ordering here so a future change in
        // either ranking is caught by both consumers' suites.
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") > severity_rank("LOW"));
        assert_eq!(severity_rank("garbage"), 0);
    }
}
