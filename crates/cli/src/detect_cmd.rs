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
use wafrift_detect::dns_fingerprint::{CnameRuleEngine, DnsProbe};
use wafrift_detect::waf_detect;

use crate::helpers::parse_headers;

#[derive(clap::Args, Debug)]
pub struct DetectArgs {
    /// Target URL to detect against, as the FIRST positional argument
    /// — matches every other wafrift subcommand
    /// (`wafrift scan <URL>`, `wafrift header-diff <URL>`, etc.)
    /// so operator muscle memory works across the toolkit.
    /// Equivalent to `--url <URL>`; pass either form, not both.
    #[arg(value_name = "URL", conflicts_with_all = ["url", "status", "headers"])]
    pub url_positional: Option<String>,

    /// Fetch the target URL directly and run detection on the live
    /// response — no manual `curl` + `--status`/`--headers` round-trip.
    /// `wafrift detect --url https://target.com`. Mutually exclusive
    /// with `--status`/`--headers` and the positional form above.
    /// Kept on equal footing for backwards-compatibility.
    #[arg(long, conflicts_with_all = ["status", "headers", "url_positional"])]
    pub url: Option<String>,

    /// HTTP status code (100–599). Required unless a URL is given
    /// (either positional or via `--url`).
    #[arg(long, value_parser = parse_http_status, required_unless_present_any = ["url", "url_positional"])]
    pub status: Option<u16>,

    /// Repeated "key: value" header arguments. Required unless a URL
    /// is given (either positional or via `--url`).
    #[arg(long, required_unless_present_any = ["url", "url_positional"])]
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

    /// With `--url`: also fire a SECOND probe with an obvious SQLi
    /// payload and compare the responses. When the server header
    /// differs, status flips, or body length swings >50%, that's
    /// strong evidence of a WAF in "block but don't fingerprint"
    /// mode (e.g. ModSec returning Apache's generic 403, or any
    /// WAF that strips its own block-page markers). Off by default
    /// because it sends a real attack-shaped string — only enable
    /// against targets you own / are authorized to test.
    #[arg(long, default_value_t = false)]
    pub differential: bool,

    /// Output format: `text` (default, colored summary) or `json`
    /// (machine-readable; downstream tools can parse the detected
    /// WAF name + confidence + indicators).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

impl DetectArgs {
    /// Resolved target URL: prefers the positional form (modern,
    /// matches every other wafrift cmd) and falls back to the long
    /// `--url` flag (backwards-compatible). `None` when the operator
    /// supplied the `--status` / `--headers` triple instead.
    #[must_use]
    pub fn resolved_url(&self) -> Option<&str> {
        self.url_positional.as_deref().or(self.url.as_deref())
    }
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
    // Shared floor via base_client_builder + caller-owned redirect
    // policy (intentionally `none()` so detect sees redirects as
    // signals, not as transparent next-hops to follow).
    let ua = crate::config::shared_user_agent();
    let client =
        wafrift_transport::base_client_builder(timeout_secs.clamp(1, 120), insecure, Some(&ua))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start tokio runtime: {e}"))?;
    rt.block_on(async move {
        let resp = client.get(url).send().await.map_err(|e| {
            // reqwest::Error's Display often shows only "error
            // sending request" without the underlying DNS / TCP cause.
            // walk_reqwest_error (helpers.rs) surfaces the full chain
            // (NXDOMAIN, connection refused, TLS, etc.).
            format!(
                "request to {url} failed: {}",
                crate::helpers::walk_reqwest_error(&e)
            )
        })?;
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
        // Cap the body read against decompression bombs — reqwest
        // ships gzip/brotli features and auto-decodes Content-Encoding,
        // so a 1 KB gzip bomb expanding to 100 GB would OOM the CLI
        // before reaching .bytes().await. The bounded stream reader
        // aborts AS SOON as the cap is exceeded; we then truncate to
        // the detection corpus's expected upper bound (64 KiB).
        let bytes = match crate::safe_body::read_bounded(
            resp,
            crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => return Err(format!("read body: {e}")),
        };
        let body = bytes[..bytes.len().min(64 * 1024)].to_vec();
        Ok((status, headers, body))
    })
}

/// Extract the bare host (no scheme, port, path, fragment, or query)
/// from a URL string.  Used by `fetch_cname_chain`.
///
/// Thin wrapper around [`wafrift_transport::host_from_url`] — the
/// shared canonical impl (4 sites collapsed). Returns an owned String
/// because the upstream helper lowercases the host, so a borrowed
/// `&str` into the input would carry the wrong case for callers that
/// compare against DNS names.
pub(crate) fn host_from_url(url: &str) -> Option<String> {
    wafrift_transport::host_from_url(url)
}

/// Resolve a URL's CNAME chain to a `DnsProbe`.  Synchronous wrapper
/// around the async resolver — builds a one-shot tokio runtime so
/// the rest of `run_detect` can stay synchronous and easy to read.
/// Returns `None` on any error (resolver init, timeout, NXDOMAIN);
/// callers fall back to header-only detection.  We log the failure
/// via `tracing::debug!` so dogfooding can pin down WHY DNS dropped
/// out without making the CLI noisy by default. Resolves through
/// `tracing::debug!` (under the `wafrift::detect` target) — the
/// CLI's `tracing-subscriber` is wired with an `EnvFilter` so
/// `RUST_LOG=wafrift=debug` surfaces the failure detail.
pub(crate) fn fetch_cname_chain(url: &str) -> Option<DnsProbe> {
    let host = host_from_url(url)?;
    // Multi-thread runtime with two workers because hickory-resolver
    // spawns its background task for the UDP socket and a separate
    // task for the response decoder; on a current-thread runtime
    // those two tasks compete for the same scheduler slot and we
    // see frequent timeouts under cold-start conditions.  Two
    // workers eliminate the contention without measurable cost.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .ok()?;
    match rt.block_on(wafrift_detect::probe_cname_chain(&host)) {
        Ok(probe) => Some(probe),
        Err(e) => {
            // Tracing-subscriber is initialised in main() with
            // EnvFilter — `RUST_LOG=wafrift=debug` surfaces this
            // line, default `warn` filter hides it. Pre-fix the
            // doc comment promised `tracing::debug!` but the code
            // used a hand-rolled RUST_LOG-env check + eprintln; the
            // structured form is consistent with the rest of the
            // CLI's instrumentation (sonnet 5 pass).
            tracing::debug!(
                target: "wafrift::detect",
                host = %host,
                error = %e,
                "DNS CNAME probe failed"
            );
            None
        }
    }
}

/// Evidence of a WAF inferred from differential probing — a benign
/// GET vs a SQLi-payload GET produced significantly different
/// responses, which is strong WAF presence signal even when no rule
/// in the 160+ corpus matched. Surfaced under "differential
/// detection" in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DifferentialEvidence {
    /// Status of the benign baseline.
    pub baseline_status: u16,
    /// Status of the attack probe.
    pub attack_status: u16,
    /// Server header on benign (e.g. "gunicorn/19.9.0").
    pub baseline_server: String,
    /// Server header on attack (e.g. "Apache" — different stack
    /// answering means a WAF intercepted).
    pub attack_server: String,
    /// Body length on benign.
    pub baseline_body_len: usize,
    /// Body length on attack.
    pub attack_body_len: usize,
    /// Specific reasons the differential classifier flagged.
    pub reasons: Vec<String>,
}

/// Compare a benign-probe response with an attack-probe response.
/// Returns `Some(evidence)` when the differences are strong enough
/// to infer a WAF is intercepting, `None` otherwise. Pure function
/// — no I/O, fully testable on synthetic inputs.
#[must_use]
pub fn classify_differential(
    baseline_status: u16,
    baseline_headers: &[(String, String)],
    baseline_body_len: usize,
    attack_status: u16,
    attack_headers: &[(String, String)],
    attack_body_len: usize,
) -> Option<DifferentialEvidence> {
    fn server_of(h: &[(String, String)]) -> String {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
    let baseline_server = server_of(baseline_headers);
    let attack_server = server_of(attack_headers);

    let mut reasons: Vec<String> = Vec::new();
    // 1. Status flip: benign 200 vs attack 403/406/429/501/etc.
    if baseline_status != attack_status {
        reasons.push(format!(
            "status flipped {baseline_status} → {attack_status}"
        ));
    }
    // 2. Server-header change: different proxy answering attacks
    // = a WAF is intercepting (the typical Apache+ModSec in front
    // of gunicorn pattern lives here).
    if !baseline_server.is_empty()
        && !attack_server.is_empty()
        && !baseline_server.eq_ignore_ascii_case(&attack_server)
    {
        reasons.push(format!(
            "server header changed: '{baseline_server}' → '{attack_server}'"
        ));
    }
    // 3. Body length swing > 50%. The threshold is generous —
    // small differences (different timestamps, request IDs) don't
    // count; a swing from 1 KB origin response to 200-byte block
    // page does.
    if baseline_body_len > 0 {
        let larger = baseline_body_len.max(attack_body_len);
        let smaller = baseline_body_len.min(attack_body_len);
        let pct_diff = ((larger - smaller) as f64 / baseline_body_len as f64) * 100.0;
        if pct_diff >= 50.0 {
            reasons.push(format!(
                "body length swung {pct_diff:.0}% ({baseline_body_len} → {attack_body_len} bytes)"
            ));
        }
    } else if attack_body_len > 0 {
        // Benign returned an empty body; attack returned content.
        // Unusual on its own; combined with other signals it's
        // meaningful.
        reasons.push(format!(
            "attack response had {attack_body_len} bytes vs empty baseline"
        ));
    }

    if reasons.is_empty() {
        None
    } else {
        Some(DifferentialEvidence {
            baseline_status,
            attack_status,
            baseline_server,
            attack_server,
            baseline_body_len,
            attack_body_len,
            reasons,
        })
    }
}

/// Inject a canonical SQLi probe into the `q` query parameter of a
/// URL, preserving fragment placement. Naive `?q=...` concatenation
/// breaks for fragmented URLs (`https://t/p#sec`) because the `?`
/// would land INSIDE the fragment, and the query never reaches the
/// server. Splits the fragment first, mutates the URL portion, then
/// re-attaches the fragment. Pure / testable.
#[must_use]
pub fn inject_sqli_probe(url: &str) -> String {
    const PROBE: &str = "q=%27+OR+1%3D1--";
    // Split off the fragment (only the first `#` counts per RFC 3986).
    let (base, frag) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let mutated_base = if base.contains('?') {
        format!("{base}&{PROBE}")
    } else {
        format!("{base}?{PROBE}")
    };
    match frag {
        Some(f) => format!("{mutated_base}#{f}"),
        None => mutated_base,
    }
}

/// Fire two probes against `url`: a benign GET, then an attack
/// GET with a canonical SQLi payload in the `q` parameter.
/// Returns `Some(evidence)` when the responses differ enough to
/// infer a WAF.
pub(crate) fn fetch_differential(
    url: &str,
    timeout_secs: u64,
    insecure: bool,
) -> Result<Option<DifferentialEvidence>, String> {
    let (b_status, b_headers, b_body) = fetch_for_detect(url, timeout_secs, insecure)?;
    let attack_url = inject_sqli_probe(url);
    let (a_status, a_headers, a_body) = fetch_for_detect(&attack_url, timeout_secs, insecure)?;
    Ok(classify_differential(
        b_status,
        &b_headers,
        b_body.len(),
        a_status,
        &a_headers,
        a_body.len(),
    ))
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
    // Last-wins dedup on the lowercased header name: an upstream
    // proxy sandwich (Python's BaseHTTPServer adding its own
    // `Server: BaseHTTP/...` on top of a backend's `Server:
    // cloudflare`) used to surface BOTH as separate rows in the
    // legendary markdown table, which read as a rendering bug.
    // Last-wins because the OUTERMOST proxy is the one the operator
    // is interacting with — its identity is more informative for
    // the report than the buried backend's.
    let mut seen: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if !KEYS.contains(&lk.as_str()) {
            continue;
        }
        if !seen.contains_key(&lk) {
            order.push(lk.clone());
        }
        seen.insert(lk, (k.clone(), v.clone()));
    }
    order.into_iter().filter_map(|k| seen.remove(&k)).collect()
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    // Two input modes: live `--url` fetch, or the manual
    // `--status`/`--headers`/`--body` triple. clap's
    // `required_unless_present`/`conflicts_with_all` guarantees exactly
    // one mode is selected.
    let resolved_url = args
        .resolved_url()
        .map(|u| crate::helpers::normalize_target_url(u));
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) =
        if let Some(ref url) = resolved_url {
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

    // Differential WAF detection (opt-in): fire a SECOND probe
    // with an attack-shaped payload and compare. When the static-
    // signature corpus comes back empty but the responses to a
    // benign vs attack request differ significantly, we still know
    // a WAF is intercepting — even if its block page is generic
    // (Apache stock 403, etc.).
    // Pre-fix this used `.expect("differential gated on Some(url)")`
    // — logically infallible because the outer `&& resolved_url.is_some()`
    // gates entry, but LAW 1 (no expects outside tests) plus the
    // risk that a future refactor decouples the guard from the
    // expectation make `if let Some` strictly safer. No behaviour
    // change — both forms produce `None` for the `args.differential
    // == false || resolved_url.is_none()` cases.
    let differential_evidence: Option<DifferentialEvidence> =
        if args.differential && resolved_url.is_some() {
            let url = resolved_url
                .as_deref()
                .expect("differential gated on Some(url)");
            match fetch_differential(url, args.timeout_secs, args.insecure) {
                Ok(ev) => ev,
                Err(e) => {
                    if !quiet {
                        eprintln!(
                            "{} differential probe error (continuing without): {e}",
                            "warn:".yellow()
                        );
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

    let mut detected = waf_detect::detect(status, &headers, &body);

    // CNAME-chain detection: catches origins that strip every CDN /
    // WAF marker header but can't hide their delivery chain at the
    // DNS layer (Stripe, Dropbox, eBay-via-Akamai).  Runs only when
    // we have a URL to resolve — manual --status/--headers mode
    // skips DNS (no host to look up).
    let cname_probe: Option<DnsProbe> = resolved_url.as_deref().and_then(fetch_cname_chain);
    // Trigger CNAME-rule detection whenever we have ANY DNS signal —
    // the chain (forward CNAME hops), a PTR record on the leaf IP,
    // or an ASN org name.  Gating only on the chain swallowed the
    // PTR axis; gating only on chain+PTR swallowed the ASN axis
    // (which is the last-resort vendor signal for origins like
    // Stripe that strip everything else).
    if let Some(ref probe) = cname_probe
        && (!probe.chain.is_empty() || probe.final_ptr.is_some() || probe.asn.is_some())
    {
        // Cache the CnameRuleEngine across detect calls — the embedded
        // TOML parse + regex compile costs ~150ms on cold load. Without
        // the cache, every `wafrift detect` invocation pays that cost,
        // and `legendary` (which calls detect repeatedly) ends up
        // visibly sluggish. OnceLock is `Send + Sync` and zero-overhead
        // after init. Per perf-hunt finding F01 (2026-05-23).
        static CNAME_ENGINE: std::sync::OnceLock<CnameRuleEngine> = std::sync::OnceLock::new();
        let cname_engine =
            CNAME_ENGINE.get_or_init(|| CnameRuleEngine::load_embedded().unwrap_or_default());
        let cname_hits = cname_engine.detect(probe);
        // ── Vendor subsumption ─────────────────────────────
        //
        // Some HTTP-layer rules identify a TECH STACK (Varnish,
        // Envoy) that is downstream-OF a CDN vendor.  When the DNS
        // layer authoritatively names the CDN (Fastly uses Varnish
        // underneath; the Varnish header is a Fastly artefact, not
        // an independent vendor), the CDN name should win the
        // primary slot AND absorb the component's confidence
        // rather than competing with it.
        //
        // Subsumption table: `child` is the header-derived
        // component, `parent` is the CDN vendor.  When both fire
        // and the parent was DNS-derived (any of cname / ptr /
        // asn), the child gets dropped and its confidence rolls
        // into the parent (clamped to 1.0).
        fn subsumes(parent: &str) -> &'static [&'static str] {
            match parent {
                "Fastly" | "Fastly (CNAME)" | "Fastly (ASN)" => &["CacheWall"],
                _ => &[],
            }
        }
        fn is_dns_derived(detected_entry: &waf_detect::DetectedWaf) -> bool {
            // Heuristic: CNAME/PTR/ASN-derived entries carry
            // indicators tagged with `cname:` / `ptr:` / `asn:`.
            // Header-derived entries use `header N: V` form.
            detected_entry.indicators.iter().any(|ind| {
                ind.starts_with("cname: ") || ind.starts_with("ptr: ") || ind.starts_with("asn: ")
            })
        }

        // Merge CNAME hits into detected[], deduping by name.  When
        // both layers agree (header-AND-cname say "Fastly"), keep
        // the header-side hit (higher-confidence indicators) and
        // append the CNAME hop as one more indicator on it.
        for hit in cname_hits {
            // Strip "(CNAME)" / "(PTR)" suffixes on the rule name
            // so the three signals (HTTP header + CNAME hop + PTR
            // record) collapse onto a single vendor entry per
            // company.  Each independent signal becomes one more
            // indicator on the same row, not a duplicate row.
            let canonical = hit
                .name
                .strip_suffix(" (CNAME)")
                .or_else(|| hit.name.strip_suffix(" (PTR)"))
                .unwrap_or(&hit.name)
                .to_string();
            if let Some(existing) = detected
                .iter_mut()
                .find(|d| d.name == canonical || d.name == hit.name)
            {
                for ind in &hit.indicators {
                    if !existing.indicators.contains(ind) {
                        existing.indicators.push(ind.clone());
                    }
                }
                existing.confidence = existing.confidence.max(hit.confidence);
            } else {
                let mut renamed = hit.clone();
                renamed.name = canonical;
                detected.push(renamed);
            }
        }
        // Apply vendor-subsumption: when a DNS-derived parent
        // (Fastly, etc.) co-exists with its header-derived child
        // (Varnish/CacheWall), absorb the child's confidence
        // into the parent and drop the child row.  Without this,
        // reddit.com / nytimes.com would surface "CacheWall" as
        // the primary vendor — technically true (Varnish IS in
        // path) but the CDN-level name Fastly is what an
        // operator actually wants to see.
        let parent_names: Vec<String> = detected
            .iter()
            .filter(|d| is_dns_derived(d))
            .map(|d| {
                d.name
                    .strip_suffix(" (CNAME)")
                    .or_else(|| d.name.strip_suffix(" (PTR)"))
                    .or_else(|| d.name.strip_suffix(" (ASN)"))
                    .unwrap_or(&d.name)
                    .to_string()
            })
            .collect();
        for parent in &parent_names {
            let children = subsumes(parent);
            if children.is_empty() {
                continue;
            }
            let mut absorbed_confidence = 0.0;
            let mut absorbed_indicators: Vec<String> = Vec::new();
            detected.retain(|d| {
                if children.iter().any(|c| d.name == *c) {
                    absorbed_confidence += d.confidence;
                    for ind in &d.indicators {
                        absorbed_indicators.push(ind.clone());
                    }
                    false
                } else {
                    true
                }
            });
            if absorbed_confidence > 0.0
                && let Some(parent_entry) = detected.iter_mut().find(|d| {
                    d.name == *parent
                        || d.name == format!("{parent} (CNAME)")
                        || d.name == format!("{parent} (PTR)")
                        || d.name == format!("{parent} (ASN)")
                })
            {
                // Absorbed confidence boosts the parent at half
                // weight (so two independent signals add up but
                // don't double-count) — clamped to 1.0.
                parent_entry.confidence =
                    (parent_entry.confidence + absorbed_confidence * 0.5).min(1.0);
                for ind in absorbed_indicators {
                    if !parent_entry.indicators.contains(&ind) {
                        parent_entry.indicators.push(ind);
                    }
                }
            }
        }

        // Sort by confidence descending for deterministic output.
        detected.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
    }

    // JSON output is selected by either `--quiet` (legacy) OR the
    // newer `--format json` (uniform with every other subcommand —
    // closes the dogfood bug where `wafrift detect --url X --format
    // json` failed with "unexpected argument").
    let emit_json = quiet || args.format == "json";
    if emit_json {
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
        let dns_json = cname_probe.as_ref().map(|p| {
            let hops: Vec<_> = p
                .chain
                .iter()
                .map(|h| json!({ "query": h.query, "target": h.target }))
                .collect();
            let asn = p
                .asn
                .as_ref()
                .map(|a| json!({ "number": a.number, "name": a.name }));
            json!({
                "chain": hops,
                "final_ip": p.first_a.map(|i| i.to_string()),
                "final_ptr": p.final_ptr,
                "asn": asn,
            })
        });
        // Dogfood sonnet 3 (2026-05): pre-fix the JSON envelope was
        // identical with and without `--differential`. The text mode
        // surfaced "WAF inferred via differential probe: status
        // flipped 200 → 403, body shifted 336%" but downstream
        // jq pipelines saw zero signal. Now: serialise the
        // differential evidence so a `wafrift detect --differential
        // --format json | jq .differential.reasons` reports the same
        // verdict the text mode does.
        let differential_json = differential_evidence.as_ref().map(|ev| {
            json!({
                "baseline_status": ev.baseline_status,
                "attack_status": ev.attack_status,
                "baseline_server": ev.baseline_server,
                "attack_server": ev.attack_server,
                "baseline_body_len": ev.baseline_body_len,
                "attack_body_len": ev.attack_body_len,
                "reasons": ev.reasons,
            })
        });
        println!(
            "{}",
            json!({
                "status": status,
                "detected": results,
                "infrastructure": infra,
                "dns": dns_json,
                "differential": differential_json,
            })
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
        // Other layers in the WAF chain (Envoy sidecar + Fastly
        // origin, Cloudflare in front of Cloudfront, etc.) get
        // condensed under "Also detected" so the operator sees the
        // whole stack at a glance.
        if detected.len() > 1 {
            println!();
            println!("{}", "Also detected:".bold().cyan());
            for r in &detected[1..] {
                println!(
                    "  {} {} ({:.0}%)",
                    "-".bright_black(),
                    r.name.yellow(),
                    (r.confidence * 100.0).round()
                );
            }
        }
        if let Some(ref p) = cname_probe
            && (!p.chain.is_empty() || p.final_ptr.is_some() || p.asn.is_some())
        {
            println!();
            println!("{}", "DNS lookup:".bold().cyan());
            for hop in &p.chain {
                println!(
                    "  {} {} {} {}",
                    "-".bright_black(),
                    hop.query.bright_white(),
                    "→".bright_black(),
                    hop.target.yellow()
                );
            }
            if let Some(ref ptr) = p.final_ptr {
                println!(
                    "  {} PTR {} {}",
                    "-".bright_black(),
                    "→".bright_black(),
                    ptr.yellow()
                );
            }
            if let Some(ref asn) = p.asn {
                println!(
                    "  {} ASN {} {} {}",
                    "-".bright_black(),
                    "→".bright_black(),
                    format!("AS{}", asn.number).bright_white(),
                    asn.name.yellow()
                );
            }
        }
        ExitCode::SUCCESS
    } else {
        println!("{}", "No WAF confidently detected.".yellow().bold());
        // Hint operators that the static rule corpus may have missed a
        // WAF that strips its own marker headers — try the active
        // differential probe (only fires a second request when
        // --differential is set; that's why we suggest it, not silently
        // run it). Found during pentest dogfood 2026-05: against any
        // target with a server-header proxy in front (gunicorn behind
        // nginx, BaseHTTP test server, etc.) the static corpus is silent
        // but `--differential` immediately catches a 200→403 swing.
        if resolved_url.is_some() && !args.differential {
            println!(
                "  {} pass {} to actively probe with an attack-shaped \
                 string — catches WAFs in 'block but don't fingerprint' mode.",
                "hint:".bright_cyan().bold(),
                "--differential".bright_white(),
            );
        }
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
        // CNAME chain — even when headers are clean, the DNS layer
        // often gives away the CDN / WAF (Stripe / Dropbox / eBay
        // case study).  Surfacing the chain lets the operator see
        // exactly which delivery network is in front of the origin.
        if let Some(ref p) = cname_probe
            && (!p.chain.is_empty() || p.final_ptr.is_some() || p.asn.is_some())
        {
            println!();
            println!("{}", "DNS lookup:".bold().cyan());
            for hop in &p.chain {
                println!(
                    "  {} {} {} {}",
                    "-".bright_black(),
                    hop.query.bright_white(),
                    "→".bright_black(),
                    hop.target.yellow()
                );
            }
            if let Some(ref ptr) = p.final_ptr {
                println!(
                    "  {} PTR {} {}",
                    "-".bright_black(),
                    "→".bright_black(),
                    ptr.yellow()
                );
            }
            if let Some(ref asn) = p.asn {
                println!(
                    "  {} ASN {} {} {}",
                    "-".bright_black(),
                    "→".bright_black(),
                    format!("AS{}", asn.number).bright_white(),
                    asn.name.yellow()
                );
            }
        }
        // Differential evidence — even when the static-corpus came
        // back empty, a differing response on a benign vs attack
        // probe is strong WAF-presence signal (the typical
        // ModSec-in-front-of-gunicorn-returning-generic-Apache-403
        // pattern lives here).
        if let Some(ev) = differential_evidence.as_ref() {
            println!();
            println!(
                "{}",
                "WAF inferred via differential probing:".bold().green()
            );
            for reason in &ev.reasons {
                println!("  {} {}", "✓".green(), reason.yellow());
            }
            println!(
                "  {}",
                format!(
                    "(benign GET → HTTP {} from '{}'; attack GET → HTTP {} from '{}')",
                    ev.baseline_status, ev.baseline_server, ev.attack_status, ev.attack_server
                )
                .bright_black()
            );
        }
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // F127 regression: inject_sqli_probe must place the query before
    // the fragment. Pre-fix code naively appended `?q=...` whenever the
    // URL had no `?`, but `https://t/p#sec` has no `?` — the appended
    // text landed INSIDE the fragment and the probe never reached the
    // server. Silent false-negative for any fragmented URL.
    #[test]
    fn inject_sqli_probe_appends_query_when_no_query() {
        let out = inject_sqli_probe("https://t/p");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--");
    }

    #[test]
    fn inject_sqli_probe_uses_ampersand_when_query_present() {
        let out = inject_sqli_probe("https://t/p?a=1");
        assert_eq!(out, "https://t/p?a=1&q=%27+OR+1%3D1--");
    }

    #[test]
    fn inject_sqli_probe_preserves_fragment_no_existing_query() {
        // Pre-fix would produce "https://t/p#sec?q=..." — query inside
        // the fragment, never reaches the server.
        let out = inject_sqli_probe("https://t/p#sec");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#sec");
    }

    #[test]
    fn inject_sqli_probe_preserves_fragment_with_existing_query() {
        let out = inject_sqli_probe("https://t/p?a=1#sec");
        assert_eq!(out, "https://t/p?a=1&q=%27+OR+1%3D1--#sec");
    }

    #[test]
    fn inject_sqli_probe_handles_url_with_multiple_hashes() {
        // Only the FIRST `#` counts per RFC 3986; the rest are
        // fragment characters.
        let out = inject_sqli_probe("https://t/p#sec#more");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#sec#more");
    }

    #[test]
    fn inject_sqli_probe_handles_empty_fragment() {
        let out = inject_sqli_probe("https://t/p#");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#");
    }

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
        assert!(
            !m.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        );
    }

    // ── Live --url path against a mock server (added 2026-05-20).

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock(body: &'static str, status: u16) -> std::net::SocketAddr {
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\
                         Connection: close\r\nServer: nginx/1.25.3\r\n\
                         CF-Ray: abc123-LHR\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    /// `fetch_for_detect` builds its own tokio runtime — we drive it
    /// from a sync `#[test]` (no `#[tokio::test]`) so the nested
    /// runtime panic doesn't trip.
    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_against_local_mock_returns_status_and_headers() {
        // Run the mock from a worker tokio runtime, then call the
        // sync fetch_for_detect against the bound address.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("hello world", 200));
        let url = format!("http://{addr}/");
        let (status, headers, body) =
            fetch_for_detect(&url, 5, false).expect("fetch_for_detect must succeed");
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
        let has_server = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("server") && v.contains("nginx"));
        assert!(has_server, "Server header should be present: {headers:?}");
        let has_cf = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cf-ray") && v.contains("abc123"));
        assert!(has_cf, "CF-Ray header should be present");
    }

    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_caps_body_at_64_kib() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        // Mock that ships 128 KiB of body — we want to confirm the
        // fetch caps the read at 64 KiB.
        let big_body = Box::leak("X".repeat(128 * 1024).into_boxed_str()) as &'static str;
        let addr = rt.block_on(spawn_mock(big_body, 200));
        let url = format!("http://{addr}/");
        let (_, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(
            body.len(),
            64 * 1024,
            "body must be capped at 64 KiB, got {}",
            body.len()
        );
    }

    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_passes_through_403_status() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("blocked by WAF", 403));
        let url = format!("http://{addr}/");
        let (status, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(status, 403);
        assert_eq!(body, b"blocked by WAF");
    }

    #[test]
    fn fetch_for_detect_returns_err_on_connection_refused() {
        // Connect to a localhost port that's almost certainly not
        // listening. Must surface as Err, not panic. Use the
        // unassigned port range (49152–65535 IANA dynamic, but
        // 65501 specifically is rarely used).
        let result = fetch_for_detect("http://127.0.0.1:1/", 2, false);
        assert!(result.is_err(), "unreachable target must return Err");
    }

    #[test]
    fn fetch_for_detect_with_unparseable_url_returns_err() {
        let result = fetch_for_detect("not-a-url://", 2, false);
        assert!(result.is_err(), "unparseable URL must return Err");
    }

    #[test]
    fn fetch_for_detect_connection_refused_error_walks_source_chain() {
        // Regression guard for the "swallowed error chain" UX bug
        // (P3 from sonnet dogfood pass 4, 2026-05).  Prior to the
        // fix, the error message just said "error sending request"
        // with no DNS/TCP cause attached.  Now the source chain is
        // walked and surfaced via " — caused by: ..." appends.
        let err = fetch_for_detect("http://127.0.0.1:1/", 2, false)
            .expect_err("connect-refused must Err");
        assert!(
            err.contains("caused by:"),
            "error must walk the source chain — got: {err}"
        );
        // The URL must still appear in the top-level message so the
        // operator can grep their command log.
        assert!(
            err.contains("127.0.0.1:1"),
            "error must include the URL that failed: {err}"
        );
    }

    #[test]
    fn fetch_for_detect_nxdomain_surfaces_dns_layer_cause() {
        // Stress: hit a guaranteed-NXDOMAIN host.  `.invalid` is
        // RFC 6761 reserved → DNS resolvers MUST return NXDOMAIN.
        // We rely on the source chain walker exposing the dns-layer
        // cause so a sysadmin reading the error sees "DNS" not just
        // a generic "request failed".
        let err = fetch_for_detect("http://nonexistent.invalid/", 2, false);
        match err {
            Ok(_) => panic!("invalid TLD must NXDOMAIN"),
            Err(msg) => {
                // The exact phrasing depends on the resolver (Windows
                // says "No such host is known", Unix typically
                // surfaces "Name or service not known") but every
                // platform's reqwest chain includes "dns" or "Connect"
                // in the chain.
                assert!(
                    msg.to_lowercase().contains("dns")
                        || msg.to_lowercase().contains("connect")
                        || msg.contains("caused by:"),
                    "NXDOMAIN error must surface DNS / Connect layer: {msg}"
                );
            }
        }
    }

    // ── classify_differential ────────────────────────────────────
    //
    // Pure function — tested without I/O. Each case names the
    // real-world WAF detection pattern it gates.

    fn hdr(server: &str) -> Vec<(String, String)> {
        vec![("Server".into(), server.into())]
    }

    #[test]
    fn differential_identical_responses_returns_none() {
        // Anti-rig: if benign and attack produce identical
        // responses, NO inference. Returning Some here would be
        // a false-positive WAF detection on every plain HTTP host.
        let ev = classify_differential(200, &hdr("nginx"), 1024, 200, &hdr("nginx"), 1024);
        assert!(ev.is_none(), "identical responses must not infer a WAF");
    }

    #[test]
    fn differential_status_flip_alone_is_evidence() {
        // The bare 200 → 403 case: server header may not even be
        // present, but the status flip is unambiguous WAF signal.
        let ev =
            classify_differential(200, &[], 100, 403, &[], 200).expect("status flip must classify");
        assert_eq!(ev.baseline_status, 200);
        assert_eq!(ev.attack_status, 403);
        assert!(
            ev.reasons.iter().any(|r| r.contains("status flipped")),
            "reasons should mention status flip"
        );
    }

    #[test]
    fn differential_server_change_classifies_as_waf() {
        // The exact ModSec-in-front-of-gunicorn case from dogfooding:
        // benign 200 from 'gunicorn/19.9.0', attack 403 from
        // 'Apache' (ModSec block page). The server-change reason
        // must surface.
        let ev = classify_differential(200, &hdr("gunicorn/19.9.0"), 445, 403, &hdr("Apache"), 239)
            .expect("classify");
        assert!(
            ev.reasons
                .iter()
                .any(|r| r.contains("server header changed")),
            "expected server-change reason: {:?}",
            ev.reasons
        );
        assert_eq!(ev.baseline_server, "gunicorn/19.9.0");
        assert_eq!(ev.attack_server, "Apache");
    }

    #[test]
    fn differential_server_change_is_case_insensitive() {
        // Apache vs apache should NOT count as a server change —
        // it's the same software, just different casing on the
        // server's part.
        let ev = classify_differential(403, &hdr("Apache"), 100, 403, &hdr("apache"), 100);
        assert!(
            ev.is_none(),
            "case-only server difference must not classify"
        );
    }

    #[test]
    fn differential_body_swing_over_50pct_is_evidence() {
        // Same status + same server, but body collapses from 10 KB
        // (real response) to 200 bytes (block page). The 50%+
        // shrinkage is the only signal in this case.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 200)
            .expect("body swing must classify");
        assert!(
            ev.reasons.iter().any(|r| r.contains("body length swung")),
            "reasons should mention body swing: {:?}",
            ev.reasons
        );
    }

    #[test]
    fn differential_small_body_change_is_not_evidence() {
        // 10% difference (timestamps, request IDs, jitter in
        // body) must NOT classify. 50% is the threshold.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 9_500);
        assert!(ev.is_none(), "5% body change must not classify");
    }

    #[test]
    fn differential_multiple_signals_all_listed_in_reasons() {
        // The strongest case: status flip + server change + body
        // swing all together. Every reason should appear in the
        // output so the operator sees the full picture.
        let ev = classify_differential(200, &hdr("gunicorn"), 10_000, 403, &hdr("Apache"), 200)
            .expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(reasons.contains("status flipped"));
        assert!(reasons.contains("server header changed"));
        assert!(reasons.contains("body length swung"));
    }

    #[test]
    fn differential_empty_baseline_with_attack_body_still_signal() {
        // Edge: benign returned 0 bytes (unusual but valid for a
        // HEAD-style endpoint), attack returned a block page.
        // We can't compute pct_diff against zero, but the
        // non-zero attack body IS still signal.
        let ev = classify_differential(200, &[], 0, 403, &[], 500).expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(
            reasons.contains("attack response had 500 bytes") || reasons.contains("status flipped"),
            "expected either body-vs-empty or status-flip reason: {:?}",
            ev.reasons
        );
    }
}
