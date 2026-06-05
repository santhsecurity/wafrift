//! `wafrift smuggle-fire` — fire smuggle probes against a live target.
//!
//! Takes the same seed flags as `smuggle-emit` but instead of emitting
//! JSON artifacts, builds an HTTP request per probe and fires it at
//! the supplied `--target` URL. Reports per-probe verdict as JSON
//! (one per line): status code, body length, latency, plus a
//! `bypass_signal` field that compares against a baseline request.
//!
//! ## Bypass signal
//!
//! Every run fires ONE baseline request first (same shape as the
//! probes — GET for header probes, POST for body probes — but with
//! no smuggle-specific bytes). Each probe is then compared against
//! that baseline:
//!
//! - `canary-reflected`: a probe canary token (sent via `--canary-header`)
//!   appeared verbatim in the response headers or body — the smuggled marker
//!   reached a reflecting surface. STRONGEST signal; precedes the rest.
//! - `none`            : probe response matches baseline status + body length
//! - `status-diverged` : probe status differs (e.g. 200 vs 403 baseline)
//! - `body-diverged`   : probe body length differs >5% from baseline
//! - `both-diverged`   : both status AND body length diverged
//!
//! A `canary-reflected` verdict is the highest-confidence bypass
//! signal — a 16-char random token can't reflect by chance. Absent
//! reflection, a `status-diverged` to 200 against a baseline 403 is
//! the next strongest. When reflection is in play the report also
//! carries the reflected token(s) in `reflected_canaries`. Operators
//! triage by filtering on the JSON field.
//!
//! ## Frame probes
//!
//! Frame artifacts (HTTP/3 capsule, QUIC datagram, WebSocket
//! compression) cannot ride a normal HTTP/1.1 / 2 request — they
//! live at a lower transport layer. They are SKIPPED with a stderr
//! warning. To exercise them, use the wire-format dry-run via
//! `wafrift smuggle-emit --family frames | jq` and feed into a raw
//! socket driver.

use clap::Parser;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use wafrift_core::probe_aggregator::{ProbeSeeds, all_probes};
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

use crate::permission;
use crate::smuggle_transport;

#[derive(Debug, Parser)]
pub struct SmuggleFireArgs {
    /// Target URL — every probe is fired at this exact URL. For
    /// HTTP/1.1 path-smuggle probes, the URL path is REPLACED by
    /// the artifact's `:path` value; for everything else, the URL
    /// is used verbatim. May be given POSITIONALLY
    /// (`wafrift smuggle-fire https://…`) for consistency with every
    /// other network subcommand, OR via `--target`; the explicit
    /// `--target` wins if both are supplied.
    #[arg(long, value_name = "URL", default_value = "")]
    pub target: String,

    /// Positional target URL — the consistency alias for `--target`
    /// (§13 dogfood round-2 DEFECT 4: every other network subcommand
    /// accepts the URL positionally, so `smuggle-fire` must too).
    /// Resolved into `target` at startup; explicit `--target` wins.
    #[arg(value_name = "URL")]
    pub target_positional: Option<String>,

    /// WAF go-around: connect every probe to this origin IP while
    /// keeping the `--target` URL's `Host` header and TLS SNI. The edge
    /// proxy / WAF is bypassed at the connection layer, so an origin
    /// that trusts its edge (admin panel behind a hard 404, an
    /// IP-allowlisted backend, an `--family auth` edge-trust header) is
    /// probed directly. Find the IP first with `unmask <host>`, then
    /// pass it here. The URL's scheme port (443 for https, 80 for http)
    /// is used unless the URL specifies one.
    #[arg(long, value_name = "IP")]
    pub origin_ip: Option<String>,

    /// Optional family prefix to fire — e.g. `cookie`, `auth`,
    /// `range`, `path`, `host`, `content-type`, `json`. Frame
    /// families (`capsule`, `quic-datagram`, `compression`) are
    /// always skipped (can't ride reqwest). Empty = every non-frame
    /// family.
    #[arg(long, default_value = "")]
    pub family: String,

    /// Cookie / Authorization name seed.
    #[arg(long, default_value = "session")]
    pub cookie_name: String,

    /// Credential value seed.
    #[arg(long, default_value = "wafrift-test-token")]
    pub credential: String,

    /// Opaque payload seed.
    #[arg(long, default_value = "wafrift-smuggle-payload")]
    pub payload: String,

    /// Form params for multipart / JSON smuggle.
    #[arg(long, default_value = "user=admin&token=wafrift-test-token")]
    pub form: String,

    /// Protected path seed for path-normalize probes.
    #[arg(long, default_value = "/admin")]
    pub protected_path: String,

    /// Protected hostname seed for host-header probes.
    #[arg(long, default_value = "admin.example.com")]
    pub protected_host: String,

    /// Per-request HTTP timeout in seconds.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_TIMEOUT_SECS)]
    pub timeout_secs: u64,

    /// Inter-request delay in milliseconds (rate-limit-friendliness).
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_DELAY_MS)]
    pub delay_ms: u64,

    /// Maximum probes to fire after filtering. 0 = unlimited.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,

    /// Authorization gate. Required for any target NOT on the
    /// built-in allowlist (CumulusFire, ginandjuice.shop, RFC1918,
    /// loopback). Pass any non-empty reason (e.g. HackerOne ticket).
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// When set, emit a `<HEADER_NAME>: <token>` header (e.g.
    /// `X-Wafrift-Canary`) on every probe request so OOB-callback
    /// correlation lands the technique-distinguishing token in
    /// inbound traffic. The response headers AND body are ALSO
    /// scanned for the token: a verbatim echo (Location, Set-Cookie,
    /// a debug echo header, or the body) yields the `canary-reflected`
    /// signal (the strongest, false-positive-free bypass confirmation)
    /// and is reported in `reflected_canaries`.
    #[arg(long, default_value = "", value_name = "HEADER_NAME")]
    pub canary_header: String,

    /// Body-length divergence threshold (fraction). A probe whose
    /// response body length differs from baseline by MORE than this
    /// fraction emits `body-diverged`. Default 0.05 = 5% delta.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_BODY_DIVERGENCE_THRESHOLD)]
    pub body_divergence_threshold: f64,

    /// When set, suppress the end-of-run summary written to stderr.
    /// Useful for scripts that parse stderr or want pure stdout
    /// streams.
    #[arg(long)]
    pub no_summary: bool,

    /// When set, every per-probe JSON report carries an extra
    /// `reproducer_curl` field — a single-line, paste-into-bash
    /// curl command that reproduces the exact request that probe
    /// fired. Operators jq-filter on `bypass_signal != "none"` and
    /// `.reproducer_curl` is the pentest-report-ready reproducer.
    #[arg(long)]
    pub include_reproducer: bool,

    /// Maximum probes fired concurrently. 1 = sequential
    /// (respects `--delay-ms`). N > 1 = up to N in-flight requests
    /// at any time; `--delay-ms` is IGNORED in parallel mode (a
    /// timed delay defeats the purpose of concurrency). Reports
    /// are emitted in COMPLETION order (not start order). Use
    /// against rate-tolerant targets to get a 10-50x speedup.
    #[arg(long, default_value_t = wafrift_types::DEFAULT_SMUGGLE_FIRE_PARALLEL)]
    pub parallel: usize,

    /// When set, append every bypassing probe (signal != "none")
    /// to the named NDJSON corpus file (one JSON report per line).
    /// Operators feed this back via `--prioritize-bypasses` on
    /// future runs to fire known winners first — the wafrift
    /// learning loop. Reproducer curl is included if the probe
    /// has one.
    #[arg(long, value_name = "FILE")]
    pub save_bypasses: Option<std::path::PathBuf>,

    /// Read a bypasses NDJSON corpus (as produced by
    /// `--save-bypasses`) and fire those probes' techniques FIRST,
    /// before the rest of the family sweep. Operators iterate:
    /// `smuggle-fire --save-bypasses corpus.ndjson` then
    /// `smuggle-fire --prioritize-bypasses corpus.ndjson` to keep
    /// re-validating known winners while expanding coverage.
    #[arg(long, value_name = "FILE")]
    pub prioritize_bypasses: Option<std::path::PathBuf>,

    /// HTTP method for the baseline request. Default `GET`. For
    /// POST-only endpoints, pair with `--baseline-body` so the
    /// baseline is shape-equivalent to what probes fire.
    #[arg(long, default_value = "GET", value_name = "METHOD")]
    pub baseline_method: String,

    /// Baseline request body (raw bytes). Pair with
    /// `--baseline-method POST` for body-shape probes. Empty
    /// (default) = no body.
    #[arg(long, default_value = "", value_name = "BYTES")]
    pub baseline_body: String,

    /// Baseline request header in `Name: Value` form, repeatable.
    /// Use for auth-required endpoints (e.g. a valid `Cookie` or
    /// `Authorization` header) so the baseline reflects the
    /// authenticated normal response — divergence vs that baseline
    /// is then the bypass signal.
    #[arg(long, value_name = "HEADER", num_args = 0..)]
    pub baseline_header: Vec<String>,
}

#[derive(serde::Serialize)]
struct FireReport {
    technique: String,
    canary: String,
    status: u16,
    body_len: usize,
    latency_ms: u128,
    baseline_status: u16,
    baseline_body_len: usize,
    bypass_signal: String,
    /// Canary token(s) reflected verbatim in the probe response body
    /// — present (and non-empty) only when `--canary-header` placed
    /// the token on the wire and the origin echoed it. Omitted from
    /// JSON when empty (additive, backwards-compatible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reflected_canaries: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reproducer_curl: Option<String>,
}

/// Build the reqwest `.resolve` override for `--origin-ip`: pins the
/// `target` URL's host to `origin_ip` on the URL's effective port, so
/// every probe connects to the origin while `Host` + SNI stay the real
/// target. Pure + fallible so the parse/validation is unit-tested
/// without opening a socket. Errors are operator-facing strings.
fn origin_resolve_override(target: &str, origin_ip: &str) -> Result<(String, SocketAddr), String> {
    let ip: IpAddr = origin_ip
        .parse()
        .map_err(|_| format!("--origin-ip {origin_ip:?} is not a valid IP address"))?;
    let url = reqwest::Url::parse(target)
        .map_err(|e| format!("--target {target:?} is not a valid URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("--target {target:?} has no host to pin to the origin IP"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        format!("--target {target:?} has no port and no known default for its scheme")
    })?;
    Ok((host.to_string(), SocketAddr::new(ip, port)))
}

pub fn run_smuggle_fire(mut args: SmuggleFireArgs) -> ExitCode {
    // §13 dogfood round-2 DEFECT 4: accept the target URL positionally
    // (consistency with scan/detect/bypass-probe/model-evade/…) by resolving
    // it into `args.target` here, so every downstream read is unchanged.
    // `--target` wins when both forms are supplied.
    if args.target.is_empty()
        && let Some(pos) = args.target_positional.take()
    {
        args.target = pos;
    }
    if args.target.trim().is_empty() {
        return crate::helpers::input_error(
            "smuggle-fire needs a target URL — pass it positionally \
             (`wafrift smuggle-fire https://example.com/ …`) or via --target",
        );
    }
    permission::assert_permitted(&args.target, args.i_have_permission.as_deref());
    // §7 DEDUPLICATION: delegate to the canonical one-liner so the 6-line
    // match-Runtime::new boilerplate lives in exactly one place.
    crate::helpers::block_on_with_runtime(run_async(args))
}

async fn run_async(args: SmuggleFireArgs) -> ExitCode {
    let form_params = crate::helpers::parse_form_pairs(&args.form);
    let seeds = ProbeSeeds {
        cookie_name: &args.cookie_name,
        credential_value: &args.credential,
        form_params,
        payload: args.payload.as_bytes().to_vec(),
        protected_path: &args.protected_path,
        protected_host: &args.protected_host,
    };
    let probes: Vec<_> = all_probes(&seeds)
        .into_iter()
        .filter(|p| args.family.is_empty() || p.technique().starts_with(&args.family))
        .filter(|p| !matches!(p.artifact(), SmuggleArtifact::Frames(_)))
        .collect();

    // Optional: re-order so techniques listed in `--prioritize-bypasses`
    // corpus fire FIRST. Unlisted probes follow in their original
    // aggregator order — preserves coverage while front-loading
    // known winners.
    let probes = if let Some(corpus_path) = &args.prioritize_bypasses {
        match load_priority_techniques(corpus_path) {
            Ok(priority_set) => reorder_priority_first(probes, &priority_set),
            Err(e) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "wafrift smuggle-fire: failed to load prioritize-bypasses corpus {}: {e}",
                    corpus_path.display()
                );
                return ExitCode::from(1);
            }
        }
    } else {
        probes
    };

    if probes.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-fire: family filter {:?} matched zero non-frame probes",
            args.family
        );
        return ExitCode::from(2);
    }

    // --origin-ip: pin the target host to a discovered origin IP so the
    // probes connect past the edge/WAF (see `origin_resolve_override`).
    let origin_resolve = match &args.origin_ip {
        Some(ip) => match origin_resolve_override(&args.target, ip) {
            Ok(r) => Some(r),
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "wafrift smuggle-fire: {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    if let Some((host, addr)) = &origin_resolve {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-fire: origin-direct mode — connecting to {} for Host {host} (edge/WAF bypassed)",
            addr.ip()
        );
    }

    let client = match smuggle_transport::build_client_with_resolve(
        args.timeout_secs,
        origin_resolve.as_ref().map(|(h, a)| (h.as_str(), *a)),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            return ExitCode::from(1);
        }
    };

    // Parse --baseline-header entries into name/value pairs.
    let baseline_headers: Vec<(String, String)> = args
        .baseline_header
        .iter()
        .filter_map(|h| {
            let (n, v) = h.split_once(':')?;
            Some((n.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let baseline = match smuggle_transport::fire_baseline(
        &client,
        &args.target,
        &args.baseline_method,
        args.baseline_body.as_bytes(),
        &baseline_headers,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "wafrift smuggle-fire: baseline request failed: {e}"
            );
            return ExitCode::from(1);
        }
    };
    // Collapse the baseline FireOutcome to the (status, body_len)
    // tuple the per-probe classification path consumes — the baseline
    // never carries smuggle canaries, so its reflection set is empty.
    let baseline = (baseline.status, baseline.body_len);

    // §13 dogfood round-2 DEFECT 8: if the baseline request ITSELF was
    // blocked (4xx/5xx — typically the default `--payload` tripping the WAF),
    // every `*-diverged` signal below is measured against a BLOCKED page. A
    // probe returning 400 then reads as "WAF rejected the malformed header
    // differently", NOT "smuggling bypass" — the comparison is muddied. Warn
    // on stderr (JSON stdout stays clean) and point at the inert-baseline
    // knobs. Non-fatal: a blocked baseline is still a usable reference for
    // some differentials, but the operator must know it is blocked.
    if baseline.0 >= 400 {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-fire: WARNING — baseline request returned status {} \
             (the baseline is itself blocked, likely the default payload tripping \
             the WAF). Divergence signals are measured against this blocked page; \
             a probe diverging to another error is not necessarily a bypass. For a \
             meaningful reference, set an inert baseline the WAF lets through via \
             --baseline-method / --baseline-body / --baseline-header.",
            baseline.0
        );
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut fired = 0usize;
    let frames_skipped = 0usize;
    let mut signal_counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

    // Pre-filter the probe list to honour --limit. Sets the upper
    // bound on what we fire — both sequential and parallel paths
    // operate on the same slice.
    let to_fire: Vec<_> = if args.limit > 0 {
        probes.into_iter().take(args.limit).collect()
    } else {
        probes
    };

    let reports: Vec<FireReport> = if args.parallel <= 1 {
        // Sequential path — respects --delay-ms.
        let mut acc = Vec::with_capacity(to_fire.len());
        for probe in to_fire {
            let report = run_one(&client, &args, baseline, probe.as_ref()).await;
            acc.push(report);
            if args.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(args.delay_ms)).await;
            }
        }
        acc
    } else {
        // Concurrent path — buffered up to args.parallel in-flight.
        // Reports come back in COMPLETION order.
        use futures_util::StreamExt;
        let parallel = args.parallel;
        let client = &client;
        let args_ref = &args;
        let baseline_ref = baseline;
        futures_util::stream::iter(to_fire)
            .map(|probe| async move {
                run_one(client, args_ref, baseline_ref, probe.as_ref()).await
            })
            .buffer_unordered(parallel)
            .collect()
            .await
    };

    // Optional bypasses-corpus sink — opened lazily so a permission
    // error surfaces with context instead of a generic IO panic.
    let mut bypasses_sink: Option<std::fs::File> = match &args.save_bypasses {
        Some(path) => match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => Some(f),
            Err(e) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "wafrift smuggle-fire: cannot open --save-bypasses {}: {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        },
        None => None,
    };

    let mut canary_reflected = 0usize;
    for report in reports {
        if !report.reflected_canaries.is_empty() {
            canary_reflected += 1;
        }
        let signal_key: &'static str = match report.bypass_signal.as_str() {
            "canary-reflected" => "canary-reflected",
            "none" => "none",
            "status-diverged" => "status-diverged",
            "body-diverged" => "body-diverged",
            "both-diverged" => "both-diverged",
            "error" => "error",
            _ => "other",
        };
        *signal_counts.entry(signal_key).or_insert(0) += 1;

        match serde_json::to_string(&report) {
            Ok(s) => {
                let _ = writeln!(out, "{s}");
                fired += 1;
                // Append to the bypasses corpus when this report
                // is a non-`none` signal (and not an error).
                let is_bypass = !matches!(report.bypass_signal.as_str(), "none" | "error");
                if is_bypass && let Some(sink) = bypasses_sink.as_mut() {
                    let _ = writeln!(sink, "{s}");
                }
            }
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "serialize error: {e}");
                return ExitCode::from(1);
            }
        }
    }

    if !args.no_summary {
        let summary = serde_json::json!({
            "kind": "summary",
            "target": &args.target,
            "fired": fired,
            "frames_skipped": frames_skipped,
            "baseline_status": baseline.0,
            "baseline_body_len": baseline.1,
            "canary_reflected": canary_reflected,
            "per_signal": signal_counts,
        });
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            serde_json::to_string(&summary).unwrap_or_default()
        );
    }

    if frames_skipped > 0 {
        let _ = writeln!(
            std::io::stderr(),
            "wafrift smuggle-fire: skipped {frames_skipped} frame-artifact probe(s) (can't ride reqwest)"
        );
    }
    ExitCode::SUCCESS
}

/// Load the set of techniques to prioritize from a saved-bypasses
/// NDJSON corpus. Each line is a [`FireReport`]-shaped JSON object;
/// we extract just the `technique` field. Returns the set of
/// techniques to front-load.
///
/// §15 OOM / TOCTOU fix: the old unbounded `read_to_string` on the
/// operator path had no size cap AND a stat()+open() TOCTOU race — a symlink swap between
/// size check and read could redirect to `/dev/zero` or a multi-GB file.
/// `safe_body::read_bounded_text_file` opens + reads in one fd with a
/// hard byte cap, closing both gaps at once.
fn load_priority_techniques(
    path: &std::path::Path,
) -> std::io::Result<std::collections::HashSet<String>> {
    // A saved-bypasses NDJSON corpus is at most a few hundred KB in
    // practice; 4 MiB is a generous cap that prevents `/dev/zero` OOM.
    const CORPUS_MAX_BYTES: usize = 4 * 1024 * 1024;
    let s = crate::safe_body::read_bounded_text_file(path, CORPUS_MAX_BYTES)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut out = std::collections::HashSet::new();
    for line in s.lines().filter(|l| !l.is_empty()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(t) = v["technique"].as_str()
        {
            out.insert(t.to_string());
        }
    }
    Ok(out)
}

/// Re-order the probe list so techniques in `priority` fire FIRST.
/// Within each group, the original aggregator order is preserved —
/// operators get reproducible iteration even after re-prioritisation.
fn reorder_priority_first(
    probes: Vec<Box<dyn SmuggleProbe>>,
    priority: &std::collections::HashSet<String>,
) -> Vec<Box<dyn SmuggleProbe>> {
    let (front, back): (Vec<_>, Vec<_>) = probes
        .into_iter()
        .partition(|p| priority.contains(&p.technique()));
    front.into_iter().chain(back).collect()
}

/// Fire one probe and build the [`FireReport`]. Used by both the
/// sequential and concurrent execution paths so the per-probe logic
/// (firing, classifying, reproducer rendering) lives in one place.
async fn run_one(
    client: &reqwest::Client,
    args: &SmuggleFireArgs,
    baseline: (u16, usize),
    probe: &dyn SmuggleProbe,
) -> FireReport {
    let tech = probe.technique();
    let canary = probe.canary().token.clone();
    let artifact = probe.artifact();

    let reproducer_curl = if args.include_reproducer {
        let extras: Vec<(String, String)> = if args.canary_header.is_empty() {
            Vec::new()
        } else {
            vec![(args.canary_header.clone(), canary.clone())]
        };
        crate::helpers::render_artifact_as_curl(&artifact, &args.target, &extras)
    } else {
        None
    };

    let t0 = Instant::now();
    let result = fire_one(client, args, &canary, &artifact).await;
    let latency_ms = t0.elapsed().as_millis();

    match result {
        Ok(outcome) => {
            let reflected = !outcome.reflected_canaries.is_empty();
            let signal = smuggle_transport::classify_with_reflection(
                outcome.status,
                outcome.body_len,
                baseline.0,
                baseline.1,
                args.body_divergence_threshold,
                reflected,
            );
            FireReport {
                technique: tech,
                canary,
                status: outcome.status,
                body_len: outcome.body_len,
                latency_ms,
                baseline_status: baseline.0,
                baseline_body_len: baseline.1,
                bypass_signal: signal.to_string(),
                reflected_canaries: outcome.reflected_canaries,
                error: None,
                reproducer_curl,
            }
        }
        Err(e) => FireReport {
            technique: tech,
            canary,
            status: 0,
            body_len: 0,
            latency_ms,
            baseline_status: baseline.0,
            baseline_body_len: baseline.1,
            bypass_signal: "error".into(),
            reflected_canaries: Vec::new(),
            error: Some(e),
            reproducer_curl,
        },
    }
}

/// Fire ONE smuggle probe via the shared transport. Converts a
/// [`SmuggleArtifact`] into the (headers, body) shape that
/// [`smuggle_transport::fire_smuggle_request`] expects. Frame
/// artifacts are not transportable via reqwest — the caller filters
/// those out before reaching this function.
async fn fire_one(
    client: &reqwest::Client,
    args: &SmuggleFireArgs,
    canary: &str,
    artifact: &SmuggleArtifact,
) -> Result<smuggle_transport::FireOutcome, String> {
    let canary_header_name = if args.canary_header.is_empty() {
        None
    } else {
        Some(args.canary_header.as_str())
    };
    let canaries_owned = vec![canary.to_string()];
    let canaries_slice: &[String] = if canary_header_name.is_some() {
        &canaries_owned
    } else {
        &[]
    };
    match artifact {
        SmuggleArtifact::Headers(hs) => {
            smuggle_transport::fire_smuggle_request(
                client,
                &args.target,
                hs,
                None,
                canary_header_name,
                canaries_slice,
            )
            .await
        }
        SmuggleArtifact::BodyWithContentType { content_type, body } => {
            smuggle_transport::fire_smuggle_request(
                client,
                &args.target,
                &[],
                Some((content_type.as_str(), body.as_slice())),
                canary_header_name,
                canaries_slice,
            )
            .await
        }
        SmuggleArtifact::Frames(_) => Err("frame artifact cannot ride reqwest".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_resolve_keeps_target_host_and_uses_https_port() {
        let (host, addr) =
            origin_resolve_override("https://protected.example.com/admin", "203.0.113.7")
                .expect("valid https target + IPv4 origin");
        // Anti-rig: the pinned Host MUST stay the real target, never the
        // origin IP — keeping Host+SNI on the target while connecting to
        // the origin IS the WAF go-around. If this ever flips, the probe
        // would hit the origin's default vhost and silently stop testing
        // the intended host.
        assert_eq!(host, "protected.example.com");
        assert_eq!(addr.ip(), "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 443, "https scheme default port");
    }

    #[test]
    fn origin_resolve_uses_http_default_port() {
        let (_host, addr) = origin_resolve_override("http://insecure.example.com/", "198.51.100.9")
            .expect("valid http target");
        assert_eq!(addr.port(), 80, "http scheme default port");
    }

    #[test]
    fn origin_resolve_honours_explicit_url_port() {
        let (_host, addr) = origin_resolve_override("https://example.com:8443/x", "203.0.113.7")
            .expect("explicit port target");
        assert_eq!(
            addr.port(),
            8443,
            "explicit URL port must override the scheme default"
        );
    }

    #[test]
    fn origin_resolve_accepts_ipv6_origin() {
        let (host, addr) =
            origin_resolve_override("https://example.com/", "2001:db8::1").expect("IPv6 origin");
        assert_eq!(host, "example.com");
        assert!(addr.is_ipv6(), "IPv6 origin yields an IPv6 socket addr");
    }

    #[test]
    fn origin_resolve_rejects_out_of_range_ip() {
        let err = origin_resolve_override("https://example.com/", "999.999.0.1")
            .expect_err("octet > 255 is not a valid IP");
        assert!(err.contains("origin-ip"), "error names the flag: {err}");
    }

    #[test]
    fn origin_resolve_rejects_non_ip_origin() {
        let err = origin_resolve_override("https://example.com/", "origin.example.org")
            .expect_err("a hostname is not an IP — must be resolved first");
        assert!(err.contains("valid IP address"), "{err}");
    }

    #[test]
    fn origin_resolve_rejects_unparseable_target() {
        let err =
            origin_resolve_override("not a url", "203.0.113.7").expect_err("garbage target URL");
        assert!(err.contains("valid URL"), "{err}");
    }

    #[test]
    fn origin_resolve_rejects_target_without_host() {
        let err = origin_resolve_override("mailto:admin@example.com", "203.0.113.7")
            .expect_err("a host-less URL has nothing to pin");
        assert!(err.contains("no host"), "{err}");
    }
}
