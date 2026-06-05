use clap::Args;
use futures_util::StreamExt;
use serde::Serialize;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_recon::active::{ActiveProbeConfig, StackTag, probe_http_headers};
use wafrift_recon::{discover_subdomains_ct, resolve_origins};

/// Hard cap on concurrent active probes — keeps the recon step from
/// hammering crt.sh-discovered subdomains in parallel (anti-DoS) and
/// keeps the local fd budget bounded on large domains with hundreds
/// of subdomains.
const PROBE_CONCURRENCY_MAX: usize = 32;

#[derive(Args, Debug)]
pub(crate) struct ReconArgs {
    /// Target domain to discover origin IPs for (e.g., example.com).
    #[arg(long)]
    pub domain: String,

    /// Output format. `text` (default) is human-friendly with hints;
    /// `json` is a stable, machine-parseable surface for piping into
    /// jq, ansible, or downstream automation. JSON mode emits the full
    /// schema including a `probes` array when `--probe` is set (text
    /// mode prints the same data in human-readable form but only JSON
    /// is guaranteed machine-stable).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Manual subdomain list (comma-separated) to use INSTEAD of the
    /// CT-log discovery step. Use when crt.sh is rate-limiting or
    /// returning 5xx (dogfood report: hard-fail with no fallback was
    /// a dead end for the operator). Combine with `--probe` to run
    /// just the active-fingerprint half: `wafrift recon --domain
    /// example.com --subdomains api.example.com,login.example.com
    /// --probe`. Skips DNS resolution too — the subdomains you pass
    /// in are used verbatim for active probing.
    #[arg(long, value_delimiter = ',')]
    pub subdomains: Vec<String>,

    /// After CT-log discovery (or `--subdomains`), actively probe each
    /// subdomain for WAF/CDN/framework fingerprints via the same HTTP
    /// header classification used by `wafrift detect`. Off by default
    /// to keep `recon` a passive operation. When enabled, probes are
    /// rate-limited by `--probe-concurrency` and `--probe-timeout-secs`.
    #[arg(long, default_value_t = false)]
    pub probe: bool,

    /// Per-probe HTTP timeout (connect + headers + body). Only used
    /// when `--probe` is set.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=120))]
    pub probe_timeout_secs: u64,

    /// Max concurrent active probes. Clamped to [1, PROBE_CONCURRENCY_MAX].
    /// Only used when `--probe` is set.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..=PROBE_CONCURRENCY_MAX as i64))]
    pub probe_concurrency: u32,
}

#[derive(Serialize)]
struct ReconReport<'a> {
    schema_version: u32,
    wafrift_version: &'static str,
    domain: &'a str,
    subdomains: Vec<String>,
    origin_ips: Vec<String>,
    /// Per-subdomain active fingerprint results. Only emitted when
    /// `--probe` is set. Probes that errored (DNS failure, timeout,
    /// TLS failure) are still listed with an `error` field — anti-rig:
    /// a silently-dropped probe must not look like a clean unfingerprinted
    /// host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    probes: Vec<ProbeResult>,
}

/// One active-probe outcome per subdomain. JSON schema is stable —
/// either `tags` is populated and `error` is None, or vice versa.
#[derive(Serialize)]
struct ProbeResult {
    subdomain: String,
    /// HTTPS first, falls back to HTTP only on bare connection refusal.
    url: String,
    /// HTTP response status when the probe completed. None on transport error.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    /// Matched WAF/CDN/framework rule tags. Empty if no rules fired.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<StackTag>,
    /// Transport-level failure message. None on probe success.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// LAW 2: `probes` is an additive field (skipped when empty). Schema
/// version stays at 1 — old consumers that don't read `probes`
/// continue to parse the output unchanged.
const RECON_SCHEMA_VERSION: u32 = 1;

pub(crate) fn run_recon(args: ReconArgs) -> ExitCode {
    // §7 DEDUPLICATION: delegate to the canonical runtime helper so the
    // 6-line match-Runtime::new boilerplate lives in exactly one place.
    crate::helpers::block_on_with_runtime(run_recon_async(args))
}

async fn run_recon_async(args: ReconArgs) -> ExitCode {
    {
        let json_mode = args.format == "json";
        let manual_subdomains = !args.subdomains.is_empty();
        if !json_mode {
            if manual_subdomains {
                println!(
                    "🔍 Using {} manually-supplied subdomain(s) (skipping CT discovery): {}",
                    args.subdomains.len(),
                    args.domain
                );
            } else {
                println!("🔍 Starting discovery for domain: {}", args.domain);
            }
        }

        let subdomains = if manual_subdomains {
            // Dogfood UX-4: when crt.sh is rate-limiting or 5xx-ing,
            // the operator can pass the list directly via `--subdomains`.
            // Trim whitespace per entry, drop empties.
            args.subdomains
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            match discover_subdomains_ct(&args.domain).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("✗ CT log discovery failed: {e}");
                    eprintln!(
                        "  hint: when crt.sh is unavailable, supply subdomains directly: --subdomains a.{0},b.{0}",
                        args.domain
                    );
                    return ExitCode::from(1);
                }
            }
        };

        if !json_mode {
            println!("✓ Found {} potential subdomains.", subdomains.len());
            for sub in &subdomains {
                println!("  - {sub}");
            }
            // §13 dogfood round-2 DEFECT 7: a SUCCESSFUL crt.sh query that
            // returns zero subdomains is ambiguous — the domain may genuinely
            // have no Certificate Transparency entries, OR crt.sh returned an
            // empty 200 under load. The bare "✓ Found 0" reads as "recon
            // complete, nothing exists", hiding the possible crt.sh flake.
            // Disambiguate and point at the --subdomains fallback. (The Err
            // path above already hints when crt.sh outright fails; this covers
            // the empty-but-OK case it can't see.)
            if subdomains.is_empty() && !manual_subdomains {
                eprintln!(
                    "  note: 0 subdomains from crt.sh — either {0} has no \
                     Certificate Transparency entries, or crt.sh returned an \
                     empty result under load. To probe known hosts directly, \
                     pass --subdomains a.{0},b.{0} (optionally with --probe).",
                    args.domain
                );
            }
        }

        // Skip DNS resolution when the operator supplied subdomains
        // directly — they typically already know the IPs and want
        // straight to active probing.
        let ips = if subdomains.is_empty() || manual_subdomains {
            Vec::new()
        } else {
            if !json_mode {
                println!("\n🔍 Resolving subdomains to identify potential origin IPs...");
            }
            match resolve_origins(&subdomains).await {
                Ok(ips) => {
                    if !json_mode {
                        if ips.is_empty() {
                            println!("⚠ No IPs resolved.");
                        } else {
                            println!("✓ Found {} origin IPs:", ips.len());
                            for ip in &ips {
                                println!("  - {ip}");
                            }
                        }
                    }
                    ips
                }
                Err(e) => {
                    eprintln!("✗ Resolution failed: {e}");
                    return ExitCode::from(1);
                }
            }
        };

        let probes = if args.probe && !subdomains.is_empty() {
            if !json_mode {
                println!(
                    "\n🛡  Active-probing {} subdomain(s) for WAF/CDN/framework fingerprints (concurrency={}, timeout={}s)...",
                    subdomains.len(),
                    args.probe_concurrency,
                    args.probe_timeout_secs,
                );
            }
            let probe_cfg = ActiveProbeConfig {
                http_timeout: Duration::from_secs(args.probe_timeout_secs),
                ..ActiveProbeConfig::default()
            };
            let probe_concurrency =
                (args.probe_concurrency as usize).clamp(1, PROBE_CONCURRENCY_MAX);
            run_active_probes(&subdomains, &probe_cfg, probe_concurrency).await
        } else {
            Vec::new()
        };

        if !json_mode && !probes.is_empty() {
            println!("\n✓ Active probe results:");
            for p in &probes {
                if let Some(err) = &p.error {
                    println!("  - {}: ✗ {err}", p.subdomain);
                } else if p.tags.is_empty() {
                    println!(
                        "  - {}: status {} — no WAF/CDN/framework signature matched",
                        p.subdomain,
                        p.status.unwrap_or(0)
                    );
                } else {
                    let tag_strs: Vec<String> = p
                        .tags
                        .iter()
                        .map(|t| format!("{:?}:{}", t.family, t.id))
                        .collect();
                    println!(
                        "  - {}: status {} — {}",
                        p.subdomain,
                        p.status.unwrap_or(0),
                        tag_strs.join(", ")
                    );
                }
            }
        }

        if json_mode {
            let report = ReconReport {
                schema_version: RECON_SCHEMA_VERSION,
                wafrift_version: env!("CARGO_PKG_VERSION"),
                domain: &args.domain,
                subdomains,
                origin_ips: ips,
                probes,
            };
            match serde_json::to_string_pretty(&report) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("✗ Failed to serialize JSON: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        ExitCode::SUCCESS
    }
}

/// Probe every subdomain via HTTPS GET, classifying response headers
/// against the embedded `HeaderRules` (WAF/CDN/framework signatures).
///
/// Concurrency-bounded by `buffer_unordered(concurrency)` — at most
/// `concurrency` probes are in flight at any moment, so a 200-subdomain
/// CT result doesn't blow the local fd budget or hammer the targets.
///
/// Probe failures are returned as `ProbeResult` entries with `error`
/// populated — anti-rig: a silently dropped probe must not look like
/// a clean unfingerprinted host.
async fn run_active_probes(
    subdomains: &[String],
    cfg: &ActiveProbeConfig,
    concurrency: usize,
) -> Vec<ProbeResult> {
    let mut stream = futures_util::stream::iter(subdomains.iter().cloned())
        .map(|sub| async move {
            let url = format!("https://{sub}/");
            match probe_http_headers(&url, cfg).await {
                Ok(snap) => ProbeResult {
                    subdomain: sub,
                    url,
                    status: Some(snap.status),
                    tags: snap.tags,
                    error: None,
                },
                Err(e) => ProbeResult {
                    subdomain: sub,
                    url,
                    status: None,
                    tags: Vec::new(),
                    error: Some(e.to_string()),
                },
            }
        })
        .buffer_unordered(concurrency);
    let mut out = Vec::with_capacity(subdomains.len());
    while let Some(result) = stream.next().await {
        out.push(result);
    }
    // Stable ordering for deterministic JSON output across runs.
    out.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_recon::active::TagFamily;

    /// Anti-rig pin (LAW 2): the JSON `probes` field is OMITTED when
    /// no active probes ran. A passive `wafrift recon` invocation
    /// emits the same shape it did before the probe wiring landed,
    /// so existing downstream parsers don't break.
    #[test]
    fn probes_field_omitted_when_empty() {
        let r = ReconReport {
            schema_version: RECON_SCHEMA_VERSION,
            wafrift_version: "test",
            domain: "example.com",
            subdomains: vec!["a.example.com".into()],
            origin_ips: vec!["10.0.0.1".into()],
            probes: Vec::new(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("probes"), "empty probes must not appear: {s}");
    }

    /// Anti-rig pin (LAW 2): when probes ran, the `probes` field IS
    /// emitted with the documented sub-schema (subdomain + url + status
    /// or error + tags).
    #[test]
    fn probes_field_emitted_when_present() {
        let r = ReconReport {
            schema_version: RECON_SCHEMA_VERSION,
            wafrift_version: "test",
            domain: "example.com",
            subdomains: vec!["a.example.com".into()],
            origin_ips: vec![],
            probes: vec![ProbeResult {
                subdomain: "a.example.com".into(),
                url: "https://a.example.com/".into(),
                status: Some(403),
                tags: vec![StackTag {
                    family: TagFamily::Waf,
                    id: "cloudflare".into(),
                }],
                error: None,
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"probes\""), "expected probes field: {s}");
        assert!(s.contains("\"cloudflare\""));
        assert!(s.contains("\"status\":403"));
    }

    /// LAW 12 boundary test: a transport-failed probe MUST include the
    /// error string and omit status/tags — anti-rig: a silently dropped
    /// probe must not look like a clean unfingerprinted host.
    #[test]
    fn probe_error_serialises_with_error_only() {
        let p = ProbeResult {
            subdomain: "down.example.com".into(),
            url: "https://down.example.com/".into(),
            status: None,
            tags: Vec::new(),
            error: Some("connection refused".into()),
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"error\":\"connection refused\""));
        assert!(!s.contains("\"status\""));
        assert!(!s.contains("\"tags\""));
    }

    /// LAW 12 pin: the concurrency cap is a fixed safety boundary —
    /// a silent re-tune up would expose the recon step to fd-exhaustion
    /// on large CT-log discoveries. If this constant changes, the bump
    /// must be deliberate.
    #[test]
    fn probe_concurrency_max_is_pinned() {
        assert_eq!(PROBE_CONCURRENCY_MAX, 32);
    }

    /// LAW 2 pin: schema version stays at 1 — the `probes` field is
    /// additive and skipped when absent, so old consumers still parse.
    #[test]
    fn recon_schema_version_stable() {
        assert_eq!(RECON_SCHEMA_VERSION, 1);
    }

    /// Dogfood UX-4 regression: `wafrift recon --subdomains a,b,c` must
    /// be parsable as a Vec<String>. The `--subdomains` flag is the
    /// operator's escape hatch when crt.sh is down — if it stops
    /// parsing comma-lists, the whole fallback path breaks.
    #[test]
    fn subdomains_flag_parses_comma_separated() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct Wrapper {
            #[command(flatten)]
            args: ReconArgs,
        }
        let parsed = Wrapper::try_parse_from([
            "test",
            "--domain",
            "example.com",
            "--subdomains",
            "a.example.com,b.example.com,c.example.com",
        ])
        .expect("--subdomains comma-list must parse");
        assert_eq!(parsed.args.subdomains.len(), 3);
        assert_eq!(parsed.args.subdomains[0], "a.example.com");
        assert_eq!(parsed.args.subdomains[2], "c.example.com");
    }

    /// Default state: --subdomains omitted → empty Vec → CT discovery
    /// path runs. Pin the default so a silent flip (e.g. someone
    /// setting `default_values` to a magic list) can't change the
    /// recon flow.
    #[test]
    fn subdomains_default_is_empty_so_ct_path_runs() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct Wrapper {
            #[command(flatten)]
            args: ReconArgs,
        }
        let parsed = Wrapper::try_parse_from(["test", "--domain", "example.com"]).unwrap();
        assert!(parsed.args.subdomains.is_empty());
    }
}
