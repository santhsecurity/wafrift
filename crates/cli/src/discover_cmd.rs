//! `wafrift discover` — surface the `OpenAPI` / GraphQL / parameter-mining
//! engines as a single CLI command. Output is a list of
//! `DiscoveredEndpoint`s suitable for piping into `wafrift scan
//! --from-discovery <file>`.
//!
//! All three modes can run together; results are concatenated and
//! deduplicated by `(method, url)`.

use clap::Args;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_recon::discovery::graphql::from_graphql;
use wafrift_recon::discovery::openapi::{DiscoveryError, from_openapi};
use wafrift_recon::discovery::param_miner::{MiningConfig, mine_params};
use wafrift_types::discovery::DiscoveredEndpoint;

/// OpenAPI/Swagger specs in the wild are kilobytes to a couple of
/// megabytes. 16 MiB is generous (catches `--spec /dev/zero`, a
/// hostile symlink, or a runaway-generated spec) without blocking
/// any legitimate document.
const OPENAPI_SPEC_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Param-mining wordlists CAN be large — rockyou.txt is ~130 MiB,
/// SecLists has files up to ~200 MiB. 256 MiB matches cluster_cmd's
/// bench-grade cap: real wordlists fit; `--wordlist /dev/zero` /
/// multi-GB accident / symlink trap do not.
const WORDLIST_MAX_BYTES: usize = 256 * 1024 * 1024;

#[derive(Args, Debug)]
pub(crate) struct DiscoverArgs {
    /// Target URL (used by --introspect and --mine-params).
    /// Required when either of those modes is enabled. Ignored by --spec.
    /// Accepts `--url` as an alias for consistency with every other
    /// command (`detect --url`, `scan --target`, `attack --url` …).
    #[arg(long, alias = "url")]
    pub target: Option<String>,

    /// Path to an `OpenAPI` 2.0 (Swagger) or 3.x JSON spec file. The
    /// spec's `paths.<path>.<method>` entries become discovered
    /// endpoints; parameters become injection points (Query / Path /
    /// Header / Cookie / Body, with media-type-aware context inference
    /// for request bodies).
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// POST a GraphQL introspection query to --target and emit one
    /// endpoint per top-level field on Query / Mutation / Subscription.
    /// Returns `IntrospectionDisabled` if the server blocks introspection.
    #[arg(long, default_value_t = false)]
    pub introspect: bool,

    /// Differential parameter mining: collect a baseline, then probe
    /// each candidate from --wordlist. Hits are flagged when the
    /// response status / body length / latency diverges from the
    /// baseline beyond the configured thresholds.
    #[arg(long, default_value_t = false)]
    pub mine_params: bool,

    /// Newline-delimited wordlist file for --mine-params. Required when
    /// that mode is enabled. Common picks: `SecLists`' burp-parameter-names.
    #[arg(long)]
    pub wordlist: Option<PathBuf>,

    /// Concurrency cap for --mine-params probes (default 8).
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Per-worker delay between consecutive --mine-params probes (ms).
    #[arg(long, default_value_t = crate::DEFAULT_DELAY_MS)]
    pub delay_ms: u64,

    /// Number of baseline requests for --mine-params (default 5). More
    /// = tighter envelope, slower start.
    #[arg(long, default_value_t = 5)]
    pub baseline_requests: usize,

    /// Body-length divergence threshold for --mine-params (fraction;
    /// default 0.10 = ±10%). Lower = more sensitive, more false positives.
    #[arg(long, default_value_t = 0.10)]
    pub body_length_threshold: f64,

    /// Response-time divergence threshold for --mine-params (ms;
    /// default 500). A candidate's median latency must exceed the
    /// baseline median by this many ms to flag.
    #[arg(long, default_value_t = 500)]
    pub response_time_threshold_ms: u64,

    /// Output format. `text` (default) is human-friendly; `json` is a
    /// stable, machine-parseable surface piped into `wafrift scan
    /// --from-discovery`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Write JSON output to this file instead of stdout. Refuses
    /// to clobber an existing file unless `--force-overwrite` is
    /// set (R50 pass-12 I7).
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Override the --output overwrite guard.
    #[arg(long, default_value_t = false)]
    pub force_overwrite: bool,

    /// Per-request HTTP timeout in seconds for introspect / mine-params
    /// probes. 0 = use `DEFAULT_REQUEST_TIMEOUT_SECS`. Can be overridden
    /// by `.wafrift.toml`'s `http.timeout_secs` when the flag is not
    /// passed explicitly.
    #[arg(long, default_value_t = 0)]
    pub timeout_secs: u64,

    /// Disable TLS certificate verification for HTTPS targets.
    /// Equivalent to `curl --insecure`. Can be overridden by
    /// `.wafrift.toml`'s `http.insecure` when the flag is not
    /// passed explicitly.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
}

#[derive(Serialize)]
struct DiscoverReport<'a> {
    schema_version: u32,
    wafrift_version: &'static str,
    target: Option<&'a str>,
    sources: Vec<&'static str>,
    endpoints: Vec<DiscoveredEndpoint>,
}

const DISCOVER_SCHEMA_VERSION: u32 = 1;

pub(crate) fn run_discover(mut args: DiscoverArgs) -> ExitCode {
    if let Some(ref t) = args.target.clone() {
        args.target = Some(crate::helpers::normalize_target_url(t));
    }
    if args.spec.is_none() && !args.introspect && !args.mine_params {
        eprintln!(
            "error: discover requires at least one of --spec, --introspect, --mine-params\n\
             Examples:\n  \
             wafrift discover --spec api.json\n  \
             wafrift discover --target https://api.example.com/graphql --introspect\n  \
             wafrift discover --target https://example.com/search --mine-params --wordlist params.txt"
        );
        return ExitCode::from(2);
    }
    if (args.introspect || args.mine_params) && args.target.is_none() {
        eprintln!("error: --introspect and --mine-params require --target");
        return ExitCode::from(2);
    }
    if args.mine_params && args.wordlist.is_none() {
        eprintln!("error: --mine-params requires --wordlist <path>");
        return ExitCode::from(2);
    }

    // §7 DEDUPLICATION: delegate to the canonical runtime helper so the
    // 6-line match-Runtime::new boilerplate lives in exactly one place.
    crate::helpers::block_on_with_runtime(run_discover_async(args))
}

async fn run_discover_async(args: DiscoverArgs) -> ExitCode {
    {
        let mut endpoints = Vec::new();
        let mut sources: Vec<&'static str> = Vec::new();
        // Track per-source failures so a silent `warn:` from one
        // source doesn't get hidden when its sibling produced 0
        // endpoints either. If every requested source failed to
        // produce anything actionable, return exit 1 — an empty
        // result with SUCCESS exit code is indistinguishable from
        // "ran fine, found nothing" and corrupts CI pipelines.
        let mut warnings: usize = 0;

        if let Some(spec_path) = &args.spec {
            sources.push("openapi");
            #[rustfmt::skip]
            let raw_result = crate::safe_body::read_bounded_text_file(
                spec_path,
                OPENAPI_SPEC_MAX_BYTES,
            );
            let raw = match raw_result {
                Ok(s) => s,
                Err(e) => {
                    return crate::helpers::input_error(format!(
                        "read {}: {e}",
                        spec_path.display()
                    ));
                }
            };
            match from_openapi(&raw) {
                Ok(eps) => endpoints.extend(eps),
                Err(e) => {
                    return crate::helpers::input_error(format!(
                        "parse {}: {e}",
                        spec_path.display()
                    ));
                }
            }
        }

        if args.introspect || args.mine_params {
            // Build a reqwest client: honour --timeout-secs / --insecure
            // flags (and their .wafrift.toml equivalents applied before
            // run_discover is called). Fall back to DEFAULT_REQUEST_TIMEOUT_SECS
            // when the flag was left at 0 so recon doesn't hang on a slow
            // upstream without an explicit cap.
            let timeout_secs = if args.timeout_secs > 0 {
                args.timeout_secs
            } else {
                wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS
            };
            let scan_identity = match crate::config::shared_scan_browser_headers(None) {
                Ok(identity) => identity,
                Err(e) => {
                    eprintln!("error: build shared browser headers: {e}");
                    return ExitCode::from(1);
                }
            };
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .danger_accept_invalid_certs(args.insecure)
                // §15 SSRF: don't follow redirects. Without this, reqwest's
                // default chases up to 10 redirects to ANY host, so a discovery
                // target answering `302 → http://169.254.169.254/` walks the
                // introspection/param-mining probes into cloud metadata /
                // RFC1918. Discovery wants the target's DIRECT response anyway
                // (a redirect would also confound param-mining's length diff).
                .redirect(reqwest::redirect::Policy::none())
                .default_headers(scan_identity.headers)
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: build http client: {e}");
                    return ExitCode::from(1);
                }
            };
            let Some(target) = args.target.as_deref() else {
                eprintln!("error: --target is required for discovery");
                return ExitCode::from(1);
            };

            if args.introspect {
                sources.push("graphql");
                match from_graphql(target, &client).await {
                    Ok(eps) => endpoints.extend(eps),
                    Err(e) => {
                        eprintln!("warn: graphql introspection failed: {e}");
                        warnings += 1;
                        // Don't fail the whole command yet — introspection-
                        // disabled is informative, not immediately fatal.
                        // The end-of-run check converts "all sources failed
                        // and no endpoints" into a non-zero exit so CI can
                        // see the difference between "found nothing" and
                        // "every source errored."
                    }
                }
            }

            if args.mine_params {
                sources.push("mine");
                let Some(words_path) = args.wordlist.as_ref() else {
                    eprintln!("error: --wordlist is required for --mine-params");
                    return ExitCode::from(1);
                };
                let words = match crate::safe_body::read_bounded_text_file(
                    words_path,
                    WORDLIST_MAX_BYTES,
                ) {
                    Ok(s) => s
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        return crate::helpers::input_error(format!(
                            "read wordlist {}: {e}",
                            words_path.display()
                        ));
                    }
                };
                if words.is_empty() {
                    eprintln!("error: wordlist is empty");
                    return ExitCode::from(2);
                }
                let cfg = MiningConfig {
                    concurrency: args.concurrency,
                    delay_ms: args.delay_ms,
                    baseline_requests: args.baseline_requests,
                    body_length_threshold: args.body_length_threshold,
                    response_time_threshold_ms: args.response_time_threshold_ms,
                };
                match mine_params(target, &client, &words, &cfg).await {
                    Ok(eps) => endpoints.extend(eps),
                    Err(DiscoveryError::WordlistEmpty) => {
                        eprintln!("error: wordlist contained no candidates");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("warn: param mining failed: {e}");
                        warnings += 1;
                    }
                }
            }
        }

        // Merge by (method, url) — order-preserving, injection-point
        // accumulating. Naive `retain(|e| seen.insert(key))` discards
        // the second occurrence's `injection_points`, so if two
        // sources (e.g. openapi spec + mine_params) hit the same URL,
        // the second source's parameters silently disappear. Instead
        // we merge: same key → extend the existing endpoint's
        // injection_points, deduped on (name, location).
        let merged = {
            use std::collections::HashMap;
            let mut order: Vec<(wafrift_types::Method, String)> = Vec::new();
            let mut by_key: HashMap<(wafrift_types::Method, String), DiscoveredEndpoint> =
                HashMap::new();
            for ep in endpoints.drain(..) {
                let key = (ep.method.clone(), ep.url.clone());
                if let Some(existing) = by_key.get_mut(&key) {
                    for ip in ep.injection_points {
                        let dup = existing
                            .injection_points
                            .iter()
                            .any(|x| x.name == ip.name && x.location == ip.location);
                        if !dup {
                            existing.injection_points.push(ip);
                        }
                    }
                } else {
                    order.push(key.clone());
                    by_key.insert(key, ep);
                }
            }
            order
                .into_iter()
                .filter_map(|k| by_key.remove(&k))
                .collect::<Vec<_>>()
        };
        endpoints = merged;

        // F124: per-source warning + zero-output → non-zero exit.
        // Applies BEFORE the format branch so the JSON path is also
        // gated. The print order (still print JSON / text, then bump
        // exit code) lets CI grep the actual output while the wrapper
        // sees the non-zero status.
        let abort_due_to_silent_failure = warnings > 0 && endpoints.is_empty();
        if abort_due_to_silent_failure {
            eprintln!(
                "discover: {warnings} source(s) failed and 0 endpoints produced — exiting non-zero"
            );
        }

        match args.format.as_str() {
            "json" => {
                let report = DiscoverReport {
                    schema_version: DISCOVER_SCHEMA_VERSION,
                    wafrift_version: env!("CARGO_PKG_VERSION"),
                    target: args.target.as_deref(),
                    sources,
                    endpoints,
                };
                let ok_exit = if abort_due_to_silent_failure {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                };
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => match args.output.as_ref() {
                        Some(p) => {
                            // R50 pass-12 I7 (CLAUDE.md §7 + §15):
                            // shared overwrite guard. Pre-fix
                            // discover --output silently clobbered
                            // an existing file; CI pipelines that
                            // re-ran discover overwrote their first
                            // result with no warning.
                            if let Err(msg) = crate::helpers::confirm_output_overwrite_safe(
                                p,
                                args.force_overwrite,
                            ) {
                                eprintln!("error: {msg}");
                                return ExitCode::from(2);
                            }
                            match std::fs::write(p, &s) {
                                Ok(()) => {
                                    eprintln!(
                                        "wrote {} bytes ({} endpoint(s)) → {}",
                                        s.len(),
                                        report.endpoints.len(),
                                        p.display()
                                    );
                                    ok_exit
                                }
                                Err(e) => {
                                    eprintln!("error: write {}: {e}", p.display());
                                    ExitCode::from(1)
                                }
                            }
                        }
                        None => {
                            println!("{s}");
                            ok_exit
                        }
                    },
                    Err(e) => {
                        eprintln!("error: serialize: {e}");
                        ExitCode::from(1)
                    }
                }
            }
            _ => {
                println!(
                    "Discovered {} endpoint(s) from {}.",
                    endpoints.len(),
                    if sources.is_empty() {
                        "(no sources)".to_string()
                    } else {
                        sources.join(" + ")
                    }
                );
                for ep in &endpoints {
                    println!(
                        "  {:?} {}  ({} injection point(s), source={:?})",
                        ep.method,
                        ep.url,
                        ep.injection_points.len(),
                        ep.source,
                    );
                    for ip in &ep.injection_points {
                        println!(
                            "      - {} [{:?}, ctx={:?}{}]",
                            ip.name,
                            ip.location,
                            ip.context,
                            if ip.required { ", required" } else { "" }
                        );
                    }
                }
                if endpoints.is_empty() {
                    println!(
                        "\nhint: 0 endpoints — for --mine-params try lowering --body-length-threshold,\n      \
                         for --introspect check that the GraphQL server allows __schema queries"
                    );
                }
                if abort_due_to_silent_failure {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

#[cfg(test)]
mod round17_bounded_input_tests {
    //! Round 17 regression: `discover --spec <PATH>` and
    //! `discover --wordlist <PATH>` previously slurped the operator-
    //! supplied file with `std::fs::read_to_string`, which OOMs the
    //! process on `--spec /dev/zero`, a hostile symlink to a
    //! multi-GB file, or any rockyou-sized accident. Both reads
    //! must go through `safe_body::read_bounded_text_file` with
    //! the per-source caps defined above.
    //!
    //! Both tests use `concat!()` to embed the needle so the test
    //! source itself does not contain the literal string being
    //! searched for — without that, the assertion would be a
    //! tautology (test source contains needle, src contains test
    //! source, src "contains" needle).
    use super::{OPENAPI_SPEC_MAX_BYTES, WORDLIST_MAX_BYTES};

    #[test]
    fn discover_spec_read_is_bounded() {
        let src = include_str!("discover_cmd.rs");
        let needle = concat!(
            "safe_body::read_bounded_text_file(\n",
            "                spec_path,\n",
            "                OPENAPI_SPEC_MAX_BYTES,\n",
            "            )"
        );
        assert!(
            src.contains(needle),
            "discover_cmd.rs must read --spec through bounded reader \
             with OPENAPI_SPEC_MAX_BYTES — unbounded read regression"
        );
        // concat!() avoids embedding the literal in the test source,
        // which would otherwise be a tautology via include_str! self-
        // reference.
        let banned = concat!("std::fs::", "read_to_", "string(spec_", "path)");
        assert!(
            !src.contains(banned),
            "raw unbounded fs read of spec_path reintroduced — OOM regression"
        );
    }

    #[test]
    fn discover_wordlist_read_is_bounded() {
        let src = include_str!("discover_cmd.rs");
        let needle = concat!(
            "safe_body::read_bounded_text_file(\n",
            "                    words_path,\n",
            "                    WORDLIST_MAX_BYTES,\n",
            "                )"
        );
        assert!(
            src.contains(needle),
            "discover_cmd.rs must read --wordlist through bounded reader \
             with WORDLIST_MAX_BYTES — unbounded read regression"
        );
        let banned = concat!("std::fs::", "read_to_", "string(words_", "path)");
        assert!(
            !src.contains(banned),
            "raw unbounded fs read of words_path reintroduced — OOM regression"
        );
    }

    #[test]
    fn bounded_file_read_reports_overrun_when_cap_exceeded() {
        // Sanity: confirm the primitive we depend on actually
        // refuses to slurp past its cap. If safe_body ever loses
        // the Overrun behaviour, both fixes above become silent
        // no-ops — this test catches that.
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wafrift-discover-overrun-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        {
            let mut f = std::fs::File::create(&path).expect("create tmp");
            f.write_all(&vec![b'a'; 4096]).expect("write tmp");
        }
        let res = crate::safe_body::read_bounded_text_file(&path, 256);
        let _ = std::fs::remove_file(&path);
        match res {
            Err(crate::safe_body::ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            }) => {
                assert_eq!(cap_bytes, 256);
                assert!(observed_bytes > cap_bytes, "observed must exceed cap");
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
    }

    #[test]
    fn caps_are_sane_for_real_world_inputs() {
        // OpenAPI: typical specs are <10 MiB even for huge schemas.
        // Wordlist: rockyou.txt = ~133 MiB. Both caps must comfortably
        // exceed those — if anyone ever tightens them below, fail loud.
        assert!(
            OPENAPI_SPEC_MAX_BYTES >= 8 * 1024 * 1024,
            "OPENAPI_SPEC_MAX_BYTES tightened below 8 MiB — would reject legitimate specs"
        );
        assert!(
            WORDLIST_MAX_BYTES >= 200 * 1024 * 1024,
            "WORDLIST_MAX_BYTES tightened below 200 MiB — would reject rockyou-sized wordlists"
        );
    }
}
