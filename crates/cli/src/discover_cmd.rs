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

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Target URL (used by --introspect and --mine-params).
    /// Required when either of those modes is enabled. Ignored by --spec.
    #[arg(long)]
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
    #[arg(long, default_value_t = 50)]
    pub delay_ms: u64,

    /// Number of baseline requests for --mine-params (default 5). More
    /// = tighter envelope, slower start.
    #[arg(long, default_value_t = 5)]
    pub baseline_requests: usize,

    /// Output format. `text` (default) is human-friendly; `json` is a
    /// stable, machine-parseable surface piped into `wafrift scan
    /// --from-discovery`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Write JSON output to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
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

pub fn run_discover(args: DiscoverArgs) -> ExitCode {
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

    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    rt.block_on(async {
        let mut endpoints = Vec::new();
        let mut sources: Vec<&'static str> = Vec::new();

        if let Some(spec_path) = &args.spec {
            sources.push("openapi");
            let raw = match std::fs::read_to_string(spec_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: read {}: {e}", spec_path.display());
                    return ExitCode::from(1);
                }
            };
            match from_openapi(&raw) {
                Ok(eps) => endpoints.extend(eps),
                Err(e) => {
                    eprintln!("error: parse {}: {e}", spec_path.display());
                    return ExitCode::from(1);
                }
            }
        }

        if args.introspect || args.mine_params {
            // Build a reqwest client with a sensible default timeout —
            // recon shouldn't hang on a slow upstream.
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
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
                        // Don't fail the whole command — introspection-disabled
                        // is informative, not fatal.
                    }
                }
            }

            if args.mine_params {
                sources.push("mine");
                let Some(words_path) = args.wordlist.as_ref() else {
                    eprintln!("error: --wordlist is required for --mine-params");
                    return ExitCode::from(1);
                };
                let words = match std::fs::read_to_string(words_path) {
                    Ok(s) => s
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        eprintln!("error: read wordlist {}: {e}", words_path.display());
                        return ExitCode::from(1);
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
                    body_length_threshold: 0.10,
                    response_time_threshold_ms: 500,
                };
                match mine_params(target, &client, &words, &cfg).await {
                    Ok(eps) => endpoints.extend(eps),
                    Err(DiscoveryError::WordlistEmpty) => {
                        eprintln!("error: wordlist contained no candidates");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("warn: param mining failed: {e}");
                    }
                }
            }
        }

        // De-dup by (method, url). Order-preserving.
        let mut seen = std::collections::HashSet::new();
        endpoints.retain(|e| seen.insert((e.method.clone(), e.url.clone())));

        match args.format.as_str() {
            "json" => {
                let report = DiscoverReport {
                    schema_version: DISCOVER_SCHEMA_VERSION,
                    wafrift_version: env!("CARGO_PKG_VERSION"),
                    target: args.target.as_deref(),
                    sources,
                    endpoints,
                };
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => match args.output.as_ref() {
                        Some(p) => match std::fs::write(p, &s) {
                            Ok(()) => {
                                eprintln!(
                                    "wrote {} bytes ({} endpoint(s)) → {}",
                                    s.len(),
                                    report.endpoints.len(),
                                    p.display()
                                );
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                eprintln!("error: write {}: {e}", p.display());
                                ExitCode::from(1)
                            }
                        },
                        None => {
                            println!("{s}");
                            ExitCode::SUCCESS
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
                ExitCode::SUCCESS
            }
        }
    })
}
