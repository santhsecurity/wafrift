use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

mod bank;
mod bank_registry;
mod bench_diff;
mod bench_waf;
mod bypass_probe;
mod callback_token;
mod compress_cmd;
mod config;
mod detect_cmd;
mod discover_cmd;
mod egress_example;
mod equiv_engine;
mod evade_cmd;
mod explain;
mod helpers;
mod import_curl;
mod init_cmd;
mod interactive;
mod jwt_cmd;
mod legendary;
mod listener_cmd;
mod man_cmd;
mod origin_hints;
mod parser_diff_cmd;
mod probe_classify;
mod probe_cmd;
mod recon_cmd;
mod replay;
mod report;
mod retry_after;
mod scan;
mod seed;
mod session_init;
mod smuggle_cmd;
mod takeover_cmd;
mod target_context;
mod technique_filter;
mod wafmodel_cmd;

// All per-command helpers are imported by their command modules now.
// main.rs is reduced to dispatch + the top-level Cli/Commands surface.

#[derive(Parser, Debug)]
#[command(
    name = "wafrift",
    about = "WAF evasion toolkit — run without arguments for interactive mode",
    long_about = "WAF evasion toolkit — run without arguments for interactive mode.\n\n\
                  Exit codes (CI-friendly):\n\
                    0  success\n\
                    1  generic error (bad input, IO, etc.)\n\
                    2  bench-waf: zero bypasses on any case in --evade mode\n\
                    2  replay:    saved bypass got blocked (regression signal)\n\
                    3  bench-diff: regression vs baseline (see --bypass-drop-pp)\n\
                    4  bench-waf --validate-only: corpus integrity errors\n\
                    5  scan: aborted — target rate-limited the probes (inconclusive, not 'no bypass')",
    version
)]
struct Cli {
    /// Suppress human-readable output — emit only machine-parseable results (JSON).
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Path to a TOML config file. Default: `.wafrift.toml` in CWD or
    /// `~/.config/wafrift/config.toml`.
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Transform a payload with evasion techniques.
    Evade(evade_cmd::EvadeArgs),
    /// Identify a WAF from response metadata.
    Detect(detect_cmd::DetectArgs),
    /// Generate differential analysis probes.
    Probe(probe_cmd::ProbeArgs),
    /// Fire evasion variants against a live target and report bypass results.
    Scan(ScanArgs),
    /// Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.
    /// Pass `--evade` to actually run the evasion engine (off by default — without it,
    /// only the WAF's raw rejection rate is measured, no bypass claim is made).
    #[command(name = "bench-waf")]
    BenchWaf(bench_waf::BenchWafArgs),
    /// Compare two `bench-waf --output` JSON blobs and gate on regression.
    #[command(name = "bench-diff")]
    BenchDiff(bench_diff::BenchDiffArgs),
    /// DNS hints for `origin_bypass` (authorized targets only).
    #[command(name = "origin-hints")]
    OriginHints(origin_hints::OriginHintsArgs),
    /// Print JSON snippets for egress presets (e.g. Tor SOCKS).
    #[command(name = "egress-example")]
    EgressExample(egress_example::EgressExampleArgs),
    /// List or explain available technique selectors for `--only`/`--exclude`.
    Techniques(TechniquesArgs),
    /// Generate shell completions for bash, zsh, fish, or PowerShell.
    Completion(CompletionArgs),
    /// Origin discovery via crt.sh + DNS (authorized targets only).
    Recon(recon_cmd::ReconArgs),
    /// Endpoint discovery: parse OpenAPI/Swagger, run GraphQL introspection,
    /// or fire differential parameter mining. Emits `DiscoveredEndpoint` JSON
    /// suitable for piping into `wafrift scan --from-discovery`.
    Discover(discover_cmd::DiscoverArgs),
    /// Replay a saved bypass against a target — proves reproducibility.
    Replay(replay::ReplayArgs),
    /// Generate a markdown findings report from the proxy gene bank.
    Report(report::ReportArgs),
    /// Scaffold a `.wafrift.toml` config in the current directory.
    Init(init_cmd::InitArgs),
    /// Pre-load a gene-bank with known-working techniques (per-WAF or per-host).
    Seed(seed::SeedArgs),
    /// Take a curl invocation (e.g. from Burp's "Copy as cURL"), run scan against the parsed target.
    #[command(name = "import-curl")]
    ImportCurl(import_curl::ImportCurlArgs),
    /// Manage gene-banks: list / export / import.
    Bank(bank::BankArgs),
    /// Differential bypass scanner against a single protected URL.
    /// Fires 136 auth-bypass header probes + path-routing-disagreement
    /// variants + HTTP method overrides; reports any probe that diverges
    /// from the baseline response. The Tsai-class vuln finder.
    #[command(name = "bypass-probe")]
    BypassProbe(bypass_probe::BypassProbeArgs),
    /// Generate a troff man page for `wafrift` (and optionally subcommands).
    Man(man_cmd::ManArgs),
    /// Decompile a CRS-class ruleset and report the holes an attacker
    /// can drive through it (the WAF X-ray). Zero-config; `--ruleset`
    /// audits a custom Tier-B config.
    Audit(wafmodel_cmd::AuditArgs),
    /// Synthesize the minimal CRS-grade rules that close the holes
    /// `audit` finds, prove zero benign false positives, and exit
    /// non-zero unless closure is proven (usable as a CI gate).
    Harden(wafmodel_cmd::HardenArgs),
    /// One-shot demo command — runs detect + fingerprint + bypass-probe
    /// (and optionally scan) against a single target, and stitches the
    /// results into one polished markdown writeup.
    Legendary(legendary::LegendaryArgs),
    /// Out-of-band callback receiver — pre-mints unique tokens to
    /// embed in payloads (blind SQLi / stored XSS / blind SSRF / OOB
    /// command injection); logs any inbound HTTP request matching a
    /// minted token. The oracle for the vuln classes that never echo
    /// a verdict on the same response.
    Listener(listener_cmd::ListenerArgs),
    /// Parser-differential fingerprinter — fires URL-shape variants
    /// that exercise known WAF↔origin parser disagreements
    /// (semicolon-strip, backslash-as-separator, NUL truncation,
    /// double-URL-decode, fullwidth slash, dot-segment, percent
    /// case, empty-segment collapse, trailing dot). A divergence
    /// from baseline is evidence the WAF and the origin disagree
    /// on what the URL means — exploit the seam without any
    /// payload mutation.
    #[command(name = "parser-diff")]
    ParserDiff(parser_diff_cmd::ParserDiffArgs),
    /// Wrap a request body in one or more `Content-Encoding` layers
    /// (gzip / deflate / brotli / chain). The compression-confusion
    /// attack: WAFs that inspect raw bytes pass over the encoded
    /// body while the origin decompresses normally. Brotli is the
    /// headline gap — many WAFs don't ship a brotli decompressor
    /// even though Chrome / nginx / Apache all do.
    Compress(compress_cmd::CompressArgs),
    /// JWT weakness analyzer + forgery generator. Decodes the
    /// token, identifies weak algorithms (none / HS* with cracked
    /// secret), surfaces dangerous header surface (kid / jku /
    /// jwk), flags time-claim issues, and emits forged variants
    /// the operator pastes into Authorization: Bearer to test.
    Jwt(jwt_cmd::JwtArgs),
    /// Subdomain takeover detector — resolves the target, fetches
    /// the HTTP response, and matches against a curated database
    /// of vulnerable third-party services (Heroku, S3, GitHub
    /// Pages, Fastly, Squarespace, etc.). A match means the
    /// subdomain dangles at a service whose resource has been
    /// deleted: an attacker who re-registers the resource serves
    /// arbitrary content on the victim's subdomain. One of the
    /// highest-impact, lowest-effort findings in bug bounty.
    Takeover(takeover_cmd::TakeoverArgs),
    /// HTTP request smuggling probes (CL.TE / TE.CL / TE.TE /
    /// CL.0 / dual-CL / multi-value-CL). Subcommands:
    /// `detect` runs the SAFE timing-differential probes that
    /// can't poison the connection pool; `probe` fires the
    /// exploit-grade payloads (requires `--unsafe`); `dry-run`
    /// renders the raw wire bytes without sending anything;
    /// `list` enumerates the variants. Built on the same engine
    /// powering the `wafrift-smuggling` library, but exposed as
    /// a first-class CLI surface so pentesters don't need to
    /// roll their own runner.
    Smuggle(smuggle_cmd::SmuggleArgs),
}

// Per-command structs + entry points live in their own modules:
// - `ManArgs` + `run_man`               -> crate::man_cmd
// - `EvadeArgs` + `run_evade` + helpers -> crate::evade_cmd
// - `DetectArgs` + `run_detect` + helpers -> crate::detect_cmd
// - `ProbeArgs` + `run_probe`           -> crate::probe_cmd

/// Arguments for the live WAF scan command. `pub` so sibling modules
/// (e.g. `import_curl`) can construct one and dispatch through
/// `scan::run_scan` without duplicating CLI state.
#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Target URL to test evasion variants against (e.g.,
    /// <http://localhost:8080>). Accepted as the first positional
    /// argument (`wafrift scan <URL> --payload ...`); kept on equal
    /// footing with the long-form `--target <URL>` below for
    /// backwards-compatibility. Required unless `--from-discovery`
    /// is given (then targets come from the discovery report).
    #[arg(value_name = "URL")]
    pub target_positional: Option<String>,

    /// Long-form alias for the positional target URL — kept so every
    /// pre-existing `wafrift scan --target <URL>` invocation continues
    /// to parse. Mutually exclusive with the positional form.
    #[arg(
        long = "target",
        value_name = "URL",
        conflicts_with = "target_positional",
        required_unless_present_any = ["target_positional", "from_discovery"],
    )]
    pub target: Option<String>,

    /// Ingest a `wafrift discover` JSON report (file, or `-` for
    /// stdin) and scan every discovered endpoint × injection point with
    /// `--payload`. This is the gossan/recon → wafrift pipe the docs
    /// promised but never actually wired:
    /// `wafrift discover ... | wafrift scan --from-discovery - --payload '<x>'`.
    #[arg(long)]
    pub from_discovery: Option<PathBuf>,

    /// Payload to mutate and test.
    #[arg(long)]
    pub payload: String,

    /// Query parameter name to inject into.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Payload class label (`sql`, `xss`, `cmdi`, `ssti`, `path`,
    /// `ldap`, `xxe`, `ssrf`, `nosql`, `log4shell`) used for the
    /// per-class warm-start in the gene bank. When set, the pre-scan
    /// winner pool is biased toward techniques that historically
    /// beat THIS WAF on THIS payload class — a SQLi scan against
    /// Cloudflare starts from "what beat CF on SQLi yesterday", not
    /// "what beat anything on anything". When unset, the global
    /// warm-start path runs (unchanged behaviour). The post-scan
    /// merge also records the per-class breakdown so subsequent
    /// scans benefit.
    #[arg(long, value_name = "CLASS")]
    pub payload_class: Option<String>,

    /// Out-of-band callback URL — the base address of a `wafrift
    /// listener` instance. When set, every occurrence of
    /// `{{CALLBACK}}` in the payload is replaced per-variant with
    /// `<URL>/<unique-token>`. The operator then correlates any
    /// inbound callback at the listener back to a specific variant
    /// by token — the oracle for blind SQLi (time-based), stored
    /// XSS, blind SSRF, OOB command injection. The token is also
    /// surfaced in each variant's scan report.
    #[arg(long, value_name = "URL")]
    pub callback_url: Option<String>,

    /// Stateful chain mode — fire this curl-format request FIRST,
    /// capture cookies + Authorization, then re-use them on every
    /// variant. The file format is identical to `wafrift import-curl`'s
    /// input (Burp / Chromium "Copy as cURL" pastes work verbatim).
    /// Defeats WAFs that scrutinise unauthenticated traffic more —
    /// most do, by a wide margin.
    #[arg(long, value_name = "CURL_FILE")]
    pub session_init: Option<PathBuf>,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Heavy)]
    pub level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    #[arg(long)]
    pub encoding_only: bool,

    /// Delay between requests in milliseconds (avoid rate-limit bans).
    #[arg(long, default_value_t = 50)]
    pub delay_ms: u64,

    /// Output format: text or json.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Optional browser fingerprint to impersonate (e.g., 'chrome', 'safari', 'edge').
    #[arg(long)]
    pub stealth_browser: Option<String>,

    /// Disable TLS verification.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// With `--format json`, add a `layer_report` object (network / detection / baseline / evasion).
    #[arg(long = "report-layers", default_value_t = false)]
    pub report_layers: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub only: Vec<String>,

    /// Drop listed technique paths (comma-separated).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Write JSON output to a file instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

impl ScanArgs {
    /// Resolved target URL — the positional form if supplied, else the
    /// long-form `--target` flag, else `None` (only possible when
    /// `--from-discovery` is in play; clap's
    /// `required_unless_present_any` guarantees the user-facing
    /// invariant).
    #[must_use]
    pub fn resolved_target(&self) -> Option<&str> {
        self.target_positional
            .as_deref()
            .or(self.target.as_deref())
    }
}

#[derive(clap::Args, Debug)]
struct TechniquesArgs {
    #[command(subcommand)]
    action: TechniquesAction,
}

#[derive(Subcommand, Debug)]
enum TechniquesAction {
    /// Print the technique tree.
    List,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Light,
    Medium,
    Heavy,
}
/// Arguments for `wafrift completion <SHELL>`.
#[derive(clap::Args, Debug)]
struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: Shell,
}
fn main() -> ExitCode {
    // Pentesters routinely pipe wafrift's output to `head`, `jq`, `grep
    // -m 1`, etc. Rust's default behaviour is to ignore SIGPIPE and
    // panic on EPIPE the next time stdout is written, which surfaces
    // as `thread 'main' panicked at 'failed printing to stdout: Broken
    // pipe'`. Reset the SIGPIPE handler to SIG_DFL so the process
    // exits silently when the consumer closes the pipe — the canonical
    // CLI idiom that `cat`, `ls`, `grep`, etc. all use.
    #[cfg(unix)]
    {
        // SAFETY: signal(2) is async-signal-safe; we install SIG_DFL
        // before any I/O so no concurrent writers race the handler
        // change.
        #[allow(unsafe_code)]
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    // Keep the raw `ArgMatches` (not just the derived struct) so the
    // scan path can ask clap whether each field came from the command
    // line vs a compiled default — required to layer `.wafrift.toml`
    // underneath CLI flags with correct precedence.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // Store quiet flag for use in subcommands.
    if cli.quiet {
        // In quiet mode, disable colored output entirely.
        colored::control::set_override(false);
    }

    // Load config file (--config flag overrides default search paths).
    let cfg = if let Some(ref path) = cli.config {
        match config::WafRiftConfig::load_from(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} {e}", "Config error:".red().bold());
                return ExitCode::from(1);
            }
        }
    } else {
        config::WafRiftConfig::load()
    };

    let quiet = cli.quiet;
    match cli.command {
        None => interactive::run_interactive(),
        Some(Commands::Evade(args)) => evade_cmd::run_evade(args, quiet),
        Some(Commands::Detect(args)) => detect_cmd::run_detect(args, quiet),
        Some(Commands::Probe(args)) => {
            probe_cmd::run_probe(args);
            ExitCode::SUCCESS
        }
        Some(Commands::Scan(args)) => {
            // Layer .wafrift.toml under the CLI flags (CLI wins).
            let args = cfg.apply_to_scan(args, matches.subcommand_matches("scan"));
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: failed to start tokio runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(async {
                // Install graceful Ctrl+C handler so gene bank can be saved on interrupt.
                let cancel = tokio_util::sync::CancellationToken::new();
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!(
                            "\n{}",
                            "⚠ Ctrl+C received — finishing current request and saving results..."
                                .yellow()
                                .bold()
                        );
                        cancel_clone.cancel();
                    }
                });
                if args.from_discovery.is_some() {
                    run_scan_from_discovery(args, cancel).await
                } else {
                    scan::run_scan(args, cancel).await
                }
            })
        }
        Some(Commands::BenchWaf(args)) => bench_waf::run_bench_waf(args),
        Some(Commands::BenchDiff(args)) => bench_diff::run_bench_diff(args),
        Some(Commands::OriginHints(args)) => origin_hints::run_origin_hints(args),
        Some(Commands::EgressExample(args)) => egress_example::run_egress_example(args),
        Some(Commands::Techniques(args)) => match args.action {
            TechniquesAction::List => {
                print!("{}", technique_filter::render_tree());
                ExitCode::SUCCESS
            }
        },
        Some(Commands::Completion(args)) => {
            let mut cmd = Cli::command();
            generate(args.shell, &mut cmd, "wafrift", &mut io::stdout());
            ExitCode::SUCCESS
        }
        Some(Commands::Recon(args)) => recon_cmd::run_recon(args),
        Some(Commands::Discover(args)) => discover_cmd::run_discover(args),
        Some(Commands::Replay(args)) => replay::run_replay(args),
        Some(Commands::Report(args)) => report::run_report(args),
        Some(Commands::Init(args)) => init_cmd::run_init(args),
        Some(Commands::Seed(args)) => seed::run_seed(args),
        Some(Commands::ImportCurl(args)) => import_curl::run_import_curl(args),
        Some(Commands::Bank(args)) => bank::run_bank(args),
        Some(Commands::BypassProbe(args)) => match bypass_probe::run_bypass_probe(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("bypass-probe failed: {e}");
                ExitCode::from(1)
            }
        },
        Some(Commands::Man(args)) => man_cmd::run_man(args),
        Some(Commands::Audit(args)) => wafmodel_cmd::run_audit(args),
        Some(Commands::Harden(args)) => wafmodel_cmd::run_harden(args),
        Some(Commands::Legendary(args)) => legendary::run_legendary(args),
        Some(Commands::Listener(args)) => listener_cmd::run_listener(args),
        Some(Commands::ParserDiff(args)) => match parser_diff_cmd::run_parser_diff(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("parser-diff failed: {e}");
                ExitCode::from(1)
            }
        },
        Some(Commands::Compress(args)) => compress_cmd::run_compress(args),
        Some(Commands::Jwt(args)) => jwt_cmd::run_jwt(args),
        Some(Commands::Takeover(args)) => takeover_cmd::run_takeover(args),
        Some(Commands::Smuggle(args)) => smuggle_cmd::run_smuggle(args),
    }
}

// (interactive TUI body lives in `crate::interactive::run_interactive`;
//  `run_man` lives in `crate::man_cmd`.)

// `run_evade` + `resolve_payload` live in `crate::evade_cmd`.

// `DetectFetch`, `fetch_for_detect`, `infra_markers` live in
// `crate::detect_cmd` and are re-exported pub(crate) for use by
// `crate::legendary`.

/// Expand a `wafrift discover` JSON report into one `run_scan` per
/// (endpoint URL × injection-point name) and run them in sequence with
/// the operator's `--payload`. This is the recon → wafrift pipe the
/// help text advertised for releases but never actually implemented
/// (`scan --from-discovery` was a documented flag that did not exist).
async fn run_scan_from_discovery(
    args: ScanArgs,
    cancel: tokio_util::sync::CancellationToken,
) -> ExitCode {
    let Some(ref src) = args.from_discovery else {
        unreachable!("caller checked from_discovery.is_some()");
    };
    let raw = if src.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut buf) {
            eprintln!("{} read discovery report from stdin: {e}", "error:".red());
            return ExitCode::from(1);
        }
        buf
    } else {
        match std::fs::read_to_string(src) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} read {}: {e}", "error:".red(), src.display());
                return ExitCode::from(1);
            }
        }
    };
    let report: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} parse discovery report: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    let endpoints = report
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if endpoints.is_empty() {
        eprintln!(
            "{} discovery report has no `endpoints` — nothing to scan (is this `wafrift discover` JSON?)",
            "error:".red()
        );
        return ExitCode::from(1);
    }

    // Flatten to concrete (url, param) jobs. An endpoint with no
    // injection points still gets scanned on the default param so a
    // bare URL list is usable.
    let mut jobs: Vec<(String, String)> = Vec::new();
    for ep in &endpoints {
        let Some(url) = ep.get("url").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let points: Vec<String> = ep
            .get("injection_points")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        p.get("name")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if points.is_empty() {
            jobs.push((url.to_string(), args.param.clone()));
        } else {
            for name in points {
                jobs.push((url.to_string(), name));
            }
        }
    }

    eprintln!(
        "[wafrift scan] --from-discovery: {} endpoint(s) → {} scan job(s)",
        endpoints.len(),
        jobs.len()
    );

    let mut last = ExitCode::SUCCESS;
    for (i, (url, param)) in jobs.iter().enumerate() {
        if cancel.is_cancelled() {
            eprintln!(
                "[wafrift scan] cancelled — {} job(s) not run",
                jobs.len() - i
            );
            break;
        }
        eprintln!(
            "\n[wafrift scan] ── job {}/{}: {url} (param={param}) ──",
            i + 1,
            jobs.len()
        );
        let job_args = ScanArgs {
            target_positional: None,
            target: Some(url.clone()),
            from_discovery: None,
            payload: args.payload.clone(),
            param: param.clone(),
            payload_class: args.payload_class.clone(),
            callback_url: args.callback_url.clone(),
            session_init: args.session_init.clone(),
            level: args.level,
            encoding_only: args.encoding_only,
            delay_ms: args.delay_ms,
            format: args.format.clone(),
            stealth_browser: args.stealth_browser.clone(),
            insecure: args.insecure,
            report_layers: args.report_layers,
            only: args.only.clone(),
            exclude: args.exclude.clone(),
            output: None, // per-job: don't clobber one file repeatedly
        };
        last = scan::run_scan(job_args, cancel.clone()).await;
    }
    last
}

// `run_detect` lives in `crate::detect_cmd`.

// `run_probe` lives in `crate::probe_cmd`.
