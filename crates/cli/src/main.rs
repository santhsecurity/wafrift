use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use serde_json::json;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_detect::waf_detect;
use wafrift_evolution::differential;
use wafrift_grammar::grammar;
use wafrift_strategy::gene_bank::GeneBank;

mod bank;
mod bank_registry;
mod bench_diff;
mod bench_waf;
mod bypass_probe;
mod config;
mod discover_cmd;
mod egress_example;
mod equiv_engine;
mod explain;
mod helpers;
mod import_curl;
mod init_cmd;
mod origin_hints;
mod recon_cmd;
mod replay;
mod report;
mod scan;
mod seed;
mod target_context;
mod technique_filter;
mod wafmodel_cmd;

use explain::ExplainTrace;
use helpers::{
    build_variants_explained, confidence_badge, max_mutations_for_level, parse_headers,
    payload_type_label, probe_target_label, strategy_pool,
};
use target_context::TargetContext;
use technique_filter::TechniqueFilter;

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
    Evade(EvadeArgs),
    /// Identify a WAF from response metadata.
    Detect(DetectArgs),
    /// Generate differential analysis probes.
    Probe(ProbeArgs),
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
    Man(ManArgs),
    /// Decompile a CRS-class ruleset and report the holes an attacker
    /// can drive through it (the WAF X-ray). Zero-config; `--ruleset`
    /// audits a custom Tier-B config.
    Audit(wafmodel_cmd::AuditArgs),
    /// Synthesize the minimal CRS-grade rules that close the holes
    /// `audit` finds, prove zero benign false positives, and exit
    /// non-zero unless closure is proven (usable as a CI gate).
    Harden(wafmodel_cmd::HardenArgs),
}

/// Arguments for `wafrift man` — emits a troff(1) man page suitable for
/// `man -l` consumption or installation under `/usr/local/share/man/man1/`.
#[derive(clap::Args, Debug)]
struct ManArgs {
    /// Subcommand to render. Default: render the top-level `wafrift`
    /// page. Pass `all` to emit a concatenated stream covering every
    /// subcommand (one page per `\n.SH` section).
    #[arg(long)]
    sub: Option<String>,

    /// Write to this file instead of stdout. Conventional install path
    /// is `/usr/local/share/man/man1/wafrift.1`.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct EvadeArgs {
    /// Payload to mutate and encode. Mutually exclusive with `--stdin`
    /// and `--payload-b64`.
    #[arg(
        long,
        conflicts_with_all = ["stdin", "payload_b64"],
        required_unless_present_any = ["stdin", "payload_b64"]
    )]
    payload: Option<String>,

    /// Base64-encoded payload, for bytes a shell cannot pass on argv.
    /// `--payload $'\x00\x01\x02'` is silently truncated at the first
    /// NUL by the OS (argv is NUL-terminated C strings), so binary /
    /// control-byte payloads MUST come in out-of-band: base64 here, or
    /// raw bytes via `--stdin`. Decoded bytes are interpreted as UTF-8
    /// (lossless for control/extended characters; the engine is text).
    #[arg(long, value_name = "BASE64", conflicts_with_all = ["payload", "stdin"])]
    payload_b64: Option<String>,

    /// Read the payload from stdin instead of `--payload`. Useful for
    /// piping (`echo 'X' | wafrift evade --stdin ...`) and the only
    /// binary-safe path for payloads containing NUL/control bytes.
    /// Refuses to run on an interactive terminal so it doesn't hang
    /// silently.
    #[arg(long)]
    stdin: bool,

    /// Output format: `text` (default) or `json`. `--format json` is
    /// equivalent to the global `--quiet` for this command and exists
    /// so `evade` matches `scan`/`bypass-probe`/`import-curl`, whose
    /// `--format` flag pentesters already script against.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Medium)]
    level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    /// (Shorthand for `--exclude grammar`.)
    #[arg(long)]
    encoding_only: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    /// Explicit selection here overrides `--level` for which strategies
    /// are eligible (the level still bounds variant count).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only: Vec<String>,

    /// Drop listed technique paths (comma-separated; e.g.
    /// `encoding/url/triple,smuggling`).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    exclude: Vec<String>,

    /// Filter techniques by where the payload will land (header, body,
    /// query-param, cookie). Encoding strategies whose output is
    /// unusable in the chosen context are skipped (visible with --explain).
    #[arg(long, value_enum)]
    target_context: Option<TargetContext>,

    /// Show per-technique trace: which strategies ran, which were
    /// skipped, and why.
    #[arg(long)]
    explain: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct DetectArgs {
    /// Fetch the target URL directly and run detection on the live
    /// response — no manual `curl` + `--status`/`--headers` round-trip.
    /// `wafrift detect --url https://target.com`. Mutually exclusive
    /// with `--status`/`--headers`.
    #[arg(long, conflicts_with_all = ["status", "headers"])]
    url: Option<String>,

    /// HTTP status code (100–599). Required unless `--url` is given.
    #[arg(long, value_parser = parse_http_status, required_unless_present = "url")]
    status: Option<u16>,

    /// Repeated "key: value" header arguments. Required unless `--url`
    /// is given.
    #[arg(long, required_unless_present = "url")]
    headers: Vec<String>,

    /// Response body fragment.
    #[arg(long, default_value = "")]
    body: String,

    /// With `--url`: per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// With `--url`: disable TLS certificate verification (lab targets).
    #[arg(long, default_value_t = false)]
    insecure: bool,
}

/// clap value-parser for an HTTP status code. RFC 9110 status codes are
/// three digits in the range 100–599; anything else (`0`, `99`, `999`,
/// `1000`) is a typo or an attempt to smuggle a nonsense value past
/// detection and is rejected at parse time rather than silently scored.
fn parse_http_status(s: &str) -> Result<u16, String> {
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

#[derive(clap::Args, Debug)]
struct ProbeArgs {
    /// Generate a smaller probe set.
    #[arg(long)]
    quick: bool,
}

/// Arguments for the live WAF scan command. `pub` so sibling modules
/// (e.g. `import_curl`) can construct one and dispatch through
/// `scan::run_scan` without duplicating CLI state.
#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Target URL to test evasion variants against (e.g.,
    /// <http://localhost:8080>). Required unless `--from-discovery` is
    /// given (then targets come from the discovery report).
    #[arg(long, required_unless_present = "from_discovery")]
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
        None => run_interactive(),
        Some(Commands::Evade(args)) => run_evade(args, quiet),
        Some(Commands::Detect(args)) => run_detect(args, quiet),
        Some(Commands::Probe(args)) => {
            run_probe(args);
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
        Some(Commands::Man(args)) => run_man(args),
        Some(Commands::Audit(args)) => wafmodel_cmd::run_audit(args),
        Some(Commands::Harden(args)) => wafmodel_cmd::run_harden(args),
    }
}

fn run_man(args: ManArgs) -> ExitCode {
    let cmd = Cli::command();
    let target_cmd = match args.sub.as_deref() {
        None | Some("wafrift") => cmd,
        Some("all") => cmd, // future: walk every subcommand and concat
        Some(name) => match cmd
            .get_subcommands()
            .find(|c| c.get_name() == name)
            .cloned()
        {
            Some(c) => c,
            None => {
                let cmd = Cli::command();
                let names: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
                eprintln!("error: unknown subcommand {name:?}. Available: {names:?}");
                return ExitCode::from(1);
            }
        },
    };
    let man = clap_mangen::Man::new(target_cmd);
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = man.render(&mut buf) {
        eprintln!("error: render man page: {e}");
        return ExitCode::from(1);
    }
    match args.output {
        Some(p) => {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&p, &buf) {
                eprintln!("error: write {}: {e}", p.display());
                return ExitCode::from(1);
            }
            eprintln!("wrote man page ({} bytes) → {}", buf.len(), p.display());
        }
        None => {
            use std::io::Write;
            if let Err(e) = std::io::stdout().write_all(&buf) {
                eprintln!("error: write stdout: {e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
/// Interactive TUI — the default experience when running `wafrift` with no args.
fn run_interactive() -> ExitCode {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    };
    use ratatui::{
        Terminal,
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };
    use std::io::IsTerminal;

    // Without a real TTY (CI, piped invocation) the TUI's poll loop would
    // hang forever waiting for keys. Exit cleanly with a usage hint instead.
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "{}\n  {}",
            "wafrift: no TTY detected — interactive mode is unavailable.".yellow(),
            "Run `wafrift --help` for headless commands.".bright_black()
        );
        return ExitCode::from(1);
    }

    // Set up terminal.
    let Ok(()) = enable_raw_mode() else {
        eprintln!("Failed to enable raw mode — try using a subcommand instead.");
        return ExitCode::from(1);
    };
    let mut stdout = io::stdout();
    let _ = execute!(stdout, EnterAlternateScreen);
    let backend = CrosstermBackend::new(stdout);
    let Ok(mut terminal) = Terminal::new(backend) else {
        let _ = disable_raw_mode();
        eprintln!("Failed to create terminal.");
        return ExitCode::from(1);
    };

    // State.
    let mut selected_menu = 0_usize;
    let mut show_help = false;
    let menu_items = [
        (
            "🔍  Scan",
            "Fire evasion variants against a live WAF target",
        ),
        ("🧬  Gene Bank", "Browse learned WAF bypass genomes"),
        (
            "⚡  Evade",
            "Transform a single payload with evasion techniques",
        ),
        ("🛡️  Detect", "Identify a WAF from response headers"),
        ("📡  Probe", "Generate differential analysis probes"),
    ];

    // Load gene bank stats.
    let gene_bank_info = match GeneBank::open_default() {
        Ok(bank) => {
            let wafs = bank.list_wafs();
            if wafs.is_empty() {
                "No learned genomes yet — scan a target to start learning".to_string()
            } else {
                format!("{} WAF genomes stored: {}", wafs.len(), wafs.join(", "))
            }
        }
        Err(_) => "Gene bank not initialized".to_string(),
    };

    loop {
        let _ = terminal.draw(|frame| {
            let size = frame.area();

            // Main layout: header + body + footer.
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6), // header
                    Constraint::Min(10),   // body
                    Constraint::Length(3), // footer
                ])
                .split(size);

            // ── Header ──
            let header_text = vec![
                Line::from(vec![Span::styled(
                    "  ██╗    ██╗ █████╗ ███████╗██████╗ ██╗███████╗████████╗",
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ██║    ██║██╔══██╗██╔════╝██╔══██╗██║██╔════╝╚══██╔══╝",
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ██║ █╗ ██║███████║█████╗  ██████╔╝██║█████╗     ██║   ",
                    Style::default().fg(Color::LightCyan),
                )]),
                Line::from(vec![Span::styled(
                    "  ╚██╔╝██╔╝██╔══██║██╔══╝  ██╔══██╗██║██╔══╝     ██║   ",
                    Style::default().fg(Color::Blue),
                )]),
                Line::from(vec![Span::styled(
                    "   ╚═╝  ╚═╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═══════╝     ╚═╝   ",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![
                    Span::styled(
                        "  Evolutionary WAF Evasion Engine",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::ITALIC),
                    ),
                    Span::raw("   ·   "),
                    Span::styled(
                        concat!("v", env!("CARGO_PKG_VERSION")),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ];
            let header = Paragraph::new(header_text);
            frame.render_widget(header, chunks[0]);

            // ── Body: menu + info panel ──
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(chunks[1]);

            // Menu. Use a ▶ prefix on the selected row plus REVERSED
            // video so the selection is visible on every terminal —
            // bg/fg color overrides alone don't render reliably under
            // some emulators (notably when a row's background hasn't
            // been pre-painted), so the prefix + reverse pair gives
            // the operator a visible cursor regardless.
            let items: Vec<ListItem> = menu_items
                .iter()
                .enumerate()
                .map(|(i, (name, _))| {
                    let (prefix, style) = if i == selected_menu {
                        (
                            "▶ ",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                                .add_modifier(Modifier::REVERSED),
                        )
                    } else {
                        ("  ", Style::default().fg(Color::White))
                    };
                    ListItem::new(Line::from(Span::styled(format!("{prefix}{name}  "), style)))
                })
                .collect();
            let menu = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Actions ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(menu, body_chunks[0]);

            // Info panel.
            let (_, desc) = menu_items[selected_menu];
            // Per-action context block — shows real usage hints
            // tailored to the highlighted entry, not the same Gene
            // Bank stats glued to every panel.
            let mut info_text = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {desc}"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];
            let (heading, body): (&str, Vec<&str>) = match selected_menu {
                0 => (
                    "─ Scan example ─",
                    vec![
                        "wafrift scan \\",
                        "    --target https://api.example.com/login \\",
                        "    --payload \"' OR 1=1 --\" \\",
                        "    --param q  --level heavy",
                    ],
                ),
                1 => (
                    "─ Gene Bank ─",
                    vec![
                        gene_bank_info.as_str(),
                        "wafrift bank list                    # show every stored WAF",
                        "wafrift bank export <waf> -o pack    # share a winning genome",
                    ],
                ),
                2 => (
                    "─ Evade example ─",
                    vec![
                        "wafrift evade --payload \"' OR 1=1 --\" --level heavy",
                        "wafrift evade --quiet --payload \"<script>\" | jq '.'",
                    ],
                ),
                3 => (
                    "─ Detect example ─",
                    vec![
                        "wafrift detect --status 403 \\",
                        "    --headers 'Server: cloudflare' \\",
                        "    --headers 'CF-Ray: abc123-LHR'",
                    ],
                ),
                4 => (
                    "─ Probe example ─",
                    vec![
                        "wafrift probe                # full differential probe set",
                        "wafrift probe --quick        # smaller set for fast iteration",
                    ],
                ),
                _ => ("", vec![]),
            };
            info_text.push(Line::from(Span::styled(
                format!("  {heading}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            for line in &body {
                info_text.push(Line::from(Span::styled(
                    format!("  {line}"),
                    Style::default().fg(Color::Gray),
                )));
            }
            info_text.push(Line::from(""));
            info_text.push(Line::from(Span::styled(
                "  Enter  launch  ·  ?  show all keybinds  ·  q  quit",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
            let info = Paragraph::new(info_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Details ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(info, body_chunks[1]);

            // ── Footer ──
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(
                    " ↑↓ / j k ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Navigate  "),
                Span::styled(
                    " Enter ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Launch  "),
                Span::styled(
                    " ? ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Help  "),
                Span::styled(
                    " q / Esc ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" Quit  "),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            frame.render_widget(footer, chunks[2]);

            // Help overlay — modal popup, only when show_help is set.
            if show_help {
                use ratatui::layout::Rect;
                let area = frame.area();
                let pop_w = 60.min(area.width.saturating_sub(4));
                let pop_h = 16.min(area.height.saturating_sub(4));
                let pop_x = (area.width.saturating_sub(pop_w)) / 2;
                let pop_y = (area.height.saturating_sub(pop_h)) / 2;
                let popup = Rect::new(pop_x, pop_y, pop_w, pop_h);
                frame.render_widget(ratatui::widgets::Clear, popup);
                let help_lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Keyboard shortcuts",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from("    ↑ / k         Move selection up"),
                    Line::from("    ↓ / j         Move selection down"),
                    Line::from("    Enter         Launch the selected action"),
                    Line::from("    ?             Toggle this help"),
                    Line::from("    q / Esc       Quit"),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Tip: every action prints the exact CLI",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(Span::styled(
                        "  command — paste it into your shell to repeat.",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Press ? again to dismiss.",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::ITALIC),
                    )),
                ];
                let help = Paragraph::new(help_lines).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Help ")
                        .border_style(
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                );
                frame.render_widget(help, popup);
            }
        });

        // Handle input.
        #[allow(clippy::collapsible_match)]
        if event::poll(Duration::from_millis(100)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('?') => {
                    show_help = !show_help;
                    continue;
                }
                _ if show_help => {
                    // Any other key dismisses help.
                    show_help = false;
                    continue;
                }
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    selected_menu = selected_menu.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected_menu < menu_items.len() - 1 {
                        selected_menu += 1;
                    }
                }
                KeyCode::Enter => {
                    // Exit TUI and print guidance for the selected action.
                    let _ = disable_raw_mode();
                    let _ = execute!(io::stdout(), LeaveAlternateScreen);
                    match selected_menu {
                        0 => {
                            println!("{}", "\nLaunch a scan with:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift scan".bold().green(),
                                "--target <URL> --payload <PAYLOAD>".yellow()
                            );
                            println!("\n  {}", "Example:".bold());
                            println!(
                                "  {} {}",
                                "wafrift scan".green(),
                                "--target http://localhost:8080 --payload \"' OR 1=1--\"".yellow()
                            );
                        }
                        1 => {
                            // Show gene bank contents inline.
                            println!("\n{}", "Gene Bank Contents:".bold().cyan());
                            match GeneBank::open_default() {
                                Ok(mut bank) => {
                                    let wafs = bank.list_wafs();
                                    if wafs.is_empty() {
                                        println!(
                                            "  {}",
                                            "No genomes yet — scan a target to start learning."
                                                .yellow()
                                        );
                                    } else {
                                        for waf in &wafs {
                                            println!(
                                                "\n  {} {}",
                                                "WAF:".bold(),
                                                waf.bold().yellow()
                                            );
                                            if let Some(genome) = bank.load(waf) {
                                                println!(
                                                    "    {} {}",
                                                    "Targets scanned:".cyan(),
                                                    genome.targets_scanned
                                                );
                                                let winners = genome.seed_winners();
                                                if winners.is_empty() {
                                                    println!(
                                                        "    {}",
                                                        "No proven winners yet".bright_black()
                                                    );
                                                } else {
                                                    println!(
                                                        "    {} {}",
                                                        "Proven bypasses:".green(),
                                                        winners.join(", ").yellow()
                                                    );
                                                }
                                                for tech in genome.top_techniques(5, 1) {
                                                    println!(
                                                        "    {} {:>5.0}% ({}/{}) {}",
                                                        "·".bright_black(),
                                                        tech.success_rate() * 100.0,
                                                        tech.total_successes,
                                                        tech.total_attempts,
                                                        tech.name,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => println!("  {}", format!("Error: {e}").red()),
                            }
                        }
                        2 => {
                            println!("\n{}", "Transform a payload:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift evade".bold().green(),
                                "--payload <PAYLOAD> --level heavy".yellow()
                            );
                        }
                        3 => {
                            println!("\n{}", "Detect a WAF:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift detect".bold().green(),
                                "--status 403 --headers \"server: cloudflare\"".yellow()
                            );
                        }
                        4 => {
                            println!("\n{}", "Generate probes:".bold().cyan());
                            println!(
                                "  {} {}",
                                "wafrift probe".bold().green(),
                                "[--quick]".yellow()
                            );
                        }
                        _ => {}
                    }
                    return ExitCode::SUCCESS;
                }
                _ => {}
            }
        }
    }

    // Clean up terminal.
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    ExitCode::SUCCESS
}

#[allow(clippy::needless_pass_by_value)]
fn run_evade(args: EvadeArgs, quiet: bool) -> ExitCode {
    // `--format json` is the per-command spelling of the global
    // `--quiet`: both select machine-readable NDJSON. Shadow `quiet`
    // so every downstream branch honours either spelling.
    let quiet = quiet || args.format == "json";
    let payload = match resolve_payload(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{} {msg}", "Input error:".red().bold());
            return ExitCode::from(2);
        }
    };

    let filter = match TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(2);
        }
    };
    let payload_type = grammar::classify(&payload);
    let pool = strategy_pool(args.level, !args.only.is_empty());
    let strategies = filter.filter_strategies(pool);
    let max_mutations = max_mutations_for_level(args.level);
    let encoding_only = args.encoding_only || !filter.grammar_enabled();

    let mut trace = args.explain.then(ExplainTrace::default);
    let variants = build_variants_explained(
        &payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
        args.target_context,
        trace.as_mut(),
    );

    if variants.is_empty() {
        if quiet {
            let mut body = json!({
                "error": "no variants generated",
                "payload_type": payload_type_label(payload_type),
            });
            if let Some(t) = trace.as_ref() {
                body["explain"] = t.to_json()["explain"].clone();
            }
            if let Some(ref path) = args.output {
                if let Err(e) = std::fs::write(path, format!("{body}\n")) {
                    eprintln!("failed to write evade output to {}: {e}", path.display());
                }
            } else {
                println!("{body}");
            }
        } else {
            eprintln!(
                "{}",
                "No variants generated for the supplied payload."
                    .red()
                    .bold()
            );
            if let Some(ctx) = args.target_context {
                eprintln!(
                    "  Target context: {} — strategies whose output is unusable here were skipped.",
                    ctx.label()
                );
            }
            if !args.only.is_empty() && !args.explain {
                eprintln!(
                    "  Hint: re-run with --explain to see which techniques were considered and why each was skipped."
                );
            }
            if let Some(t) = trace.as_ref() {
                t.print_text();
            }
        }
        return ExitCode::from(1);
    }

    if quiet {
        // JSON output: one object per line (NDJSON), then an optional trailing
        // {"explain": [...]} object so consumers can stream variants and still
        // pick up the trace.
        let mut buf = String::new();
        for variant in &variants {
            let obj = json!({
                "payload": variant.payload,
                "techniques": variant.techniques,
                "confidence": variant.confidence,
            });
            if args.output.is_some() {
                buf.push_str(&obj.to_string());
                buf.push('\n');
            } else {
                println!("{obj}");
            }
        }
        if let Some(t) = trace.as_ref() {
            let explain_obj = t.to_json();
            if args.output.is_some() {
                buf.push_str(&explain_obj.to_string());
                buf.push('\n');
            } else {
                println!("{explain_obj}");
            }
        }
        if let Some(ref path) = args.output {
            if let Err(e) = std::fs::write(path, &buf) {
                eprintln!("failed to write evade output to {}: {e}", path.display());
                return ExitCode::from(1);
            }
            eprintln!("evade results written to {}", path.display());
        }
    } else {
        println!(
            "{} {}",
            "Payload Type:".bold().cyan(),
            payload_type_label(payload_type).bold()
        );
        println!(
            "{} {}",
            "Encoding Level:".bold().cyan(),
            format!("{:?}", args.level).to_lowercase().yellow()
        );
        if let Some(ctx) = args.target_context {
            println!(
                "{} {}",
                "Target Context:".bold().cyan(),
                ctx.label().yellow()
            );
        }

        for (index, variant) in variants.iter().enumerate() {
            println!(
                "\n{} {} {}",
                "Variant".bold().green(),
                format!("#{}", index + 1).bold().green(),
                confidence_badge(variant.confidence)
            );
            println!(
                "{} {}",
                "Techniques:".bold().cyan(),
                variant.techniques.join(" -> ").yellow()
            );
            println!(
                "{} {}",
                "Payload:".bold().cyan(),
                variant.payload.bright_white()
            );
        }

        if let Some(t) = trace.as_ref() {
            t.print_text();
        }
    }

    ExitCode::SUCCESS
}

/// Resolve the evade payload from `--payload`, `--payload-b64`, or
/// `--stdin`. Clap's `required_unless_present_any` + `conflicts_with`
/// guarantees exactly one source at the CLI layer; this validates and
/// decodes the value.
///
/// Binary-safety: `--stdin` is read as raw bytes (not
/// `read_to_string`, which hard-errors on the first invalid UTF-8 byte
/// and so could never accept a binary payload) and `--payload-b64`
/// carries arbitrary bytes past the shell's NUL-terminated argv. Both
/// are lossily decoded to UTF-8 because the mutation/encoding engine
/// is text — control bytes (`\x00`–`\x1f`) survive losslessly; only
/// genuinely invalid UTF-8 sequences become U+FFFD.
fn resolve_payload(args: &EvadeArgs) -> Result<String, String> {
    use base64::Engine as _;

    if let Some(b64) = &args.payload_b64 {
        let trimmed = b64.trim();
        if trimmed.is_empty() {
            return Err("--payload-b64 is empty".to_string());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .map_err(|e| format!("--payload-b64 is not valid base64: {e}"))?;
        if bytes.is_empty() {
            return Err("--payload-b64 decoded to zero bytes".to_string());
        }
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }

    if args.stdin {
        use std::io::{IsTerminal, Read};
        if io::stdin().is_terminal() {
            return Err(
                "--stdin requires a pipe (e.g. `echo 'X' | wafrift evade --stdin ...`); refusing to wait on an interactive terminal".to_string(),
            );
        }
        let mut buf: Vec<u8> = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read payload from stdin: {e}"))?;
        // Strip a single trailing newline (the `echo 'x' |` case) without
        // mangling embedded control bytes in a deliberate binary payload.
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            return Err("stdin produced an empty payload".to_string());
        }
        return Ok(String::from_utf8_lossy(&buf).into_owned());
    }

    let raw = args.payload.clone().ok_or_else(|| {
        "no payload supplied (use --payload, --payload-b64, or --stdin)".to_string()
    })?;
    if raw.is_empty() {
        // The overwhelmingly common cause of an *empty* `--payload`
        // value is a shell binary literal: `--payload $'\x00\x01\x02'`.
        // execve(2) passes argv as NUL-terminated C strings, so the
        // kernel truncates the argument at the first NUL *before* the
        // process ever sees it — wafrift receives "", not the bytes.
        // No amount of in-process parsing can recover them; the only
        // fix is an out-of-band channel. Say so, with the exact
        // commands.
        return Err("--payload is empty. If you passed binary/NUL bytes (e.g. \
             $'\\x00\\x01\\x02'), the shell truncated the argument at the \
             first NUL byte before wafrift could see it — argv cannot \
             carry NULs. Use a binary-safe channel instead:\n  \
             printf '\\x00\\x01\\x02' | wafrift evade --stdin ...\n  \
             wafrift evade --payload-b64 \"$(printf '\\x00\\x01\\x02' | base64)\" ..."
            .to_string());
    }
    Ok(raw)
}

/// Fetch a URL for passive WAF detection: one GET, redirects NOT
/// followed (a 301/302/403 may itself be the WAF/CDN response we want
/// `(status, response headers, body)` from a detect fetch, or an error
/// string. Aliased so the nested generic isn't a `type_complexity`
/// lint at every use site.
type DetectFetch = Result<(u16, Vec<(String, String)>, Vec<u8>), String>;

/// to fingerprint), realistic browser UA so the edge behaves normally.
/// Returns `(status, headers, body)` with the body capped at 64 KiB —
/// WAF/CDN banners and block pages are always in the head.
fn fetch_for_detect(url: &str, timeout_secs: u64, insecure: bool) -> DetectFetch {
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
fn infra_markers(headers: &[(String, String)]) -> Vec<(String, String)> {
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
            target: Some(url.clone()),
            from_discovery: None,
            payload: args.payload.clone(),
            param: param.clone(),
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

#[allow(clippy::needless_pass_by_value)]
fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
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

#[allow(clippy::needless_pass_by_value)]
fn run_probe(args: ProbeArgs) {
    let probes = if args.quick {
        differential::generate_quick_probes()
    } else {
        differential::generate_probes()
    };

    for probe in probes {
        let line = json!({
            "payload": probe.payload,
            "tests": probe_target_label(&probe.tests),
            "description": probe.description,
            "expected_blocked": probe.expected_blocked,
        });
        println!("{}", line.to_string().blue());
    }
}
