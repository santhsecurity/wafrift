use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
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
                    4  bench-waf --validate-only: corpus integrity errors",
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
    /// Payload to mutate and encode. Mutually exclusive with `--stdin`.
    #[arg(long, conflicts_with = "stdin", required_unless_present = "stdin")]
    payload: Option<String>,

    /// Read the payload from stdin instead of `--payload`. Useful for
    /// piping (`echo 'X' | wafrift evade --stdin ...`). Refuses to run
    /// on an interactive terminal so it doesn't hang silently.
    #[arg(long)]
    stdin: bool,

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
    /// HTTP status code.
    #[arg(long)]
    status: u16,

    /// Repeated "key: value" header arguments.
    #[arg(long, required = true)]
    headers: Vec<String>,

    /// Response body fragment.
    #[arg(long, default_value = "")]
    body: String,
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
    /// Target URL to test evasion variants against (e.g., <http://localhost:8080>).
    #[arg(long)]
    pub target: String,

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

    let cli = Cli::parse();

    // Store quiet flag for use in subcommands.
    if cli.quiet {
        // In quiet mode, disable colored output entirely.
        colored::control::set_override(false);
    }

    // Load config file (--config flag overrides default search paths).
    let _cfg = if let Some(ref path) = cli.config {
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
                scan::run_scan(args, cancel).await
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

/// Resolve the evade payload from either `--payload` or `--stdin`.
/// Clap's `required_unless_present` + `conflicts_with` enforces that
/// exactly one is supplied at the CLI layer; this validates the value.
fn resolve_payload(args: &EvadeArgs) -> Result<String, String> {
    if args.stdin {
        use std::io::{IsTerminal, Read};
        if io::stdin().is_terminal() {
            return Err(
                "--stdin requires a pipe (e.g. `echo 'X' | wafrift evade --stdin ...`); refusing to wait on an interactive terminal".to_string(),
            );
        }
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read payload from stdin: {e}"))?;
        let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
        if trimmed.is_empty() {
            return Err("stdin produced an empty payload".to_string());
        }
        Ok(trimmed)
    } else {
        let raw = args
            .payload
            .clone()
            .ok_or_else(|| "no payload supplied (use --payload or --stdin)".to_string())?;
        if raw.is_empty() {
            return Err("--payload is empty; pass a non-empty string".to_string());
        }
        Ok(raw)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    let headers = match parse_headers(&args.headers) {
        Ok(headers) => headers,
        Err(message) => {
            eprintln!("{} {}", "Header parse error:".red().bold(), message);
            return ExitCode::from(2);
        }
    };

    let detected = waf_detect::detect(args.status, &headers, args.body.as_bytes());
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
        println!("{}", json!({ "detected": results }));
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
