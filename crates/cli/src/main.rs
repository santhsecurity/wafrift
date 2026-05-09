use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use serde_json::json;
use std::io;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_detect::waf_detect;
use wafrift_evolution::differential;
use wafrift_grammar::grammar;
use wafrift_strategy::gene_bank::GeneBank;

mod bench_diff;
mod bench_waf;
mod config;
mod egress_example;
mod helpers;
mod init_cmd;
mod origin_hints;
mod recon_cmd;
mod replay;
mod report;
mod scan;
mod technique_filter;

use helpers::{
    build_variants, confidence_badge, max_mutations_for_level, parse_headers, payload_type_label,
    probe_target_label, strategies_for_level,
};
use technique_filter::TechniqueFilter;

#[derive(Parser, Debug)]
#[command(
    name = "wafrift",
    about = "WAF evasion toolkit — run without arguments for interactive mode",
    long_about = "WAF evasion toolkit — run without arguments for interactive mode.\n\n\
                  Exit codes (CI-friendly):\n\
                    0  success\n\
                    1  generic error (bad input, IO, transport failure, etc.)\n\
                    2  bench-waf: zero bypasses on any case in --evade mode\n\
                    3  bench-diff: regression vs baseline (see --bypass-drop-pp)\n\
                    4  bench-waf --validate-only: corpus integrity errors",
    version
)]
struct Cli {
    /// Suppress human-readable output — emit only machine-parseable results (JSON).
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Transform a payload with evasion techniques.
    #[command(long_about = "Transform a payload with evasion techniques.\n\nExample:\n  wafrift evade --payload \"' OR 1=1--\" --level heavy")]
    Evade(EvadeArgs),
    /// Identify a WAF from response metadata.
    #[command(long_about = "Identify a WAF from response metadata.\n\nExample:\n  wafrift detect --status 403 --headers \"server: cloudflare\"")]
    Detect(DetectArgs),
    /// Generate differential analysis probes.
    #[command(long_about = "Generate differential analysis probes.\n\nExample:\n  wafrift probe --quick")]
    Probe(ProbeArgs),
    /// Fire evasion variants against a live target and report bypass results.
    #[command(long_about = "Fire evasion variants against a live target and report bypass results.\n\nExample:\n  wafrift scan --target http://localhost:8080 --payload \"' OR 1=1--\" --level heavy")]
    Scan(ScanArgs),
    /// Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.
    /// Pass `--evade` to actually run the evasion engine (off by default — without it,
    /// only the WAF's raw rejection rate is measured, no bypass claim is made).
    #[command(
        name = "bench-waf",
        long_about = "Reproducible WAF benchmark: measure raw block rate AND wafrift bypass rate.\nPass `--evade` to actually run the evasion engine (off by default).\n\nExample:\n  wafrift bench-waf --base-url http://127.0.0.1:18081 --evade --format json"
    )]
    BenchWaf(bench_waf::BenchWafArgs),
    /// Compare two `bench-waf --output` JSON blobs and gate on regression.
    #[command(
        name = "bench-diff",
        long_about = "Compare two `bench-waf --output` JSON blobs and gate on regression.\n\nExample:\n  wafrift bench-diff --current run.json --baseline baseline.json"
    )]
    BenchDiff(bench_diff::BenchDiffArgs),
    /// DNS hints for `origin_bypass` (authorized targets only).
    #[command(
        name = "origin-hints",
        long_about = "DNS hints for `origin_bypass` (authorized targets only).\n\nExample:\n  wafrift origin-hints --host api.example.com --format json"
    )]
    OriginHints(origin_hints::OriginHintsArgs),
    /// Print JSON snippets for egress presets (e.g. Tor SOCKS).
    #[command(
        name = "egress-example",
        long_about = "Print JSON snippets for egress presets (e.g. Tor SOCKS).\n\nExample:\n  wafrift egress-example --preset tor"
    )]
    EgressExample(egress_example::EgressExampleArgs),
    /// List or explain available technique selectors for `--only`/`--exclude`.
    #[command(long_about = "List or explain available technique selectors for `--only`/`--exclude`.\n\nExample:\n  wafrift techniques list")]
    Techniques(TechniquesArgs),
    /// Generate shell completions for bash, zsh, fish, or PowerShell.
    #[command(long_about = "Generate shell completions for bash, zsh, fish, or PowerShell.\n\nExample:\n  wafrift completion bash > /etc/bash_completion.d/wafrift")]
    Completion(CompletionArgs),
    /// Origin discovery via crt.sh + DNS (authorized targets only).
    #[command(long_about = "Origin discovery via crt.sh + DNS (authorized targets only).\n\nExample:\n  wafrift recon --domain example.com")]
    Recon(recon_cmd::ReconArgs),
    /// Replay a saved bypass against a target — proves reproducibility.
    #[command(long_about = "Replay a saved bypass against a target — proves reproducibility.\n\nExample:\n  wafrift replay --target https://api.example.com/search --payload \"' OR 1=1--\" --from-host api.example.com")]
    Replay(replay::ReplayArgs),
    /// Generate a markdown findings report from the proxy gene bank.
    #[command(long_about = "Generate a markdown findings report from the proxy gene bank.\n\nExample:\n  wafrift report --proxy-bank ~/.wafrift/gene-bank.json --output findings.md")]
    Report(report::ReportArgs),
    /// Scaffold a `.wafrift.toml` config in the current directory.
    #[command(long_about = "Scaffold a `.wafrift.toml` config in the current directory.\n\nExample:\n  wafrift init --force")]
    Init(init_cmd::InitArgs),
}

#[derive(clap::Args, Debug)]
struct EvadeArgs {
    /// Payload to mutate and encode.
    #[arg(long)]
    payload: String,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Medium)]
    level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    /// (Shorthand for `--exclude grammar`.)
    #[arg(long)]
    encoding_only: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only: Vec<String>,

    /// Drop listed technique paths (comma-separated; e.g.
    /// `encoding/url/triple,smuggling`).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    exclude: Vec<String>,
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

/// Arguments for the live WAF scan command.
#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Target URL to test evasion variants against (e.g., http://localhost:8080).
    #[arg(long)]
    target: String,

    /// Payload to mutate and test.
    #[arg(long)]
    payload: String,

    /// Query parameter name to inject into.
    #[arg(long, default_value = "q")]
    param: String,

    /// Evasion intensity.
    #[arg(long, value_enum, default_value_t = Level::Heavy)]
    level: Level,

    /// Apply encoding only, without grammar-aware mutations.
    #[arg(long)]
    encoding_only: bool,

    /// Delay between requests in milliseconds (avoid rate-limit bans).
    #[arg(long, default_value_t = 50)]
    delay_ms: u64,

    /// Output format: text or json.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Optional browser fingerprint to impersonate (e.g., 'chrome', 'safari', 'edge').
    #[arg(long)]
    stealth_browser: Option<String>,

    /// Disable TLS verification.
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// With `--format json`, add a `layer_report` object (network / detection / baseline / evasion).
    #[arg(long = "report-layers", default_value_t = false)]
    report_layers: bool,

    /// Restrict to listed technique paths (comma-separated; e.g.
    /// `encoding/url,grammar`). Run `wafrift techniques list` for paths.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    only: Vec<String>,

    /// Drop listed technique paths (comma-separated).
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    exclude: Vec<String>,
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
enum Level {
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
    let cli = Cli::parse();

    // Disable colored output when --quiet is set or stdout is not a TTY
    // (so pipes don't get polluted with ANSI escape sequences).
    if cli.quiet || !io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    let quiet = cli.quiet;
    match cli.command {
        None => run_interactive(),
        Some(Commands::Evade(args)) => run_evade(args, quiet),
        Some(Commands::Detect(args)) => run_detect(args, quiet),
        Some(Commands::Probe(args)) => {
            run_probe(args, quiet);
            ExitCode::SUCCESS
        }
        Some(Commands::Scan(args)) => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(async {
                // Install graceful Ctrl+C handler so gene bank can be saved on interrupt.
                let cancel = tokio_util::sync::CancellationToken::new();
                let cancel_clone = cancel.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        eprintln!("\nCtrl+C received — finishing current request and saving results...");
                        cancel_clone.cancel();
                    }
                });
                scan::run_scan(args, cancel, quiet).await
            })
        }
        Some(Commands::BenchWaf(args)) => bench_waf::run_bench_waf(args, quiet),
        Some(Commands::BenchDiff(args)) => bench_diff::run_bench_diff(args, quiet),
        Some(Commands::OriginHints(args)) => origin_hints::run_origin_hints(args, quiet),
        Some(Commands::EgressExample(args)) => egress_example::run_egress_example(args, quiet),
        Some(Commands::Techniques(args)) => match args.action {
            TechniquesAction::List => {
                if quiet {
                    let tree = technique_filter::render_tree();
                    let lines: Vec<&str> = tree.lines().collect();
                    println!("{}", json!({ "schema_version": 1, "techniques": lines }));
                } else {
                    print!("{}", technique_filter::render_tree());
                }
                ExitCode::SUCCESS
            }
        },
        Some(Commands::Completion(args)) => {
            let mut cmd = Cli::command();
            generate(args.shell, &mut cmd, "wafrift", &mut io::stdout());
            ExitCode::SUCCESS
        }
        Some(Commands::Recon(args)) => recon_cmd::run_recon(args, quiet),
        Some(Commands::Replay(args)) => replay::run_replay(args, quiet),
        Some(Commands::Report(args)) => report::run_report(args, quiet),
        Some(Commands::Init(args)) => init_cmd::run_init(args, quiet),
    }
}
/// Interactive TUI — the default experience when running `wafrift` with no args.
fn run_interactive() -> ExitCode {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    };

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
    use ratatui::{
        Terminal,
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

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
    let menu_items = [
        (
            "Scan",
            "Fire evasion variants against a live WAF target",
        ),
        ("Gene Bank", "Browse learned WAF bypass genomes"),
        (
            "Evade",
            "Transform a single payload with evasion techniques",
        ),
        ("Detect", "Identify a WAF from response headers"),
        ("Probe", "Generate differential analysis probes"),
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
                    Span::styled("v0.1.0", Style::default().fg(Color::DarkGray)),
                ]),
            ];
            let header = Paragraph::new(header_text);
            frame.render_widget(header, chunks[0]);

            // ── Body: menu + info panel ──
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(chunks[1]);

            // Menu.
            let items: Vec<ListItem> = menu_items
                .iter()
                .enumerate()
                .map(|(i, (name, _))| {
                    let style = if i == selected_menu {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(Line::from(Span::styled(format!("  {name}  "), style)))
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
            let info_text = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {desc}"),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  ── Gene Bank ──",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  {gene_bank_info}"),
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press Enter to launch · q to quit",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )),
            ];
            let info = Paragraph::new(info_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Details ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(info, body_chunks[1]);

            // ── Footer ──
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" ↑↓ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(" Navigate  "),
                Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(" Select  "),
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Red)),
                Span::raw(" Quit  "),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            frame.render_widget(footer, chunks[2]);
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

fn run_evade(args: EvadeArgs, quiet: bool) -> ExitCode {
    let filter = match TechniqueFilter::parse(&args.only, &args.exclude) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{} {msg}", "Filter error:".red().bold());
            return ExitCode::from(1);
        }
    };
    let payload_type = grammar::classify(&args.payload);
    let strategies = filter.filter_strategies(strategies_for_level(args.level));
    let max_mutations = max_mutations_for_level(args.level);
    let encoding_only = args.encoding_only || !filter.grammar_enabled();
    let variants = build_variants(
        &args.payload,
        payload_type,
        encoding_only,
        &strategies,
        max_mutations,
    );

    if variants.is_empty() {
        if quiet {
            println!(
                "{}",
                json!({ "schema_version": 1, "error": "no variants generated", "payload_type": payload_type_label(payload_type) })
            );
        } else {
            eprintln!(
                "{}",
                "No variants generated for the supplied payload."
                    .red()
                    .bold()
            );
        }
        return ExitCode::from(1);
    }

    if quiet {
        // JSON output: one object per line (NDJSON)
        for variant in &variants {
            let obj = json!({
                "schema_version": 1,
                "payload": variant.payload,
                "techniques": variant.techniques,
                "confidence": variant.confidence,
            });
            println!("{obj}");
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
    }

    ExitCode::SUCCESS
}

fn run_detect(args: DetectArgs, quiet: bool) -> ExitCode {
    let headers = match parse_headers(&args.headers) {
        Ok(headers) => headers,
        Err(message) => {
            eprintln!("{} {}", "Header parse error:".red().bold(), message);
            return ExitCode::from(1);
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
        println!("{}", json!({ "schema_version": 1, "detected": results }));
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

fn run_probe(args: ProbeArgs, quiet: bool) {
    let probes = if args.quick {
        differential::generate_quick_probes()
    } else {
        differential::generate_probes()
    };

    for probe in probes {
        let line = json!({
            "schema_version": 1,
            "payload": probe.payload,
            "tests": probe_target_label(&probe.tests),
            "description": probe.description,
            "expected_blocked": probe.expected_blocked,
        });
        if quiet {
            println!("{}", line);
        } else {
            println!("{}", line.to_string().blue());
        }
    }
}
