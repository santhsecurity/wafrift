//! The interactive TUI shown when `wafrift` is run with no subcommand.
//!
//! A ratatui-driven menu that gives a first-touch operator a feel for
//! what wafrift does and prints copy-paste shell invocations for each
//! action when they hit Enter. Not a substitute for the headless
//! commands — it's a discoverability layer. CI / piped invocations
//! exit cleanly with a usage hint instead of hanging on a non-TTY
//! event loop.

use colored::Colorize;
use std::io;
use std::process::ExitCode;
use std::time::Duration;
use wafrift_strategy::gene_bank::GeneBank;

/// Entry point. Returns `ExitCode::SUCCESS` after the user quits the
/// menu, or `ExitCode::from(1)` if the terminal cannot be put into raw
/// mode (rare — pre-flight TTY check catches the common case).
pub fn run_interactive() -> ExitCode {
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
