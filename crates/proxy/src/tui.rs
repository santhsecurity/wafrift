//! Terminal dashboard for wafrift-proxy.
//!
//! Active when `wafrift-proxy --tui` is passed. Runs in a dedicated
//! tokio task, draws via ratatui + crossterm.
//!
//! # What it shows
//!
//! Top → bottom:
//! - **Header**: bind addr, evasion mode, active TLS stack, body
//!   padding bytes, conn-reuse state, uptime.
//! - **Counters**: total requests, bypassed (with %), blocked, errors,
//!   padded bodies, average upstream latency.
//! - **TLS rotation**: per-profile request counts + percentages, with
//!   a horizontal bar each. Empty when neither --tls-impersonate nor
//!   --tls-impersonate-rotate is set.
//! - **Per-host top-N**: most-active hosts with sent/blocked/bypassed
//!   columns and the technique chain that worked best.
//! - **Recent stream**: last 200 requests, oldest first scroll-back.
//!
//! # Keys
//! - `q` or `Esc` quits the proxy (graceful shutdown — gene bank gets
//!   flushed, in-flight requests finish).
//! - `r` resets the counters (rotation, per-host, recent stream).
//! - `c` clears the recent stream only.
//! - `+` / `-` adjusts the redraw interval (rare, mostly for slow
//!   ttys).
//!
//! # Why a dedicated module
//! The proxy's hot path (`forward_wafrift_request`) only emits an
//! [`Event`] over an unbounded mpsc — no rendering, no terminal I/O,
//! no shared mutexes. All the heavy ratatui work lives here so the
//! request path stays a tight tokio task.

use std::collections::{HashMap, VecDeque};
use std::io::{self};
use std::time::{Duration, Instant};

use crossterm::event::{self as ce, Event as CtEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// One thing the request handler tells the dashboard about.
#[derive(Debug, Clone)]
pub enum Event {
    /// A finished proxied request.
    Request {
        host: String,
        method: String,
        path: String,
        status: u16,
        bypassed: bool,
        blocked: bool,
        techniques: String,
        tls_profile: Option<String>,
        body_padded: bool,
        upstream_latency_ms: u64,
    },
    /// Soft reset of all counters (called by `r` keybinding).
    ResetCounters,
}

/// Shape passed to [`run`] so the TUI can label its header without
/// re-importing the proxy CLI args.
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub bind_addr: String,
    pub mode: String,
    pub tls_stack_label: String,
    pub body_padding_bytes: usize,
    pub conn_reuse: bool,
}

#[derive(Default)]
struct HostStats {
    sent: u64,
    blocked: u64,
    bypassed: u64,
    top_technique: String,
}

#[derive(Default)]
struct TlsStats {
    counts: HashMap<String, u64>,
}

impl TlsStats {
    fn record(&mut self, profile: &str) {
        *self.counts.entry(profile.to_string()).or_insert(0) += 1;
    }
    fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

#[derive(Default)]
struct State {
    started: Option<Instant>,
    total: u64,
    bypassed: u64,
    blocked: u64,
    errors: u64,
    padded: u64,
    latency_sum_ms: u64,
    hosts: HashMap<String, HostStats>,
    tls: TlsStats,
    recent: VecDeque<String>,
}

impl State {
    fn new() -> Self {
        let mut s = Self::default();
        s.started = Some(Instant::now());
        s
    }

    fn record(&mut self, ev: &Event) {
        match ev {
            Event::Request {
                host,
                method,
                path,
                status,
                bypassed,
                blocked,
                techniques,
                tls_profile,
                body_padded,
                upstream_latency_ms,
            } => {
                self.total += 1;
                if *bypassed {
                    self.bypassed += 1;
                }
                if *blocked {
                    self.blocked += 1;
                }
                if *status >= 500 {
                    self.errors += 1;
                }
                if *body_padded {
                    self.padded += 1;
                }
                self.latency_sum_ms = self.latency_sum_ms.saturating_add(*upstream_latency_ms);

                let hs = self.hosts.entry(host.clone()).or_default();
                hs.sent += 1;
                if *blocked {
                    hs.blocked += 1;
                }
                if *bypassed {
                    hs.bypassed += 1;
                }
                if !techniques.is_empty() {
                    hs.top_technique = techniques.clone();
                }

                if let Some(p) = tls_profile {
                    self.tls.record(p);
                }

                let now = chrono_now();
                let pad_tag = if *body_padded { " +pad" } else { "" };
                let tls_tag = tls_profile
                    .as_ref()
                    .map(|s| format!(" {s}"))
                    .unwrap_or_default();
                let outcome = if *bypassed {
                    "BYPASS"
                } else if *blocked {
                    "BLOCK"
                } else {
                    "PASS"
                };
                let line = format!(
                    "{now} {method:>5} {path:<32.32} {host:<28.28} → {status} {outcome}{tls_tag}{pad_tag} ({techniques})",
                );
                if self.recent.len() == 200 {
                    self.recent.pop_front();
                }
                self.recent.push_back(line);
            }
            Event::ResetCounters => {
                let started = self.started;
                *self = State::default();
                self.started = started;
            }
        }
    }

    fn uptime(&self) -> Duration {
        self.started
            .map(|s| s.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    fn avg_latency_ms(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            self.latency_sum_ms / self.total
        }
    }

    fn bypass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.bypassed as f64 / self.total as f64) * 100.0
        }
    }

    fn top_hosts(&self, n: usize) -> Vec<(&String, &HostStats)> {
        let mut v: Vec<_> = self.hosts.iter().collect();
        v.sort_by(|a, b| b.1.sent.cmp(&a.1.sent));
        v.truncate(n);
        v
    }
}

fn chrono_now() -> String {
    // Avoid pulling in chrono just for HH:MM:SS — use the std epoch +
    // a tiny manual format. Local TZ would be nicer; UTC is fine for a
    // proxy console (and matches log output).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = now % 86400;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn humanize_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Run the dashboard until the user presses `q` or the request channel
/// closes. Returns once the terminal has been restored.
///
/// `quit_tx` is fired when the user requests shutdown so the proxy's
/// main loop can begin graceful shutdown.
pub async fn run(
    cfg: DashboardConfig,
    mut events: mpsc::UnboundedReceiver<Event>,
    quit_tx: oneshot::Sender<()>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut state = State::new();
    let mut redraw = tokio::time::interval(Duration::from_millis(150));
    let mut quit = Some(quit_tx);

    loop {
        // Drain a burst of events without redrawing for each — keeps
        // the TUI responsive under heavy load.
        while let Ok(ev) = events.try_recv() {
            state.record(&ev);
        }

        // Redraw on tick OR on next pending event.
        tokio::select! {
            _ = redraw.tick() => {
                term.draw(|f| draw(f, &cfg, &state))?;
            }
            ev = events.recv() => {
                match ev {
                    Some(ev) => state.record(&ev),
                    None => break, // channel closed; proxy shutting down
                }
            }
        }

        // Non-blocking key polling. Crossterm's poll(0) returns false
        // immediately if no event is ready.
        if ce::poll(Duration::from_millis(0))? {
            match ce::read()? {
                CtEvent::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if let Some(tx) = quit.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(tx) = quit.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    KeyCode::Char('r') => state.record(&Event::ResetCounters),
                    KeyCode::Char('c') => state.recent.clear(),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn draw(f: &mut ratatui::Frame, cfg: &DashboardConfig, state: &State) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Length(5), // counters
            Constraint::Length(8), // tls rotation
            Constraint::Length(8), // per-host
            Constraint::Min(5),    // recent (fills remainder)
        ])
        .split(area);

    draw_header(f, chunks[0], cfg, state);
    draw_counters(f, chunks[1], state);
    draw_tls(f, chunks[2], state);
    draw_hosts(f, chunks[3], state);
    draw_recent(f, chunks[4], state);
}

fn draw_header(f: &mut ratatui::Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let title = format!(
        " wafrift-proxy — uptime {} ",
        humanize_uptime(state.uptime())
    );
    let body = vec![
        Line::from(vec![
            Span::styled("Bind ", Style::default().fg(Color::DarkGray)),
            Span::styled(&cfg.bind_addr, Style::default().fg(Color::Yellow)),
            Span::raw("   "),
            Span::styled("Mode ", Style::default().fg(Color::DarkGray)),
            Span::styled(&cfg.mode, Style::default().fg(Color::Cyan)),
            Span::raw("   "),
            Span::styled("Stealth ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &cfg.tls_stack_label,
                Style::default().fg(Color::LightMagenta),
            ),
        ]),
        Line::from(vec![
            Span::styled("Body padding ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if cfg.body_padding_bytes == 0 {
                    "off".to_string()
                } else {
                    format!("{} bytes", cfg.body_padding_bytes)
                },
                Style::default().fg(Color::Green),
            ),
            Span::raw("   "),
            Span::styled("Conn reuse ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if cfg.conn_reuse { "on" } else { "OFF" },
                Style::default().fg(if cfg.conn_reuse {
                    Color::White
                } else {
                    Color::Red
                }),
            ),
        ]),
    ];
    let p = Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn draw_counters(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let body = vec![
        Line::from(vec![
            Span::styled("Total ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.total.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled("Bypassed ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ({:.1}%)", state.bypassed, state.bypass_rate()),
                Style::default().fg(Color::Green),
            ),
            Span::raw("   "),
            Span::styled("Blocked ", Style::default().fg(Color::DarkGray)),
            Span::styled(state.blocked.to_string(), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled("Errors ", Style::default().fg(Color::DarkGray)),
            Span::styled(state.errors.to_string(), Style::default().fg(Color::Yellow)),
            Span::raw("   "),
            Span::styled("Padded bodies ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.padded.to_string(),
                Style::default().fg(Color::LightCyan),
            ),
            Span::raw("   "),
            Span::styled("Avg latency ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}ms", state.avg_latency_ms()),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    let p = Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(" Counters "));
    f.render_widget(p, area);
}

fn draw_tls(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let total = state.tls.total();
    if total == 0 || state.tls.counts.is_empty() {
        let p = Paragraph::new("(no TLS rotation active — start with --tls-impersonate-rotate)")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" TLS Rotation "),
            );
        f.render_widget(p, area);
        return;
    }
    let mut profiles: Vec<_> = state.tls.counts.iter().collect();
    profiles.sort_by(|a, b| b.1.cmp(a.1));
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" TLS Rotation ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let row_height = 1;
    let max_rows = (inner.height / row_height) as usize;
    for (i, (profile, count)) in profiles.iter().take(max_rows).enumerate() {
        let y = inner.y + (i as u16) * row_height;
        let row_area = Rect::new(inner.x, y, inner.width, row_height);
        let pct = (**count as f64 / total as f64) * 100.0;
        let label = format!("{:<14} {:>5} ({:>4.1}%)", profile, count, pct);
        let g = Gauge::default()
            .ratio((**count as f64 / total as f64).min(1.0))
            .label(label)
            .gauge_style(Style::default().fg(Color::Magenta).bg(Color::DarkGray));
        f.render_widget(g, row_area);
    }
}

fn draw_hosts(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let header = Row::new(vec![
        Cell::from("HOST"),
        Cell::from("SENT"),
        Cell::from("BLOCKED"),
        Cell::from("BYPASSED"),
        Cell::from("BYPASS%"),
        Cell::from("TOP TECHNIQUE"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = state
        .top_hosts(5)
        .into_iter()
        .map(|(host, hs)| {
            let pct = if hs.sent == 0 {
                0.0
            } else {
                (hs.bypassed as f64 / hs.sent as f64) * 100.0
            };
            Row::new(vec![
                Cell::from(host.clone()),
                Cell::from(hs.sent.to_string()),
                Cell::from(hs.blocked.to_string()),
                Cell::from(hs.bypassed.to_string()),
                Cell::from(format!("{pct:.1}%")),
                Cell::from(truncate(&hs.top_technique, 30).to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(28),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Percentage(40),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Per-Host (top 5) "),
    );
    f.render_widget(table, area);
}

fn draw_recent(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Recent (q quit · r reset · c clear) ");
    let inner_h = block.inner(area).height as usize;
    let lines: Vec<Line> = state
        .recent
        .iter()
        .rev()
        .take(inner_h)
        .rev()
        .map(|s| {
            let style = if s.contains("BYPASS") {
                Style::default().fg(Color::Green)
            } else if s.contains("BLOCK") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };
            Line::styled(s.clone(), style)
        })
        .collect();
    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        // Find a char boundary at or before n.
        let mut idx = n;
        while !s.is_char_boundary(idx) && idx > 0 {
            idx -= 1;
        }
        &s[..idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str, status: u16, bypassed: bool, padded: bool, profile: Option<&str>) -> Event {
        Event::Request {
            host: host.to_string(),
            method: "GET".into(),
            path: "/".into(),
            status,
            bypassed,
            blocked: !bypassed && status == 403,
            techniques: "encoding:UrlEncode".into(),
            tls_profile: profile.map(|s| s.to_string()),
            body_padded: padded,
            upstream_latency_ms: 50,
        }
    }

    #[test]
    fn state_counts_bypass_block_padding() {
        let mut s = State::new();
        s.record(&req("a.com", 200, true, true, Some("chrome131")));
        s.record(&req("a.com", 403, false, true, Some("firefox133")));
        s.record(&req("b.com", 500, false, false, None));
        assert_eq!(s.total, 3);
        assert_eq!(s.bypassed, 1);
        assert_eq!(s.blocked, 1);
        assert_eq!(s.errors, 1);
        assert_eq!(s.padded, 2);
    }

    #[test]
    fn tls_stats_round_robin_distribution() {
        let mut s = State::new();
        s.record(&req("h", 200, true, false, Some("chrome131")));
        s.record(&req("h", 200, true, false, Some("firefox133")));
        s.record(&req("h", 200, true, false, Some("safari18")));
        s.record(&req("h", 200, true, false, Some("chrome131")));
        assert_eq!(s.tls.total(), 4);
        assert_eq!(s.tls.counts.get("chrome131"), Some(&2));
        assert_eq!(s.tls.counts.get("firefox133"), Some(&1));
        assert_eq!(s.tls.counts.get("safari18"), Some(&1));
    }

    #[test]
    fn reset_clears_counters_keeps_uptime() {
        let mut s = State::new();
        let started = s.started;
        s.record(&req("a", 200, true, true, Some("chrome131")));
        assert_eq!(s.total, 1);
        s.record(&Event::ResetCounters);
        assert_eq!(s.total, 0);
        assert_eq!(s.bypassed, 0);
        assert_eq!(s.padded, 0);
        assert_eq!(s.started, started, "uptime must persist across reset");
    }

    #[test]
    fn recent_capped_at_200() {
        let mut s = State::new();
        for i in 0..250 {
            s.record(&req(&format!("h{i}"), 200, true, false, None));
        }
        assert_eq!(s.recent.len(), 200);
    }

    #[test]
    fn top_hosts_sorts_by_sent() {
        let mut s = State::new();
        for _ in 0..10 {
            s.record(&req("a", 200, true, false, None));
        }
        for _ in 0..3 {
            s.record(&req("b", 200, true, false, None));
        }
        for _ in 0..7 {
            s.record(&req("c", 200, true, false, None));
        }
        let top = s.top_hosts(5);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[1].0, "c");
        assert_eq!(top[2].0, "b");
    }

    #[test]
    fn humanize_handles_seconds_minutes_hours() {
        assert_eq!(humanize_uptime(Duration::from_secs(5)), "5s");
        assert_eq!(humanize_uptime(Duration::from_secs(95)), "1m35s");
        assert_eq!(humanize_uptime(Duration::from_secs(3725)), "1h02m");
    }

    #[test]
    fn truncate_handles_multibyte() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello");
        // "café" is c(1)+a(1)+f(1)+é(2) = 5 bytes. At idx=4 we land
        // mid-multibyte (inside é), so truncate must walk back to 3.
        assert_eq!(truncate("café", 4), "caf");
        // idx=3 sits at the start of é (a valid char boundary), so it
        // is preserved and we get "caf".
        assert_eq!(truncate("café", 3), "caf");
    }
}
