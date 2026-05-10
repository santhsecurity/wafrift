//! Terminal dashboard for wafrift-proxy.
//!
//! Active when `wafrift-proxy --tui` is passed. Runs in a dedicated
//! tokio task, draws via ratatui + crossterm.
//!
//! # Layout
//!
//! ```text
//!  ┌─ wafrift ─ proxy 127.0.0.1:8080 ─ stealth chrome131 ─ uptime 03:47 ─ rps 12.4 ┐
//!  │  [F]low   [O]verview   [H]osts                                                │
//!  ├──────────────────────────────────────────────────────────────────────────────┤
//!  │  REQUESTS                                                  DETAIL            │
//!  │  ▶ POST /admin     api.target.com  403→200  cf:dz          POST /admin       │
//!  │    GET  /v1/users  api.target.com  403→403                  X-Original-URL   │
//!  │    POST /search    api.target.com  403→200  sql:tautology   ...              │
//!  │                                                                              │
//!  │  ░░▒▒▓▓██▓▓▒▒░░  req/s 60s                                                  │
//!  │  ░▒▓██▓▒░▒▓██▓░  bypass-rate 60s                                            │
//!  ├──────────────────────────────────────────────────────────────────────────────┤
//!  │  q quit │ tab/F O H switch │ j/k navigate │ enter inspect │ r reset │ c clear│
//!  └──────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Tabs
//! - **Flow** — live request stream (default), per-request inspect via Enter
//! - **Overview** — counters, TLS rotation, WAF identifications
//! - **Hosts** — per-host top-N with bypass rate + winner technique
//!
//! # Keys
//! - `q` / `Esc` — quit (flushes gene bank)
//! - `Tab` / `1` `2` `3` / `f` `o` `h` — switch tab
//! - `j` / `k` (or `↑` `↓`) — navigate request list (Flow tab)
//! - `Enter` — toggle detail pane on selected request
//! - `r` — reset counters
//! - `c` — clear request list
//! - `g` / `G` — jump to oldest / newest request

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
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Sparkline, Table, Wrap,
};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Maximum bytes of a request OR response body that the dashboard
/// keeps per record. Bigger bodies are truncated upstream by the
/// emitter; the dashboard only displays what arrives.
pub const MAX_BODY_EXCERPT: usize = 1024;

/// Maximum number of past requests retained for the Flow detail view.
const REQUEST_RING: usize = 500;

/// Number of seconds of history retained for the sparklines.
const SPARK_WINDOW_SECS: usize = 60;

/// One thing the request handler tells the dashboard about.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
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
        /// WAF identified for this host, if any (e.g. "Cloudflare").
        waf_name: Option<String>,
        /// Outgoing request headers AFTER evasion was applied.
        req_headers: Vec<(String, String)>,
        /// Outgoing request body excerpt (capped at `MAX_BODY_EXCERPT`).
        req_body_excerpt: Vec<u8>,
        /// Upstream response headers.
        resp_headers: Vec<(String, String)>,
        /// Upstream response body excerpt (capped at `MAX_BODY_EXCERPT`).
        resp_body_excerpt: Vec<u8>,
        /// Total upstream response body size before excerpting.
        resp_body_total: u64,
        /// Number of evade-retry attempts (0 = first try succeeded).
        attempts: u32,
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

/// Single inspectable record — one proxied request + its response.
#[derive(Debug, Clone)]
struct RequestRecord {
    timestamp: String, // pre-formatted HH:MM:SS for display
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
    waf_name: Option<String>,
    req_headers: Vec<(String, String)>,
    req_body_excerpt: Vec<u8>,
    resp_headers: Vec<(String, String)>,
    resp_body_excerpt: Vec<u8>,
    resp_body_total: u64,
    attempts: u32,
}

impl RequestRecord {
    fn outcome(&self) -> &'static str {
        if self.bypassed {
            "BYPASS"
        } else if self.blocked {
            "BLOCK"
        } else {
            "PASS"
        }
    }
}

#[derive(Default)]
struct HostStats {
    sent: u64,
    blocked: u64,
    bypassed: u64,
    top_technique: String,
    waf_name: Option<String>,
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

/// Which top-level view is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Flow,
    Overview,
    Hosts,
}
impl Tab {
    fn next(self) -> Self {
        match self {
            Self::Flow => Self::Overview,
            Self::Overview => Self::Hosts,
            Self::Hosts => Self::Flow,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Flow => "Flow",
            Self::Overview => "Overview",
            Self::Hosts => "Hosts",
        }
    }
}

/// Per-second tally bucket used to drive the sparklines.
#[derive(Default, Clone, Copy)]
struct SecBucket {
    requests: u64,
    bypasses: u64,
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
    /// Most-recent request first? No — back is newest.
    recent: VecDeque<RequestRecord>,
    /// Selected index INTO `recent` for the Flow tab. `None` = no
    /// selection (auto-follow newest at the bottom).
    selected: Option<usize>,
    /// Whether the inspect/detail pane is open in Flow tab.
    inspect: bool,
    /// Currently focused tab.
    tab: Tab,
    /// Per-second buckets for the sparklines, oldest first.
    spark: VecDeque<SecBucket>,
    /// Wall-clock second the current spark bucket belongs to.
    spark_current_sec: u64,
    /// WAFs identified on any host so far + the count of hosts where
    /// each was confirmed.
    waf_seen: HashMap<String, u64>,
    /// Total of `attempts` across all requests — drives "evade-retry
    /// rate" indicator.
    attempts_sum: u64,
}

impl State {
    fn new() -> Self {
        Self {
            started: Some(Instant::now()),
            tab: Tab::Flow,
            ..Self::default()
        }
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
                waf_name,
                req_headers,
                req_body_excerpt,
                resp_headers,
                resp_body_excerpt,
                resp_body_total,
                attempts,
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
                self.attempts_sum = self.attempts_sum.saturating_add(u64::from(*attempts));

                let hs = self.hosts.entry(host.clone()).or_default();
                hs.sent += 1;
                if *blocked {
                    hs.blocked += 1;
                }
                if *bypassed {
                    hs.bypassed += 1;
                }
                if !techniques.is_empty() {
                    hs.top_technique.clone_from(techniques);
                }
                if let Some(w) = waf_name {
                    if hs.waf_name.is_none() {
                        // first identification of this host's WAF — bump
                        // the global "WAFs seen" counter once.
                        *self.waf_seen.entry(w.clone()).or_insert(0) += 1;
                    }
                    hs.waf_name = Some(w.clone());
                }

                if let Some(p) = tls_profile {
                    self.tls.record(p);
                }

                self.bump_spark(*bypassed);

                let rec = RequestRecord {
                    timestamp: chrono_now(),
                    host: host.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    status: *status,
                    bypassed: *bypassed,
                    blocked: *blocked,
                    techniques: techniques.clone(),
                    tls_profile: tls_profile.clone(),
                    body_padded: *body_padded,
                    upstream_latency_ms: *upstream_latency_ms,
                    waf_name: waf_name.clone(),
                    req_headers: req_headers.clone(),
                    req_body_excerpt: req_body_excerpt.clone(),
                    resp_headers: resp_headers.clone(),
                    resp_body_excerpt: resp_body_excerpt.clone(),
                    resp_body_total: *resp_body_total,
                    attempts: *attempts,
                };
                if self.recent.len() == REQUEST_RING {
                    self.recent.pop_front();
                    // adjust selection if we trimmed an older entry
                    if let Some(i) = self.selected.as_mut() {
                        *i = i.saturating_sub(1);
                    }
                }
                self.recent.push_back(rec);
            }
            Event::ResetCounters => {
                let started = self.started;
                let tab = self.tab;
                *self = State::default();
                self.started = started;
                self.tab = tab;
            }
        }
    }

    fn bump_spark(&mut self, bypassed: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.spark_current_sec != now {
            self.spark_current_sec = now;
            self.spark.push_back(SecBucket::default());
            while self.spark.len() > SPARK_WINDOW_SECS {
                self.spark.pop_front();
            }
        }
        if let Some(b) = self.spark.back_mut() {
            b.requests += 1;
            if bypassed {
                b.bypasses += 1;
            }
        }
    }

    fn uptime(&self) -> Duration {
        self.started
            .map(|s| s.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0))
    }

    fn avg_latency_ms(&self) -> u64 {
        self.latency_sum_ms.checked_div(self.total).unwrap_or(0)
    }

    fn bypass_rate_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let r = (self.bypassed as f64 / self.total as f64) * 100.0;
        r
    }

    fn rps_recent(&self) -> f64 {
        // Average req/s over the last 5 spark buckets (≈ 5 s).
        let n = self.spark.len().min(5);
        if n == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let sum: f64 = self.spark.iter().rev().take(n).map(|b| b.requests as f64).sum();
        sum / (n as f64)
    }

    fn top_hosts(&self, n: usize) -> Vec<(&String, &HostStats)> {
        let mut v: Vec<_> = self.hosts.iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1.sent));
        v.truncate(n);
        v
    }

    fn select_offset(&mut self, delta: i64) {
        if self.recent.is_empty() {
            self.selected = None;
            return;
        }
        let cur = self.selected.unwrap_or(self.recent.len().saturating_sub(1));
        let max = self.recent.len() - 1;
        let new = (cur as i64 + delta).clamp(0, max as i64) as usize;
        self.selected = Some(new);
    }

    fn select_first(&mut self) {
        if !self.recent.is_empty() {
            self.selected = Some(0);
        }
    }
    fn select_last(&mut self) {
        if !self.recent.is_empty() {
            self.selected = Some(self.recent.len() - 1);
        }
    }
}

/// Format the current wall-clock time as HH:MM:SS UTC.
fn chrono_now() -> String {
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

/// Status-code → severity colour. 2xx green, 3xx cyan, 4xx yellow,
/// 5xx red, anything else gray.
fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Cyan,
        400..=499 => Color::Yellow,
        500..=599 => Color::Red,
        _ => Color::DarkGray,
    }
}

/// Outcome label colour: BYPASS = bright green, BLOCK = red, PASS = white.
fn outcome_color(rec: &RequestRecord) -> Color {
    if rec.bypassed {
        Color::LightGreen
    } else if rec.blocked {
        Color::LightRed
    } else {
        Color::White
    }
}

/// Run the dashboard until the user presses `q` or the request channel
/// closes. Returns once the terminal has been restored.
///
/// `quit_tx` is fired when the user requests shutdown so the proxy's
/// main loop can begin graceful shutdown.
pub async fn run(
    cfg: DashboardConfig,
    mut events: mpsc::Receiver<Event>,
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

        // Non-blocking key polling.
        if ce::poll(Duration::from_millis(0))? {
            match ce::read()? {
                CtEvent::Key(k) if k.kind == KeyEventKind::Press && handle_key(&mut state, k.code, k.modifiers, &mut quit) => {
                    break;
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

/// Dispatch one keystroke. Returns `true` when the loop should exit.
fn handle_key(
    state: &mut State,
    code: KeyCode,
    mods: KeyModifiers,
    quit: &mut Option<oneshot::Sender<()>>,
) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if let Some(tx) = quit.take() {
                let _ = tx.send(());
            }
            return true;
        }
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
            if let Some(tx) = quit.take() {
                let _ = tx.send(());
            }
            return true;
        }
        KeyCode::Tab => state.tab = state.tab.next(),
        KeyCode::Char('1') | KeyCode::Char('f') | KeyCode::Char('F') => state.tab = Tab::Flow,
        KeyCode::Char('2') | KeyCode::Char('o') | KeyCode::Char('O') => state.tab = Tab::Overview,
        KeyCode::Char('3') | KeyCode::Char('h') | KeyCode::Char('H') => state.tab = Tab::Hosts,
        KeyCode::Char('r') => state.record(&Event::ResetCounters),
        KeyCode::Char('c') => {
            state.recent.clear();
            state.selected = None;
        }
        KeyCode::Char('j') | KeyCode::Down if state.tab == Tab::Flow => state.select_offset(1),
        KeyCode::Char('k') | KeyCode::Up if state.tab == Tab::Flow => state.select_offset(-1),
        KeyCode::Char('g') if state.tab == Tab::Flow => state.select_first(),
        KeyCode::Char('G') if state.tab == Tab::Flow => state.select_last(),
        KeyCode::Enter if state.tab == Tab::Flow => {
            state.inspect = !state.inspect;
            if state.inspect && state.selected.is_none() {
                state.select_last();
            }
        }
        _ => {}
    }
    false
}

fn draw(f: &mut ratatui::Frame, cfg: &DashboardConfig, state: &State) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // tab strip
            Constraint::Min(5),    // body (per tab)
            Constraint::Length(1), // footer key-help
        ])
        .split(area);

    draw_header(f, chunks[0], cfg, state);
    draw_tabs(f, chunks[1], state);
    match state.tab {
        Tab::Flow => draw_flow(f, chunks[2], state),
        Tab::Overview => draw_overview(f, chunks[2], cfg, state),
        Tab::Hosts => draw_hosts(f, chunks[2], state),
    }
    draw_footer(f, chunks[3], state);
}

fn draw_header(f: &mut ratatui::Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let body = Line::from(vec![
        Span::styled("wafrift", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("proxy ", Style::default().fg(Color::DarkGray)),
        Span::styled(&cfg.bind_addr, Style::default().fg(Color::Yellow)),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("stealth ", Style::default().fg(Color::DarkGray)),
        Span::styled(&cfg.tls_stack_label, Style::default().fg(Color::LightMagenta)),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("uptime ", Style::default().fg(Color::DarkGray)),
        Span::styled(humanize_uptime(state.uptime()), Style::default().fg(Color::White)),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("rps ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:.1}", state.rps_recent()), Style::default().fg(Color::Cyan)),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        Span::styled("bypass ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{:.1}%", state.bypass_rate_pct()),
            Style::default().fg(Color::LightGreen),
        ),
    ]);
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(p, area);
}

fn draw_tabs(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let mut spans = vec![Span::raw("  ")];
    for (i, t) in [Tab::Flow, Tab::Overview, Tab::Hosts].iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }
        let style = if state.tab == *t {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightCyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let label = format!(" {} {} ", i + 1, t.label());
        spans.push(Span::styled(label, style));
    }
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

fn draw_footer(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let mut spans = vec![
        key_hint("q", "quit"),
        sep(),
        key_hint("tab", "switch"),
        sep(),
    ];
    if state.tab == Tab::Flow {
        spans.extend([
            key_hint("j/k", "navigate"),
            sep(),
            key_hint("g/G", "first/last"),
            sep(),
            key_hint("enter", "inspect"),
            sep(),
        ]);
    }
    spans.extend([
        key_hint("r", "reset"),
        sep(),
        key_hint("c", "clear"),
        Span::raw("    "),
        Span::styled(
            format!("({} reqs · {} retries)", state.total, state.attempts_sum),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

fn key_hint(key: &str, label: &str) -> Span<'static> {
    Span::styled(
        format!(" {} {} ", key, label),
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    )
}

fn sep() -> Span<'static> {
    Span::raw(" ")
}

// ── Flow tab ────────────────────────────────────────────────────────

fn draw_flow(f: &mut ratatui::Frame, area: Rect, state: &State) {
    // Two columns: left = list + sparklines, right = detail (when inspect on
    // and a selection exists).
    let detail_open = state.inspect && state.selected.is_some();
    let cols = if detail_open {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100)])
            .split(area)
    };

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(6)])
        .split(cols[0]);

    draw_request_list(f, left[0], state);
    draw_sparklines(f, left[1], state);

    if detail_open {
        draw_detail(f, cols[1], state);
    }
}

fn draw_request_list(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Requests ",
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.recent.is_empty() {
        let p = Paragraph::new("(no requests yet — proxy a request through this address)")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }

    // Show the tail of the ring buffer that fits the inner height.
    let inner_h = inner.height as usize;
    let total = state.recent.len();
    // Anchor the visible window around the selected row when one exists.
    let anchor = state.selected.unwrap_or(total - 1);
    let start = anchor.saturating_sub(inner_h.saturating_sub(1));
    let visible: Vec<(usize, &RequestRecord)> = state
        .recent
        .iter()
        .enumerate()
        .skip(start)
        .take(inner_h)
        .collect();

    let mut lines = Vec::with_capacity(visible.len());
    for (idx, rec) in visible {
        let is_sel = state.selected == Some(idx);
        let marker = if is_sel { "▶ " } else { "  " };
        let row_style = if is_sel {
            Style::default().bg(Color::Rgb(28, 32, 40)).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        // Format: HH:MM:SS METHOD path host status outcome (techniques)
        let path_disp = truncate(&rec.path, 24);
        let host_disp = truncate(&rec.host, 22);
        let line = Line::from(vec![
            Span::styled(marker, Style::default().fg(outcome_color(rec))),
            Span::styled(rec.timestamp.clone(), Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(format!("{:>5}", rec.method), Style::default().fg(Color::Cyan)),
            Span::raw(" "),
            Span::styled(format!("{:<24}", path_disp), Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(format!("{:<22}", host_disp), Style::default().fg(Color::Gray)),
            Span::raw(" "),
            Span::styled(format!("{:>3}", rec.status), Style::default().fg(status_color(rec.status)).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled(
                format!("{:<6}", rec.outcome()),
                Style::default().fg(outcome_color(rec)),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{}ms", rec.upstream_latency_ms),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(" "),
            Span::styled(
                truncate(&rec.techniques, 30).to_string(),
                Style::default().fg(Color::Magenta),
            ),
        ]);
        lines.push(line.style(row_style));
    }
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

fn draw_sparklines(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let req_data: Vec<u64> = state.spark.iter().map(|b| b.requests).collect();
    let bypass_data: Vec<u64> = state.spark.iter().map(|b| b.bypasses).collect();

    let max_req = req_data.iter().copied().max().unwrap_or(1).max(1);
    let max_byp = bypass_data.iter().copied().max().unwrap_or(1).max(1);

    let req_spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    format!(" req/s · 60s · max {max_req} "),
                    Style::default().fg(Color::Cyan),
                )),
        )
        .data(&req_data)
        .style(Style::default().fg(Color::LightCyan));
    f.render_widget(req_spark, cols[0]);

    let byp_spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    format!(" bypasses/s · 60s · max {max_byp} "),
                    Style::default().fg(Color::LightGreen),
                )),
        )
        .data(&bypass_data)
        .style(Style::default().fg(Color::Green));
    f.render_widget(byp_spark, cols[1]);
}

fn draw_detail(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let Some(idx) = state.selected else {
        return;
    };
    let Some(rec) = state.recent.get(idx) else {
        return;
    };
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightCyan))
        .title(Span::styled(
            format!(
                " Detail · {} {} → {} {} ",
                rec.method,
                truncate(&rec.path, 30),
                rec.status,
                rec.outcome()
            ),
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(5), Constraint::Min(5)])
        .split(inner);

    // ── Summary box ────
    let waf_label = rec.waf_name.as_deref().unwrap_or("(unknown)");
    let pad_label = if rec.body_padded { "yes" } else { "no" };
    let tls_label = rec.tls_profile.as_deref().unwrap_or("(none)");
    let summary = vec![
        Line::from(vec![
            Span::styled("host ", Style::default().fg(Color::DarkGray)),
            Span::styled(&rec.host, Style::default().fg(Color::Yellow)),
            Span::raw("    "),
            Span::styled("waf ", Style::default().fg(Color::DarkGray)),
            Span::styled(waf_label, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            Span::styled("attempts ", Style::default().fg(Color::DarkGray)),
            Span::styled(rec.attempts.to_string(), Style::default().fg(Color::White)),
            Span::raw("    "),
            Span::styled("latency ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}ms", rec.upstream_latency_ms),
                Style::default().fg(Color::White),
            ),
            Span::raw("    "),
            Span::styled("body padding ", Style::default().fg(Color::DarkGray)),
            Span::styled(pad_label, Style::default().fg(Color::Cyan)),
            Span::raw("    "),
            Span::styled("tls ", Style::default().fg(Color::DarkGray)),
            Span::styled(tls_label, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            Span::styled("techniques ", Style::default().fg(Color::DarkGray)),
            Span::styled(&rec.techniques, Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("response body ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} bytes", rec.resp_body_total),
                Style::default().fg(Color::White),
            ),
            Span::raw("    "),
            Span::styled("excerpt ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} bytes", rec.resp_body_excerpt.len()),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    let s = Paragraph::new(summary).wrap(Wrap { trim: false });
    f.render_widget(s, split[0]);

    // ── Outgoing request ────
    let mut req_lines = vec![Line::from(vec![Span::styled(
        format!("{} {} HTTP/1.1", rec.method, rec.path),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )])];
    for (k, v) in &rec.req_headers {
        req_lines.push(Line::from(vec![
            Span::styled(format!("{k}: "), Style::default().fg(Color::DarkGray)),
            Span::styled(v.clone(), Style::default().fg(Color::White)),
        ]));
    }
    if !rec.req_body_excerpt.is_empty() {
        req_lines.push(Line::from(""));
        req_lines.push(Line::styled(
            String::from_utf8_lossy(&rec.req_body_excerpt).to_string(),
            Style::default().fg(Color::Yellow),
        ));
    }
    let req_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " ↑ outgoing ",
            Style::default().fg(Color::Cyan),
        ));
    let p = Paragraph::new(req_lines).block(req_block).wrap(Wrap { trim: false });
    f.render_widget(p, split[1]);

    // ── Incoming response ────
    let status_style = Style::default()
        .fg(status_color(rec.status))
        .add_modifier(Modifier::BOLD);
    let mut resp_lines = vec![Line::from(vec![Span::styled(
        format!("HTTP/1.1 {}", rec.status),
        status_style,
    )])];
    for (k, v) in &rec.resp_headers {
        resp_lines.push(Line::from(vec![
            Span::styled(format!("{k}: "), Style::default().fg(Color::DarkGray)),
            Span::styled(v.clone(), Style::default().fg(Color::White)),
        ]));
    }
    if !rec.resp_body_excerpt.is_empty() {
        resp_lines.push(Line::from(""));
        resp_lines.push(Line::styled(
            String::from_utf8_lossy(&rec.resp_body_excerpt).to_string(),
            Style::default().fg(Color::Gray),
        ));
    }
    let resp_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " ↓ incoming ",
            Style::default().fg(status_color(rec.status)),
        ));
    let p = Paragraph::new(resp_lines).block(resp_block).wrap(Wrap { trim: false });
    f.render_widget(p, split[2]);
}

// ── Overview tab ─────────────────────────────────────────────────────

fn draw_overview(f: &mut ratatui::Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // counters block
            Constraint::Length(9),  // tls
            Constraint::Min(5),     // wafs identified
        ])
        .split(area);

    draw_counters(f, chunks[0], cfg, state);
    draw_tls(f, chunks[1], state);
    draw_wafs(f, chunks[2], state);
}

fn draw_counters(f: &mut ratatui::Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let body = vec![
        Line::from(vec![
            Span::styled("total ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.total.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("    "),
            Span::styled("bypassed ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ({:.1}%)", state.bypassed, state.bypass_rate_pct()),
                Style::default().fg(Color::LightGreen),
            ),
            Span::raw("    "),
            Span::styled("blocked ", Style::default().fg(Color::DarkGray)),
            Span::styled(state.blocked.to_string(), Style::default().fg(Color::LightRed)),
            Span::raw("    "),
            Span::styled("errors ", Style::default().fg(Color::DarkGray)),
            Span::styled(state.errors.to_string(), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("avg latency ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ms", state.avg_latency_ms()),
                Style::default().fg(Color::White),
            ),
            Span::raw("    "),
            Span::styled("padded bodies ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.padded.to_string(),
                Style::default().fg(Color::LightCyan),
            ),
            Span::raw("    "),
            Span::styled("evade retries ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.attempts_sum.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("body padding cfg ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if cfg.body_padding_bytes == 0 {
                    "off".to_string()
                } else {
                    format!("{} bytes", cfg.body_padding_bytes)
                },
                Style::default().fg(Color::LightCyan),
            ),
            Span::raw("    "),
            Span::styled("conn reuse ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if cfg.conn_reuse { "on" } else { "OFF" },
                Style::default().fg(if cfg.conn_reuse {
                    Color::White
                } else {
                    Color::LightRed
                }),
            ),
            Span::raw("    "),
            Span::styled("mode ", Style::default().fg(Color::DarkGray)),
            Span::styled(&cfg.mode, Style::default().fg(Color::Cyan)),
        ]),
    ];
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Counters ",
                Style::default().fg(Color::LightCyan),
            )),
    );
    f.render_widget(p, area);
}

fn draw_tls(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let total = state.tls.total();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " TLS Rotation ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if total == 0 || state.tls.counts.is_empty() {
        let p = Paragraph::new("(no TLS rotation active — start with --tls-impersonate-rotate)")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }
    let mut profiles: Vec<_> = state.tls.counts.iter().collect();
    profiles.sort_by(|a, b| b.1.cmp(a.1));
    let row_height = 1;
    let max_rows = (inner.height / row_height) as usize;
    for (i, (profile, count)) in profiles.iter().take(max_rows).enumerate() {
        let y = inner.y + (i as u16) * row_height;
        let row_area = Rect::new(inner.x, y, inner.width, row_height);
        #[allow(clippy::cast_precision_loss)]
        let pct = (**count as f64 / total as f64) * 100.0;
        let label = format!("{:<14} {:>5} ({:>4.1}%)", profile, count, pct);
        #[allow(clippy::cast_precision_loss)]
        let ratio = (**count as f64 / total as f64).min(1.0);
        let g = Gauge::default()
            .ratio(ratio)
            .label(label)
            .gauge_style(Style::default().fg(Color::LightMagenta).bg(Color::DarkGray));
        f.render_widget(g, row_area);
    }
}

fn draw_wafs(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " WAFs Identified ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.waf_seen.is_empty() {
        let p = Paragraph::new("(no WAFs identified yet — proxy more requests)")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }

    let mut entries: Vec<(&String, &u64)> = state.waf_seen.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));

    let max_rows = inner.height as usize;
    let lines: Vec<Line> = entries
        .iter()
        .take(max_rows)
        .map(|(name, hosts)| {
            Line::from(vec![
                Span::styled("• ", Style::default().fg(Color::LightMagenta)),
                Span::styled(
                    format!("{:<24}", truncate(name, 24)),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{} host(s)", hosts),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();
    let p = Paragraph::new(lines);
    f.render_widget(p, inner);
}

// ── Hosts tab ────────────────────────────────────────────────────────

fn draw_hosts(f: &mut ratatui::Frame, area: Rect, state: &State) {
    let header = Row::new(vec![
        Cell::from("HOST"),
        Cell::from("WAF"),
        Cell::from("SENT"),
        Cell::from("BLOCKED"),
        Cell::from("BYPASSED"),
        Cell::from("BYPASS%"),
        Cell::from("TOP TECHNIQUE"),
    ])
    .style(
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = state
        .top_hosts(20)
        .into_iter()
        .map(|(host, hs)| {
            #[allow(clippy::cast_precision_loss)]
            let pct = if hs.sent == 0 {
                0.0
            } else {
                (hs.bypassed as f64 / hs.sent as f64) * 100.0
            };
            let pct_color = match pct {
                p if p >= 75.0 => Color::LightGreen,
                p if p >= 25.0 => Color::Yellow,
                _ => Color::DarkGray,
            };
            let waf_label = hs.waf_name.as_deref().unwrap_or("—").to_string();
            Row::new(vec![
                Cell::from(host.clone()).style(Style::default().fg(Color::White)),
                Cell::from(waf_label).style(Style::default().fg(Color::LightMagenta)),
                Cell::from(hs.sent.to_string()),
                Cell::from(hs.blocked.to_string())
                    .style(Style::default().fg(Color::LightRed)),
                Cell::from(hs.bypassed.to_string())
                    .style(Style::default().fg(Color::LightGreen)),
                Cell::from(format!("{pct:.1}%")).style(Style::default().fg(pct_color)),
                Cell::from(truncate(&hs.top_technique, 36).to_string())
                    .style(Style::default().fg(Color::Magenta)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(22),
        Constraint::Length(14),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Percentage(36),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Per-Host (top 20) ",
                Style::default().fg(Color::LightCyan),
            )),
    );
    f.render_widget(table, area);
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
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
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 0,
        }
    }

    fn req_with_waf(host: &str, waf: &str) -> Event {
        let mut e = req(host, 403, false, false, None);
        if let Event::Request { waf_name, .. } = &mut e {
            *waf_name = Some(waf.to_string());
        }
        e
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
    fn reset_clears_counters_keeps_uptime_and_tab() {
        let mut s = State::new();
        s.tab = Tab::Hosts;
        let started = s.started;
        s.record(&req("a", 200, true, true, Some("chrome131")));
        assert_eq!(s.total, 1);
        s.record(&Event::ResetCounters);
        assert_eq!(s.total, 0);
        assert_eq!(s.bypassed, 0);
        assert_eq!(s.padded, 0);
        assert_eq!(s.started, started, "uptime must persist across reset");
        assert_eq!(s.tab, Tab::Hosts, "tab must persist across reset");
    }

    #[test]
    fn recent_capped() {
        let mut s = State::new();
        for i in 0..(REQUEST_RING + 50) {
            s.record(&req(&format!("h{i}"), 200, true, false, None));
        }
        assert_eq!(s.recent.len(), REQUEST_RING);
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
        assert_eq!(truncate("héllo", 3), "hé");
    }

    #[test]
    fn waf_seen_increments_once_per_host() {
        let mut s = State::new();
        s.record(&req_with_waf("a.com", "Cloudflare"));
        s.record(&req_with_waf("a.com", "Cloudflare"));
        s.record(&req_with_waf("a.com", "Cloudflare"));
        s.record(&req_with_waf("b.com", "Cloudflare"));
        s.record(&req_with_waf("c.com", "ModSecurity"));
        assert_eq!(s.waf_seen.get("Cloudflare"), Some(&2));
        assert_eq!(s.waf_seen.get("ModSecurity"), Some(&1));
    }

    #[test]
    fn select_navigation_clamps() {
        let mut s = State::new();
        for i in 0..5 {
            s.record(&req(&format!("h{i}"), 200, false, false, None));
        }
        s.select_last();
        assert_eq!(s.selected, Some(4));
        s.select_offset(1);
        assert_eq!(s.selected, Some(4), "must not go past end");
        s.select_offset(-10);
        assert_eq!(s.selected, Some(0), "must clamp to first");
        s.select_offset(2);
        assert_eq!(s.selected, Some(2));
    }

    #[test]
    fn select_first_no_op_when_empty() {
        let mut s = State::new();
        s.select_first();
        assert_eq!(s.selected, None);
    }

    #[test]
    fn status_color_classification() {
        assert_eq!(status_color(200), Color::Green);
        assert_eq!(status_color(301), Color::Cyan);
        assert_eq!(status_color(403), Color::Yellow);
        assert_eq!(status_color(503), Color::Red);
        assert_eq!(status_color(0), Color::DarkGray);
    }

    #[test]
    fn tab_cycles_in_order() {
        assert_eq!(Tab::Flow.next(), Tab::Overview);
        assert_eq!(Tab::Overview.next(), Tab::Hosts);
        assert_eq!(Tab::Hosts.next(), Tab::Flow);
    }
}
