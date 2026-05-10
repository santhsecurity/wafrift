//! Terminal dashboard for `wafrift-proxy`.
//!
//! Active when `wafrift-proxy --tui` is passed. Runs in a dedicated
//! tokio task, draws via ratatui + crossterm. The module is split:
//!
//! - [`state`]            — counters, request ring, filter state, toast queue
//! - [`format`]           — palette + truncation helpers
//! - [`keymap`]           — keystroke dispatch (Normal + FilterEdit modes)
//! - [`yank`]             — render selected request as `curl` + clipboard set
//! - [`render_chrome`]    — header bar, tab strip, footer key-help
//! - [`render_flow`]      — Flow tab: live stream + sparklines + detail pane
//! - [`render_overview`]  — Overview tab: counters, percentiles, status mix
//! - [`render_hosts`]     — Hosts tab: per-host bypass leaderboard
//! - [`render_techniques`]— Techniques tab: per-evasion-key leaderboard
//!
//! # Layout
//!
//! ```text
//!  ┌─ wafrift · proxy 127.0.0.1:8080 · stealth chrome131 · uptime 3m  · rps 12.4 · bypass 27.3%   FOLLOW   FILTER:admin ┐
//!  │  [1 Flow]  2 Overview │ 3 Hosts │ 4 Techniques                                                                    │
//!  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
//!  │  Requests · 14 of 327                                                       Detail · POST /admin → 200 BYPASS    │
//!  │  ▶ 12:01:03  POST  /admin     api.target.com  200 BYPASS  encoding:UrlEncode    host  api.target.com               │
//!  │    12:01:02  GET   /v1/users  api.target.com  403 BLOCK                          waf   Cloudflare                   │
//!  │    ...                                                                           ↑ outgoing request                 │
//!  │  ▒▒▓▓██▓▓▒▒  req/s  ░░▒▓██▓▒░  bypasses/s                                       POST /admin HTTP/1.1               │
//!  ├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
//!  │ q quit │ tab switch │ / filter │ o outcome │ p follow │ j/k nav │ enter inspect │ y yank curl │ r reset           │
//!  └──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::io;
use std::time::Duration;

use crossterm::event::{self as ce, Event as CtEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use tokio::sync::{mpsc, oneshot};

pub mod format;
pub mod keymap;
pub mod render_chrome;
pub mod render_flow;
pub mod render_hosts;
pub mod render_overview;
pub mod render_techniques;
pub mod state;
pub mod yank;

pub use state::{Event, MAX_BODY_EXCERPT};
use state::{State, Tab};

/// Header-bar metadata so the TUI can label its chrome without
/// re-importing the proxy CLI args.
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub bind_addr: String,
    pub mode: String,
    pub tls_stack_label: String,
    pub body_padding_bytes: usize,
    pub conn_reuse: bool,
}

/// Run the dashboard until `q` is pressed or the request channel
/// closes. Returns once the terminal has been restored.
///
/// `quit_tx` is fired on user-requested shutdown so the proxy main
/// loop can begin graceful shutdown.
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
        // Drain a burst of events without redrawing per-event — keeps
        // the TUI responsive under heavy load.
        while let Ok(ev) = events.try_recv() {
            state.record(&ev);
        }
        state.tick_toast();

        tokio::select! {
            _ = redraw.tick() => {
                term.draw(|f| draw(f, &cfg, &state))?;
            }
            ev = events.recv() => {
                match ev {
                    Some(ev) => state.record(&ev),
                    None => break, // proxy shut down
                }
            }
        }

        // Non-blocking key polling.
        if ce::poll(Duration::from_millis(0))?
            && let CtEvent::Key(k) = ce::read()?
            && k.kind == KeyEventKind::Press
            && keymap::handle_key(&mut state, k.code, k.modifiers, &mut quit)
        {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

/// Top-level draw — header / tab strip / body / footer.
fn draw(f: &mut ratatui::Frame, cfg: &DashboardConfig, state: &State) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // tab strip
            Constraint::Min(5),    // body (per tab)
            Constraint::Length(1), // footer
        ])
        .split(area);

    render_chrome::draw_header(f, chunks[0], cfg, state);
    render_chrome::draw_tabs(f, chunks[1], state);
    match state.tab {
        Tab::Flow => render_flow::draw(f, chunks[2], state),
        Tab::Overview => render_overview::draw(f, chunks[2], cfg, state),
        Tab::Hosts => render_hosts::draw(f, chunks[2], state),
        Tab::Techniques => render_techniques::draw(f, chunks[2], state),
    }
    render_chrome::draw_footer(f, chunks[3], state);
}
