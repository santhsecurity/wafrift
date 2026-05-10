//! Persistent chrome: header bar, tab strip, footer key-help.
//!
//! All three are drawn on every frame regardless of active tab.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::DashboardConfig;
use super::format::humanize_uptime;
use super::state::{InputMode, OutcomeFilter, State, Tab, ToastKind};

pub fn draw_header(f: &mut Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let mut spans = vec![
        Span::styled("wafrift", title_style()),
        sep(),
        meta_label("proxy"),
        Span::styled(cfg.bind_addr.clone(), Style::default().fg(Color::Yellow)),
        sep(),
        meta_label("stealth"),
        Span::styled(cfg.tls_stack_label.clone(), Style::default().fg(Color::LightMagenta)),
        sep(),
        meta_label("uptime"),
        Span::styled(humanize_uptime(state.uptime()), Style::default().fg(Color::White)),
        sep(),
        meta_label("rps"),
        Span::styled(format!("{:.1}", state.rps_recent()), Style::default().fg(Color::Cyan)),
        sep(),
        meta_label("bypass"),
        Span::styled(
            format!("{:.1}%", state.bypass_rate_pct()),
            Style::default().fg(Color::LightGreen),
        ),
        Span::raw("   "),
        follow_chip(state),
    ];

    if state.outcome_filter != OutcomeFilter::All {
        spans.push(Span::raw(" "));
        spans.push(outcome_chip(state.outcome_filter));
    }
    if !state.filter_query.is_empty() || state.input_mode == InputMode::FilterEdit {
        spans.push(Span::raw(" "));
        spans.push(filter_chip(state));
    }
    if let Some(t) = &state.toast {
        spans.push(Span::raw("   "));
        spans.push(toast_chip(&t.message, t.kind));
    }

    let p = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(p, area);
}

pub fn draw_tabs(f: &mut Frame, area: Rect, state: &State) {
    let mut spans = vec![Span::raw("  ")];
    for (i, t) in Tab::ORDER.iter().enumerate() {
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
        spans.push(Span::styled(format!(" {} {} ", i + 1, t.label()), style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub fn draw_footer(f: &mut Frame, area: Rect, state: &State) {
    if state.input_mode == InputMode::FilterEdit {
        let p = Paragraph::new(Line::from(vec![
            Span::styled(
                " filter ",
                Style::default().fg(Color::Black).bg(Color::LightCyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(state.filter_query.clone(), Style::default().fg(Color::Yellow)),
            Span::styled("█", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)),
            Span::raw("    "),
            key_hint("Enter", "commit"),
            sep(),
            key_hint("Esc", "cancel"),
            sep(),
            key_hint("BS", "delete"),
        ]));
        f.render_widget(p, area);
        return;
    }

    let mut spans: Vec<Span<'static>> = vec![
        key_hint("q", "quit"),
        sep(),
        key_hint("tab", "switch"),
        sep(),
    ];
    if state.tab == Tab::Flow {
        spans.extend([
            key_hint("/", "filter"),
            sep(),
            key_hint("o", "outcome"),
            sep(),
            key_hint("p", "follow"),
            sep(),
            key_hint("j/k", "nav"),
            sep(),
            key_hint("PgUp/Dn", "page"),
            sep(),
            key_hint("g/G", "first/last"),
            sep(),
            key_hint("enter", "inspect"),
            sep(),
            key_hint("y", "yank curl"),
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

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── Local style helpers ─────────────────────────────────────────────

fn title_style() -> Style {
    Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)
}

fn meta_label(s: &str) -> Span<'static> {
    Span::styled(format!("{s} "), Style::default().fg(Color::DarkGray))
}

fn sep() -> Span<'static> {
    Span::styled(" · ", Style::default().fg(Color::DarkGray))
}

fn follow_chip(state: &State) -> Span<'static> {
    if state.follow {
        Span::styled(
            " FOLLOW ",
            Style::default().fg(Color::Black).bg(Color::LightGreen).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " PAUSED ",
            Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    }
}

fn outcome_chip(f: OutcomeFilter) -> Span<'static> {
    let (label, color) = match f {
        OutcomeFilter::All => ("ALL", Color::Gray),
        OutcomeFilter::BypassOnly => ("BYPASS", Color::LightGreen),
        OutcomeFilter::BlockOnly => ("BLOCK", Color::LightRed),
        OutcomeFilter::PassOnly => ("PASS", Color::White),
    };
    Span::styled(
        format!(" {label} "),
        Style::default().fg(Color::Black).bg(color).add_modifier(Modifier::BOLD),
    )
}

fn filter_chip(state: &State) -> Span<'static> {
    let label = if state.filter_query.is_empty() {
        " FILTER:_ ".to_string()
    } else {
        format!(" FILTER:{} ", state.filter_query)
    };
    Span::styled(
        label,
        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
    )
}

fn toast_chip(msg: &str, kind: ToastKind) -> Span<'static> {
    let color = match kind {
        ToastKind::Info => Color::Blue,
        ToastKind::Ok => Color::Green,
        ToastKind::Warn => Color::Yellow,
        ToastKind::Err => Color::Red,
    };
    Span::styled(
        format!(" {msg} "),
        Style::default().fg(Color::Black).bg(color).add_modifier(Modifier::BOLD),
    )
}

fn key_hint(key: &str, label: &str) -> Span<'static> {
    Span::styled(
        format!(" {key} {label} "),
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    )
}
