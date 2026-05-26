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
        Span::styled(
            cfg.tls_stack_label.clone(),
            Style::default().fg(Color::LightMagenta),
        ),
        sep(),
        meta_label("uptime"),
        Span::styled(
            humanize_uptime(state.uptime()),
            Style::default().fg(Color::White),
        ),
        sep(),
        meta_label("rps"),
        Span::styled(
            format!("{:.1}", state.rps_recent()),
            Style::default().fg(Color::Cyan),
        ),
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
            .border_style(crate::tui::style::DIM),
    );
    f.render_widget(p, area);
}

pub fn draw_tabs(f: &mut Frame, area: Rect, state: &State) {
    let mut spans = vec![Span::raw("  ")];
    for (i, t) in Tab::ORDER.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", crate::tui::style::DIM));
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
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                state.filter_query.clone(),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                "█",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
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
        key_hint("i", "intercept"),
        sep(),
    ];
    if state.tab == Tab::Intercept {
        spans.extend([
            key_hint("r", "release"),
            sep(),
            key_hint("k", "kill"),
            sep(),
        ]);
    }
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
            key_hint("R", "replay"),
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
            crate::tui::style::DIM,
        ),
    ]);

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── Local style helpers ─────────────────────────────────────────────

fn title_style() -> Style {
    Style::default()
        .fg(Color::LightCyan)
        .add_modifier(Modifier::BOLD)
}

fn meta_label(s: &str) -> Span<'static> {
    Span::styled(format!("{s} "), crate::tui::style::DIM)
}

fn sep() -> Span<'static> {
    Span::styled(" · ", crate::tui::style::DIM)
}

fn follow_chip(state: &State) -> Span<'static> {
    if state.follow {
        Span::styled(
            " FOLLOW ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " PAUSED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
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
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
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
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
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
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

fn key_hint(key: &str, label: &str) -> Span<'static> {
    Span::styled(
        format!(" {key} {label} "),
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn cfg() -> DashboardConfig {
        DashboardConfig {
            bind_addr: "127.0.0.1:8080".to_string(),
            mode: "forward".to_string(),
            tls_stack_label: "rustls".to_string(),
            body_padding_bytes: 0,
            conn_reuse: true,
        }
    }

    fn render_to_buffer<F>(width: u16, height: u16, draw: F) -> String
    where
        F: FnOnce(&mut Frame, Rect),
    {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("backend init");
        terminal
            .draw(|f| {
                let area = f.area();
                draw(f, area);
            })
            .expect("draw");
        // Concatenate buffer lines into a single string for substring
        // assertions.  Trailing whitespace on each row is dropped so
        // golden strings don't need to track padding.
        let mut out = String::new();
        let buffer = terminal.backend().buffer().clone();
        for y in 0..buffer.area().height {
            let mut line = String::new();
            for x in 0..buffer.area().width {
                line.push_str(buffer[(x, y)].symbol());
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    // ── draw_header ─────────────────────────────────────────

    #[test]
    fn header_includes_bind_addr_and_uptime() {
        let c = cfg();
        let s = State::new();
        let buf = render_to_buffer(120, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("wafrift"));
        assert!(buf.contains("127.0.0.1:8080"));
        assert!(buf.contains("uptime"));
    }

    #[test]
    fn header_shows_follow_chip_when_following() {
        let c = cfg();
        let mut s = State::new();
        s.follow = true;
        let buf = render_to_buffer(140, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("FOLLOW"));
        assert!(!buf.contains("PAUSED"));
    }

    #[test]
    fn header_shows_paused_chip_when_not_following() {
        let c = cfg();
        let mut s = State::new();
        s.follow = false;
        let buf = render_to_buffer(140, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("PAUSED"));
        assert!(!buf.contains("FOLLOW"));
    }

    #[test]
    fn header_outcome_filter_visible_when_set() {
        let c = cfg();
        let mut s = State::new();
        s.outcome_filter = OutcomeFilter::BypassOnly;
        let buf = render_to_buffer(160, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("BYPASS"));
    }

    #[test]
    fn header_outcome_filter_hidden_when_all() {
        let c = cfg();
        let mut s = State::new();
        s.outcome_filter = OutcomeFilter::All;
        let buf = render_to_buffer(160, 3, |f, area| draw_header(f, area, &c, &s));
        // "ALL" chip is suppressed when filter is the default.
        // Any other text containing "all" (the meta_label `meta`,
        // for example) must not produce a false hit.
        assert!(!buf.to_uppercase().contains(" ALL "));
    }

    #[test]
    fn header_filter_chip_visible_when_query_set() {
        let c = cfg();
        let mut s = State::new();
        s.filter_query = "host=foo".to_string();
        let buf = render_to_buffer(160, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("host=foo"));
    }

    #[test]
    fn header_toast_visible_when_present() {
        let c = cfg();
        let mut s = State::new();
        s.toast = Some(super::super::state::Toast::new("yanked!", ToastKind::Ok));
        let buf = render_to_buffer(160, 3, |f, area| draw_header(f, area, &c, &s));
        assert!(buf.contains("yanked!"));
    }

    #[test]
    fn header_renders_without_panic_on_narrow_width() {
        // Defensive: a 20-col terminal should not crash the draw
        // even though most spans get clipped.
        let c = cfg();
        let s = State::new();
        let _ = render_to_buffer(20, 3, |f, area| draw_header(f, area, &c, &s));
    }

    // ── draw_tabs ───────────────────────────────────────────

    #[test]
    fn tabs_show_all_known_tabs() {
        let s = State::new();
        let buf = render_to_buffer(120, 1, |f, area| draw_tabs(f, area, &s));
        for t in Tab::ORDER {
            assert!(
                buf.to_lowercase().contains(&t.label().to_lowercase()),
                "tab label `{}` missing from rendered output: `{buf}`",
                t.label()
            );
        }
    }

    #[test]
    fn tabs_highlight_active_tab_via_numeric_index() {
        let mut s = State::new();
        s.tab = Tab::ORDER[0];
        let buf = render_to_buffer(120, 1, |f, area| draw_tabs(f, area, &s));
        // The active tab label appears at index "1" (1-indexed).
        let first_label = Tab::ORDER[0].label();
        assert!(buf.contains(&format!("1 {first_label}")));
    }

    // ── draw_footer ─────────────────────────────────────────

    #[test]
    fn footer_includes_quit_key_hint() {
        let s = State::new();
        let buf = render_to_buffer(160, 1, |f, area| draw_footer(f, area, &s));
        assert!(buf.contains("quit"));
        assert!(buf.contains("switch"));
    }

    #[test]
    fn footer_flow_tab_shows_filter_outcome_keys() {
        let mut s = State::new();
        s.tab = Tab::Flow;
        let buf = render_to_buffer(180, 1, |f, area| draw_footer(f, area, &s));
        assert!(buf.contains("filter"));
        assert!(buf.contains("outcome"));
        assert!(buf.contains("yank curl"));
    }

    #[test]
    fn footer_intercept_tab_shows_release_kill_keys() {
        let mut s = State::new();
        s.tab = Tab::Intercept;
        let buf = render_to_buffer(160, 1, |f, area| draw_footer(f, area, &s));
        assert!(buf.contains("release"));
        assert!(buf.contains("kill"));
    }

    #[test]
    fn footer_filter_edit_mode_shows_input_with_cursor() {
        let mut s = State::new();
        s.input_mode = InputMode::FilterEdit;
        s.filter_query = "abc".to_string();
        let buf = render_to_buffer(120, 1, |f, area| draw_footer(f, area, &s));
        assert!(buf.contains("filter"));
        assert!(buf.contains("abc"));
        // Cursor block (█) is visible in filter-edit mode.
        assert!(buf.contains('█'));
    }

    #[test]
    fn footer_shows_request_counters() {
        let mut s = State::new();
        // Switch to a non-Flow tab so the footer doesn't fill its
        // width with Flow-specific hints — keeps the counter span
        // inside a 200-col render area.
        s.tab = Tab::Intercept;
        s.total = 42;
        s.attempts_sum = 7;
        let buf = render_to_buffer(200, 1, |f, area| draw_footer(f, area, &s));
        // The counters appear at the right edge in the form
        // "(42 reqs · 7 retries)".
        assert!(
            buf.contains("42 reqs"),
            "footer must surface request count.  Got: {buf:?}"
        );
        assert!(
            buf.contains("7 retries"),
            "footer must surface retries count. Got: {buf:?}"
        );
    }

    // ── Local style helpers (pure functions) ──────────────

    #[test]
    fn outcome_chip_labels_match_filter() {
        // outcome_chip is private — exercise through draw_header
        // by setting each filter mode.
        for (filter, expected) in [
            (OutcomeFilter::BypassOnly, "BYPASS"),
            (OutcomeFilter::BlockOnly, "BLOCK"),
            (OutcomeFilter::PassOnly, "PASS"),
        ] {
            let c = cfg();
            let mut s = State::new();
            s.outcome_filter = filter;
            let buf = render_to_buffer(160, 3, |f, area| draw_header(f, area, &c, &s));
            assert!(
                buf.contains(expected),
                "filter {filter:?} should render `{expected}`. Got: `{buf}`"
            );
        }
    }

    #[test]
    fn header_renders_high_volume_counters_without_overflow() {
        let c = cfg();
        let mut s = State::new();
        s.total = u64::MAX;
        s.attempts_sum = u64::MAX;
        // Should not panic on integer-overflow style arithmetic.
        let _ = render_to_buffer(200, 3, |f, area| draw_header(f, area, &c, &s));
    }
}
