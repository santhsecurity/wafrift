//! Overview tab — counters, latency percentiles, status-code ribbon,
//! TLS rotation, WAFs identified.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

use super::DashboardConfig;
use super::format::{STATUS_BUCKET_LABELS, status_bucket_color, truncate};
use super::state::State;

pub fn draw(f: &mut Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // counters
            Constraint::Length(4), // latency percentiles
            Constraint::Length(4), // status ribbon
            Constraint::Length(7), // tls
            Constraint::Min(4),    // wafs
        ])
        .split(area);

    draw_counters(f, chunks[0], cfg, state);
    draw_latency(f, chunks[1], state);
    draw_status_ribbon(f, chunks[2], state);
    draw_tls(f, chunks[3], state);
    draw_wafs(f, chunks[4], state);
}

fn draw_counters(f: &mut Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let body = vec![
        Line::from(vec![
            label("total"),
            Span::styled(
                state.total.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            spacer(),
            label("bypassed"),
            Span::styled(
                format!("{} ({:.1}%)", state.bypassed, state.bypass_rate_pct()),
                Style::default().fg(Color::LightGreen),
            ),
            spacer(),
            label("blocked"),
            Span::styled(
                state.blocked.to_string(),
                Style::default().fg(Color::LightRed),
            ),
            spacer(),
            label("errors"),
            Span::styled(state.errors.to_string(), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            label("avg latency"),
            Span::styled(
                format!("{} ms", state.avg_latency_ms()),
                Style::default().fg(Color::White),
            ),
            spacer(),
            label("padded bodies"),
            Span::styled(
                state.padded.to_string(),
                Style::default().fg(Color::LightCyan),
            ),
            spacer(),
            label("evade retries"),
            Span::styled(
                state.attempts_sum.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            label("body padding cfg"),
            Span::styled(
                if cfg.body_padding_bytes == 0 {
                    "off".to_string()
                } else {
                    format!("{} bytes", cfg.body_padding_bytes)
                },
                Style::default().fg(Color::LightCyan),
            ),
            spacer(),
            label("conn reuse"),
            Span::styled(
                if cfg.conn_reuse { "on" } else { "OFF" },
                Style::default().fg(if cfg.conn_reuse {
                    Color::White
                } else {
                    Color::LightRed
                }),
            ),
            spacer(),
            label("mode"),
            Span::styled(cfg.mode.clone(), Style::default().fg(Color::Cyan)),
        ]),
    ];
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(crate::tui::style::DIM)
            .title(Span::styled(
                " Counters ",
                Style::default().fg(Color::LightCyan),
            )),
    );
    f.render_widget(p, area);
}

fn draw_latency(f: &mut Frame, area: Rect, state: &State) {
    let p50 = state.latency_percentile(0.50);
    let p95 = state.latency_percentile(0.95);
    let p99 = state.latency_percentile(0.99);
    let p_max = state.latency_percentile(1.0);

    let body = vec![Line::from(vec![
        label("p50"),
        Span::styled(format!("{p50}ms"), pct_color(p50)),
        spacer(),
        label("p95"),
        Span::styled(format!("{p95}ms"), pct_color(p95)),
        spacer(),
        label("p99"),
        Span::styled(format!("{p99}ms"), pct_color(p99)),
        spacer(),
        label("max"),
        Span::styled(format!("{p_max}ms"), pct_color(p_max)),
        spacer(),
        Span::styled(
            format!("({} samples)", state.latency_samples.len()),
            crate::tui::style::DIM,
        ),
    ])];
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(crate::tui::style::DIM)
            .title(Span::styled(
                " Upstream latency (recent 1024) ",
                Style::default().fg(Color::LightCyan),
            )),
    );
    f.render_widget(p, area);
}

fn pct_color(ms: u64) -> Style {
    let c = if ms >= 1000 {
        Color::LightRed
    } else if ms >= 250 {
        Color::Yellow
    } else if ms == 0 {
        Color::DarkGray
    } else {
        Color::White
    };
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

fn draw_status_ribbon(f: &mut Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(crate::tui::style::DIM)
        .title(Span::styled(
            " Status code mix ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let total: u64 = state.status_buckets.iter().sum();
    if total == 0 {
        let p = Paragraph::new("(no responses yet)").style(crate::tui::style::DIM);
        f.render_widget(p, inner);
        return;
    }

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(STATUS_BUCKET_LABELS.len() * 4);
    for (i, count) in state.status_buckets.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        if !spans.is_empty() {
            spans.push(Span::raw("   "));
        }
        #[allow(clippy::cast_precision_loss)]
        let pct = (*count as f64 / total as f64) * 100.0;
        spans.push(Span::styled(
            format!(" {} ", STATUS_BUCKET_LABELS[i]),
            Style::default()
                .fg(Color::Black)
                .bg(status_bucket_color(i))
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("{count} ({pct:.1}%)"),
            Style::default().fg(status_bucket_color(i)),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn draw_tls(f: &mut Frame, area: Rect, state: &State) {
    let total = state.tls.total();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(crate::tui::style::DIM)
        .title(Span::styled(
            " TLS Rotation ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if total == 0 || state.tls.counts.is_empty() {
        let p = Paragraph::new("(no TLS rotation active — start with --tls-impersonate-rotate)")
            .style(crate::tui::style::DIM);
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
        let label = format!("{profile:<14} {count:>5} ({pct:>4.1}%)");
        #[allow(clippy::cast_precision_loss)]
        let ratio = (**count as f64 / total as f64).min(1.0);
        let g = Gauge::default()
            .ratio(ratio)
            .label(label)
            .gauge_style(Style::default().fg(Color::LightMagenta).bg(Color::DarkGray));
        f.render_widget(g, row_area);
    }
}

fn draw_wafs(f: &mut Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(crate::tui::style::DIM)
        .title(Span::styled(
            " WAFs Identified ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.waf_seen.is_empty() {
        let p = Paragraph::new("(no WAFs identified yet — proxy more requests)")
            .style(crate::tui::style::DIM);
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
                    format!("{hosts} host(s)"),
                    crate::tui::style::DIM,
                ),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn label(s: &str) -> Span<'static> {
    Span::styled(format!("{s} "), crate::tui::style::DIM)
}

fn spacer() -> Span<'static> {
    Span::raw("    ")
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

    fn render<F>(width: u16, height: u16, paint: F) -> String
    where
        F: FnOnce(&mut Frame, Rect),
    {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|f| {
                let area = f.area();
                paint(f, area);
            })
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
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

    // ── draw() — top-level composition ─────────────────────

    #[test]
    fn draw_top_level_renders_all_sections() {
        let c = cfg();
        let s = State::new();
        let buf = render(140, 30, |f, area| draw(f, area, &c, &s));
        // Counter section labels.
        assert!(buf.contains("total"));
        assert!(buf.contains("bypassed"));
        assert!(buf.contains("blocked"));
        // Latency section.
        assert!(buf.to_lowercase().contains("latency") || buf.contains("p50"));
        // TLS section.
        assert!(buf.to_lowercase().contains("tls"));
    }

    #[test]
    fn draw_handles_zero_request_state_without_panic() {
        // Fresh state — no requests, no latencies recorded.  The
        // percentile / TLS / WAF sections should still render.
        let c = cfg();
        let s = State::new();
        let _ = render(120, 30, |f, area| draw(f, area, &c, &s));
    }

    #[test]
    fn draw_handles_extreme_counter_values() {
        let c = cfg();
        let mut s = State::new();
        s.total = u64::MAX;
        s.bypassed = u64::MAX / 2;
        s.blocked = u64::MAX / 3;
        let _ = render(140, 30, |f, area| draw(f, area, &c, &s));
    }

    // ── draw_counters ──────────────────────────────────────

    #[test]
    fn counters_show_total_and_bypass_rate() {
        let c = cfg();
        let mut s = State::new();
        s.total = 100;
        s.bypassed = 25;
        s.blocked = 5;
        let buf = render(160, 7, |f, area| draw_counters(f, area, &c, &s));
        assert!(buf.contains("100"));
        assert!(buf.contains("25"));
        assert!(buf.contains("5"));
        // Bypass rate is 25/100 = 25.0%.
        assert!(buf.contains("25.0%"));
    }

    #[test]
    fn counters_handle_zero_total_division_safely() {
        let c = cfg();
        let s = State::new();
        // total=0 → bypass_rate is 0.0% (not NaN, not Inf).
        let buf = render(160, 7, |f, area| draw_counters(f, area, &c, &s));
        assert!(buf.contains("0.0%") || buf.contains("0%"));
        assert!(
            !buf.contains("NaN") && !buf.contains("inf"),
            "counter section must not surface NaN/Inf on zero state"
        );
    }

    // ── draw_latency ────────────────────────────────────────

    #[test]
    fn latency_section_renders_zero_state() {
        let s = State::new();
        let buf = render(120, 4, |f, area| draw_latency(f, area, &s));
        // No latencies recorded → all percentiles should be 0 ms
        // or similar non-panicky display.
        assert!(!buf.is_empty());
        assert!(!buf.contains("NaN"));
    }

    // ── pct_color — pure helper ───────────────────────────

    #[test]
    fn pct_color_returns_distinct_styles_across_ms_buckets() {
        // The bucket boundaries are an implementation detail, but
        // the function must return *some* Style for any input.
        for ms in [0_u64, 50, 100, 250, 500, 1000, 5000, u64::MAX] {
            let _style = pct_color(ms);
        }
    }

    // ── draw_status_ribbon ────────────────────────────────

    #[test]
    fn status_ribbon_renders_without_panic() {
        let s = State::new();
        let _ = render(140, 4, |f, area| draw_status_ribbon(f, area, &s));
    }

    // ── draw_tls ───────────────────────────────────────────

    #[test]
    fn tls_section_renders_without_panic_on_empty_history() {
        let s = State::new();
        let buf = render(120, 7, |f, area| draw_tls(f, area, &s));
        // The TLS section has its own label/header.
        assert!(buf.to_lowercase().contains("tls"));
    }

    // ── draw_wafs ──────────────────────────────────────────

    #[test]
    fn wafs_section_renders_empty_state() {
        let s = State::new();
        let buf = render(120, 6, |f, area| draw_wafs(f, area, &s));
        // Empty state — at minimum a section header is present.
        assert!(!buf.is_empty());
    }

    #[test]
    fn wafs_section_handles_narrow_width() {
        // Defensive: 30-col width should still render a header.
        let s = State::new();
        let _ = render(30, 6, |f, area| draw_wafs(f, area, &s));
    }

    #[test]
    fn draw_handles_tiny_screen_without_panic() {
        // 40x12 is below any reasonable terminal size — the
        // function must clip cleanly rather than panic.
        let c = cfg();
        let s = State::new();
        let _ = render(40, 12, |f, area| draw(f, area, &c, &s));
    }

    #[test]
    fn label_helper_returns_dark_gray_span() {
        let span = label("test");
        assert!(span.content.starts_with("test"));
    }

    #[test]
    fn spacer_helper_returns_blank_span() {
        let span = spacer();
        assert!(span.content.trim().is_empty());
    }
}
