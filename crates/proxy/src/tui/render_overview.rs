//! Overview tab — counters, latency percentiles, status-code ribbon,
//! TLS rotation, WAFs identified.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

use super::DashboardConfig;
use super::format::{
    STATUS_BUCKET_LABELS, status_bucket_color, truncate,
};
use super::state::State;

pub fn draw(f: &mut Frame, area: Rect, cfg: &DashboardConfig, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // counters
            Constraint::Length(4),  // latency percentiles
            Constraint::Length(4),  // status ribbon
            Constraint::Length(7),  // tls
            Constraint::Min(4),     // wafs
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
            Span::styled(state.total.to_string(), Style::default().add_modifier(Modifier::BOLD)),
            spacer(),
            label("bypassed"),
            Span::styled(
                format!("{} ({:.1}%)", state.bypassed, state.bypass_rate_pct()),
                Style::default().fg(Color::LightGreen),
            ),
            spacer(),
            label("blocked"),
            Span::styled(state.blocked.to_string(), Style::default().fg(Color::LightRed)),
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
            Span::styled(state.padded.to_string(), Style::default().fg(Color::LightCyan)),
            spacer(),
            label("evade retries"),
            Span::styled(state.attempts_sum.to_string(), Style::default().fg(Color::White)),
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
                Style::default().fg(if cfg.conn_reuse { Color::White } else { Color::LightRed }),
            ),
            spacer(),
            label("mode"),
            Span::styled(cfg.mode.clone(), Style::default().fg(Color::Cyan)),
        ]),
    ];
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(" Counters ", Style::default().fg(Color::LightCyan))),
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
            Style::default().fg(Color::DarkGray),
        ),
    ])];
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
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
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Status code mix ",
            Style::default().fg(Color::LightCyan),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let total: u64 = state.status_buckets.iter().sum();
    if total == 0 {
        let p = Paragraph::new("(no responses yet)").style(Style::default().fg(Color::DarkGray));
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
            Style::default().fg(Color::Black).bg(status_bucket_color(i)).add_modifier(Modifier::BOLD),
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
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(" TLS Rotation ", Style::default().fg(Color::LightCyan)));
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

fn draw_wafs(f: &mut Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(" WAFs Identified ", Style::default().fg(Color::LightCyan)));
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
                Span::styled(format!("{hosts} host(s)"), Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn label(s: &str) -> Span<'static> {
    Span::styled(format!("{s} "), Style::default().fg(Color::DarkGray))
}

fn spacer() -> Span<'static> {
    Span::raw("    ")
}
