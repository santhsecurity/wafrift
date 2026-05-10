//! Techniques tab — per-evasion-key leaderboard with bypass rate.
//!
//! Techniques with fewer than `MIN_TRIES_FOR_RANK` samples are listed
//! at the bottom in a separate "low-confidence" section so a single
//! lucky bypass doesn't dominate the ranking.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use super::state::{State, TechStats};

const MIN_TRIES_FOR_RANK: u64 = 5;

pub fn draw(f: &mut Frame, area: Rect, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8)])
        .split(area);

    draw_leaderboard(f, chunks[0], state);
    draw_low_confidence(f, chunks[1], state);
}

fn draw_leaderboard(f: &mut Frame, area: Rect, state: &State) {
    let header = Row::new(vec![
        Cell::from("RANK"),
        Cell::from("TECHNIQUE"),
        Cell::from("TRIED"),
        Cell::from("BYPASSED"),
        Cell::from("RATE"),
        Cell::from("LAST BYPASS"),
    ])
    .style(
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );

    let mut ranked: Vec<(&String, &TechStats)> = state
        .tech_stats
        .iter()
        .filter(|(_, t)| t.tried >= MIN_TRIES_FOR_RANK)
        .collect();
    // sort by bypass rate desc, then by tried desc as tie-breaker
    ranked.sort_by(|a, b| {
        b.1.bypass_rate()
            .partial_cmp(&a.1.bypass_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.tried.cmp(&a.1.tried))
    });

    let rows: Vec<Row> = ranked
        .iter()
        .take(50)
        .enumerate()
        .map(|(i, (name, t))| {
            let rate = t.bypass_rate() * 100.0;
            let rate_color = match rate {
                r if r >= 75.0 => Color::LightGreen,
                r if r >= 25.0 => Color::Yellow,
                _ => Color::DarkGray,
            };
            let last = format_last_bypass(t.last_bypass_unix_secs);
            Row::new(vec![
                Cell::from((i + 1).to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from((*name).clone()).style(Style::default().fg(Color::White)),
                Cell::from(t.tried.to_string()),
                Cell::from(t.bypassed.to_string())
                    .style(Style::default().fg(Color::LightGreen)),
                Cell::from(format!("{rate:.1}%")).style(Style::default().fg(rate_color)),
                Cell::from(last).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(
        " Technique leaderboard (≥{MIN_TRIES_FOR_RANK} tries · top 50 by bypass rate) "
    );
    let widths = [
        Constraint::Length(5),
        Constraint::Percentage(45),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(14),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(title, Style::default().fg(Color::LightCyan)));
    if rows.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        let p = Paragraph::new(format!(
            "(no technique has reached {MIN_TRIES_FOR_RANK} tries yet — proxy more requests)"
        ))
        .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
    } else {
        let table = Table::new(rows, widths).header(header).block(block);
        f.render_widget(table, area);
    }
}

fn draw_low_confidence(f: &mut Frame, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            format!(" Low-confidence (<{MIN_TRIES_FOR_RANK} tries) "),
            Style::default().fg(Color::DarkGray),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut low: Vec<(&String, &TechStats)> = state
        .tech_stats
        .iter()
        .filter(|(_, t)| t.tried < MIN_TRIES_FOR_RANK)
        .collect();
    low.sort_by_key(|(_, t)| std::cmp::Reverse(t.tried));

    if low.is_empty() {
        let p = Paragraph::new("(none)").style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }
    let max_rows = inner.height as usize;
    let lines: Vec<Line> = low
        .iter()
        .take(max_rows)
        .map(|(name, t)| {
            Line::from(vec![
                Span::styled("• ", Style::default().fg(Color::DarkGray)),
                Span::styled((*name).clone(), Style::default().fg(Color::Gray)),
                Span::raw("  "),
                Span::styled(
                    format!("{}/{}", t.bypassed, t.tried),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn format_last_bypass(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "—".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dt = now.saturating_sub(unix_secs);
    if dt < 60 {
        format!("{dt}s ago")
    } else if dt < 3600 {
        format!("{}m ago", dt / 60)
    } else if dt < 86400 {
        format!("{}h ago", dt / 3600)
    } else {
        format!("{}d ago", dt / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{Event, State};

    fn req(t: &str, bypassed: bool) -> Event {
        Event::Request {
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed,
            blocked: !bypassed,
            techniques: t.into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 1,
            waf_name: None,
            req_headers: vec![],
            req_body_excerpt: vec![],
            req_headers_pre: vec![],
            req_body_pre_excerpt: vec![],
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 0,
        }
    }

    #[test]
    fn leaderboard_only_includes_techniques_above_min_tries() {
        let mut s = State::new();
        // url has 6 tries, 6 bypass — qualifies
        for _ in 0..6 {
            s.record(&req("encoding:UrlEncode", true));
        }
        // grammar has 4 tries — does NOT qualify (< MIN_TRIES_FOR_RANK)
        for _ in 0..4 {
            s.record(&req("grammar:cmd", true));
        }
        let qualified: Vec<_> = s
            .tech_stats
            .iter()
            .filter(|(_, t)| t.tried >= MIN_TRIES_FOR_RANK)
            .collect();
        assert_eq!(qualified.len(), 1);
        assert_eq!(qualified[0].0, "encoding:UrlEncode");
    }

    #[test]
    fn last_bypass_format_buckets() {
        assert_eq!(format_last_bypass(0), "—");
    }

    #[test]
    fn bypass_rate_computed_correctly() {
        let mut s = State::new();
        for _ in 0..7 {
            s.record(&req("a", true));
        }
        for _ in 0..3 {
            s.record(&req("a", false));
        }
        let t = s.tech_stats.get("a").unwrap();
        assert_eq!(t.tried, 10);
        assert_eq!(t.bypassed, 7);
        assert!((t.bypass_rate() - 0.7).abs() < 1e-9);
    }
}
