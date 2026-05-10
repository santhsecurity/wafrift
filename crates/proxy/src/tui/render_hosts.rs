//! Hosts tab — top-N table sorted by request volume, with bypass rate
//! and most-recent winning technique per host.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::format::truncate;
use super::state::State;

pub fn draw(f: &mut Frame, area: Rect, state: &State) {
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
                Cell::from(hs.blocked.to_string()).style(Style::default().fg(Color::LightRed)),
                Cell::from(hs.bypassed.to_string()).style(Style::default().fg(Color::LightGreen)),
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
                " Per-Host (top 20 by volume) ",
                Style::default().fg(Color::LightCyan),
            )),
    );
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::{Event, State};

    fn req(host: &str, bypassed: bool) -> Event {
        Event::Request {
            host: host.into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed,
            blocked: !bypassed,
            techniques: "encoding:UrlEncode".into(),
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
    fn top_hosts_sorted_by_volume() {
        let mut s = State::new();
        for _ in 0..10 {
            s.record(&req("a", true));
        }
        for _ in 0..3 {
            s.record(&req("b", true));
        }
        for _ in 0..7 {
            s.record(&req("c", true));
        }
        let top = s.top_hosts(5);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[1].0, "c");
        assert_eq!(top[2].0, "b");
    }
}
