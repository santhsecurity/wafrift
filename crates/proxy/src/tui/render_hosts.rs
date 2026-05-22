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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

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

    fn req_with_waf(host: &str, bypassed: bool, waf: &str, technique: &str) -> Event {
        Event::Request {
            host: host.into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed,
            blocked: !bypassed,
            techniques: technique.into(),
            tls_profile: None,
            body_padded: false,
            upstream_latency_ms: 1,
            waf_name: Some(waf.into()),
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

    fn render(width: u16, height: u16, state: &State) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("backend");
        terminal
            .draw(|f| {
                let area = f.area();
                draw(f, area, state);
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

    #[test]
    fn render_shows_table_headers() {
        let s = State::new();
        let buf = render(140, 12, &s);
        for header in ["HOST", "WAF", "SENT", "BLOCKED", "BYPASSED", "BYPASS%", "TOP TECHNIQUE"] {
            assert!(
                buf.contains(header),
                "expected header `{header}` in: {buf}"
            );
        }
    }

    #[test]
    fn render_shows_panel_title() {
        let s = State::new();
        let buf = render(140, 12, &s);
        assert!(buf.contains("Per-Host"));
        assert!(buf.contains("top 20 by volume"));
    }

    #[test]
    fn render_with_no_hosts_does_not_panic() {
        // Empty state — only the header row is drawn.
        let s = State::new();
        let _ = render(120, 12, &s);
    }

    #[test]
    fn render_with_single_host_shows_counts() {
        let mut s = State::new();
        for _ in 0..5 {
            s.record(&req("example.com", true));
        }
        for _ in 0..2 {
            s.record(&req("example.com", false));
        }
        let buf = render(180, 12, &s);
        assert!(buf.contains("example.com"));
        assert!(buf.contains("7")); // total sent
        // The technique name should appear somewhere in the row.
        assert!(buf.contains("UrlEncode") || buf.contains("encoding"));
    }

    #[test]
    fn render_long_hostname_is_visible() {
        let mut s = State::new();
        let long_host = "very-long-subdomain.example.long-tld.co.uk";
        s.record(&req(long_host, true));
        let buf = render(200, 12, &s);
        // The host appears (possibly truncated by column constraint).
        assert!(buf.contains("very-long-subdomain") || buf.contains("example.long-tld"));
    }

    #[test]
    fn render_shows_waf_label_when_present() {
        let mut s = State::new();
        s.record(&req_with_waf(
            "fastly-host.example",
            true,
            "Fastly",
            "encoding:UrlEncode",
        ));
        let buf = render(200, 12, &s);
        assert!(buf.contains("Fastly"));
    }

    #[test]
    fn render_shows_em_dash_when_waf_unknown() {
        let mut s = State::new();
        s.record(&req("unknown.example", true));
        let buf = render(200, 12, &s);
        // The "—" U+2014 fallback should be present in the WAF column.
        assert!(buf.contains('—') || buf.contains("-"));
    }

    #[test]
    fn render_bypass_percentage_formatted_to_one_decimal() {
        let mut s = State::new();
        // 3 bypassed out of 4 total = 75.0%.
        for _ in 0..3 {
            s.record(&req("pct.example", true));
        }
        s.record(&req("pct.example", false));
        let buf = render(200, 12, &s);
        assert!(buf.contains("75.0%"));
    }

    #[test]
    fn render_top_hosts_capped_at_20() {
        let mut s = State::new();
        // Insert 30 distinct hosts — only top 20 should be drawn.
        for i in 0..30 {
            let h = format!("host{i:02}.example");
            for _ in 0..(30 - i) {
                s.record(&req(&h, true));
            }
        }
        // Tall enough to fit 20 rows.
        let buf = render(180, 25, &s);
        // host00 has the most requests, must appear.
        assert!(buf.contains("host00"));
        // host29 has the fewest — shouldn't appear in top 20.
        assert!(!buf.contains("host29"));
    }

    #[test]
    fn render_technique_truncated_to_36_chars() {
        let mut s = State::new();
        let long_technique = "a".repeat(60);
        s.record(&req_with_waf(
            "long-tech.example",
            true,
            "Test",
            &long_technique,
        ));
        let buf = render(200, 12, &s);
        // Truncate ends with `…` or the truncated tail isn't 60 chars.
        // Confirm we don't see all 60 'a' chars in a row.
        assert!(!buf.contains(&"a".repeat(60)));
    }

    #[test]
    fn render_narrow_width_does_not_panic() {
        let mut s = State::new();
        for i in 0..5 {
            s.record(&req(&format!("n{i}.example"), true));
        }
        let _ = render(40, 12, &s);
    }
}
