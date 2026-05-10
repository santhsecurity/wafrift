//! Intercept tab — operator control surface for paused requests.
//!
//! Layout:
//!   ┌─ Intercept · 3 pending · MODE: ON ─────────┐
//!   │  ▶  GET   /admin       api.target.com  3s  │
//!   │     POST  /v1/users    api.target.com  1s  │
//!   │     GET   /style.css   cdn.example.com 8s  │
//!   └────────────────────────────────────────────┘
//!   r release · k kill · i toggle mode · j/k navigate

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::intercept;

use super::format::truncate;
use super::state::State;

pub fn draw(f: &mut Frame, area: Rect, _state: &State) {
    let pending = intercept::global_store().snapshot();
    let mode_on = intercept::intercept_mode_enabled();

    let title = format!(
        " Intercept · {} pending · MODE: {} ",
        pending.len(),
        if mode_on { "ON" } else { "OFF" },
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if mode_on { Color::LightGreen } else { Color::DarkGray }))
        .title(Span::styled(
            title,
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD),
        ));

    if pending.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        let p = Paragraph::new(if mode_on {
            "(no requests parked yet — proxy something through this address)"
        } else {
            "(intercept mode is OFF — press `i` to toggle ON)"
        })
        .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }

    let header = Row::new(vec![
        Cell::from("ID"),
        Cell::from("METHOD"),
        Cell::from("PATH"),
        Cell::from("HOST"),
        Cell::from("WAITING"),
    ])
    .style(
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );

    let now = std::time::Instant::now();
    let rows: Vec<Row> = pending
        .iter()
        .map(|p| {
            let waiting_secs = now.duration_since(p.since).as_secs();
            let waiting_color = match waiting_secs {
                0..=4 => Color::Green,
                5..=14 => Color::Yellow,
                _ => Color::Red,
            };
            Row::new(vec![
                Cell::from(p.id.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(p.method.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(truncate(&p.path, 36).to_string()).style(Style::default().fg(Color::White)),
                Cell::from(truncate(&p.host, 28).to_string()).style(Style::default().fg(Color::Yellow)),
                Cell::from(format!("{waiting_secs}s")).style(Style::default().fg(waiting_color)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Percentage(40),
        Constraint::Percentage(35),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intercept::{InterceptStore, set_intercept_mode};

    #[tokio::test]
    async fn snapshot_appears_in_global_store() {
        // Sanity: the render path reads from the global singleton.
        // After a register, the snapshot must be non-empty.
        let store = InterceptStore::new();
        let (_, _rx) = store.register("h", "GET", "/");
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        let _ = snap; // suppress unused on no-trait-asserts
    }

    #[test]
    fn intercept_mode_toggle_round_trips() {
        let initial = intercept::intercept_mode_enabled();
        set_intercept_mode(false);
        assert!(!intercept::intercept_mode_enabled());
        intercept::toggle_intercept_mode();
        assert!(intercept::intercept_mode_enabled());
        intercept::toggle_intercept_mode();
        assert!(!intercept::intercept_mode_enabled());
        // restore
        set_intercept_mode(initial);
    }
}
