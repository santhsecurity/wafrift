//! Flow tab — live request stream with optional detail pane.
//!
//! Layout when no inspect:
//!   ┌─ Requests ──────────────┐
//!   │ ▶ rows...               │
//!   ├─ req/s ─┬─ bypasses/s ──┤
//!   └─────────┴───────────────┘
//!
//! With inspect, the right column hosts the detail pane.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Sparkline, Wrap};

use super::format::{outcome_color, status_color, truncate};
use super::state::{RequestRecord, State};

pub fn draw(f: &mut Frame, area: Rect, state: &State) {
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

fn draw_request_list(f: &mut Frame, area: Rect, state: &State) {
    let visible = state.visible_indices();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            format!(" Requests · {} of {} ", visible.len(), state.recent.len()),
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
    if visible.is_empty() {
        let p = Paragraph::new("(filter matches nothing — `/` to edit, `o` to cycle outcome)")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(p, inner);
        return;
    }

    let inner_h = inner.height as usize;
    let total = visible.len();
    // Anchor visible window around the selected row when present.
    let anchor_visible = state
        .selected
        .and_then(|sel| visible.iter().position(|&v| v == sel))
        .unwrap_or(total - 1);
    let start = anchor_visible.saturating_sub(inner_h.saturating_sub(1));
    let window: Vec<usize> = visible.iter().copied().skip(start).take(inner_h).collect();

    let mut lines = Vec::with_capacity(window.len());
    for ridx in window {
        let Some(rec) = state.recent.get(ridx) else { continue };
        let is_sel = state.selected == Some(ridx);
        let marker = if is_sel { "▶ " } else { "  " };
        let row_style = if is_sel {
            Style::default().bg(Color::Rgb(28, 32, 40)).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let path_disp = truncate(&rec.path, 24);
        let host_disp = truncate(&rec.host, 22);
        let line = Line::from(vec![
            Span::styled(marker, Style::default().fg(outcome_color(rec))),
            Span::styled(rec.timestamp.clone(), Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(format!("{:>5}", rec.method), Style::default().fg(Color::Cyan)),
            Span::raw(" "),
            Span::styled(format!("{path_disp:<24}"), Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(format!("{host_disp:<22}"), Style::default().fg(Color::Gray)),
            Span::raw(" "),
            Span::styled(
                format!("{:>3}", rec.status),
                Style::default().fg(status_color(rec.status)).add_modifier(Modifier::BOLD),
            ),
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
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn draw_sparklines(f: &mut Frame, area: Rect, state: &State) {
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

fn draw_detail(f: &mut Frame, area: Rect, state: &State) {
    let Some(idx) = state.selected else { return };
    let Some(rec) = state.recent.get(idx) else { return };

    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightCyan))
        .title(Span::styled(
            format!(
                " Detail · {} {} → {} {} · scroll j/k PgUp/Dn ",
                rec.method,
                truncate(&rec.path, 30),
                rec.status,
                rec.outcome()
            ),
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Build a single flat line stream so the scroll offset is a real
    // line index — much simpler than maintaining three independent
    // scroll offsets.
    let lines = render_detail_lines(rec);
    let total = lines.len() as u16;
    let scroll = if total > inner.height {
        state.detail_scroll.min(total - inner.height)
    } else {
        0
    };

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(p, inner);
}

/// Build the detail pane as a flat line stream (summary, then outgoing
/// request, then incoming response). Public for unit tests.
pub fn render_detail_lines(rec: &RequestRecord) -> Vec<Line<'static>> {
    let waf_label = rec.waf_name.clone().unwrap_or_else(|| "(unknown)".into());
    let pad_label = if rec.body_padded { "yes" } else { "no" }.to_string();
    let tls_label = rec.tls_profile.clone().unwrap_or_else(|| "(none)".into());

    let mutation_diff = render_mutation_diff(rec);

    let mut lines = vec![
        Line::from(vec![
            label("host"),
            Span::styled(rec.host.clone(), Style::default().fg(Color::Yellow)),
            spacer(),
            label("waf"),
            Span::styled(waf_label, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            label("attempts"),
            Span::styled(rec.attempts.to_string(), Style::default().fg(Color::White)),
            spacer(),
            label("latency"),
            Span::styled(
                format!("{}ms", rec.upstream_latency_ms),
                Style::default().fg(Color::White),
            ),
            spacer(),
            label("body padding"),
            Span::styled(pad_label, Style::default().fg(Color::Cyan)),
            spacer(),
            label("tls"),
            Span::styled(tls_label, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            label("techniques"),
            Span::styled(rec.techniques.clone(), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            label("response body"),
            Span::styled(
                format!("{} bytes", rec.resp_body_total),
                Style::default().fg(Color::White),
            ),
            spacer(),
            label("excerpt"),
            Span::styled(
                format!("{} bytes", rec.resp_body_excerpt.len()),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "──── ↑ outgoing request ────",
            Style::default().fg(Color::Cyan),
        ),
        Line::from(vec![Span::styled(
            format!("{} {} HTTP/1.1", rec.method, rec.path),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )]),
    ];
    for (k, v) in &rec.req_headers {
        lines.push(Line::from(vec![
            Span::styled(format!("{k}: "), Style::default().fg(Color::DarkGray)),
            Span::styled(v.clone(), Style::default().fg(Color::White)),
        ]));
    }
    if !rec.req_body_excerpt.is_empty() {
        lines.push(Line::from(""));
        for body_line in body_lines(&rec.req_body_excerpt, Color::Yellow) {
            lines.push(body_line);
        }
    }

    // ── Mutation diff (#109) ──────────────────────────────────
    // Show what wafrift's evade pipeline changed between
    // client-side request and the bytes that hit the wire. Empty
    // when the proxy was in passthrough (req_headers_pre is empty).
    if !mutation_diff.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "──── ⇄ evade mutation diff ────",
            Style::default().fg(Color::LightMagenta),
        ));
        for diff_line in mutation_diff {
            lines.push(diff_line);
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "──── ↓ incoming response ────",
        Style::default().fg(status_color(rec.status)),
    ));
    lines.push(Line::from(vec![Span::styled(
        format!("HTTP/1.1 {}", rec.status),
        Style::default().fg(status_color(rec.status)).add_modifier(Modifier::BOLD),
    )]));
    for (k, v) in &rec.resp_headers {
        lines.push(Line::from(vec![
            Span::styled(format!("{k}: "), Style::default().fg(Color::DarkGray)),
            Span::styled(v.clone(), Style::default().fg(Color::White)),
        ]));
    }
    if !rec.resp_body_excerpt.is_empty() {
        lines.push(Line::from(""));
        for body_line in body_lines(&rec.resp_body_excerpt, Color::Gray) {
            lines.push(body_line);
        }
    }

    lines
}

/// Build the evade-mutation diff section: header-set difference
/// (added / removed / value-changed) plus a one-line body byte-count
/// delta. Returns empty when no pre-evade snapshot is recorded
/// (passthrough mode).
fn render_mutation_diff(rec: &RequestRecord) -> Vec<Line<'static>> {
    if rec.req_headers_pre.is_empty() && rec.req_body_pre_excerpt.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Line<'static>> = Vec::new();

    let pre: std::collections::HashMap<String, &str> = rec
        .req_headers_pre
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    let post: std::collections::HashMap<String, &str> = rec
        .req_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();

    let mut added: Vec<(String, &str)> = Vec::new();
    let mut removed: Vec<(String, &str)> = Vec::new();
    let mut changed: Vec<(String, &str, &str)> = Vec::new();
    for (k, v) in &post {
        match pre.get(k) {
            None => added.push((k.clone(), v)),
            Some(prev) if prev != v => changed.push((k.clone(), prev, v)),
            _ => {}
        }
    }
    for (k, v) in &pre {
        if !post.contains_key(k) {
            removed.push((k.clone(), v));
        }
    }
    added.sort_by(|a, b| a.0.cmp(&b.0));
    removed.sort_by(|a, b| a.0.cmp(&b.0));
    changed.sort_by(|a, b| a.0.cmp(&b.0));

    for (k, v) in &added {
        out.push(Line::from(vec![
            Span::styled("+ ", Style::default().fg(Color::LightGreen)),
            Span::styled(format!("{k}: "), Style::default().fg(Color::Green)),
            Span::styled(v.to_string(), Style::default().fg(Color::White)),
        ]));
    }
    for (k, v) in &removed {
        out.push(Line::from(vec![
            Span::styled("- ", Style::default().fg(Color::LightRed)),
            Span::styled(format!("{k}: "), Style::default().fg(Color::Red)),
            Span::styled(v.to_string(), Style::default().fg(Color::DarkGray)),
        ]));
    }
    for (k, prev, cur) in &changed {
        out.push(Line::from(vec![
            Span::styled("~ ", Style::default().fg(Color::Yellow)),
            Span::styled(format!("{k}: "), Style::default().fg(Color::Yellow)),
            Span::styled(prev.to_string(), Style::default().fg(Color::DarkGray)),
            Span::raw(" → "),
            Span::styled(cur.to_string(), Style::default().fg(Color::White)),
        ]));
    }

    if !rec.req_body_pre_excerpt.is_empty() || !rec.req_body_excerpt.is_empty() {
        let pre_len = rec.req_body_pre_excerpt.len();
        let post_len = rec.req_body_excerpt.len();
        let symbol = if pre_len == post_len {
            "="
        } else if post_len > pre_len {
            "↑"
        } else {
            "↓"
        };
        let body_byte_equal = rec.req_body_pre_excerpt == rec.req_body_excerpt;
        let body_status = if body_byte_equal {
            "byte-identical"
        } else {
            "mutated"
        };
        let body_color = if body_byte_equal {
            Color::DarkGray
        } else {
            Color::Yellow
        };
        out.push(Line::from(vec![
            Span::styled("body ", Style::default().fg(Color::DarkGray)),
            Span::styled(symbol.to_string(), Style::default().fg(body_color)),
            Span::raw(" "),
            Span::styled(
                format!("{pre_len} → {post_len} bytes ({body_status})"),
                Style::default().fg(body_color),
            ),
        ]));
    }

    if added.is_empty() && removed.is_empty() && changed.is_empty() && rec.req_body_pre_excerpt == rec.req_body_excerpt
    {
        out.push(Line::from(vec![Span::styled(
            "(no mutation — request passed through unchanged)",
            Style::default().fg(Color::DarkGray),
        )]));
    }
    out
}

fn label(s: &str) -> Span<'static> {
    Span::styled(format!("{s} "), Style::default().fg(Color::DarkGray))
}

fn spacer() -> Span<'static> {
    Span::raw("    ")
}

/// Split a UTF-8 (or lossy) body into lines preserving newlines.
/// Truncates each rendered line to ~200 chars so a one-shot 1KB blob
/// doesn't blow up the wrapped width on narrow terminals.
fn body_lines(bytes: &[u8], color: Color) -> Vec<Line<'static>> {
    let s = String::from_utf8_lossy(bytes);
    s.split('\n')
        .map(|l| {
            let truncated = truncate(l, 200);
            Line::styled(truncated.to_string(), Style::default().fg(color))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> RequestRecord {
        RequestRecord {
            timestamp: "00:00:00".into(),
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "encoding:UrlEncode".into(),
            tls_profile: Some("chrome131".into()),
            body_padded: true,
            upstream_latency_ms: 7,
            waf_name: Some("Cloudflare".into()),
            req_headers: vec![("X-A".into(), "1".into())],
            req_body_excerpt: b"hello\nworld".to_vec(),
            req_headers_pre: vec![("X-A".into(), "1".into())],
            req_body_pre_excerpt: b"hello\nworld".to_vec(),
            resp_headers: vec![("server".into(), "cloudflare".into())],
            resp_body_excerpt: b"OK".to_vec(),
            resp_body_total: 2,
            attempts: 0,
        }
    }

    #[test]
    fn detail_lines_include_summary_and_both_directions() {
        let lines = render_detail_lines(&rec());
        assert!(lines.iter().any(|l| line_text(l).contains("host")));
        assert!(lines.iter().any(|l| line_text(l).contains("outgoing request")));
        assert!(lines.iter().any(|l| line_text(l).contains("GET / HTTP/1.1")));
        assert!(lines.iter().any(|l| line_text(l).contains("X-A:")));
        assert!(lines.iter().any(|l| line_text(l).contains("incoming response")));
        assert!(lines.iter().any(|l| line_text(l).contains("HTTP/1.1 200")));
        assert!(lines.iter().any(|l| line_text(l).contains("server:")));
    }

    #[test]
    fn body_lines_split_on_newlines() {
        let ls = body_lines(b"a\nb\nc", Color::Yellow);
        assert_eq!(ls.len(), 3);
    }

    fn line_text(l: &Line<'_>) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect::<String>()
    }

    // ── mutation diff (#109) ─────────────────────────────────

    #[test]
    fn mutation_diff_empty_when_no_pre_snapshot_recorded() {
        let mut r = rec();
        r.req_headers_pre.clear();
        r.req_body_pre_excerpt.clear();
        let lines = render_mutation_diff(&r);
        assert!(lines.is_empty(), "must return zero lines on passthrough");
    }

    #[test]
    fn mutation_diff_byte_identical_emits_no_change_marker() {
        // pre == post so diff renderer reports a 'no mutation' line.
        let lines = render_mutation_diff(&rec());
        let body = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            body.contains("no mutation"),
            "expected 'no mutation' note when pre == post; got:\n{body}"
        );
    }

    #[test]
    fn mutation_diff_added_header_marked_with_plus() {
        let mut r = rec();
        r.req_headers_pre = vec![("Host".into(), "x".into())];
        r.req_headers = vec![
            ("Host".into(), "x".into()),
            ("X-Forwarded-For".into(), "127.0.0.1".into()),
        ];
        let body = render_mutation_diff(&r)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("+ x-forwarded-for:"), "added header must be tagged: {body}");
        assert!(body.contains("127.0.0.1"));
    }

    #[test]
    fn mutation_diff_removed_header_marked_with_minus() {
        let mut r = rec();
        r.req_headers_pre = vec![
            ("Host".into(), "x".into()),
            ("Cookie".into(), "session=abc".into()),
        ];
        r.req_headers = vec![("Host".into(), "x".into())];
        let body = render_mutation_diff(&r)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("- cookie:"), "removed header tagged: {body}");
    }

    #[test]
    fn mutation_diff_changed_header_shows_arrow() {
        let mut r = rec();
        r.req_headers_pre = vec![("User-Agent".into(), "curl/8".into())];
        r.req_headers = vec![("User-Agent".into(), "Mozilla/5.0".into())];
        let body = render_mutation_diff(&r)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("~ user-agent:"), "changed header tag: {body}");
        assert!(body.contains("curl/8"), "old value present: {body}");
        assert!(body.contains("→"), "arrow separator present: {body}");
        assert!(body.contains("Mozilla/5.0"), "new value present: {body}");
    }

    #[test]
    fn mutation_diff_body_size_delta_reported() {
        let mut r = rec();
        r.req_body_pre_excerpt = b"id=1' OR 1=1".to_vec();
        r.req_body_excerpt = b"id=1%27%20OR%201%3D1".to_vec();
        let body = render_mutation_diff(&r)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("body"), "body line present: {body}");
        assert!(body.contains("12 → 20 bytes"), "byte counts present: {body}");
        assert!(body.contains("mutated"), "mutated label present: {body}");
    }

    #[test]
    fn mutation_diff_byte_identical_body_marked() {
        let mut r = rec();
        r.req_body_pre_excerpt = b"same".to_vec();
        r.req_body_excerpt = b"same".to_vec();
        // Force a header change so the "no mutation" line doesn't fire.
        r.req_headers_pre = vec![("a".into(), "1".into())];
        r.req_headers = vec![("a".into(), "2".into())];
        let body = render_mutation_diff(&r)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("byte-identical"), "byte-identical body label: {body}");
    }
}
