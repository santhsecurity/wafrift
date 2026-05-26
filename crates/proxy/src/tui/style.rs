//! Shared TUI style primitives.
//!
//! Pre-extract, every `render_*.rs` file open-coded
//! `Style::default().fg(Color::DarkGray)` for separators, borders,
//! placeholders, and the "trailing-space dim label" pattern — 42 sites
//! across 6 files. A future palette change (e.g. moving the dim
//! colour from `DarkGray` to a theme-controlled value) would need to
//! touch each one independently. Lifting the trio (`DIM`, `dim_span`,
//! `dim_span_trail`) means a future palette tweak is one edit.

use ratatui::style::{Color, Style};
use ratatui::text::Span;

/// The canonical "dim" style: foreground `Color::DarkGray`, no
/// modifiers. Used for separators (` │ `, ` · `), borders, and any
/// non-emphasis text that shouldn't grab the eye.
pub const DIM: Style = Style::new().fg(Color::DarkGray);

/// Render `text` as a dim [`Span`]. Lifts the
/// `Span::styled(text, Style::default().fg(Color::DarkGray))` pattern
/// the render modules used at every separator + placeholder site.
#[must_use]
pub fn dim_span<'a>(text: impl Into<std::borrow::Cow<'a, str>>) -> Span<'a> {
    Span::styled(text, DIM)
}

/// Same as [`dim_span`] but adds a trailing space — used by the
/// `render_chrome`/`render_flow`/`render_overview` "label · value"
/// status-bar pattern where the label name is dim and immediately
/// followed by a space before the value span.
#[must_use]
pub fn dim_span_trail(text: &str) -> Span<'static> {
    Span::styled(format!("{text} "), DIM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dim_const_is_dark_gray_fg() {
        assert_eq!(DIM.fg, Some(Color::DarkGray));
    }

    #[test]
    fn dim_span_carries_dim_style() {
        let s = dim_span("hello");
        assert_eq!(s.style.fg, Some(Color::DarkGray));
        assert_eq!(s.content, "hello");
    }

    #[test]
    fn dim_span_trail_adds_trailing_space() {
        let s = dim_span_trail("uptime");
        assert_eq!(s.content, "uptime ");
        assert_eq!(s.style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn dim_span_accepts_owned_strings() {
        let owned = format!("{}", 42);
        let s = dim_span(owned);
        assert_eq!(s.content, "42");
    }

    #[test]
    fn dim_span_accepts_static_strs() {
        let s = dim_span("static");
        assert_eq!(s.content, "static");
    }
}
