//! Display-format helpers shared across the TUI render layers.
//!
//! Pure functions only — no mutable state, no I/O. Centralised so the
//! palette and truncation rules are consistent across every panel.

use std::time::Duration;

use ratatui::style::Color;

use super::state::RequestRecord;

/// Truncate `s` to at most `n` bytes, respecting char boundaries.
///
/// Returns the original slice if already within budget; otherwise
/// shaves bytes off the end until landing on a char boundary. Never
/// panics on multi-byte input (the previous slice-by-bytes panic on
/// `★cat` is the regression this guards against).
pub fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut idx = n;
    while !s.is_char_boundary(idx) && idx > 0 {
        idx -= 1;
    }
    &s[..idx]
}

/// Format wall-clock as `HH:MM:SS` (UTC, no allocation beyond the String).
pub fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = now % 86400;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Render an uptime duration as the most compact human form: `5s`,
/// `1m35s`, `1h02m`, `2d04h`. Always ≤6 chars.
pub fn humanize_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{:02}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// HTTP status → severity colour. 2xx green, 3xx cyan, 4xx yellow,
/// 5xx red, anything else dark gray.
pub fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Cyan,
        400..=499 => Color::Yellow,
        500..=599 => Color::Red,
        _ => Color::DarkGray,
    }
}

/// Outcome label colour: BYPASS bright green, BLOCK light red, PASS white.
pub fn outcome_color(rec: &RequestRecord) -> Color {
    if rec.bypassed {
        Color::LightGreen
    } else if rec.blocked {
        Color::LightRed
    } else {
        Color::White
    }
}

/// Map a status code to a 6-bucket index (1xx..5xx, other).
///
/// Used by the Overview status-code ribbon so we can keep counts in a
/// fixed-size array instead of a HashMap that gets cardinality-blown
/// by exotic codes.
pub fn status_bucket_index(status: u16) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

/// Ribbon label for each `status_bucket_index` slot.
pub const STATUS_BUCKET_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "?"];

/// Ribbon colour for each `status_bucket_index` slot.
pub fn status_bucket_color(idx: usize) -> Color {
    match idx {
        0 => Color::Magenta,
        1 => Color::Green,
        2 => Color::Cyan,
        3 => Color::Yellow,
        4 => Color::Red,
        _ => Color::DarkGray,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_handles_multibyte() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello");
        assert_eq!(truncate("héllo", 3), "hé");
        // Star-cat regression: don't panic mid-multibyte.
        assert_eq!(truncate("★cat", 2), "");
        assert_eq!(truncate("★cat", 3), "★");
        assert_eq!(truncate("★cat", 4), "★c");
    }

    #[test]
    fn humanize_handles_seconds_minutes_hours_days() {
        assert_eq!(humanize_uptime(Duration::from_secs(5)), "5s");
        assert_eq!(humanize_uptime(Duration::from_secs(95)), "1m35s");
        assert_eq!(humanize_uptime(Duration::from_secs(3725)), "1h02m");
        assert_eq!(humanize_uptime(Duration::from_secs(90000)), "1d01h");
    }

    #[test]
    fn status_color_classification() {
        assert_eq!(status_color(200), Color::Green);
        assert_eq!(status_color(301), Color::Cyan);
        assert_eq!(status_color(403), Color::Yellow);
        assert_eq!(status_color(503), Color::Red);
        assert_eq!(status_color(0), Color::DarkGray);
    }

    #[test]
    fn status_bucket_indexing_covers_every_class() {
        assert_eq!(status_bucket_index(100), 0);
        assert_eq!(status_bucket_index(200), 1);
        assert_eq!(status_bucket_index(304), 2);
        assert_eq!(status_bucket_index(404), 3);
        assert_eq!(status_bucket_index(503), 4);
        assert_eq!(status_bucket_index(0), 5);
        assert_eq!(status_bucket_index(700), 5);
    }
}
