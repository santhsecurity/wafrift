//! Shared helpers for HTTP-style fixtures under `tests/data/`.
//!
//! Format: first line is status code; then `Header-Name: value` lines;
//! blank line; remainder is body (UTF-8).

/// Parse a vendored fixture. Header names/values are kept as written; the
/// detector lowercases internally.
pub fn parse_response_spec(raw: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let normalized = raw.replace('\r', "");
    let lines: Vec<&str> = normalized.lines().collect();
    if lines.is_empty() {
        return (200, Vec::new(), Vec::new());
    }

    let status: u16 = lines[0].trim().parse().unwrap_or(200);

    let mut headers = Vec::new();
    let mut i = 1_usize;
    while i < lines.len() && !lines[i].is_empty() {
        let line = lines[i];
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
        i += 1;
    }

    if i < lines.len() && lines[i].is_empty() {
        i += 1;
    }

    let body = lines[i..].join("\n").into_bytes();
    (status, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_headers_body() {
        let raw = "404\nserver: nginx\n\nnot found\n";
        let (st, h, b) = parse_response_spec(raw);
        assert_eq!(st, 404);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "server");
        assert_eq!(String::from_utf8_lossy(&b).trim_end(), "not found");
    }
}
