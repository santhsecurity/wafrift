//! Render a captured request as a `curl` one-liner and ship it to the
//! operator's clipboard (best-effort) plus a `/tmp` file (always).
//!
//! The TUI runs inside the alt-screen so direct copy/paste isn't
//! available — the operator presses `y` on a selected request and
//! gets a portable curl command on disk and (when X11/Wayland is up)
//! on the system clipboard.

use std::path::PathBuf;

use super::state::RequestRecord;

/// Outcome of a yank attempt — drives the toast banner.
#[derive(Debug, Clone)]
pub struct YankReport {
    pub path: PathBuf,
    pub clipboard_ok: bool,
    pub clipboard_error: Option<String>,
    pub bytes: usize,
}

/// Headers that tend to be hop-by-hop or auto-managed by curl. We omit
/// them from the rendered command so the operator gets a clean
/// reproducer rather than something curl will refuse to send verbatim.
const HEADER_SKIP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "te",
    "upgrade",
    "proxy-connection",
    "keep-alive",
];

/// Render `rec` as a multi-line `curl` command.
///
/// Scheme is inferred from `tls_profile` (Some → https) with https as
/// the default fallback — production targets are rarely plain HTTP.
/// Body is emitted via `--data-binary` with single-quote escaping;
/// non-UTF-8 bodies are emitted as a `--data-binary @PATH` reference
/// to a sibling `.body` file.
#[must_use]
pub fn render_curl(rec: &RequestRecord, body_sidecar: Option<&PathBuf>) -> String {
    let scheme = if rec.tls_profile.is_some() || rec.host.ends_with(":443") {
        "https"
    } else if rec.host.ends_with(":80") {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{}{}", rec.host, rec.path);

    let mut out = String::new();
    out.push_str("curl");
    if rec.method != "GET" {
        out.push_str(" -X ");
        out.push_str(&rec.method);
    }
    out.push_str(" \\\n  ");
    out.push('\'');
    out.push_str(&shell_escape_single(&url));
    out.push('\'');

    for (k, v) in &rec.req_headers {
        if HEADER_SKIP.iter().any(|s| s.eq_ignore_ascii_case(k)) {
            continue;
        }
        out.push_str(" \\\n  -H '");
        out.push_str(&shell_escape_single(&format!("{k}: {v}")));
        out.push('\'');
    }

    if !rec.req_body_excerpt.is_empty() {
        match (body_sidecar, std::str::from_utf8(&rec.req_body_excerpt)) {
            (_, Ok(text)) => {
                out.push_str(" \\\n  --data-binary '");
                out.push_str(&shell_escape_single(text));
                out.push('\'');
            }
            (Some(path), Err(_)) => {
                out.push_str(" \\\n  --data-binary @");
                out.push_str(&path.display().to_string());
            }
            (None, Err(_)) => {
                out.push_str(" \\\n  # binary body omitted (no sidecar path provided)");
            }
        }
    }
    out.push('\n');
    out
}

/// Single-quote shell escape: replace each `'` with `'\''` so the
/// quoted string remains valid `sh` syntax.
fn shell_escape_single(s: &str) -> String {
    s.replace('\'', r"'\''")
}

/// Materialise the rendered curl onto disk and (best-effort) the
/// system clipboard. `seq` is the rotating filename counter held in
/// `State::yank_seq`.
pub fn yank_to_disk_and_clipboard(rec: &RequestRecord, seq: u64) -> std::io::Result<YankReport> {
    let dir = std::env::temp_dir();
    let curl_path = dir.join(format!("wafrift-yank-{seq}.curl"));
    let body_needs_sidecar =
        !rec.req_body_excerpt.is_empty() && std::str::from_utf8(&rec.req_body_excerpt).is_err();
    let body_path = if body_needs_sidecar {
        Some(dir.join(format!("wafrift-yank-{seq}.body")))
    } else {
        None
    };

    let curl = render_curl(rec, body_path.as_ref());
    std::fs::write(&curl_path, curl.as_bytes())?;
    if let Some(p) = &body_path {
        std::fs::write(p, &rec.req_body_excerpt)?;
    }

    let (clipboard_ok, clipboard_error) = try_set_clipboard(&curl);

    Ok(YankReport {
        path: curl_path,
        clipboard_ok,
        clipboard_error,
        bytes: curl.len(),
    })
}

/// Best-effort clipboard set. Compiled out when the `clipboard`
/// feature is off (headless boxes, CI). Returns `(ok, err_msg)`.
#[cfg(feature = "clipboard")]
fn try_set_clipboard(s: &str) -> (bool, Option<String>) {
    match arboard::Clipboard::new() {
        Ok(mut clip) => match clip.set_text(s.to_string()) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        },
        Err(e) => (false, Some(e.to_string())),
    }
}

#[cfg(not(feature = "clipboard"))]
fn try_set_clipboard(_s: &str) -> (bool, Option<String>) {
    (false, Some("clipboard feature disabled at build time".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec_full() -> RequestRecord {
        RequestRecord {
            timestamp: "12:34:56".into(),
            host: "api.target.com".into(),
            method: "POST".into(),
            path: "/admin?id=1".into(),
            status: 200,
            bypassed: true,
            blocked: false,
            techniques: "encoding:UrlEncode".into(),
            tls_profile: Some("chrome131".into()),
            body_padded: false,
            upstream_latency_ms: 45,
            waf_name: Some("Cloudflare".into()),
            req_headers: vec![
                ("Host".into(), "api.target.com".into()), // dropped (skip)
                ("X-Original-URL".into(), "/admin".into()),
                ("User-Agent".into(), "Mozilla'5.0".into()), // tests escape
                ("Content-Length".into(), "10".into()),     // dropped
            ],
            req_body_excerpt: b"q=' OR 1=1--".to_vec(),
            resp_headers: vec![],
            resp_body_excerpt: vec![],
            resp_body_total: 0,
            attempts: 1,
        }
    }

    #[test]
    fn curl_uses_https_when_tls_profile_set() {
        let r = rec_full();
        let s = render_curl(&r, None);
        assert!(s.contains("https://api.target.com/admin?id=1"));
        assert!(s.starts_with("curl -X POST"));
    }

    #[test]
    fn curl_skips_host_and_content_length_headers() {
        let s = render_curl(&rec_full(), None);
        assert!(!s.contains("'Host: "));
        assert!(!s.contains("'Content-Length: "));
        assert!(s.contains("'X-Original-URL: /admin'"));
    }

    #[test]
    fn curl_escapes_single_quotes_in_header_value() {
        let s = render_curl(&rec_full(), None);
        // 'Mozilla'5.0' must escape to "Mozilla'\''5.0"
        assert!(s.contains(r"Mozilla'\''5.0"));
    }

    #[test]
    fn curl_emits_data_binary_with_escaping() {
        let s = render_curl(&rec_full(), None);
        // body contains a `'` character — needs escape
        assert!(s.contains(r"--data-binary 'q='\''"));
    }

    #[test]
    fn curl_uses_get_implicit_when_method_is_get() {
        let mut r = rec_full();
        r.method = "GET".into();
        r.req_body_excerpt.clear();
        let s = render_curl(&r, None);
        assert!(s.starts_with("curl \\\n"), "no -X for GET — got {s:?}");
    }

    #[test]
    fn curl_falls_back_to_http_when_host_has_port_80() {
        let mut r = rec_full();
        r.tls_profile = None;
        r.host = "intranet.local:80".into();
        let s = render_curl(&r, None);
        assert!(s.contains("http://intranet.local:80/"));
    }

    #[test]
    fn curl_emits_data_binary_at_path_for_binary_body() {
        let mut r = rec_full();
        r.req_body_excerpt = vec![0xff, 0xfe, 0x00, 0x01];
        let p = PathBuf::from("/tmp/wafrift-yank-7.body");
        let s = render_curl(&r, Some(&p));
        assert!(s.contains("--data-binary @/tmp/wafrift-yank-7.body"));
    }

    #[test]
    fn shell_escape_handles_apostrophes() {
        assert_eq!(shell_escape_single("hello"), "hello");
        assert_eq!(shell_escape_single("it's me"), r"it'\''s me");
        assert_eq!(shell_escape_single("''"), r"'\'''\''");
    }
}
