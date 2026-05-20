//! Stateful chain mode — establish a session BEFORE the attack phase.
//!
//! Most real exploits are two-phase:
//!
//! 1. **Auth phase.** Hit a login or CSRF endpoint, get cookies +
//!    bearer tokens + anti-CSRF nonces.
//! 2. **Attack phase.** Use that established session — which the
//!    backend trusts more than an anonymous request — to fire the
//!    actual payload.
//!
//! Wafrift's scan path is one-shot today: every variant goes out
//! anonymous, so WAFs that scrutinise unauthenticated traffic more
//! aggressively (most do) see every probe at maximum sensitivity.
//! This module is the bridge: parse a curl file that establishes the
//! session, fire it once, capture the resulting cookies (and any
//! Authorization header from the curl itself), and hand back a
//! `reqwest::header::HeaderMap` that scan plugs into
//! `Client::builder().default_headers(...)` — every subsequent
//! variant request then carries the session for free.
//!
//! Re-uses `crate::import_curl::{parse_curl, shell_tokenize}` so the
//! curl-file format here is identical to `wafrift import-curl` — the
//! operator has one mental model for curl syntax across the CLI.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::import_curl::{ParsedCurl, parse_curl, shell_tokenize};

/// Captured session state — the headers (cookies + auth + any
/// caller-pinned values from the init curl) that should be carried
/// on every subsequent request in the scan loop.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// Headers ready to plug into `ClientBuilder::default_headers`.
    /// Always includes a `Cookie:` line when the init request
    /// returned `Set-Cookie` or the curl itself set a `Cookie:`.
    /// May include `Authorization:` when the curl set one explicitly.
    pub headers: HeaderMap,
    /// Human-readable summary of what was captured. Surfaced in
    /// scan's text output so the operator can verify the session
    /// actually established.
    pub summary: String,
}

/// Errors from establishing a session. Hand-rolled `Display` so this
/// module doesn't pull `thiserror` into the cli crate's dep graph
/// (kept lean per the pristine-code bar).
#[derive(Debug)]
pub enum SessionInitError {
    ReadFile(String, std::io::Error),
    Parse(String),
    Request(String),
    NoUrl,
}

impl fmt::Display for SessionInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile(path, e) => write!(f, "read session-init curl file {path}: {e}"),
            Self::Parse(msg) => write!(f, "parse session-init curl: {msg}"),
            Self::Request(msg) => write!(f, "session-init request: {msg}"),
            Self::NoUrl => write!(f, "session-init: no URL in curl invocation"),
        }
    }
}

impl std::error::Error for SessionInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile(_, e) => Some(e),
            _ => None,
        }
    }
}

/// Convert a parsed curl into a SessionState by firing the request
/// and collecting cookies. The fired request uses the curl's exact
/// method / headers / body / Cookie — wafrift does not mutate the
/// auth request, that's the operator's job to script correctly. We
/// only act as the cookie jar + header carrier.
pub async fn establish_from_curl(
    parsed: ParsedCurl,
    timeout: Duration,
    insecure: bool,
) -> Result<SessionState, SessionInitError> {
    let url = parsed.url.as_ref().ok_or(SessionInitError::NoUrl)?.clone();
    let method = parsed
        .method
        .clone()
        .or_else(|| if parsed.body.is_some() { Some("POST".into()) } else { None })
        .unwrap_or_else(|| "GET".into());

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        // The init request is allowed to redirect — login flows
        // routinely 302 to /home; we want the cookies set on the
        // FINAL page, not the intermediate.
        .redirect(reqwest::redirect::Policy::limited(8));
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .map_err(|e| SessionInitError::Request(format!("build client: {e}")))?;

    let method_enum = method
        .parse::<reqwest::Method>()
        .map_err(|e| SessionInitError::Parse(format!("bad method {method:?}: {e}")))?;
    let mut req = client.request(method_enum, &url);
    if let Some(ua) = &parsed.user_agent {
        req = req.header("User-Agent", ua);
    }
    for (k, v) in &parsed.headers {
        req = req.header(k, v);
    }
    if let Some(cookie) = &parsed.cookie {
        req = req.header("Cookie", cookie);
    }
    if let Some(body) = &parsed.body {
        req = req.body(body.clone());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| SessionInitError::Request(format!("send: {e}")))?;

    // Collect every Set-Cookie from the response (and from every
    // redirect hop reqwest followed; reqwest exposes only the FINAL
    // Set-Cookie set per its API, which is the typical case — the
    // login chain's intermediate 302s carry the same cookies forward
    // and the final response repeats the durable set).
    let mut cookie_pairs: Vec<(String, String)> = Vec::new();
    // Curl-supplied cookies survive — the operator may need them
    // (e.g. a long-lived refresh-token cookie not in the response).
    if let Some(cookie) = parsed.cookie.as_ref() {
        for pair in cookie.split(';') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((name, value)) = trimmed.split_once('=') {
                cookie_pairs.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    for hv in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let raw = match hv.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Only the cookie's name=value lives in the Cookie request
        // header form. Attributes (Path, Domain, Secure, HttpOnly,
        // SameSite, Expires, Max-Age) are server-directed and never
        // sent back by the client.
        let pair = raw.split(';').next().unwrap_or("").trim();
        if let Some((name, value)) = pair.split_once('=') {
            let name = name.trim().to_string();
            // Dedup by name: the most-recent value wins (mirrors
            // browser cookie-jar behaviour).
            cookie_pairs.retain(|(n, _)| *n != name);
            cookie_pairs.push((name, value.trim().to_string()));
        }
    }

    let mut headers = HeaderMap::new();
    if !cookie_pairs.is_empty() {
        let joined = cookie_pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(val) = HeaderValue::from_str(&joined) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }

    // An Authorization header explicitly set in the curl carries
    // forward — bearer tokens / basic-auth need to be replayed on
    // every attack request the same way they were set on the init.
    for (k, v) in &parsed.headers {
        if k.eq_ignore_ascii_case("authorization") {
            if let (Ok(name), Ok(val)) =
                (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v))
            {
                headers.insert(name, val);
            }
        }
    }

    let summary = format!(
        "init {method} {url} -> HTTP {} ({} cookie(s){})",
        resp.status().as_u16(),
        cookie_pairs.len(),
        if headers.contains_key(reqwest::header::AUTHORIZATION) {
            ", auth header forwarded"
        } else {
            ""
        }
    );

    Ok(SessionState { headers, summary })
}

/// Convenience: read a curl-file from disk, tokenise + parse + fire
/// it. Mirrors `wafrift import-curl`'s file-input mode.
pub async fn establish_from_file(
    path: &Path,
    timeout: Duration,
    insecure: bool,
) -> Result<SessionState, SessionInitError> {
    // Bounded read — operator-supplied curl file. Defends against
    // `/dev/zero` typo and hostile symlink. Real "Copy as cURL"
    // pastes are < 16 KiB; cap at 1 MiB is generous.
    let raw = match crate::safe_body::read_bounded_text_file(
        path,
        crate::safe_body::MAX_OPERATOR_INPUT_BYTES,
    ) {
        Ok(s) => s,
        Err(crate::safe_body::ReadError::Transport(msg)) => {
            return Err(SessionInitError::ReadFile(
                path.display().to_string(),
                std::io::Error::other(msg),
            ));
        }
        Err(crate::safe_body::ReadError::Overrun {
            cap_bytes,
            observed_bytes,
        }) => {
            return Err(SessionInitError::Parse(format!(
                "session-init file exceeded {cap_bytes}-byte cap ({observed_bytes} bytes \
                 seen) — a real `Copy as cURL` paste is < 16 KiB; check the path"
            )));
        }
    };
    let tokens = shell_tokenize(&raw).map_err(SessionInitError::Parse)?;
    let parsed = parse_curl(&tokens).map_err(SessionInitError::Parse)?;
    establish_from_curl(parsed, timeout, insecure).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_session_server<F>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let counter = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = sock.read(&mut buf).await;
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    let resp = handler(n);
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        addr
    }

    fn ok_with_setcookie(body: &str, cookies: &[(&str, &str)]) -> String {
        let mut sc = String::new();
        for (n, v) in cookies {
            sc.push_str(&format!("Set-Cookie: {n}={v}; Path=/; HttpOnly\r\n"));
        }
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{sc}Connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn curl_from_url(url: &str) -> ParsedCurl {
        ParsedCurl {
            method: Some("GET".into()),
            url: Some(url.into()),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_captures_set_cookie_from_response() {
        let addr = spawn_session_server(|_| {
            ok_with_setcookie("welcome", &[("session", "abc123"), ("csrf", "xyz")])
        })
        .await;
        let parsed = curl_from_url(&format!("http://{addr}/login"));
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init must succeed");
        let cookie = state
            .headers
            .get(reqwest::header::COOKIE)
            .expect("cookie set");
        let s = cookie.to_str().unwrap();
        assert!(s.contains("session=abc123"));
        assert!(s.contains("csrf=xyz"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_carries_curl_cookie_forward() {
        // Curl-supplied cookies that the server does NOT echo back via
        // Set-Cookie must still appear in the captured state — operator
        // may have set them manually (refresh tokens etc.).
        let addr = spawn_session_server(|_| ok_with_setcookie("ok", &[])).await;
        let mut parsed = curl_from_url(&format!("http://{addr}/"));
        parsed.cookie = Some("manual=value; persistent=keep".into());
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init must succeed");
        let cookie = state.headers.get(reqwest::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("manual=value"));
        assert!(cookie.contains("persistent=keep"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_set_cookie_overrides_curl_supplied_value_by_name() {
        // Mirrors browser cookie-jar semantics: a server Set-Cookie
        // replaces the same-name client-supplied cookie. Anti-rig
        // against a stale token surviving past its rotation.
        let addr = spawn_session_server(|_| {
            ok_with_setcookie("rotated", &[("session", "NEW")])
        })
        .await;
        let mut parsed = curl_from_url(&format!("http://{addr}/refresh"));
        parsed.cookie = Some("session=OLD".into());
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init must succeed");
        let cookie = state.headers.get(reqwest::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("session=NEW"), "rotated cookie must win: {cookie}");
        assert!(!cookie.contains("session=OLD"), "stale cookie must be evicted: {cookie}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_carries_authorization_header_forward() {
        // Bearer tokens / basic-auth on the init curl must replay on
        // every attack request — the captured state carries the
        // Authorization header verbatim.
        let addr = spawn_session_server(|_| ok_with_setcookie("ok", &[])).await;
        let mut parsed = curl_from_url(&format!("http://{addr}/"));
        parsed
            .headers
            .push(("Authorization".into(), "Bearer abc.def.ghi".into()));
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init must succeed");
        let auth = state
            .headers
            .get(reqwest::header::AUTHORIZATION)
            .expect("authorization carried")
            .to_str()
            .unwrap();
        assert_eq!(auth, "Bearer abc.def.ghi");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_strips_setcookie_attributes_keeps_only_name_value() {
        // The Cookie request header carries only the name=value pair;
        // attributes (Path, Domain, Secure, HttpOnly, SameSite,
        // Expires, Max-Age) are server-directed and the client must
        // not echo them.
        let server = ok_with_setcookie("ok", &[("k", "v")]);
        assert!(server.contains("HttpOnly")); // sanity: server sends them
        let addr = spawn_session_server(move |_| server.clone()).await;
        let parsed = curl_from_url(&format!("http://{addr}/"));
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init must succeed");
        let cookie = state.headers.get(reqwest::header::COOKIE).unwrap().to_str().unwrap();
        // Cookie request header = "k=v" exactly, no attributes.
        assert_eq!(cookie, "k=v");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_returns_no_url_error_when_curl_missing_url() {
        let parsed = ParsedCurl::default();
        let err = establish_from_curl(parsed, Duration::from_secs(2), false)
            .await
            .expect_err("missing url must error");
        match err {
            SessionInitError::NoUrl => {}
            other => panic!("expected NoUrl, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_summary_names_status_and_cookie_count() {
        let addr = spawn_session_server(|_| {
            ok_with_setcookie("ok", &[("a", "1"), ("b", "2")])
        })
        .await;
        let parsed = curl_from_url(&format!("http://{addr}/"));
        let state = establish_from_curl(parsed, Duration::from_secs(3), false)
            .await
            .expect("init");
        assert!(state.summary.contains("200"));
        assert!(state.summary.contains("2 cookie(s)"));
    }

    // ── Deep integration: full file-on-disk path ──────────────────
    //
    // The unit tests above exercise `establish_from_curl` with a
    // pre-built ParsedCurl. The wrapper `establish_from_file` adds
    // a `read_to_string` + `shell_tokenize` + `parse_curl` chain
    // that the operator's flow actually takes. These tests prove
    // the WHOLE chain works against a real temp file on disk and
    // the captured state is plug-and-play with reqwest's
    // `default_headers` — the exact wiring scan/mod.rs takes.

    fn write_curl_to_temp(text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wafrift-session-init-test-{}-{}.curl",
            std::process::id(),
            // Use a SystemTime nano for uniqueness across same-pid
            // tests running back-to-back.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::write(&path, text.as_bytes()).expect("write tmp curl file");
        path
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_from_file_full_e2e_with_real_disk_curl_file() {
        let addr = spawn_session_server(|_| {
            ok_with_setcookie("ok", &[("session", "ABC123XYZ"), ("csrf", "DEF456")])
        })
        .await;
        let curl = format!(
            "curl 'http://{addr}/login' \\\n  -X POST \\\n  -H 'Accept: application/json'"
        );
        let path = write_curl_to_temp(&curl);

        let state = establish_from_file(&path, Duration::from_secs(5), false)
            .await
            .expect("file-driven init must succeed");

        let cookie = state
            .headers
            .get(reqwest::header::COOKIE)
            .expect("cookie present")
            .to_str()
            .unwrap();
        assert!(cookie.contains("session=ABC123XYZ"));
        assert!(cookie.contains("csrf=DEF456"));

        // Verify the captured state plugs cleanly into a reqwest
        // client's default_headers (the actual wire scan/mod.rs takes).
        let client_result = reqwest::Client::builder()
            .default_headers(state.headers.clone())
            .build();
        assert!(
            client_result.is_ok(),
            "captured headers must be valid default_headers input"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_from_file_missing_file_returns_read_file_error() {
        let missing = std::env::temp_dir()
            .join("wafrift-session-init-DOES-NOT-EXIST-9999.curl");
        let err = establish_from_file(&missing, Duration::from_secs(2), false)
            .await
            .expect_err("missing file must error");
        match err {
            SessionInitError::ReadFile(path, _) => {
                assert!(path.contains("DOES-NOT-EXIST"));
            }
            other => panic!("expected ReadFile error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_from_file_with_malformed_curl_returns_typed_error() {
        // Anti-rig: malformed curl input must produce a TYPED error
        // (Parse or Request), never a panic. The specific variant
        // depends on whether shell_tokenize rejects the input outright
        // (Parse) or whether it produces a "plausible" URL that
        // then fails at the request layer (Request). Both are
        // acceptable — the bar is "no panic, structured error."
        let path = write_curl_to_temp("curl 'http://x.example/x");
        let err = establish_from_file(&path, Duration::from_secs(2), false)
            .await
            .expect_err("malformed must error");
        match err {
            SessionInitError::Parse(_) | SessionInitError::Request(_) => {}
            other => panic!("expected Parse or Request error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establish_from_file_with_empty_curl_file_returns_no_url_error() {
        let path = write_curl_to_temp("");
        let err = establish_from_file(&path, Duration::from_secs(2), false)
            .await
            .expect_err("empty must error");
        // An empty token list -> ParsedCurl with no URL -> NoUrl.
        // (The Parse path could also reach this; either is fine —
        // both are typed, neither panics.)
        match err {
            SessionInitError::NoUrl | SessionInitError::Parse(_) => {}
            other => panic!("expected NoUrl/Parse, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
