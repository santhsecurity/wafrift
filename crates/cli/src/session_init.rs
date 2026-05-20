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
    let raw = std::fs::read_to_string(path).map_err(|e| {
        SessionInitError::ReadFile(path.display().to_string(), e)
    })?;
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
}
