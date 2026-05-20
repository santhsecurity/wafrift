//! `wafrift listener` — out-of-band callback receiver for blind /
//! stored vulnerability oracles.
//!
//! Some classes of vulnerability never echo a verdict on the *same*
//! response that triggered them:
//!
//! - **Blind SQLi (time-based)** — the difference is latency, not body.
//! - **Stored XSS** — the script executes when a *different* user
//!   loads the page, hours later.
//! - **Blind SSRF** — the server-side fetch hits a host we control;
//!   the original response is just a generic 200/500.
//! - **Out-of-band command injection** — `nslookup attacker.example`
//!   reaches our DNS, not the HTTP response.
//!
//! For each of these the oracle is an **external side-channel**: a
//! callback that arrives at infrastructure WE own, tagged with a
//! unique token that lets us correlate it back to the scan request
//! that planted it. This module is the callback receiver.
//!
//! Workflow:
//!
//! ```text
//!  wafrift listener --bind 0.0.0.0:9000              # start listener
//!  wafrift scan --target T --payload "<...?token=ABCD...>"
//!  (target's backend fetches http://listener.host:9000/ABCD)
//!  listener logs the callback → operator correlates → blind hit
//! ```
//!
//! Design notes (the load-bearing ones):
//!
//! - **Tokens are 128-bit, base32-encoded, collision-resistant.**
//!   Random 16 bytes from `rand::thread_rng`; base32-no-padding so the
//!   token is URL-safe without encoding (the typical embed point is a
//!   URL path or query string). 128 bits is the same security floor
//!   as a UUIDv4.
//! - **The HTTP server is intentionally minimal.** Any GET / POST /
//!   PUT / etc. on `/<token-or-anything>` counts as a callback; the
//!   server records `(timestamp, method, path, source_ip, headers,
//!   body_prefix)` and never executes anything. Body capped at
//!   8 KiB (a callback that ships an exfil >8K is a different
//!   problem).
//! - **No HTTPS by default.** The listener runs HTTP — operators
//!   front it with their own TLS-terminating reverse proxy or
//!   Cloudflare tunnel when they need encryption. Shipping a self-
//!   signed cert that no target will trust is worse than no TLS at
//!   all.
//! - **Bind to 127.0.0.1 by default.** Public-facing listeners are
//!   an authorisation footgun. The operator has to type `--bind
//!   0.0.0.0:PORT` to expose the listener — that explicit step is
//!   the consent gate.
//! - **Token-to-request correlation is the caller's problem.** This
//!   module gives you the token, the embed point is up to the
//!   scanner. Future work integrates this directly into `scan` so
//!   the operator runs one command end-to-end; today it's a
//!   building block.

use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

#[derive(Args, Debug)]
pub struct ListenerArgs {
    /// Address to bind the callback receiver to. Defaults to
    /// loopback — public exposure (`0.0.0.0:PORT`) is an explicit
    /// opt-in so an operator does not accidentally stand up a
    /// world-readable side-channel.
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub bind: String,

    /// Number of tokens to pre-mint on startup (printed to stdout
    /// so the operator can copy them into payloads). Each token
    /// is independent — a callback on any of them is logged.
    #[arg(long, default_value_t = 4)]
    pub tokens: u32,

    /// Output format: `text` prints a human stream; `json` emits one
    /// NDJSON line per callback so the listener pipes cleanly into
    /// `jq`, `tee`, or a downstream log collector.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Cap on the body bytes recorded per callback. Anything beyond
    /// is truncated (with a `truncated_bytes` counter in the JSON).
    /// 8 KiB by default — generous for the typical "ping" payload,
    /// hostile for exfil-style abuse.
    #[arg(long, default_value_t = 8 * 1024)]
    pub max_body_bytes: usize,

    /// HTTP read timeout per connection (seconds). Closes lingering
    /// connections that send headers but never the body.
    #[arg(long, default_value_t = 10)]
    pub read_timeout_secs: u64,
}

/// One observed inbound HTTP request — the smallest unit of evidence
/// for an OOB callback. Serialised verbatim into NDJSON when
/// `--format json` is selected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Callback {
    /// Unix timestamp (seconds) the callback was received.
    pub received_at: u64,
    /// Source IP:port of the inbound connection. Parsed via
    /// `TcpStream::peer_addr`; useful when the listener is fronted by
    /// a proxy that doesn't rewrite `X-Forwarded-For` cleanly.
    pub source: String,
    /// HTTP method as the inbound client sent it (uppercased).
    pub method: String,
    /// Request path (`/foo?bar=baz` form, including query string).
    pub path: String,
    /// Token extracted from the path / query string if it matches one
    /// of the pre-minted tokens, else `None`. The token-match logic
    /// is conservative: only an exact substring match against the
    /// registered token set counts — it never tries to fuzzy-match
    /// or normalise URL-encoded forms.
    pub matched_token: Option<String>,
    /// Inbound request headers (lowercased keys for stable diffing).
    pub headers: Vec<(String, String)>,
    /// Body bytes (UTF-8-lossy decoded, capped at `max_body_bytes`).
    pub body_preview: String,
    /// How many body bytes were dropped past the cap.
    pub body_truncated_bytes: usize,
}

/// In-memory registry shared between the HTTP accept loop and the
/// caller. Holds the set of valid tokens + the running callback log.
//
// `dead_code` is silenced because this is a binary crate: `cargo build`
// only sees the call sites in `run_listener` + the tests, which exercise
// every public method, but rustc's reachability analysis on `--bin`
// targets does not always connect them. The library surface IS used.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct Registry {
    tokens: RwLock<HashMap<String, ()>>,
    callbacks: RwLock<Vec<Callback>>,
}

// See the comment on `Registry` for why these methods are marked
// `dead_code`-allowed: the unit tests exercise them, but rustc's
// reachability analysis on the binary's `main.rs` doesn't trace
// through the test cfg-gated paths. They are real public API.
#[allow(dead_code)]
impl Registry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-mint `n` random tokens and return them in registration order.
    pub async fn mint(&self, n: u32) -> Vec<String> {
        let mut out = Vec::with_capacity(n as usize);
        let mut tokens = self.tokens.write().await;
        for _ in 0..n {
            let tok = generate_token();
            tokens.insert(tok.clone(), ());
            out.push(tok);
        }
        out
    }

    /// Register an already-generated token. Useful when the caller
    /// wants control over token generation (e.g. embedding a
    /// payload-shape hint in the token prefix).
    pub async fn register(&self, token: impl Into<String>) {
        self.tokens.write().await.insert(token.into(), ());
    }

    /// Snapshot of currently registered tokens.
    pub async fn known_tokens(&self) -> Vec<String> {
        self.tokens.read().await.keys().cloned().collect()
    }

    /// Snapshot of all recorded callbacks.
    pub async fn callbacks(&self) -> Vec<Callback> {
        self.callbacks.read().await.clone()
    }

    /// Count of callbacks that matched a registered token. The
    /// scan-side oracle gates on this: zero matched callbacks for a
    /// given payload = no echo-back = no blind bypass.
    pub async fn matched_count(&self) -> usize {
        self.callbacks
            .read()
            .await
            .iter()
            .filter(|c| c.matched_token.is_some())
            .count()
    }

    /// Look for the first registered token that appears as a
    /// substring of `s`. Returns the matched token, not the location.
    /// Conservative: no URL-decoding, no case folding — the caller
    /// chose the token alphabet (base32) so it survives unmolested
    /// through every reasonable transport.
    pub async fn match_token_in(&self, s: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.keys().find(|t| s.contains(t.as_str())).cloned()
    }

    /// Append one observed callback. The matched_token field is
    /// populated by the listener loop before push (so the registry
    /// stays a pure store).
    async fn push(&self, cb: Callback) {
        self.callbacks.write().await.push(cb);
    }
}

// `generate_token` + `base32_encode` live in `crate::callback_token`
// — shared with `crate::scan` so the receiver (listener) and the
// sender (scan's payload substitution) use one source of truth for
// the token format. Re-export at the local path so existing
// listener-only call sites keep compiling.
pub use crate::callback_token::generate_token;

/// Entry point for `wafrift listener`. Blocks until SIGINT / SIGTERM.
///
/// # Errors
///
/// Returns `ExitCode::from(1)` if the bind address is malformed or
/// the socket cannot be opened.
pub fn run_listener(args: ListenerArgs) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{} tokio runtime: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        let registry = Arc::new(Registry::new());
        let minted = registry.mint(args.tokens).await;

        // Print the minted tokens so the operator can copy them into
        // payloads. In json mode emit one JSON object describing the
        // listener's startup state so downstream consumers know which
        // tokens are valid.
        if args.format == "json" {
            let startup = serde_json::json!({
                "kind": "listener_started",
                "bind": args.bind,
                "tokens": minted,
            });
            println!("{startup}");
        } else {
            println!(
                "{} {}",
                "[wafrift listener]".bold().cyan(),
                format!("binding {}", args.bind).bright_black()
            );
            for t in &minted {
                println!("  {} {}", "token:".green(), t.bold());
            }
            println!(
                "  {}",
                "(embed any of the above in your payload; callbacks log below)".bright_black()
            );
        }

        let addr: SocketAddr = match args.bind.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{} bind {} parse: {e}", "error:".red(), args.bind);
                return ExitCode::from(1);
            }
        };
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{} bind {addr}: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };

        let format = args.format.clone();
        let max_body = args.max_body_bytes;
        let read_timeout = Duration::from_secs(args.read_timeout_secs);
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{} accept: {e}", "warn:".yellow());
                    continue;
                }
            };
            let registry_c = registry.clone();
            let format_c = format.clone();
            tokio::spawn(async move {
                // handle_conn returns:
                //   Err  — malformed request, drop it
                //   Ok(None) — a `/_wafrift/...` management API hit,
                //              already answered; do NOT log as callback
                //   Ok(Some(cb)) — a real inbound, render + record
                let cb = match handle_conn(sock, peer, &registry_c, max_body, read_timeout).await {
                    Ok(Some(cb)) => cb,
                    Ok(None) | Err(_) => return,
                };
                render_callback(&cb, &format_c);
                registry_c.push(cb).await;
            });
        }
    })
}

fn render_callback(cb: &Callback, format: &str) {
    if format == "json" {
        if let Ok(line) = serde_json::to_string(cb) {
            println!("{line}");
        }
    } else {
        let tag = cb
            .matched_token
            .as_deref()
            .map(|t| format!("[token={}]", t))
            .unwrap_or_else(|| "[unknown]".to_string());
        println!(
            "{} {} {} {} {} {}",
            "callback:".bright_green(),
            cb.received_at,
            cb.source,
            cb.method.yellow(),
            cb.path.bright_white(),
            tag.cyan()
        );
    }
}

/// Read one HTTP request off the socket and translate to a Callback.
/// Handles malformed requests by returning Err — the connection is
/// closed and the listener loop moves on.
///
/// Returns `Ok(None)` when the request was handled as a MANAGEMENT
/// API hit (the path begins with `/_wafrift/`) — those are answered
/// inline with their own JSON response and intentionally NOT
/// recorded in the registry's callbacks log (otherwise the operator
/// polling the API would pollute their own evidence stream).
async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    registry: &Registry,
    max_body: usize,
    read_timeout: Duration,
) -> Result<Option<Callback>, String> {
    let mut buf = vec![0u8; 16 * 1024];
    // Cap total bytes read so a malicious client cannot keep us in
    // an infinite read loop without ever sending the header
    // terminator. 64 KiB is more than enough for any header section.
    let mut total_read = 0_usize;
    let mut header_end: Option<usize> = None;
    let header_cap = 64 * 1024;
    while header_end.is_none() {
        let read_fut = sock.read(&mut buf[total_read..]);
        let n = tokio::time::timeout(read_timeout, read_fut)
            .await
            .map_err(|_| "timeout reading headers".to_string())?
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("EOF before headers complete".into());
        }
        total_read += n;
        if let Some(pos) = find_double_crlf(&buf[..total_read]) {
            header_end = Some(pos);
            break;
        }
        if total_read >= header_cap {
            return Err("header too large".into());
        }
        if total_read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
    let header_end = header_end.expect("loop exited only when found");
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|e| format!("non-utf8 headers: {e}"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k_lc = k.trim().to_ascii_lowercase();
            let v_trim = v.trim().to_string();
            if k_lc == "content-length" {
                content_length = v_trim.parse().unwrap_or(0);
            }
            headers.push((k_lc, v_trim));
        }
    }

    // Body = (bytes already in buf past the header terminator) + the rest.
    let header_terminator_len = 4; // CRLF CRLF
    let body_start = header_end + header_terminator_len;
    let already_have = total_read.saturating_sub(body_start);
    let mut body_truncated = 0_usize;
    let mut body = Vec::with_capacity(content_length.min(max_body));
    let take = already_have.min(max_body);
    body.extend_from_slice(&buf[body_start..body_start + take]);
    let mut remaining = content_length.saturating_sub(already_have);
    while remaining > 0 {
        let mut chunk = vec![0u8; remaining.min(16 * 1024)];
        let read_fut = sock.read(&mut chunk);
        let n = tokio::time::timeout(read_timeout, read_fut)
            .await
            .map_err(|_| "timeout reading body".to_string())?
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        let want = max_body.saturating_sub(body.len());
        if want > 0 {
            let take = n.min(want);
            body.extend_from_slice(&chunk[..take]);
            body_truncated += n.saturating_sub(take);
        } else {
            body_truncated += n;
        }
        remaining = remaining.saturating_sub(n);
    }
    body_truncated += already_have.saturating_sub(take);

    // Management API: paths under `/_wafrift/` get answered inline
    // and NOT recorded as callbacks. The check endpoint lets a
    // scan-side caller (or the operator with curl) ask "has this
    // token been received yet?" without spawning a polling proxy.
    if let Some(rest) = path.strip_prefix("/_wafrift/check/") {
        // Trim any trailing query string / slash; token alphabet is
        // alnum only so anything past it is noise.
        let token = rest.split(&['/', '?', '#'][..]).next().unwrap_or("").to_string();
        let received = registry
            .callbacks()
            .await
            .iter()
            .any(|cb| cb.matched_token.as_deref() == Some(token.as_str()));
        let body = serde_json::json!({
            "received": received,
            "token": token,
        })
        .to_string();
        let status = if received { "200 OK" } else { "404 Not Found" };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
        return Ok(None);
    }

    // Reply with a tiny 200 so the upstream client gets a clean close.
    let _ = sock
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = sock.shutdown().await;

    let received_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Token match: the token may appear in the path, in a header
    // value, or in the body — search all three. We do not URL-decode
    // because the token alphabet is base32 (alphanumeric only) which
    // is already URL-safe; if a target encodes the token anyway it
    // means the URL-decoded path string is what matters, which is
    // what the inbound `path` already is (it's the raw request-line
    // path, no decoding done by the listener).
    let mut matched_token = registry.match_token_in(&path).await;
    if matched_token.is_none() {
        for (_, v) in &headers {
            if let Some(t) = registry.match_token_in(v).await {
                matched_token = Some(t);
                break;
            }
        }
    }
    if matched_token.is_none() {
        let body_str = String::from_utf8_lossy(&body);
        matched_token = registry.match_token_in(&body_str).await;
    }

    Ok(Some(Callback {
        received_at,
        source: peer.to_string(),
        method,
        path,
        matched_token,
        headers,
        body_preview: String::from_utf8_lossy(&body).into_owned(),
        body_truncated_bytes: body_truncated,
    }))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    // Standard HTTP header terminator is `\r\n\r\n`; tolerate the
    // `\n\n` form some clients send.
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos);
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some(pos);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Token-generation tests (alphabet, length, no-collision) and
    // base32_encode round-trip tests live in
    // `crate::callback_token::tests` — the functions themselves moved
    // out of listener_cmd to be shared with scan's payload
    // substitution. Duplicating them here would just guarantee one
    // pair drifts.

    // ── registry ─────────────────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn registry_mint_returns_n_distinct_tokens() {
        let r = Registry::new();
        let mints = r.mint(8).await;
        assert_eq!(mints.len(), 8);
        let mut set = std::collections::HashSet::new();
        for t in &mints {
            assert!(set.insert(t.clone()), "duplicate token in mint batch: {t}");
        }
        // The registry's known_tokens should reflect the mint.
        let known = r.known_tokens().await;
        assert_eq!(known.len(), 8);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registry_match_token_in_finds_substring() {
        let r = Registry::new();
        r.register("ABCDEFGHIJKLMNOPQRSTUVWXY2").await;
        // Exact, prefix, suffix, embedded — all must match.
        assert_eq!(
            r.match_token_in("ABCDEFGHIJKLMNOPQRSTUVWXY2").await.as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXY2")
        );
        assert_eq!(
            r.match_token_in("/ABCDEFGHIJKLMNOPQRSTUVWXY2/x").await.as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXY2")
        );
        // Different token must not falsely match.
        assert_eq!(
            r.match_token_in("ZZZZZZZZZZZZZZZZZZZZZZZZZZ").await,
            None
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registry_match_token_in_is_case_sensitive() {
        // Tokens are base32 upper-case; a lowercase substring should
        // NOT match (caller's contract — we never normalise on lookup).
        let r = Registry::new();
        r.register("ABCDEFGHIJKLMNOPQRSTUVWXY2").await;
        assert_eq!(
            r.match_token_in("abcdefghijklmnopqrstuvwxy2").await,
            None
        );
    }

    // ── header parsing ───────────────────────────────────────────

    #[test]
    fn find_double_crlf_handles_canonical_and_loose_forms() {
        // `GET / HTTP/1.1` is 14 bytes, so `\r\n\r\n` starts at
        // position 14. `\n\n` starts at position 14 in the lf-only
        // form too (request line is still 14 bytes).
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\n\n"), Some(14));
        assert_eq!(find_double_crlf(b"no terminator here"), None);
    }

    #[test]
    fn find_double_crlf_locates_terminator_at_buffer_end() {
        let mut buf = vec![b'X'; 100];
        buf.extend_from_slice(b"\r\n\r\n");
        let pos = find_double_crlf(&buf).expect("must find");
        assert_eq!(pos, 100);
    }

    // ── end-to-end: real TCP listener answers a real callback ────

    /// Drive the listener loop directly against a hand-rolled HTTP
    /// client request. Bypasses run_listener's blocking entry so the
    /// test can shut down cleanly.
    async fn drive_one_callback(
        registry: Arc<Registry>,
        request: &[u8],
    ) -> (Callback, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let req = request.to_vec();
        let server = tokio::spawn({
            let registry = registry.clone();
            async move {
                let (sock, peer) = listener.accept().await.expect("accept");
                // The drive_one_callback helper is for the
                // callback-recording path, so we always expect
                // Some(Callback). Management-API tests use their
                // own dedicated helper.
                handle_conn(sock, peer, &registry, 8 * 1024, Duration::from_secs(5))
                    .await
                    .expect("handle_conn ok")
                    .expect("handle_conn returned a callback (not a management response)")
            }
        });
        // Tiny pause so the listener has time to be ready before we
        // connect.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(&req).await.expect("write request");
        let _ = client.shutdown().await;
        let cb = server.await.expect("server join");
        (cb, addr)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_matching_token_in_path() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.method, "GET");
        assert_eq!(cb.path, format!("/{token}"));
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert!(cb.body_preview.is_empty());
        assert_eq!(cb.body_truncated_bytes, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_token_in_body_is_matched() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let body = format!("ping {token} pong");
        let req = format!(
            "POST /noise HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.method, "POST");
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert_eq!(cb.body_preview, body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_unknown_token_records_unmatched() {
        // Anti-rig: a callback we never planted (e.g. an unrelated
        // bot scan against the listener port) must record as
        // unmatched, not falsely tagged with a token we did plant.
        let registry = Arc::new(Registry::new());
        let _real = registry.mint(1).await;
        let req = b"GET /OTHERTOKEN HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let (cb, _) = drive_one_callback(registry, req).await;
        assert_eq!(cb.matched_token, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_body_above_cap_is_truncated_with_counter() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        // Body is 16 KiB — cap is 8 KiB → 8 KiB truncated.
        let body = format!("{token}{}", "x".repeat(16 * 1024 - token.len()));
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), 8 * 1024);
        assert!(cb.body_truncated_bytes >= 8 * 1024 - 8); // ~8 KiB dropped
        // The token still matches because it sits in the first chunk
        // of the body (which falls under the cap).
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registry_matched_count_excludes_unmatched_callbacks() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req_match = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        );
        let req_no_match = b"GET /random HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let (cb1, _) = drive_one_callback(registry.clone(), req_match.as_bytes()).await;
        registry.push(cb1).await;
        let (cb2, _) = drive_one_callback(registry.clone(), req_no_match).await;
        registry.push(cb2).await;
        assert_eq!(registry.callbacks().await.len(), 2);
        assert_eq!(registry.matched_count().await, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_malformed_request_does_not_crash_the_listener() {
        // A client that sends garbage MUST NOT take the listener
        // down with it. We don't drive_one_callback here because
        // handle_conn returns Err on bad input — exercise it
        // directly to assert the Err path is clean.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::new());
        let registry_c = registry.clone();
        let server = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            handle_conn(sock, peer, &registry_c, 8 * 1024, Duration::from_millis(200)).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Garbage with no \r\n\r\n terminator — the listener should
        // time out reading headers and return Err cleanly.
        client.write_all(b"this is not http").await.unwrap();
        let _ = client.shutdown().await;
        let result = server.await.unwrap();
        assert!(result.is_err(), "malformed request must return Err");
    }

    // ── Management API: GET /_wafrift/check/<TOKEN> ─────────────
    //
    // Lets a scan-side caller (or the operator with curl) ask the
    // running listener "has this token been received yet?" without
    // polluting the callback log with their own queries.

    /// Drive one /_wafrift/check/<token> request. Reads the raw
    /// response off the socket so we can assert on the status line
    /// + JSON body.
    async fn drive_management_check(
        registry: Arc<Registry>,
        token: &str,
    ) -> (String, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let registry_c = registry.clone();
        let server = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.expect("accept");
            let _ = handle_conn(sock, peer, &registry_c, 8 * 1024, Duration::from_secs(3)).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let req = format!(
            "GET /_wafrift/check/{token} HTTP/1.1\r\nHost: x\r\n\
             Content-Length: 0\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp_buf = Vec::new();
        // Read until EOF.
        let mut buf = [0u8; 4096];
        loop {
            let n = client.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&buf[..n]);
        }
        let _ = client.shutdown().await;
        let _ = server.await;
        let resp = String::from_utf8_lossy(&resp_buf).into_owned();
        // Split status line + body for the caller.
        let (status_line, rest) = resp.split_once("\r\n").unwrap_or(("", ""));
        let body = rest
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();
        (status_line.to_string(), body)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn management_check_unknown_token_returns_404_with_received_false() {
        let registry = Arc::new(Registry::new());
        let _ = registry.mint(1).await; // mint one so the registry is non-empty
        let (status, body) =
            drive_management_check(registry, "NEVERSEENABCDEFGHIJKLMNOPQ").await;
        assert!(status.contains("404"), "status was: {status}");
        assert!(body.contains("\"received\":false"), "body: {body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn management_check_known_received_token_returns_200_received_true() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        // Record a callback for this token by going through the
        // normal callback path.
        let cb_req = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry.clone(), cb_req.as_bytes()).await;
        registry.push(cb).await;
        // Now ask the management endpoint.
        let (status, body) = drive_management_check(registry, &token).await;
        assert!(status.contains("200"), "status was: {status}");
        assert!(body.contains("\"received\":true"), "body: {body}");
        assert!(body.contains(&token), "body should include the token: {body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn management_check_does_not_record_itself_as_a_callback() {
        // Anti-rig: a poll for /_wafrift/check/X must NOT append a
        // Callback to the registry (would pollute the evidence
        // stream and could match later polls).
        let registry = Arc::new(Registry::new());
        let _ = registry.mint(1).await;
        assert_eq!(registry.callbacks().await.len(), 0);
        let (_status, _body) = drive_management_check(registry.clone(), "ANYTOKEN").await;
        assert_eq!(
            registry.callbacks().await.len(),
            0,
            "management API hit must not record a callback"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn management_check_path_with_trailing_slash_still_matches() {
        // Resilience: a caller hitting /_wafrift/check/TOK/ (with
        // trailing slash) must still get the right answer.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let cb_req = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry.clone(), cb_req.as_bytes()).await;
        registry.push(cb).await;
        // Use a token with a trailing slash in the URL request.
        let path_with_slash = format!("{token}/");
        let (status, body) = drive_management_check(registry, &path_with_slash).await;
        assert!(status.contains("200"));
        assert!(body.contains("\"received\":true"));
    }

    // ── Deep edge-case sweep (added 2026-05-20 under the "deep
    // testing + over-the-top coverage" bar). Each test below names
    // the failure mode it gates against in its body so a future
    // reader can see why the case matters.

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_lowercase_method_is_normalised_to_upper() {
        // The Callback.method field must always be uppercased so
        // downstream consumers can match on `"GET"`, never having
        // to worry about `"get"` vs `"GET"`.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "post /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.method, "POST", "method must be uppercased, got `{}`", cb.method);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_token_in_header_value_is_matched() {
        // A blind SSRF callback might land with the token in a
        // header (e.g. attacker-controlled User-Agent / X-Forwarded-For)
        // not the path. Listener must scan all three (path, headers,
        // body).
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "GET /noise HTTP/1.1\r\nHost: x\r\nX-Callback: {token}\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(
            cb.matched_token.as_deref(),
            Some(token.as_str()),
            "header-value token should match"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_body_exactly_at_cap_is_not_marked_truncated() {
        // Boundary case: body length == cap (8 KiB). Nothing should
        // be truncated, truncated_bytes must be zero.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let exact = 8 * 1024_usize;
        // Body = token + padding to exactly the cap.
        let pad = exact - token.len();
        let body = format!("{token}{}", "x".repeat(pad));
        assert_eq!(body.len(), exact);
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), exact);
        assert_eq!(cb.body_truncated_bytes, 0, "exact-cap body must NOT truncate");
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_one_byte_above_cap_truncates_one_byte() {
        // Boundary: body = cap + 1 byte. Truncated counter must be
        // exactly 1, body_preview length must equal cap. Off-by-one
        // bugs in the cap logic are caught here.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let cap = 8 * 1024_usize;
        let pad = (cap + 1) - token.len();
        let body = format!("{token}{}", "y".repeat(pad));
        assert_eq!(body.len(), cap + 1);
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), cap);
        assert_eq!(
            cb.body_truncated_bytes, 1,
            "exactly one byte should be reported truncated"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_negative_content_length_does_not_crash() {
        // Adversarial Content-Length: garbage value. Our parser
        // falls back to 0 on parse-failure (already-have body bytes
        // are still captured), and the listener must NOT crash or
        // hang on the read loop.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: -7\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_huge_content_length_does_not_pre_allocate() {
        // Adversarial: Content-Length: 9999999999 (10 GiB) with
        // zero actual body bytes. The listener's Vec::with_capacity
        // is clamped to `min(content_length, max_body)`, so this
        // must NOT OOM us — and the connection EOFs immediately so
        // we just see an empty body.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 9999999999\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        // We at least got the request line + headers parsed (token
        // match in path proves it). Body is empty because the client
        // never actually sent any bytes.
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert!(
            cb.body_preview.is_empty(),
            "client sent zero body bytes; preview must be empty"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registered_tokens_persist_across_separate_mint_calls() {
        // Registry::mint can be called multiple times; previously
        // minted tokens must remain valid (the contract is "add to
        // the set", not "replace").
        let r = Registry::new();
        let first_batch = r.mint(3).await;
        let second_batch = r.mint(2).await;
        let known = r.known_tokens().await;
        assert_eq!(known.len(), 5);
        for t in first_batch.iter().chain(second_batch.iter()) {
            assert!(known.contains(t), "token {t} missing from registry");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registered_caller_supplied_token_can_match() {
        // The `register()` API lets the caller supply their own
        // token (instead of asking the registry to mint one). Useful
        // when the scan side wants to embed a payload-shape hint in
        // the token prefix. Verify the registered token is found
        // by `match_token_in`.
        let r = Registry::new();
        r.register("ATTACKERSUPPLIEDABCDEFGHIJ").await;
        assert_eq!(
            r.match_token_in("/.well-known/ATTACKERSUPPLIEDABCDEFGHIJ")
                .await
                .as_deref(),
            Some("ATTACKERSUPPLIEDABCDEFGHIJ")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registry_callbacks_log_is_in_arrival_order() {
        // Sanity: pushing three callbacks in order keeps them in
        // that order in `callbacks()` — needed so timeline
        // reconstructions are correct.
        let r = Registry::new();
        for i in 0_u64..3 {
            r.push(Callback {
                received_at: i,
                source: format!("127.0.0.1:{i}"),
                method: "GET".into(),
                path: format!("/p{i}"),
                matched_token: None,
                headers: vec![],
                body_preview: String::new(),
                body_truncated_bytes: 0,
            })
            .await;
        }
        let cbs = r.callbacks().await;
        assert_eq!(cbs.len(), 3);
        assert_eq!(cbs[0].path, "/p0");
        assert_eq!(cbs[1].path, "/p1");
        assert_eq!(cbs[2].path, "/p2");
    }

    // base32_encode byte-length tests live in
    // `crate::callback_token::tests`.
}
