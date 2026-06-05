//! Post-fire OOB callback verification.
//!
//! When `wafrift scan --callback-url URL` is set and the payload
//! contains `{{CALLBACK}}`, the scan loop substitutes a per-scan
//! token + URL into the payload (see `crate::callback_token`). This
//! module is what happens AFTER the fire loop completes: ask the
//! listener's `/_wafrift/check/<TOKEN>` management API (shipped in
//! `crate::listener_cmd`) whether any inbound matched, and surface
//! the verdict so the operator sees "VERIFIED" / "not observed"
//! without grep-ing the listener log.
//!
//! Closes the oracle loop for blind / stored vuln classes that
//! never echo a verdict on the same response.

use std::time::Duration;

/// Pending callback verification — the data scan must hold from
/// substitution time until the post-fire poll.
#[derive(Debug, Clone)]
pub(crate) struct CallbackPending {
    /// The unique 128-bit base32 token embedded in this scan's payload.
    pub token: String,
    /// The full callback URL (`<base>/<token>`) that the operator
    /// can grep their listener log for.
    pub callback_url: String,
    /// The listener's base URL (the operator-supplied
    /// `--callback-url` value, NOT the per-variant callback_url).
    /// Used to construct the management-API check path.
    pub base_url: String,
}

/// Result of the post-fire poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackVerdict {
    /// The listener confirmed an inbound matched the token —
    /// a blind / stored vuln is confirmed.
    Verified,
    /// The listener responded but no inbound matched — at least
    /// for the duration of the scan + management-API round trip,
    /// the callback hasn't fired. Could still fire later (stored
    /// XSS execution may be hours away); operator should keep the
    /// listener running.
    NotObserved,
    /// The listener was unreachable / errored. Distinguish from
    /// NotObserved so a network blip doesn't get mistaken for a
    /// confirmed-negative.
    ListenerUnreachable,
}

/// Build the management-API check URL for the given listener
/// base URL + token.
#[must_use]
pub(crate) fn check_url(base_url: &str, token: &str) -> String {
    format!("{}/_wafrift/check/{token}", base_url.trim_end_matches('/'))
}

/// Hit the listener's `/_wafrift/check/<TOKEN>` endpoint and classify
/// the response. Status 200 = Verified, 404 = NotObserved, anything
/// else (connection error, timeout, weird status) = ListenerUnreachable.
///
/// Uses a FRESH reqwest client (not the session-init one) — the
/// listener is on operator infrastructure, so replaying auth cookies
/// at it would be a privacy / leakage footgun.
pub(crate) async fn verify(pending: &CallbackPending, timeout: Duration) -> CallbackVerdict {
    let url = check_url(&pending.base_url, &pending.token);
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(_) => return CallbackVerdict::ListenerUnreachable,
    };
    match client.get(&url).send().await {
        Ok(resp) => match resp.status().as_u16() {
            200 => CallbackVerdict::Verified,
            404 => CallbackVerdict::NotObserved,
            // Any other status is the listener responding but in a
            // way we don't recognise — treat as unreachable, not
            // a confirmed negative.
            _ => CallbackVerdict::ListenerUnreachable,
        },
        Err(_) => CallbackVerdict::ListenerUnreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin a tiny mock listener that answers /_wafrift/check/<TOK>
    /// with the given response factory. `factory(n, path)` is called
    /// for the n-th request with the inbound path.
    async fn spawn_mock_listener<F>(factory: F) -> std::net::SocketAddr
    where
        F: Fn(usize, &str) -> String + Send + Sync + 'static,
    {
        let counter = Arc::new(AtomicUsize::new(0));
        let factory = Arc::new(factory);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let counter_c = counter.clone();
                let factory_c = factory.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let i = counter_c.fetch_add(1, Ordering::SeqCst);
                    let resp = factory_c(i, &path);
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    fn pending_for(addr: std::net::SocketAddr, token: &str) -> CallbackPending {
        CallbackPending {
            token: token.into(),
            callback_url: format!("http://{addr}/{token}"),
            base_url: format!("http://{addr}"),
        }
    }

    #[test]
    fn check_url_trims_trailing_slash_in_base() {
        assert_eq!(
            check_url("http://x:9000", "TOK"),
            "http://x:9000/_wafrift/check/TOK"
        );
        assert_eq!(
            check_url("http://x:9000/", "TOK"),
            "http://x:9000/_wafrift/check/TOK"
        );
        assert_eq!(
            check_url("http://x:9000///", "TOK"),
            "http://x:9000/_wafrift/check/TOK"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_returns_verified_on_200_status() {
        let addr = spawn_mock_listener(|_n, _path| {
            let body = "{\"received\":true,\"token\":\"X\"}";
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                 Content-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        })
        .await;
        let pending = pending_for(addr, "TOKHIT");
        let verdict = verify(&pending, Duration::from_secs(2)).await;
        assert_eq!(verdict, CallbackVerdict::Verified);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_returns_not_observed_on_404() {
        let addr = spawn_mock_listener(|_n, _path| {
            let body = "{\"received\":false,\"token\":\"X\"}";
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\
                 Content-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        })
        .await;
        let pending = pending_for(addr, "TOKMISS");
        let verdict = verify(&pending, Duration::from_secs(2)).await;
        assert_eq!(verdict, CallbackVerdict::NotObserved);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_returns_unreachable_on_unexpected_status() {
        // Anti-rig: a 500 from the listener is NOT a confirmed
        // negative — operator should know their oracle is broken.
        let addr = spawn_mock_listener(|_n, _path| {
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        })
        .await;
        let pending = pending_for(addr, "TOK500");
        let verdict = verify(&pending, Duration::from_secs(2)).await;
        assert_eq!(verdict, CallbackVerdict::ListenerUnreachable);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_returns_unreachable_when_listener_down() {
        // Connect to a port nothing is listening on.
        let pending = CallbackPending {
            token: "TOK".into(),
            callback_url: "http://127.0.0.1:1/TOK".into(),
            base_url: "http://127.0.0.1:1".into(),
        };
        let verdict = verify(&pending, Duration::from_secs(2)).await;
        assert_eq!(verdict, CallbackVerdict::ListenerUnreachable);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_uses_the_token_in_the_path() {
        // Sanity: the path the listener saw must contain the token.
        let received_path = Arc::new(std::sync::Mutex::new(String::new()));
        let received_path_c = received_path.clone();
        let addr = spawn_mock_listener(move |_n, path| {
            *received_path_c.lock().unwrap() = path.to_string();
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        })
        .await;
        let pending = pending_for(addr, "MYUNIQUE123TOKEN");
        let _ = verify(&pending, Duration::from_secs(2)).await;
        assert!(
            received_path.lock().unwrap().contains("MYUNIQUE123TOKEN"),
            "listener should see path containing token: {}",
            received_path.lock().unwrap()
        );
        assert!(
            received_path.lock().unwrap().contains("_wafrift/check"),
            "listener should see the management API path: {}",
            received_path.lock().unwrap()
        );
    }
}
