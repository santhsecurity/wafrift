//! Decompression-bomb defence — bounded response-body reader.
//!
//! ## The threat
//!
//! Wafrift fires probes at potentially-hostile WAFs and origins. The
//! reqwest build wafrift uses ships the `gzip` and `brotli` features,
//! which means reqwest AUTOMATICALLY decompresses every response
//! body when the server sets `Content-Encoding: gzip` or `br`.
//! Reqwest does NOT cap the decompressed size.
//!
//! A hostile target — including any WAF under test that decides to
//! retaliate against the scanner — can serve a ~1 KB gzipped response
//! that expands to many gigabytes ("zip bomb"). Without a cap, wafrift
//! exhausts memory and crashes. For a pentester running wafrift on a
//! laptop in front of a customer, that is a remote DoS triggered by a
//! single response header.
//!
//! ## The defence
//!
//! [`read_bounded`] consumes the response as a chunked stream and
//! aborts as soon as the running total exceeds `max_bytes`. The cap
//! applies to the DECOMPRESSED stream — reqwest's gzip / brotli
//! decoders sit BEHIND the bytes_stream chain, so what we count is
//! what the rule engine would see.
//!
//! The default cap [`DEFAULT_MAX_RESPONSE_BYTES`] is 8 MiB — much
//! larger than any legitimate WAF block page, JSON envelope, or
//! HTML response, but small enough to fit in a laptop's headroom
//! many times over.
//!
//! ## Where this gets used
//!
//! Every site that called `.bytes().await` or `.text().await`
//! against an operator-supplied target. Internal call sites that
//! talk to known-trusted services (e.g. the operator's own wafrift
//! listener) may use the larger [`HEADROOM_MAX_RESPONSE_BYTES`].
//!
//! ## Invariants
//!
//! - The cap is checked BEFORE each chunk is appended. The
//!   allocator never gets a chance to over-allocate based on a
//!   bomb's Content-Length lie.
//! - On overrun we return an `Err`; the caller MUST treat that as
//!   "target tried to bomb us" and abort the probe — never retry.
//! - A network read error returns a different `Err` variant so
//!   callers can distinguish bomb defence from transient I/O.
//! - The function consumes the [`reqwest::Response`] so the
//!   connection is released cleanly on early-abort.

use futures_util::StreamExt;
use reqwest::Response;
use std::fmt;

/// Default size cap for an arbitrary target's response body —
/// 8 MiB. Bigger than any legitimate WAF block page or JSON API
/// envelope, smaller than any laptop's free RAM by orders of
/// magnitude.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Larger cap for responses from operator-controlled services
/// (e.g. their own `wafrift listener`). Still bounded — even a
/// trusted service can have a bug.
pub const HEADROOM_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of [`read_bounded`].
#[derive(Debug)]
pub enum ReadError {
    /// Decompressed stream exceeded `max_bytes`. Caller should
    /// treat as hostile target — never retry.
    Overrun {
        cap_bytes: usize,
        observed_bytes: usize,
    },
    /// Network / decompression failure mid-stream.
    Transport(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overrun {
                cap_bytes,
                observed_bytes,
            } => write!(
                f,
                "response body exceeded {cap_bytes}-byte cap ({observed_bytes} bytes \
                 seen so far) — decompression-bomb defence aborted the read"
            ),
            Self::Transport(e) => write!(f, "response body read failed: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Read the response body as bytes, aborting if the running total
/// exceeds `max_bytes`. The cap is checked AGAINST the
/// decompressed stream — gzip / brotli decoders run upstream of
/// us, so this is what the WAF / origin actually emitted post-
/// decompress.
pub async fn read_bounded(resp: Response, max_bytes: usize) -> Result<Vec<u8>, ReadError> {
    let mut acc: Vec<u8> = Vec::with_capacity(64 * 1024); // small initial; grows
    let mut stream = resp.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| ReadError::Transport(e.to_string()))?;
        if acc.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ReadError::Overrun {
                cap_bytes: max_bytes,
                observed_bytes: acc.len() + chunk.len(),
            });
        }
        acc.extend_from_slice(&chunk);
    }
    Ok(acc)
}

/// String view of the bounded body. Returns `Ok` with the decoded
/// UTF-8 (lossy — replacement chars for any invalid bytes, same
/// shape reqwest's `.text()` returns).
pub async fn read_bounded_text(resp: Response, max_bytes: usize) -> Result<String, ReadError> {
    let bytes = read_bounded(resp, max_bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin up a small TCP server that returns the given body
    /// bytes verbatim under HTTP/1.1, with the given headers
    /// already framed. Returns the URL.
    async fn spawn_server(framed_response: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let resp = framed_response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&resp).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        format!("http://{addr}/")
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    #[tokio::test]
    async fn read_bounded_returns_body_under_cap() {
        let body = b"hello world";
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 1024).await.expect("under cap");
        assert_eq!(&got[..], body);
    }

    #[tokio::test]
    async fn read_bounded_errors_when_body_exceeds_cap() {
        let body = vec![b'A'; 4096];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = read_bounded(resp, 100).await.expect_err("must overrun");
        match err {
            ReadError::Overrun {
                cap_bytes,
                observed_bytes,
            } => {
                assert_eq!(cap_bytes, 100);
                assert!(observed_bytes > 100);
            }
            other => panic!("expected Overrun, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_bounded_text_handles_under_cap_utf8() {
        let body = b"normal text body";
        let url = spawn_server(ok_response(body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded_text(resp, 1024).await.unwrap();
        assert_eq!(got, "normal text body");
    }

    #[tokio::test]
    async fn read_bounded_text_handles_lossy_utf8() {
        // Body has invalid utf8 bytes — the function must NOT
        // panic and must return replacement-char-substituted
        // string (matches reqwest::Response::text behaviour).
        let body = vec![0xFF, b'a', 0xFE, b'b'];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded_text(resp, 1024).await.unwrap();
        assert!(got.contains('\u{FFFD}'));
        assert!(got.contains('a'));
        assert!(got.contains('b'));
    }

    #[tokio::test]
    async fn read_bounded_aborts_mid_stream_when_cap_reached() {
        // Body is intentionally larger than the cap. The early-
        // abort path must not consume the remainder — the network
        // read should stop as soon as the cap is hit. Functionally
        // this is observable by the elapsed time staying short:
        // a 1 GB body would otherwise take >> 1s.
        let body = vec![b'X'; 1_000_000];
        let url = spawn_server(ok_response(&body)).await;
        let resp = reqwest::get(&url).await.unwrap();
        let start = std::time::Instant::now();
        let err = read_bounded(resp, 32).await.expect_err("must overrun");
        let elapsed = start.elapsed();
        assert!(matches!(err, ReadError::Overrun { .. }));
        assert!(
            elapsed < Duration::from_secs(5),
            "early-abort should NOT read the whole body, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn read_bounded_handles_zero_cap_correctly() {
        // Cap of 0 — any non-empty response must overrun. Empty
        // body (Content-Length: 0) is the only success case.
        let url = spawn_server(ok_response(b"")).await;
        let resp = reqwest::get(&url).await.unwrap();
        let got = read_bounded(resp, 0).await.unwrap();
        assert!(got.is_empty());

        let url2 = spawn_server(ok_response(b"x")).await;
        let resp2 = reqwest::get(&url2).await.unwrap();
        let err = read_bounded(resp2, 0).await.expect_err("must overrun");
        assert!(matches!(err, ReadError::Overrun { .. }));
    }

    #[test]
    fn default_max_is_smaller_than_headroom_max() {
        // Anti-rig: a refactor that swapped the two constants
        // would silently lift the cap on every hostile target.
        assert!(DEFAULT_MAX_RESPONSE_BYTES < HEADROOM_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn default_max_is_at_least_one_megabyte() {
        // A cap smaller than 1 MiB would false-positive on
        // legitimate large block pages (some CRS PL4 setups
        // return a several-hundred-KB block page with a long
        // rule trace). 8 MiB is well above that. Lock the
        // floor in so a future "tighten to 64 KiB" refactor
        // doesn't break real-world targets silently.
        assert!(DEFAULT_MAX_RESPONSE_BYTES >= 1024 * 1024);
    }

    #[test]
    fn read_error_overrun_display_includes_both_numbers() {
        // Operator must see WHAT cap was exceeded BY HOW MUCH
        // — abbreviated errors are debugging hostile.
        let e = ReadError::Overrun {
            cap_bytes: 8388608,
            observed_bytes: 12345678,
        };
        let s = format!("{e}");
        assert!(s.contains("8388608"));
        assert!(s.contains("12345678"));
        assert!(s.contains("decompression-bomb"));
    }

    #[test]
    fn read_error_transport_display_includes_underlying_message() {
        let e = ReadError::Transport("connection reset".into());
        let s = format!("{e}");
        assert!(s.contains("connection reset"));
    }
}
