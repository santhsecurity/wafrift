//! HTTP GET probe: collect response headers and classify via [`super::HeaderRules`].
//!
//! § Safety note — body drain (§15 OOM defence):
//! After header collection the response body is drained so the underlying TCP
//! connection can return to the pool. Pre-R49 this used `.bytes().await` with
//! the comment "bounded by client timeout". A timeout bounds wall-clock time,
//! NOT decompressed bytes — a gzip bomb served at 1 KB/s exhausts the full
//! timeout window while expanding 100× in memory. The current implementation
//! uses a `DRAIN_CAP`-bounded `.chunk()` loop instead.

use super::error::ReconProbeError;
use super::rules::HeaderRules;
use super::{HttpHeaderProbeSnapshot, StackTag};
use guise::http::default_browser_header_map_without_compression;
use reqwest::header::HeaderMap;
use std::collections::BTreeMap;

use super::ActiveProbeConfig;

fn recon_http_default_headers() -> HeaderMap {
    default_browser_header_map_without_compression()
        .expect("canonical stealth browser headers must be valid")
}

/// Perform a GET request, normalize headers, and classify with embedded TOML rules.
///
/// # Errors
///
/// - [`ReconProbeError::HttpDeadline`] when the overall request exceeds `config.http_timeout`.
/// - [`ReconProbeError::Http`] for other transport failures.
pub async fn probe_http_headers(
    url: &str,
    config: &ActiveProbeConfig,
) -> Result<HttpHeaderProbeSnapshot, ReconProbeError> {
    probe_http_headers_with_rules(url, config, &HeaderRules::embedded()).await
}

/// Same as [`probe_http_headers`] but uses caller-supplied rules (e.g. loaded from disk).
pub async fn probe_http_headers_with_rules(
    url: &str,
    config: &ActiveProbeConfig,
    rules: &HeaderRules,
) -> Result<HttpHeaderProbeSnapshot, ReconProbeError> {
    // F89: send coherent browser-shaped navigation headers. The reqwest
    // default (`reqwest/<ver>`) and missing Accept-Language are on WAF
    // bot-detection signature lists; challenge-page headers would pollute
    // the stack classifier.
    let client = reqwest::Client::builder()
        .connect_timeout(config.http_timeout)
        .timeout(config.http_timeout)
        // §15 SSRF: do NOT follow redirects. reqwest's default policy chases up
        // to 10 redirects to ANY host, so a recon target that answers
        // `302 Location: http://169.254.169.254/` would walk this probe into
        // cloud metadata / RFC1918 (this client carries no BogonFilteringResolver,
        // unlike the EvasionClient/proxy). A header-fingerprint probe wants the
        // target's DIRECT response anyway — the redirect response's own headers
        // (Location, Server, …) are themselves a fingerprint signal.
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(recon_http_default_headers())
        .build()?;

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return Err(ReconProbeError::HttpDeadline {
                    limit: config.http_timeout,
                });
            }
            return Err(ReconProbeError::Http(e));
        }
    };

    let status = resp.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in resp.headers() {
        let key = name.as_str().to_ascii_lowercase();
        // Hyper injects `Date` on every response; it would make back-to-back snapshots
        // non-deterministic for idempotency tests and corpus diffing.
        if key == "date" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.insert(key, v.to_string());
        } else {
            headers.insert(key, String::from_utf8_lossy(value.as_bytes()).into_owned());
        }
    }

    // Drain body so the connection can be pooled.
    // §15 OOM / decompression-bomb defence: the old `.bytes().await` with
    // the comment "bounded by client timeout" was NOT byte-bounded — a
    // gzip bomb served at 1 KB/s exhausts the full timeout window while
    // expanding to hundreds of MiB. Read chunk-by-chunk and stop after a
    // modest cap (headers are all we need; body content is discarded).
    const DRAIN_CAP: usize = 256 * 1024;
    let mut resp = resp;
    let mut drained = 0_usize;
    while let Ok(Some(chunk)) = resp.chunk().await {
        drained = drained.saturating_add(chunk.len());
        if drained >= DRAIN_CAP {
            break; // cap hit — drop the connection; classifier already has the headers
        }
    }

    let tags: Vec<StackTag> = rules.classify(&headers);
    Ok(HttpHeaderProbeSnapshot {
        status,
        headers,
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use guise::fingerprint::default_profile_facts;

    // §15 OOM / decompression-bomb anti-regression.
    //
    // Pin that `probe_http_headers_with_rules` drains the body via a
    // bounded `.chunk()` loop and NOT the old unbounded `.bytes().await`.
    // The old code's comment "bounded by client timeout" was misleading:
    // a gzip bomb served at 1 KB/s can expand far beyond laptop RAM
    // while staying within a generous HTTP timeout.

    #[test]
    fn recon_http_body_drain_is_bounded() {
        let src = include_str!("http.rs");
        // New bounded pattern must be present.
        assert!(
            src.contains("resp.chunk().await"),
            "recon http.rs body drain must use .chunk() loop (not .bytes().await)"
        );
        assert!(
            src.contains("DRAIN_CAP"),
            "recon http.rs body drain must reference the DRAIN_CAP constant"
        );
        // Old unbounded pattern must be absent.
        let banned = concat!("resp.", "bytes().", "await");
        assert!(
            !src.contains(banned),
            "recon http.rs must not use unbounded .bytes().await drain — \
             decompression-bomb regression"
        );
    }

    fn captured_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        raw.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    #[tokio::test]
    async fn recon_http_probe_sends_profile_navigation_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let snapshot = probe_http_headers_with_rules(
            &url,
            &ActiveProbeConfig::default(),
            &HeaderRules::embedded(),
        )
        .await
        .unwrap();
        assert_eq!(snapshot.status, 200);

        let raw_request = server.await.unwrap();
        let facts = default_profile_facts();
        assert_eq!(
            captured_header(&raw_request, "User-Agent"),
            Some(facts.user_agent)
        );
        assert_eq!(captured_header(&raw_request, "Accept"), Some(facts.accept));
        assert_eq!(
            captured_header(&raw_request, "Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(
            captured_header(&raw_request, "Sec-Fetch-Mode"),
            Some("navigate")
        );
        if let Some(encoding) = captured_header(&raw_request, "Accept-Encoding") {
            let tokens: Vec<String> = encoding
                .split(',')
                .map(|token| token.trim().to_ascii_lowercase())
                .collect();
            assert!(
                !tokens
                    .iter()
                    .any(|token| token == "zstd" || token == "deflate"),
                "recon reqwest client must not advertise unsupported browser compression tokens: {encoding}"
            );
        }
    }
}
