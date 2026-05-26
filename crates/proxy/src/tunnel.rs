//! CONNECT-tunnel bidirectional copy with a per-direction byte cap.
//!
//! When the proxy serves a non-MITM HTTPS pass-through, the client
//! `CONNECT host:443`s and after the `200 OK` the proxy splices two
//! TCP streams together. Without a byte cap the splice can carry
//! unbounded data (every other proxy limit is HTTP-layer-only and
//! doesn't see the bytes once the tunnel is up), which is a clean
//! exfil channel for a misused proxy. `MAX_TUNNEL_BYTES_PER_DIRECTION`
//! is the hard ceiling.

use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Cap on bytes transferred per direction per CONNECT tunnel.
/// Prevents a client from streaming gigabytes through the proxy
/// under a single CONNECT — without this, the bidirectional copy
/// runs unbounded and `MAX_PROXY_BODY_BYTES` /
/// `max_upstream_response_bytes` (which guard the HTTP-mode paths)
/// do not apply. 2 GiB is generous for legitimate long-lived TLS
/// sessions while still blocking sustained exfil.
pub const MAX_TUNNEL_BYTES_PER_DIRECTION: u64 = 2 * 1024 * 1024 * 1024;

/// Extract the `host:port` from a URI authority. Used by the
/// CONNECT path to derive the upstream's name for DNS lookup +
/// scope filtering.
#[must_use]
pub fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().map(std::string::ToString::to_string)
}

/// Bidirectional tunnel for CONNECT (HTTPS pass-through). Per-
/// direction byte counter aborts the copy when either side exceeds
/// the cap.
///
/// Takes a pre-resolved `Vec<SocketAddr>` instead of `addr: String`.
/// The string form forced a SECOND DNS lookup at `TcpStream::connect`,
/// opening a rebinding TOCTOU window after the caller had already
/// validated the upstream as public. We now pass the validated
/// `SocketAddrs` straight in and connect to whichever answers first.
///
/// # Errors
/// Returns `io::Error` for: connection refused, byte-cap exceeded
/// in either direction, EOF on either side mid-stream.
pub async fn tunnel(upgraded: Upgraded, addrs: Vec<SocketAddr>) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut server = TcpStream::connect(addrs.as_slice()).await?;
    let mut upgraded = TokioIo::new(upgraded);
    let (mut up_r, mut up_w) = tokio::io::split(&mut upgraded);
    let (mut sv_r, mut sv_w) = server.split();

    // Each direction owns its own bounded copy loop. When either trips
    // the byte cap, drop both halves and return a clean error.
    let to_server = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = up_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_TUNNEL_BYTES_PER_DIRECTION {
                return Err(std::io::Error::other(
                    "tunnel exceeded byte cap (client→server)",
                ));
            }
            sv_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let to_client = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = sv_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_TUNNEL_BYTES_PER_DIRECTION {
                return Err(std::io::Error::other(
                    "tunnel exceeded byte cap (server→client)",
                ));
            }
            up_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(to_server, to_client)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_addr_extracts_authority_with_port() {
        let uri: hyper::Uri = "http://example.com:8080/path".parse().unwrap();
        assert_eq!(host_addr(&uri).as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn host_addr_extracts_authority_without_explicit_port() {
        let uri: hyper::Uri = "https://example.com/path".parse().unwrap();
        // No explicit port — authority returns just the host.
        assert_eq!(host_addr(&uri).as_deref(), Some("example.com"));
    }

    #[test]
    fn host_addr_extracts_ip_authority() {
        let uri: hyper::Uri = "http://127.0.0.1:9000/".parse().unwrap();
        assert_eq!(host_addr(&uri).as_deref(), Some("127.0.0.1:9000"));
    }

    #[test]
    fn host_addr_relative_uri_returns_none() {
        // CONNECT-style authority-only URIs have authority but no
        // scheme; relative URIs ("/path") have NO authority and
        // return None.
        let uri: hyper::Uri = "/path".parse().unwrap();
        assert_eq!(host_addr(&uri), None);
    }

    #[test]
    fn max_tunnel_bytes_per_direction_is_2gib() {
        // Anti-rig: a config change that bumps this to e.g.
        // u64::MAX would silently disable the exfil cap. Pin the
        // value.
        assert_eq!(MAX_TUNNEL_BYTES_PER_DIRECTION, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn max_tunnel_bytes_per_direction_is_under_u64_max() {
        // Sanity: cap is far below u64::MAX so the saturating_add
        // in the read loop never wraps anywhere near the limit.
        // Constant assertion is intentional — build-time regression
        // gate, not a runtime check.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAX_TUNNEL_BYTES_PER_DIRECTION < u64::MAX / 1000);
        }
    }
}
