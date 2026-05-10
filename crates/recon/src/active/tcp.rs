//! TCP connect + first-line read for coarse service detection.

use super::error::ReconProbeError;
use super::{ActiveProbeConfig, TcpBannerSnapshot};
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Class inferred from the first banner line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpServiceClass {
    Ssh,
    Http,
    Smtp,
    Unknown,
}

/// Connect to `addr`, read up to one `\n`-terminated line (or `max_banner_bytes`), classify.
///
/// # Errors
///
/// - [`ReconProbeError::TcpConnectDeadline`] / [`ReconProbeError::TcpReadDeadline`] on timeouts.
/// - [`ReconProbeError::Io`] for socket errors.
pub async fn probe_tcp_banner(
    addr: SocketAddr,
    config: &ActiveProbeConfig,
) -> Result<TcpBannerSnapshot, ReconProbeError> {
    let mut stream = match timeout(config.tcp_connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(ReconProbeError::TcpConnectDeadline {
                limit: config.tcp_connect_timeout,
            });
        }
    };

    let max = config.max_banner_bytes.max(1);
    let mut buf = vec![0u8; max];
    let read_fut = async {
        let mut total = 0usize;
        loop {
            if total >= max {
                return Ok::<usize, std::io::Error>(total);
            }
            let n = stream.read(&mut buf[total..]).await?;
            if n == 0 {
                return Ok(total);
            }
            total += n;
            if buf[..total].contains(&b'\n') {
                return Ok(total);
            }
        }
    };

    let n = match timeout(config.tcp_read_timeout, read_fut).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(ReconProbeError::TcpReadDeadline {
                limit: config.tcp_read_timeout,
            });
        }
    };

    let slice = &buf[..n];
    let end = slice
        .iter()
        .position(|&b| b == b'\n')
        .map_or(slice.len(), |i| i);
    let line_bytes = slice[..end].trim_ascii_end();
    let line = String::from_utf8_lossy(line_bytes).trim().to_string();
    let service = classify_line(&line);
    Ok(TcpBannerSnapshot { line, service })
}

fn classify_line(line: &str) -> TcpServiceClass {
    let t = line.trim_start();
    if t.len() >= 4 && t[..4].eq_ignore_ascii_case("SSH-") {
        return TcpServiceClass::Ssh;
    }
    if t.len() >= 5 && t[..5].eq_ignore_ascii_case("HTTP/") {
        return TcpServiceClass::Http;
    }
    if t.starts_with("220 ") || t.starts_with("220-") {
        return TcpServiceClass::Smtp;
    }
    TcpServiceClass::Unknown
}
