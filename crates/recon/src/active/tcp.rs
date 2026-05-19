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
    // `t` is `from_utf8_lossy` of an attacker-controlled TCP banner, so
    // it may contain multibyte codepoints (and U+FFFD from lossy
    // decode). `t[..4]` is a BYTE slice on a `&str`: `t.len() >= 4`
    // does not imply byte 4 is a char boundary, so a non-ASCII-prefixed
    // banner (e.g. two leading invalid bytes → `��`) panics. The probe
    // prefixes are pure ASCII, so a byte-slice compare is exactly
    // equivalent and boundary-safe.
    let b = t.as_bytes();
    if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"SSH-") {
        return TcpServiceClass::Ssh;
    }
    if b.len() >= 5 && b[..5].eq_ignore_ascii_case(b"HTTP/") {
        return TcpServiceClass::Http;
    }
    if t.starts_with("220 ") || t.starts_with("220-") {
        return TcpServiceClass::Smtp;
    }
    TcpServiceClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_line_recognises_real_banners() {
        assert_eq!(classify_line("SSH-2.0-OpenSSH_9.6"), TcpServiceClass::Ssh);
        assert_eq!(classify_line("ssh-2.0-libssh"), TcpServiceClass::Ssh);
        assert_eq!(classify_line("HTTP/1.1 200 OK"), TcpServiceClass::Http);
        assert_eq!(
            classify_line("  HTTP/1.0 404 Not Found"),
            TcpServiceClass::Http
        );
        assert_eq!(
            classify_line("220 smtp.example.com ESMTP Postfix"),
            TcpServiceClass::Smtp
        );
        assert_eq!(
            classify_line("220-multiline greeting"),
            TcpServiceClass::Smtp
        );
        assert_eq!(classify_line("+OK POP3 ready"), TcpServiceClass::Unknown);
    }

    /// Regression: a non-ASCII-prefixed banner used to `t[..4]`-panic
    /// (byte slice on a `&str` past a char boundary). The banner is
    /// `from_utf8_lossy` of attacker bytes, so this is attacker-reachable.
    #[test]
    fn classify_line_never_panics_on_multibyte_or_lossy_banners() {
        let hostile = [
            // two U+FFFD (what `\xff\xff` lossy-decodes to) then "SSH-"
            "\u{FFFD}\u{FFFD}SSH-2.0",
            "日本語SSH-2.0", // 3-byte chars straddling index 4/5
            "→éHTTP/1.1",    // 3-byte + 2-byte prefix
            "\u{FFFD}",      // shorter than every prefix
            "ab",
            "",
            "   ",
            "\u{1F3F4}\u{200D}\u{2620}\u{FE0F}", // pirate-flag ZWJ emoji
            "Ⓢ Ⓢ Ⓗ -",
        ];
        for b in hostile {
            // Must not panic; a non-ASCII prefix is simply not a known
            // ASCII service banner.
            assert_eq!(
                classify_line(b),
                TcpServiceClass::Unknown,
                "hostile banner {b:?} misclassified"
            );
        }
        // The exact real code path: lossy-decode of raw attacker bytes.
        let raw = b"\xff\xfe\xff SSH-2.0-x\r\n";
        let line = String::from_utf8_lossy(raw).trim().to_string();
        let _ = classify_line(&line); // the assertion is "did not panic"
    }
}
