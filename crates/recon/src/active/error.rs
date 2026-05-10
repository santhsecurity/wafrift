//! Errors for active probing (`http` / `tcp`).

use std::time::Duration;
use thiserror::Error;

/// Failure from HTTP or TCP active probes.
#[derive(Debug, Error)]
pub enum ReconProbeError {
    /// Underlying HTTP client error (DNS, TLS, etc.).
    #[error(
        "HTTP transport error: {0}. Fix: verify URL scheme/host, TLS trust, and outbound connectivity."
    )]
    Http(#[from] reqwest::Error),

    /// Total request time exceeded [`crate::active::ActiveProbeConfig::http_timeout`].
    #[error(
        "HTTP request exceeded {limit:?}. Fix: raise `ActiveProbeConfig::http_timeout` or probe a faster endpoint."
    )]
    HttpDeadline { limit: Duration },

    /// TCP connect did not complete within [`crate::active::ActiveProbeConfig::tcp_connect_timeout`].
    #[error(
        "TCP connect exceeded {limit:?}. Fix: raise `ActiveProbeConfig::tcp_connect_timeout` or verify the host is listening."
    )]
    TcpConnectDeadline { limit: Duration },

    /// First-line banner read did not finish within [`crate::active::ActiveProbeConfig::tcp_read_timeout`].
    #[error(
        "TCP banner read exceeded {limit:?}. Fix: raise `ActiveProbeConfig::tcp_read_timeout` or confirm the peer sends a prompt promptly."
    )]
    TcpReadDeadline { limit: Duration },

    /// Local I/O (socket) failure after connect.
    #[error("TCP I/O error: {0}. Fix: check firewall rules and socket permissions.")]
    Io(#[from] std::io::Error),

    /// Invalid TOML rules document.
    #[error(
        "Invalid header rules TOML: {0}. Fix: validate `[[rule]]` entries — family must be waf|cdn|framework."
    )]
    RulesToml(String),
}
