//! Timeouts and size limits for active probes.

use std::time::Duration;

/// Bounds for HTTP and TCP active probing.
#[derive(Debug, Clone)]
pub struct ActiveProbeConfig {
    /// Upper bound for an entire HTTP request (connect + headers + body).
    pub http_timeout: Duration,
    /// Max time to establish a TCP connection for banner grab.
    pub tcp_connect_timeout: Duration,
    /// Max time to read the first banner line after connect.
    pub tcp_read_timeout: Duration,
    /// Cap bytes read when buffering the first TCP line.
    pub max_banner_bytes: usize,
}

impl Default for ActiveProbeConfig {
    fn default() -> Self {
        Self {
            http_timeout: Duration::from_secs(30),
            tcp_connect_timeout: Duration::from_secs(10),
            tcp_read_timeout: Duration::from_secs(5),
            max_banner_bytes: 4096,
        }
    }
}
