//! [`TelemetryConfig`] — runtime configuration for the telemetry subsystem.

use std::{net::SocketAddr, path::PathBuf};

/// Configuration passed to [`crate::Telemetry::init`].
///
/// All fields have sensible defaults; use [`TelemetryConfig::default()`] and
/// override only what you need.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    // Stdout backend
    /// Write a human-readable line for every event to stdout.
    /// Default: `true`.
    pub stdout_enabled: bool,

    // JSONL backend
    /// Append events as newline-delimited JSON to [`Self::jsonl_path`].
    /// Default: `true`.
    pub jsonl_enabled: bool,

    /// Path for the JSONL log file.
    /// Default: `~/.wafrift/telemetry.jsonl`.
    pub jsonl_path: PathBuf,

    // Prometheus backend
    /// Serve a Prometheus `/metrics` endpoint.
    /// Default: `false`.  Requires the `backend-prometheus` feature.
    pub prometheus_enabled: bool,

    /// Address for the Prometheus HTTP server.
    /// Default: `127.0.0.1:9870`.
    pub prometheus_addr: SocketAddr,

    // Tracing integration
    /// Install a `tracing` subscriber layer so `tracing::*` macros also flow
    /// through the telemetry pipeline.  Default: `true`.
    pub install_tracing_layer: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        let jsonl_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".wafrift")
            .join("telemetry.jsonl");

        Self {
            stdout_enabled: true,
            jsonl_enabled: true,
            jsonl_path,
            prometheus_enabled: false,
            prometheus_addr: "127.0.0.1:9870".parse().expect("static addr"),
            install_tracing_layer: true,
        }
    }
}
