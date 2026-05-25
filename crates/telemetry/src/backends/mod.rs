//! Telemetry output backends.

pub mod drain;

#[cfg(feature = "backend-prometheus")]
pub mod prometheus;
