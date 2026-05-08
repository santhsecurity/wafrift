//! wafrift-fingerprint — Browser and TLS fingerprint profiles.
//!
//! Provides browser-accurate fingerprint profiles (User-Agent, headers,
//! Sec-Fetch-*) and TLS profiles (JA3/JA4 cipher suites, extensions,
//! GREASE values) to make requests indistinguishable from real browsers.

pub mod fingerprint;
pub mod tls_fingerprint;
