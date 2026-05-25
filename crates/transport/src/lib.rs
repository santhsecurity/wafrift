//! wafrift-transport — reqwest middleware for automatic WAF evasion.
//!
//! Drop-in wrapper around `reqwest::Client` that automatically applies
//! WAF evasion techniques from `wafrift-strategy`. Tracks per-host state
//! and escalates evasion when WAF blocks are detected.
//!
//! # Usage
//!
//! ```rust,no_run
//! use wafrift_transport::EvasionClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = EvasionClient::new().expect("build client");
//!     let response = client.get("https://target.com/?q=' OR 1=1--").await;
//! }
//! ```
//!
//! # Examples
//!
//! Sync helpers used inside the retry loop and ratelimit logic — no
//! HTTP needed, so these run in `cargo test --doc` against any
//! environment:
//!
//! ```
//! use wafrift_transport::{is_waf_block, is_waf_block_status};
//!
//! // Status-only fast path (the body may not have arrived yet).
//! assert!(is_waf_block_status(403));
//! assert!(!is_waf_block_status(429), "429 is rate-limit, not a block");
//! assert!(is_waf_block_status(503));
//! assert!(!is_waf_block_status(200));
//! assert!(!is_waf_block_status(404), "404 is not a WAF block");
//!
//! // Body-aware version: a 200 page that says "Forbidden by WAF" is
//! // still a block.
//! assert!(is_waf_block(200, b"Access denied by Web Application Firewall"));
//! assert!(!is_waf_block(200, b"<html><body>Welcome</body></html>"));
//! ```

pub mod challenge;
mod client;
pub mod egress_pool;
mod http_builder;
mod response;
pub mod session_coherence;
pub mod signal;
pub mod stealth;
mod url_util;

pub use client::EvasionClient;
pub use client::EvasionError;
pub use egress_pool::{
    EgressBackend, EgressEntry, EgressError, EgressPool, EgressPoolBuilder, EgressRouter,
    parse_http_proxy_url, parse_socks5_url,
};
pub use http_builder::{base_client_builder, base_client_builder_with_egress};
pub use response::EvasionResponse;
pub use response::{is_waf_block, is_waf_block_status, scan_body_lowercase};
pub use signal::{BlockClass, ResponseProfileDb, ResponseSignal};
pub use stealth::{ImpersonateProfile, StealthClient, StealthError, StealthResponse};
pub use url_util::host_from_url;

pub mod jwt;
pub mod session;
