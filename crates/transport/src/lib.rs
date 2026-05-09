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

mod client;
mod response;
pub mod signal;
pub mod stealth;

pub use client::EvasionClient;
pub use client::EvasionError;
pub use response::EvasionResponse;
pub use response::{is_waf_block, is_waf_block_status};
pub use signal::{BlockClass, ResponseProfileDb, ResponseSignal};
pub use stealth::{ImpersonateProfile, StealthClient, StealthError, StealthResponse};

pub mod jwt;
pub mod session;
