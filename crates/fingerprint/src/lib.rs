//! wafrift-fingerprint — Browser and TLS fingerprint profiles.
//!
//! Provides browser-accurate fingerprint profiles (User-Agent, headers,
//! Sec-Fetch-*) and TLS profiles (JA3/JA4 cipher suites, extensions,
//! GREASE values) to make requests indistinguishable from real browsers.
//!
//! # Examples
//!
//! Pick a random browser profile and stamp it onto an outgoing
//! request's headers — the User-Agent + Accept + Sec-Fetch-* fields
//! all align so a WAF heuristic can't catch a "Chrome UA but
//! Firefox Accept-Language" mismatch:
//!
//! ```
//! use wafrift_fingerprint::fingerprint::{apply_profile, random_profile};
//!
//! let profile = random_profile().expect("PROFILES is non-empty");
//! let mut headers: Vec<(String, String)> = vec![
//!     ("User-Agent".into(), "old-ua/1.0".into()),
//! ];
//! apply_profile(&mut headers, profile);
//!
//! // Old User-Agent is replaced, not appended.
//! let ua_count = headers.iter().filter(|(k, _)| k == "User-Agent").count();
//! assert_eq!(ua_count, 1);
//! let ua = headers.iter().find(|(k, _)| k == "User-Agent").unwrap();
//! assert_eq!(ua.1, profile.user_agent);
//! ```

pub mod fingerprint;
pub mod session;
pub mod tls_fingerprint;
