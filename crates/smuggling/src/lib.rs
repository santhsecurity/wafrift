//! wafrift-smuggling — HTTP request smuggling and HTTP/2 frame-level evasion.
//!
//! Generates raw HTTP payloads for CL.TE, TE.CL, TE.TE, CL.0,
//! H2C, WebSocket smuggling, and HTTP/2 downgrade / frame-level evasion.
//!
//! # Safety
//!
//! All probes carry a per-request poison canary. Exploit-grade payloads
//! are gated behind the `unsafe-probes` feature to prevent accidental
//! collateral damage on production targets.
//!
//! # Examples
//!
//! Build a `Content-Length` / `Transfer-Encoding` desync probe.
//! Every byte of the wire payload is materialised here so the caller
//! can replay it through any TCP transport (tokio, std, miri):
//!
//! ```
//! use wafrift_smuggling::smuggling::cl_te;
//!
//! let payload = cl_te("example.com", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
//! let wire = std::str::from_utf8(&payload.raw_bytes).unwrap();
//! assert!(wire.starts_with("POST"));
//! assert!(wire.contains("Host: example.com"));
//! assert!(wire.contains("Transfer-Encoding: chunked"),
//!         "TE header is the bypass primitive");
//! assert!(wire.contains("Content-Length:"));
//! // Per-payload canary so logs can correlate without leaking the
//! // original target.
//! assert_eq!(payload.canary.token.len(), 16);
//! ```

pub mod h2_evasion;
pub mod parser;
pub mod rapid_reset;
pub mod rules;
pub mod safety;
pub mod smuggling;
pub mod sse_smuggle;
pub mod ws_compression;
pub mod ws_fragmentation;
