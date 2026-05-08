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

pub mod h2_evasion;
pub mod parser;
pub mod rules;
pub mod safety;
pub mod smuggling;
