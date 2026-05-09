//! wafrift-core — Façade crate re-exporting all WAF Rift modules.
//!
//! This crate is a convenience umbrella. Each module lives in its own
//! focused crate; this crate re-exports them all under a single namespace
//! so existing consumers (`wafrift-cli`, `wafrift-transport`, integration
//! tests) can continue using `wafrift_core::*`.
//!
//! # Crate structure
//!
//! | Crate                   | Purpose                                       |
//! |-------------------------|-----------------------------------------------|
//! | `wafrift-types`         | Core types: Request, Technique, EvasionResult  |
//! | `wafrift-encoding`      | Payload encoding + header obfuscation          |
//! | `wafrift-grammar`       | Grammar-aware payload mutations                |
//! | `wafrift-content-type`  | WAFFLED Content-Type switching                 |
//! | `wafrift-smuggling`     | HTTP smuggling + HTTP/2 evasion                |
//! | `wafrift-fingerprint`   | Browser + TLS fingerprint profiles             |
//! | `wafrift-detect`        | WAF detection + response fingerprinting        |
//! | `wafrift-evolution`     | Genetic algorithm + differential + advisor     |
//! | `wafrift-strategy`      | Evasion strategy pipeline                      |

// ── Foundation types ──
pub use wafrift_types::*;

// ── Technique modules (re-exported as submodules) ──
pub use wafrift_content_type as content_type;
pub use wafrift_encoding::encoding;
pub use wafrift_encoding::header;
pub use wafrift_fingerprint::fingerprint;
pub use wafrift_fingerprint::tls_fingerprint;
pub use wafrift_grammar::grammar;
pub use wafrift_smuggling::h2_evasion;
pub use wafrift_smuggling::smuggling;

// ── Intelligence modules ──
pub use wafrift_detect::response_fingerprint;
pub use wafrift_detect::waf_detect;
pub use wafrift_evolution::advisor;
pub use wafrift_evolution::custom_rules;
pub use wafrift_evolution::differential;
pub use wafrift_evolution::evolution;
pub use wafrift_evolution::intelligence;

// ── Pipeline ──
pub use wafrift_strategy::host_state;
pub use wafrift_strategy::strategy;

// ── Validation / oracle layer ──
pub use wafrift_oracle as oracle;

// ── Transport / network ──
pub use wafrift_pool as pool;
pub use wafrift_transport as transport;

// ── Discovery ──
pub use wafrift_recon as recon;

// Re-export key types that integration tests expect at crate root
pub use wafrift_strategy::host_state::HostState;
pub use wafrift_strategy::strategy::{CalibrationResult, EscalationLevel, EvasionConfig};
