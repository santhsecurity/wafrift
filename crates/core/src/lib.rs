//! wafrift-core -- Facade crate (integration-test surface only).
//!
//! This crate is NOT a public entry-point for production consumers.
//! wafrift-cli, wafrift-proxy, and wafrift-transport all depend on
//! individual subcrates directly. This facade exists solely to give the
//! workspace integration tests (crates/core/tests/) a single import
//! namespace so each test file does not list a dozen dev-dependencies.
//!
//! # Symbol inventory (everything the tests actually use)
//!
//! Use the umbrella to drive a payload through three subsystems
//! without depending on each subcrate by name:
//!
//! ```
//! use wafrift_core::{encoding, grammar};
//!
//! // Classify, mutate, encode — three lego-blocks, one façade.
//! let p = "' OR 1=1 --";
//! assert_eq!(grammar::classify(p), grammar::PayloadType::Sql);
//!
//! let mutations = grammar::mutate(p, 3);
//! assert!(!mutations.is_empty());
//!
//! let encoded = encoding::encode(p, encoding::Strategy::UrlEncode).unwrap();
//! assert!(encoded.contains("%27"));
//! ```
//!
//! Use the re-exported types to build a request without naming
//! `wafrift_types`:
//!
//! ```
//! use wafrift_core::{Method, Request};
//!
//! let r = Request::get("https://example.com").header("X-Test", "1");
//! assert_eq!(r.method(), &Method::Get);
//! assert_eq!(r.headers().len(), 1);
//! ```
//!
//! # Crate structure
//!
//! | Crate                        | Purpose                                             |
//! |------------------------------|-----------------------------------------------------|
//! | `wafrift-types`              | Core types: Request, Technique, EvasionResult       |
//! | `wafrift-encoding`           | Payload encoding + header obfuscation               |
//! | `wafrift-grammar`            | Grammar-aware payload mutations                     |
//! | `wafrift-content-type`       | WAFFLED Content-Type switching                      |
//! | `wafrift-smuggling`          | HTTP smuggling + HTTP/2 frame-level evasion         |
//! | `wafrift-fingerprint`        | Browser + TLS JA3/JA4 fingerprint profiles          |
//! | `wafrift-detect`             | WAF detection (HTTP headers, DNS CNAME, BGP ASN)    |
//! | `wafrift-evolution`          | Genetic algorithm + MCTS + differential + advisor   |
//! | `wafrift-wafmodel`           | L* WAF decompiler + offline SFA bypass mining       |
//! | `wafrift-oracle`             | Payload validity oracles (SQL, XSS, SSTI, …)        |
//! | `wafrift-strategy`           | Evasion pipeline + gene bank + adaptive host state  |
//! | `wafrift-transport`          | Evasion-aware HTTP client + stealth profiles         |
//! | `wafrift-pool`               | Round-robin HTTP/SOCKS5 proxy pool                  |
//! | `wafrift-recon`              | Origin discovery via CT logs + DNS history           |
//! | `wafrift-genome-registry`    | ed25519 genome signing + trust-list management      |

// -- Foundation types (Request, Technique, Method, EvasionResult, config::*, ...) --
pub use wafrift_types::*;

// -- Technique modules --
pub use wafrift_content_type as content_type;
pub use wafrift_encoding::encoding;
pub use wafrift_fingerprint::fingerprint;
pub use wafrift_grammar::grammar;
pub use wafrift_smuggling::h2_evasion;
pub use wafrift_smuggling::smuggling;

// -- Detection --
pub use wafrift_detect::waf_detect;

// -- Pipeline --
pub use wafrift_strategy::host_state;
pub use wafrift_strategy::strategy;

// -- Root-level re-exports that tests import without a module path --
pub use wafrift_strategy::host_state::HostState;
pub use wafrift_strategy::strategy::{CalibrationResult, EscalationLevel, EvasionConfig};
