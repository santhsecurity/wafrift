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
//! | Re-export path                      | Used by                             |
//! |-------------------------------------|-------------------------------------|
//! | wafrift_types::*                    | all tests (Request, Technique, ...) |
//! | content_type                        | adversarial, failure_tests          |
//! | encoding                            | all tests                           |
//! | fingerprint                         | adversarial                         |
//! | grammar                             | pipeline_integration                |
//! | smuggling, h2_evasion               | pipeline_integration                |
//! | waf_detect                          | adversarial, pipeline_integration   |
//! | host_state, strategy                | all tests                           |
//! | HostState, EscalationLevel          | strategy_adversarial, failure_tests |
//! | EvasionConfig, CalibrationResult    | strategy_adversarial, failure_tests |

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
