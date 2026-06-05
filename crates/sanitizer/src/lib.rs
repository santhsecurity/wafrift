//! # wafrift-sanitizer — the client-side sanitizer decompiler
//!
//! The dual of the [WAF decompiler](wafrift_wafmodel): where that crate learns a
//! server WAF's decision boundary, this one targets the **client-side HTML
//! sanitizer** — the DOMPurify config or hand-rolled `replace()` chain that
//! stands between a DOM source (`location.hash`, `window.name`, …) and a sink.
//!
//! Pipeline:
//!
//! 1. **Recover** ([`sourcemap`]). Parse the shipped `*.map` and pull the
//!    original, unminified sanitizer source out of `sourcesContent`.
//! 2. **Extract** ([`extract`]). Identify the sanitizer and read off its
//!    allow/deny model — forbidden tags, stripped patterns, blocked URL schemes
//!    — from Tier-B signatures.
//! 3. **Model & mine** ([`model`], [`mine`]). Turn the extracted model into a
//!    [`WafOracle`](wafrift_wafmodel::WafOracle), active-learn it with the same
//!    L*/SFA machinery, and mine inputs that survive sanitization while staying
//!    executable — bypass candidates for that exact sanitizer config.
//!
//! Sound by construction: the model is derived from the sanitizer's own source,
//! mining only proposes survivors of that model, and execution is confirmed in a
//! real browser by scald — never fabricated here.

#![forbid(unsafe_code)]

pub mod extract;
pub mod mine;
pub mod model;
pub mod mxss;
pub mod sourcemap;

pub use extract::{
    SanitizerKind, SanitizerModel, SanitizerSignature, extract_sanitizer, sanitizer_signatures,
};
pub use mine::{MineResult, SanitizerBypass, decompile_and_mine};
pub use model::{SanitizerOracle, is_executable_html};
pub use mxss::{MxssCandidate, MxssCombination, mxss_candidates, mxss_combinations};
pub use sourcemap::{RecoveredSource, Segment, SourceMap, SourceMapError};
