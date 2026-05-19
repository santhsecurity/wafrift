//! # wafrift-wafmodel — the WAF decompiler
//!
//! Stop searching a black box. **Reconstruct the WAF's decision
//! boundary as an executable symbolic automaton**, then turn evasion
//! from search into deduction:
//!
//! - **P1 — Decompile.** Active-learn the WAF
//!   ([`learn`](mod@learn)) over a [`WafOracle`](oracle::WafOracle)
//!   into a [`Sfa`](sfa::Sfa), spending the minimum membership-query
//!   budget. Emit it as a provenance-stamped artifact.
//! - **P1 — Mine.** Intersect the learned pass-language with an attack
//!   grammar *offline* to harvest minimal-edit bypasses with no further
//!   live queries.
//! - **P2 — Solve.** Compose the learned WAF view with the pipeline's
//!   normalization transducers and solve for inputs that survive every
//!   stage (the double-decode trick, rediscovered — not hard-coded).
//! - **P3 — Dominate.** The same model drives constrained adversarial
//!   evasion of ML-WAFs *and* provable hole-closure for defenders.
//!
//! Everything here is zero-config and pure-Rust: no GPU, no external
//! Coraza, no network required for the core. Acceleration (vyre/GPU,
//! live HTTP oracles) is strictly additive.
//!
//! The crate is built bottom-up; each module is landed complete (no
//! stubs) before the next depends on it. This file only declares
//! modules that are fully implemented.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod canon;
pub mod equiv_bridge;
pub mod equiv_query;
pub mod error;
pub mod fingerprint;
pub mod harden;
pub mod learn;
pub mod mine;
pub mod mlwaf;
pub mod normalize;
pub mod oracle;
pub mod outcome;
pub mod sfa;
pub mod solve;
pub mod transduce;

pub use artifact::{LearnedModel, Provenance};
pub use canon::{CanonView, Channel, Segment, canonicalize};
pub use equiv_bridge::{norm_mismatch_members, sink_for_tag, solution_member};
pub use equiv_query::{ChainedEq, PacBound, SampledEq, UcbBanditEq, WMethodEq};
pub use error::{Result, WafModelError};
pub use fingerprint::{Candidate, Fingerprinter, Identification, default_battery};
pub use harden::{ClosureReport, synthesize_closure};
pub use learn::{Alphabet, BoundedExhaustiveEq, EquivalenceOracle, LearnReport, kv_learn, l_star};
pub use mine::{attack_grammar, mine_bypasses, minimal_bypass, waf_diff};
pub use mlwaf::{MlEvasion, MlWaf, evade_ml};
pub use normalize::{Transform, apply_chain};
pub use oracle::{ChannelSet, FnOracle, Rule, SimRegexWaf, WafOracle};
pub use outcome::Outcome;
pub use sfa::{BytePred, Sfa, StateId};
pub use solve::{Solution, solve_bypass};
pub use transduce::{Pipeline, Stage, json_unescape, url_decode_once};
