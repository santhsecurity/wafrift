//! Community-contributed genome distribution for wafrift.
//!
//! Three primitives:
//!
//! - [`Genome`] / [`GenomeBundle`]   wire format for a named pack of
//!   evasion recipes
//! - [`SigningKey`] / [`SignedBundle`]  ed25519 sign + verify
//! - [`TrustList`]                  publisher allowlist (per-host TOML)
//!
//! No HTTP / network I/O — pull/submit live in `wafrift-cli`.
//! This crate is the trust + serialisation core.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod signing;
pub mod trust;

pub use bundle::{Genome, GenomeBundle, SignedBundle};
pub use signing::{RegistryError, SigningKey, VerifyingKeyHex};
pub use trust::{Publisher, TrustList};
