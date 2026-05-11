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
//!
//! # Examples
//!
//! Round-trip: build a bundle, sign it with a fresh key, verify it
//! against a trust list that has the matching publisher key.
//!
//! ```
//! use wafrift_genome_registry::{
//!     Genome, GenomeBundle, SigningKey, TrustList,
//! };
//!
//! // 1. Author makes a bundle.
//! let key = SigningKey::generate();
//! let bundle = GenomeBundle::new(
//!     "demo-pack",
//!     vec![Genome::new("xss-svg-onload", "<svg onload=alert(1)>")],
//! );
//!
//! // 2. Sign + serialize. Two senders building the same bundle
//! //    produce byte-equal signatures (deterministic canonical encoding).
//! let signed = bundle.clone().sign(&key).unwrap();
//!
//! // 3. Operator's trust-list whitelists this publisher's pubkey.
//! let mut trust = TrustList::new();
//! trust.allow_hex(&key.verifying_key_hex().to_string(), "demo-author");
//! assert!(trust.contains(&key.verifying_key_hex().to_string()));
//!
//! // 4. Verification succeeds and yields back the original bundle.
//! let verified = signed.verify(&trust).unwrap();
//! assert_eq!(verified.bundle_name, "demo-pack");
//! assert_eq!(verified.genomes.len(), 1);
//! assert_eq!(verified.genomes[0].name, "xss-svg-onload");
//! ```

#![forbid(unsafe_code)]

pub mod bundle;
pub mod signing;
pub mod trust;

pub use bundle::{Genome, GenomeBundle, SignedBundle};
pub use signing::{RegistryError, SigningKey, VerifyingKeyHex};
pub use trust::{Publisher, TrustList};
