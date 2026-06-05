//! # wafrift-liveoracle — the calibrated live oracle
//!
//! Reliability-aware classification of a live WAF response, extracted from the
//! wafrift CLI so any tool can reuse it.
//!
//! - [`verdict`] — map a response to `Allowed` / `Blocked` / `Transient` from the
//!   status code AND a Tier-B block-page signature set, with a bounded transient
//!   retry that honours `Retry-After`. Kills the 200-block-page-as-pass and
//!   429-as-block reliability bugs.
//! - [`calibration`] — learn THIS target's block signal from benign/malicious
//!   control probes (reflection-aware), catching bespoke block pages no
//!   signature lists.
//!
//! The core is pure and network-free: probe and sleep are injected, so the whole
//! oracle is unit-testable offline.

#![forbid(unsafe_code)]

pub mod calibration;
pub mod verdict;

pub use calibration::{Baseline, Calibration, benign_control, calibrate, malicious_controls};
pub use verdict::{
    BLOCK_SCAN_BYTES, LiveVerdict, MAX_TRANSIENT_RETRIES, ProbeResponse, classify_live_response,
    classify_with_retry, default_block_signatures, load_block_signatures,
};
