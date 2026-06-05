//! # wafrift-tcpoverlap — genuine TCP sequence-overlap desync
//!
//! Target-based TCP reassembly evasion (Ptacek & Newsham 1998; Snort
//! `stream5`), done for real. Overlapping TCP segments carrying *different* bytes
//! in the same sequence range are resolved differently by different stacks — so
//! a WAF/IDS and the origin behind it can reassemble the **same packets** into
//! two **different** byte streams. The WAF inspects the benign stream; the origin
//! executes the attack stream.
//!
//! - [`policy`] — the reassembly policies (`first`/`last`/`bsd`/`linux`) and
//!   their precise overlap-resolution rules.
//! - [`reassemble`] — simulate reassembly of a segment set under a policy.
//! - [`plan`] — construct overlapping segment sets and self-verifying
//!   [`DifferentialPlan`](plan::DifferentialPlan)s that split a WAF from its
//!   origin.
//!
//! This crate produces segment **descriptors** (sequence number + bytes) and
//! simulates reassembly; emitting them on the wire is a raw-socket transport
//! concern, exactly as the smuggling probes emit wire artifacts for a sender to
//! deliver.

#![forbid(unsafe_code)]

pub mod plan;
pub mod policy;
pub mod reassemble;

pub use plan::{DifferentialPlan, differential_matrix, differential_plan, full_overlap};
pub use policy::ReassemblyPolicy;
pub use reassemble::{Segment, reassemble};
