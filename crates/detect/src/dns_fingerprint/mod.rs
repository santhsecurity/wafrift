//! DNS-layer WAF / CDN fingerprinting.
//!
//! Three sub-modules carve up the responsibilities cleanly:
//!
//! * [`types`] — the public shape of a DNS probe (`DnsProbe`,
//!   `CnameHop`, `AsnInfo`, `DnsProbeError`) plus the constants
//!   that bound a single probe (`RESOLVER_TIMEOUT`,
//!   `MAX_CNAME_CHAIN_DEPTH`).
//! * [`probe`] — the async resolver path that actually walks a
//!   host's CNAME chain, follows it with a PTR lookup, then hits
//!   cymru.com's TXT service for the BGP-origin ASN.  Behind the
//!   `dns-cname` cargo feature so detection callers that don't
//!   need a tokio runtime can disable it.
//! * [`rules`] — the `CnameRuleEngine` that turns
//!   `rules/detect/cname/*.toml` into compiled regexes and scores
//!   probes against them, returning the same `DetectedWaf` shape
//!   the HTTP-layer engine uses.
//!
//! HTTP-level detection (`waf_detect`) fails when an origin strips
//! every CDN / WAF marker header — Stripe and Dropbox both serve a
//! bare `Server: nginx` or `Server: envoy` with no other clue.  The
//! DNS layer (CNAME chain → PTR → ASN) lives below anything the
//! application tier controls; this module catches what HTTP can't.
//!
//! Examples observed 2026-05-21 against the live internet:
//!
//! - `www.ebay.com   → e88167.a.akamaiedge.net`             → Akamai
//! - `www.reddit.com → reddit.map.fastly.net`               → Fastly
//! - `aws.amazon.com → dr49lng3n1n2s.cloudfront.net`        → Cloudfront
//! - `stripe.com`    → ASN 16509 (AMAZON-02)                → AWS hosted

pub mod probe;
pub mod rules;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export the public surface so external crates can use
// `wafrift_detect::dns_fingerprint::probe_cname_chain(...)`
// without having to know the internal module layout.
pub use probe::probe_cname_chain;
pub use rules::CnameRuleEngine;
pub use types::{
    AsnInfo, CnameHop, DnsProbe, DnsProbeError, MAX_CNAME_CHAIN_DEPTH, RESOLVER_TIMEOUT,
};

// Used by the `crate::lib` re-export module — keeps the top-level
// `wafrift_detect::probe_cname_chain` alias working across the
// modularisation.
#[doc(hidden)]
pub use probe::probe_cname_chain as _probe_cname_chain;
