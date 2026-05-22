//! Public data types for DNS-layer fingerprinting.
//!
//! These are split out from `probe` and `rules` so external
//! consumers can construct `DnsProbe` values for synthetic
//! detection (tests, e2e harnesses, gene-bank replay) without
//! pulling in the tokio resolver code path behind the
//! `dns-cname` feature flag.

use std::time::Duration;

/// Maximum CNAME-chain depth followed.  Chains that loop or exceed
/// this depth are truncated — the longest legitimate chain observed
/// in the wild is six hops (akamaitechnologies → akamaiedge → leaf).
pub const MAX_CNAME_CHAIN_DEPTH: usize = 12;

/// Resolver query budget.  Multi-second blocking on detection is a
/// non-starter — if DNS is sick we return an empty chain rather
/// than wedging the CLI.  The default of 8 seconds is intentionally
/// generous because we cold-build the resolver on every probe (no
/// connection pool yet); the first query absorbs the full
/// TLS+UDP+conf overhead.
pub const RESOLVER_TIMEOUT: Duration = Duration::from_secs(8);

/// A single hop in a CNAME chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameHop {
    /// The name being queried at this hop (e.g. `www.reddit.com`).
    pub query: String,
    /// The target the resolver returned (e.g. `reddit.map.fastly.net`).
    pub target: String,
}

/// CNAME-chain probe result.  When the resolver returns an A/AAAA
/// directly (no CNAME), `chain` is empty and `final_a` holds the
/// resolved address tier.  `final_ptr` carries the PTR (reverse
/// DNS) lookup of the leaf IP when available — for origin-direct
/// sites like Stripe this is sometimes the only vendor signal:
/// `198.137.150.111` PTRs to `198-137-150-111.s.stripe.com`,
/// betraying Stripe-managed hosting even though the HTTP layer
/// strips every banner.  `asn` carries the BGP-origin ASN of the
/// leaf IP as resolved via cymru.com's `origin.asn.cymru.com` TXT
/// service — the ONLY layer that consistently catches origins
/// like Stripe that strip every other identifier.
#[derive(Debug, Clone, Default)]
pub struct DnsProbe {
    /// The full CNAME chain in resolution order.
    pub chain: Vec<CnameHop>,
    /// First A record returned at the end of the chain (if any).
    pub first_a: Option<std::net::IpAddr>,
    /// PTR (reverse-DNS) name of `first_a`, when the IP has one.
    /// Many hosting providers expose ownership here even when the
    /// forward chain is opaque.
    pub final_ptr: Option<String>,
    /// BGP ASN number + organisation name of the leaf IP, looked
    /// up via cymru.com's `origin.asn.cymru.com` TXT service.
    /// The ASN org name (e.g. `STRIPE-AS, US`) is the only public
    /// signal that names origin-direct vendors who strip every
    /// HTTP / DNS / PTR identifier.
    pub asn: Option<AsnInfo>,
}

/// BGP / autonomous-system lookup result for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    /// The ASN number (e.g. 395812 for Stripe).
    pub number: u32,
    /// The ASN organisation name as registered (e.g. `STRIPE-AS, US`).
    pub name: String,
}

impl DnsProbe {
    /// All hostnames seen in the chain, including the original
    /// query.  Used by signature matching — every host gets a
    /// chance to fire any rule's regex.  Also includes the ASN
    /// organisation name when present, so a rule can fire on
    /// `STRIPE-AS, US` the same way it would on a hostname.
    pub fn all_hosts(&self) -> Vec<&str> {
        self.tagged_hosts().into_iter().map(|(_, h)| h).collect()
    }

    /// Every signal labeled by source — `(label, host)` tuples
    /// where `label` is one of `cname`, `ptr`, `asn`.  Engines use
    /// this to attribute matches in indicator strings so the
    /// operator can see WHICH layer fingerprinted the vendor.
    pub fn tagged_hosts(&self) -> Vec<(&'static str, &str)> {
        let mut out: Vec<(&'static str, &str)> = Vec::with_capacity(self.chain.len() + 3);
        for hop in &self.chain {
            out.push(("cname", hop.query.as_str()));
        }
        if let Some(last) = self.chain.last() {
            out.push(("cname", last.target.as_str()));
        }
        if let Some(ref ptr) = self.final_ptr {
            out.push(("ptr", ptr.as_str()));
        }
        if let Some(ref asn) = self.asn {
            out.push(("asn", asn.name.as_str()));
        }
        out
    }
}

/// Error class for a DNS probe.  All variants are recoverable
/// from the caller's perspective — header-only detection still
/// runs when the resolver is unreachable.
#[derive(Debug, Clone, Copy)]
pub enum DnsProbeError {
    /// The resolver could not be initialised — usually means no
    /// system DNS config and no fallback was configured.  Caller
    /// should fall back to header-only detection.
    ResolverInitFailed,
    /// Lookup timed out.
    Timeout,
    /// The host returned NXDOMAIN or no records.
    NoRecords,
    /// Chain depth exceeded — possible loop or hostile resolver.
    DepthExceeded,
    /// Other I/O failure (resolver crashed, no network).
    Io,
}

impl std::fmt::Display for DnsProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolverInitFailed => write!(f, "DNS resolver init failed"),
            Self::Timeout => write!(f, "DNS lookup timed out"),
            Self::NoRecords => write!(f, "no DNS records returned"),
            Self::DepthExceeded => {
                write!(f, "CNAME chain depth exceeded {MAX_CNAME_CHAIN_DEPTH}")
            }
            Self::Io => write!(f, "DNS resolver I/O error"),
        }
    }
}

impl std::error::Error for DnsProbeError {}
