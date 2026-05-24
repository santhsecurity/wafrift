//! Async DNS probe — CNAME chain → PTR → BGP origin ASN.
//!
//! Three layers in one pass; each is best-effort so a failure on
//! one layer never blocks the others.  The whole probe is
//! gated behind the `dns-cname` cargo feature so consumers that
//! don't want a tokio runtime can disable it.

use super::types::{
    AsnInfo, CnameHop, DnsProbe, DnsProbeError, MAX_CNAME_CHAIN_DEPTH, RESOLVER_TIMEOUT,
};

/// Resolve a host's full CNAME chain, returning every intermediate
/// hop.  Returns an empty chain (not an error) when the host has an
/// A/AAAA record directly with no CNAME indirection.
#[cfg(feature = "dns-cname")]
pub async fn probe_cname_chain(host: &str) -> Result<DnsProbe, DnsProbeError> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{CLOUDFLARE, ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    // Resolver-construction strategy:
    //
    // We use Cloudflare's 1.1.1.1 anycast resolver because:
    //
    // 1. Public, stable, low-latency from every IP block.
    // 2. Doesn't expose corporate DNS / Tailscale / split-horizon
    //    configurations to the WAF being probed (some operators
    //    treat unfamiliar resolvers as a forensic signal).
    // 3. Bypasses `system-config` parsing bugs on Windows where
    //    `tokio_from_system_conf()` returns a resolver pointed at
    //    a stale or unreachable IPv6 nameserver and every lookup
    //    silently times out.
    //
    // If a future deployment needs split-horizon DNS to see
    // internal hostnames, that's a separate code path — for the
    // dogfood / pen-test use case 1.1.1.1 is the right default.
    let mut opts = ResolverOpts::default();
    opts.timeout = RESOLVER_TIMEOUT;
    opts.attempts = 2;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .map_err(|_| DnsProbeError::ResolverInitFailed)?;

    let mut chain: Vec<CnameHop> = Vec::new();
    let mut current = host.trim_end_matches('.').to_string();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for _ in 0..MAX_CNAME_CHAIN_DEPTH {
        if !seen.insert(current.to_ascii_lowercase()) {
            // Looping — give up gracefully with what we have.
            return Ok(DnsProbe {
                chain,
                first_a: None,
                final_ptr: None,
                asn: None,
            });
        }

        let lookup_fut = resolver.lookup(&current, hickory_resolver::proto::rr::RecordType::CNAME);
        let result = match tokio::time::timeout(RESOLVER_TIMEOUT, lookup_fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => break,
            Err(_) => break, // Per-step timeout — partial chain is still useful.
        };

        let mut next: Option<String> = None;
        for record in result.answers() {
            if let hickory_resolver::proto::rr::RData::CNAME(c) = &record.data {
                next = Some(c.to_string().trim_end_matches('.').to_string());
                break;
            }
        }

        match next {
            Some(target) => {
                chain.push(CnameHop {
                    query: current.clone(),
                    target: target.clone(),
                });
                current = target;
            }
            None => break,
        }
    }

    if chain.len() == MAX_CNAME_CHAIN_DEPTH {
        return Err(DnsProbeError::DepthExceeded);
    }

    // Final A lookup on the last alias so callers see the IP tier.
    // This also serves as a positive-signal anchor: if we got at
    // least one A record back, we know the resolver itself works
    // and any empty chain means "no CNAME exists" rather than
    // "DNS broken."
    let a_lookup = resolver.lookup_ip(&current);
    let first_a = match tokio::time::timeout(RESOLVER_TIMEOUT, a_lookup).await {
        Ok(Ok(ips)) => ips.iter().next(),
        _ => None,
    };

    // If the chain is empty AND we got no A record, the resolver
    // is broken — return Err so the caller doesn't silently drop
    // the DNS signal.  An empty chain with a valid A record is a
    // legitimate "no CNAME indirection" answer (cloudflare.com).
    if chain.is_empty() && first_a.is_none() {
        return Err(DnsProbeError::NoRecords);
    }

    // Reverse-DNS (PTR) lookup of the leaf IP.  For origins that
    // strip every HTTP banner and use private CNAMEs (Stripe,
    // Dropbox) the PTR is often the only vendor anchor left.  PTR
    // lookups frequently fail with NoRecords — that's fine, we
    // just don't get the extra signal.
    //
    // hickory 0.26's `reverse_lookup` takes `impl IntoName` (was
    // `IpAddr` in 0.24), so we hand-build the in-addr.arpa /
    // ip6.arpa name. `Name::from_str` accepts the dotted form.
    let final_ptr = if let Some(ip) = first_a {
        let arpa = ptr_name(ip);
        let ptr_fut = resolver.reverse_lookup(arpa.as_str());
        match tokio::time::timeout(RESOLVER_TIMEOUT, ptr_fut).await {
            Ok(Ok(records)) => records.answers().iter().find_map(|rec| match &rec.data {
                hickory_resolver::proto::rr::RData::PTR(p) => {
                    Some(p.to_string().trim_end_matches('.').to_string())
                }
                _ => None,
            }),
            _ => None,
        }
    } else {
        None
    };

    // ASN lookup via cymru.com's `origin.asn.cymru.com` TXT
    // service.  This is the FINAL fallback — the BGP-layer owner
    // of the IP is the truth even when HTTP / CNAME / PTR are all
    // stripped.  Catches origins like Stripe whose IPs are
    // self-hosted with no public identifier on any other layer.
    let asn = if let Some(ip) = first_a {
        lookup_asn(&resolver, ip).await
    } else {
        None
    };

    Ok(DnsProbe {
        chain,
        first_a,
        final_ptr,
        asn,
    })
}

#[cfg(not(feature = "dns-cname"))]
pub async fn probe_cname_chain(_host: &str) -> Result<DnsProbe, DnsProbeError> {
    // Feature disabled — treat as "no DNS support compiled in" and
    // let the caller fall back to header-only detection.
    Err(DnsProbeError::ResolverInitFailed)
}

/// Look up an IP's origin-AS via cymru.com's DNS service.
///
/// Format per cymru docs (https://team-cymru.com/community-services/ip-asn-mapping/):
/// - For IPv4 `1.2.3.4`: query `4.3.2.1.origin.asn.cymru.com TXT`.
/// - For IPv6 `2001:db8::1`: nibble-reverse + append `.origin6.asn.cymru.com`.
///
/// Response TXT format:
/// `"AS_NUM | BGP_PREFIX | CC | REGISTRY | ALLOCATED"` (no AS name)
///
/// We then chain to `AS<num>.asn.cymru.com TXT` for the ASN
/// organisation name (`STRIPE-AS, US`, `CLOUDFLARENET, US`, etc.).
/// Build the reverse-DNS query name for an IP. IPv4 `1.2.3.4`
/// becomes `4.3.2.1.in-addr.arpa.`; IPv6 nibble-reverses into
/// `....ip6.arpa.`. Caller passes the resulting string straight
/// to `resolver.reverse_lookup()`.
#[cfg(feature = "dns-cname")]
fn ptr_name(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            // Each 16-bit segment expands to 4 nibbles, all reversed.
            let mut nibbles = String::with_capacity(73);
            for byte in v6.octets().iter().rev() {
                use std::fmt::Write;
                let _ = write!(nibbles, "{:x}.{:x}.", byte & 0x0f, (byte >> 4) & 0x0f);
            }
            nibbles.push_str("ip6.arpa.");
            nibbles
        }
    }
}

/// Pull the first character-string chunk out of the first TXT
/// answer in a Lookup, or None when no TXT answer is present.
/// hickory 0.26 removed `Record::as_txt()` and `Lookup::iter()`,
/// so this hides the pattern-match boilerplate at every call site.
#[cfg(feature = "dns-cname")]
fn first_txt_chunk(lookup: &hickory_resolver::lookup::Lookup) -> Option<&[u8]> {
    lookup.answers().iter().find_map(|rec| match &rec.data {
        hickory_resolver::proto::rr::RData::TXT(t) => t.txt_data.first().map(|b| &**b),
        _ => None,
    })
}

#[cfg(feature = "dns-cname")]
async fn lookup_asn(
    resolver: &hickory_resolver::TokioResolver,
    ip: std::net::IpAddr,
) -> Option<AsnInfo> {
    let query = match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(_) => {
            // IPv6 nibble-reverse would work but adds 32 nibble
            // joins; the typical pen-test target's IPv4 record
            // exists so we skip IPv6 here for simplicity.  When
            // the user explicitly needs ASN for v6 the right
            // forward A lookup usually returns a v4 fallback.
            return None;
        }
    };
    let txt_fut = resolver.lookup(&query, hickory_resolver::proto::rr::RecordType::TXT);
    let txt = match tokio::time::timeout(RESOLVER_TIMEOUT, txt_fut).await {
        Ok(Ok(r)) => r,
        _ => return None,
    };
    let first = first_txt_chunk(&txt)?;
    // TXT records are byte-arrays; cymru's payload is ASCII.
    let raw = std::str::from_utf8(first).ok()?;
    let parts: Vec<&str> = raw.split('|').map(str::trim).collect();
    let number: u32 = parts.first()?.parse().ok()?;

    // Second-stage lookup for the AS NAME.
    let name_query = format!("AS{number}.asn.cymru.com");
    let name_fut = resolver.lookup(&name_query, hickory_resolver::proto::rr::RecordType::TXT);
    let name = match tokio::time::timeout(RESOLVER_TIMEOUT, name_fut).await {
        Ok(Ok(r)) => {
            let bytes = first_txt_chunk(&r)?;
            let raw = std::str::from_utf8(bytes).ok()?;
            // Format: `AS_NUM | CC | REGISTRY | ALLOCATED | AS_NAME`.
            raw.split('|').next_back().map(|s| s.trim().to_string())?
        }
        _ => return None,
    };
    Some(AsnInfo { number, name })
}

#[cfg(all(test, feature = "dns-cname"))]
mod tests {
    use super::ptr_name;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_ptr_name_reverses_octets() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ptr_name(ip), "4.3.2.1.in-addr.arpa.");
    }

    #[test]
    fn ipv4_ptr_handles_loopback() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ptr_name(ip), "1.0.0.127.in-addr.arpa.");
    }

    #[test]
    fn ipv6_ptr_name_uses_nibble_reversal() {
        // 2001:db8::1 — the canonical doc example.
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001));
        let arpa = ptr_name(ip);
        // 32 nibbles + ".ip6.arpa." suffix; ends with the high-order bytes
        // of the doc prefix (2001:0db8 → "8.b.d.0.1.0.0.2" reversed-leading).
        assert!(arpa.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa."), "got {arpa}");
        // Starts with the low-order nibble of the trailing ::1.
        assert!(arpa.starts_with("1.0.0.0."), "got {arpa}");
    }
}
