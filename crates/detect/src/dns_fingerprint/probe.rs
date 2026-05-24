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
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

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
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts);

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
        for record in result.iter() {
            if let Some(c) = record.as_cname() {
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
    let final_ptr = if let Some(ip) = first_a {
        let ptr_fut = resolver.reverse_lookup(ip);
        match tokio::time::timeout(RESOLVER_TIMEOUT, ptr_fut).await {
            Ok(Ok(records)) => records
                .iter()
                .next()
                .map(|n| n.to_string().trim_end_matches('.').to_string()),
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
#[cfg(feature = "dns-cname")]
async fn lookup_asn(
    resolver: &hickory_resolver::TokioAsyncResolver,
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
    let first = txt.iter().next()?.as_txt()?.iter().next()?;
    // TXT records are byte-arrays; cymru's payload is ASCII.
    let raw = std::str::from_utf8(first).ok()?;
    let parts: Vec<&str> = raw.split('|').map(str::trim).collect();
    let number: u32 = parts.first()?.parse().ok()?;

    // Second-stage lookup for the AS NAME.
    let name_query = format!("AS{number}.asn.cymru.com");
    let name_fut = resolver.lookup(&name_query, hickory_resolver::proto::rr::RecordType::TXT);
    let name = match tokio::time::timeout(RESOLVER_TIMEOUT, name_fut).await {
        Ok(Ok(r)) => {
            let bytes = r.iter().next()?.as_txt()?.iter().next()?;
            let raw = std::str::from_utf8(bytes).ok()?;
            // Format: `AS_NUM | CC | REGISTRY | ALLOCATED | AS_NAME`.
            raw.split('|').next_back().map(|s| s.trim().to_string())?
        }
        _ => return None,
    };
    Some(AsnInfo { number, name })
}
