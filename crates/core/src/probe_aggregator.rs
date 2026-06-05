//! Single aggregator that pulls every wafrift smuggle probe under
//! one operator-iterable interface.
//!
//! Each smuggle module in the workspace produces its own probe Vec:
//! `cookie_smuggle::all_variants(name, value)`,
//! `capsule::all_variants(payload)`, `multipart_smuggle::generate_smuggle_variants(params)`,
//! etc. From an operator's perspective, **they're all probes** — the
//! domain differences are noise once the
//! [`SmuggleProbe`](wafrift_types::probe::SmuggleProbe) trait is in
//! the picture.
//!
//! This module's [`all_probes`] returns a flat `Vec<Box<dyn SmuggleProbe>>`
//! across every family. Operators iterate generically, filter by
//! `technique()` prefix, splice via `apply_to_request`, and never
//! have to import the source crates by name.

use wafrift_content_type::json_smuggle as json_smuggle_family;
use wafrift_content_type::multipart_smuggle::generate_smuggle_variants as multipart_variants;
use wafrift_encoding::auth_header_smuggle;
use wafrift_encoding::cookie_smuggle;
use wafrift_encoding::host_header_smuggle;
use wafrift_encoding::jwt_smuggle;
use wafrift_encoding::path_normalize_smuggle;
use wafrift_encoding::range_header_smuggle;
use wafrift_http3_evasion::capsule;
use wafrift_http3_evasion::quic_datagram;
use wafrift_smuggling::ws_compression::{CompressionBomb, ContextTakeoverSequence};
use wafrift_types::probe::SmuggleProbe;

/// Caller-supplied seeds for the probe aggregator. Each family takes
/// the inputs that make sense for its parser-differential surface:
///
/// - `header_name` / `header_value`: seed for cookie / auth probes.
/// - `params`: form-encoded key/value pairs for multipart smuggle.
/// - `payload`: opaque bytes for capsule / datagram / compression
///   bomb probes.
#[derive(Debug, Clone)]
pub struct ProbeSeeds<'a> {
    /// Cookie / Authorization header name to target. Default
    /// `"session"` for cookie, `"Authorization"` for auth.
    pub cookie_name: &'a str,
    /// Value to splice into cookie / auth probes.
    pub credential_value: &'a str,
    /// Form-encoded parameters for multipart smuggle.
    pub form_params: Vec<(String, String)>,
    /// Opaque payload bytes for capsule / datagram / compression
    /// bomb probes.
    pub payload: Vec<u8>,
    /// Protected resource path the WAF gates (typical: `/admin`).
    /// Used by the path-normalization smuggle family to craft
    /// encoded variants that bypass literal-path WAF rules.
    pub protected_path: &'a str,
    /// Protected target hostname the WAF gates (typical:
    /// `admin.example.com`). Used by the Host-header smuggle
    /// family to craft byte-level variants that bypass literal-
    /// host vhost-matching rules.
    pub protected_host: &'a str,
}

impl<'a> Default for ProbeSeeds<'a> {
    fn default() -> Self {
        Self {
            cookie_name: "session",
            credential_value: "wafrift-test-token",
            form_params: vec![
                ("user".to_string(), "admin".to_string()),
                ("token".to_string(), "wafrift-test-token".to_string()),
            ],
            payload: b"wafrift-smuggle-payload".to_vec(),
            protected_path: "/admin",
            protected_host: "admin.example.com",
        }
    }
}

/// Return every probe wafrift can produce for the given seeds,
/// boxed as `dyn SmuggleProbe` for uniform iteration.
///
/// Ordering: cookies first, then auth, then range, then path-
/// normalization, then host-header, then multipart, then JSON, then
/// HTTP/3 capsule, then QUIC datagram, then WebSocket compression.
/// The relative order within each family follows that family's own
/// `all_variants` / `generate_smuggle_variants` output —
/// preserve-on-shape so operators that key on technique-id get
/// reproducible iteration.
#[must_use]
pub fn all_probes(seeds: &ProbeSeeds) -> Vec<Box<dyn SmuggleProbe>> {
    let mut out: Vec<Box<dyn SmuggleProbe>> = Vec::new();

    // Cookie family.
    for p in cookie_smuggle::all_variants(seeds.cookie_name, seeds.credential_value) {
        out.push(Box::new(p));
    }
    // Authorization-header family.
    for p in
        auth_header_smuggle::all_variants("Authorization", "Bearer", seeds.credential_value)
    {
        out.push(Box::new(p));
    }
    // Range-header family.
    for p in range_header_smuggle::all_variants() {
        out.push(Box::new(p));
    }
    // Path-normalization parser-differential family.
    for p in path_normalize_smuggle::all_variants(seeds.protected_path) {
        out.push(Box::new(p));
    }
    // Host-header parser-differential family.
    for p in host_header_smuggle::all_variants(seeds.protected_host) {
        out.push(Box::new(p));
    }
    // JWT validation-differential family.
    for p in jwt_smuggle::all_variants(seeds.credential_value) {
        out.push(Box::new(p));
    }
    // Multipart smuggle (content-type crate).
    for v in multipart_variants(&seeds.form_params) {
        out.push(Box::new(v));
    }
    // JSON parser-differential family (body-shape probes).
    for v in json_smuggle_family::all_variants(&seeds.form_params) {
        out.push(Box::new(v));
    }
    // HTTP/3 capsule family.
    for a in capsule::all_variants(&seeds.payload) {
        out.push(Box::new(a));
    }
    // QUIC datagram family.
    for a in quic_datagram::all_variants(&seeds.payload) {
        out.push(Box::new(a));
    }
    // WebSocket compression — bomb plus context-takeover sequence.
    out.push(Box::new(CompressionBomb::build(1000)));
    out.push(Box::new(ContextTakeoverSequence::build(&seeds.payload, 50)));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn aggregator_returns_probes_from_every_family() {
        let probes = all_probes(&ProbeSeeds::default());
        assert!(!probes.is_empty(), "aggregator must return probes");

        // Group by `family` (the prefix before the first `.` in
        // each `technique()`).
        let families: HashSet<String> = probes
            .iter()
            .map(|p| {
                p.technique()
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        // Eleven distinct families: cookie, auth, range, path,
        // host, jwt, content-type (multipart), json, capsule,
        // quic-datagram, compression.
        for required in [
            "cookie",
            "auth",
            "range",
            "path",
            "host",
            "jwt",
            "content-type",
            "json",
            "capsule",
            "quic-datagram",
            "compression",
        ] {
            assert!(
                families.contains(required),
                "missing family {required:?} in aggregator output; got {families:?}"
            );
        }
    }

    #[test]
    fn aggregator_canaries_are_unique_across_all_probes() {
        // Every probe must carry an independent canary — uniqueness
        // is the whole point.
        let probes = all_probes(&ProbeSeeds::default());
        let tokens: HashSet<String> =
            probes.iter().map(|p| p.canary().token.clone()).collect();
        assert_eq!(
            tokens.len(),
            probes.len(),
            "expected {} unique canaries, got {}",
            probes.len(),
            tokens.len()
        );
    }

    #[test]
    fn every_aggregator_probe_has_non_empty_artifact() {
        let probes = all_probes(&ProbeSeeds::default());
        for p in &probes {
            let n = p.artifact().wire_byte_count();
            assert!(
                n > 0,
                "probe {} produced empty artifact (wire_byte_count = 0)",
                p.technique()
            );
        }
    }

    #[test]
    fn aggregator_count_grows_with_ten_families() {
        // Anti-rig: pin a lower bound on probe count so a regression
        // that accidentally drops one family (e.g. typo in a `for`
        // loop dropping the iterator) breaks the test instead of
        // silently halving coverage.
        let probes = all_probes(&ProbeSeeds::default());
        // Conservative lower bound: 7 cookie + 8 auth + 8 range +
        // 10 path + 8 host + 10 jwt + 6 multipart + 10 json + 6
        // capsule + 4 quic-datagram + 2 compression = 79. We pin
        // >=78 to leave slack for downstream tweaks without losing
        // the gate.
        assert!(
            probes.len() >= 78,
            "aggregator returned only {} probes — family dropped?",
            probes.len()
        );
    }

    #[test]
    fn default_seeds_construct_without_panicking() {
        let seeds = ProbeSeeds::default();
        assert!(!seeds.cookie_name.is_empty());
        assert!(!seeds.credential_value.is_empty());
        assert!(!seeds.form_params.is_empty());
        assert!(!seeds.payload.is_empty());
        assert!(!seeds.protected_path.is_empty());
        assert!(!seeds.protected_host.is_empty());
    }

    #[test]
    fn custom_protected_path_propagates_to_path_family_probes() {
        let seeds = ProbeSeeds {
            protected_path: "/wp-admin",
            ..ProbeSeeds::default()
        };
        let probes = all_probes(&seeds);
        let mut saw_target = false;
        for p in &probes {
            if p.technique().starts_with("path.")
                && let wafrift_types::probe::SmuggleArtifact::Headers(hs) = p.artifact()
                && hs.iter().any(|(_, v)| v.contains("wp-admin"))
            {
                saw_target = true;
                break;
            }
        }
        assert!(
            saw_target,
            "custom protected_path must propagate into path-family artifacts"
        );
    }

    #[test]
    fn custom_protected_host_propagates_to_host_family_probes() {
        let seeds = ProbeSeeds {
            protected_host: "secret-internal.example.io",
            ..ProbeSeeds::default()
        };
        let probes = all_probes(&seeds);
        let mut saw_target = false;
        for p in &probes {
            if p.technique().starts_with("host.")
                && let wafrift_types::probe::SmuggleArtifact::Headers(hs) = p.artifact()
                && hs.iter().any(|(_, v)| v.contains("secret-internal.example.io"))
            {
                saw_target = true;
                break;
            }
        }
        assert!(
            saw_target,
            "custom protected_host must propagate into host-family artifacts"
        );
    }

    #[test]
    fn aggregator_contains_at_least_eight_host_family_probes() {
        let probes = all_probes(&ProbeSeeds::default());
        let host_count = probes
            .iter()
            .filter(|p| p.technique().starts_with("host."))
            .count();
        assert!(
            host_count >= 8,
            "expected >=8 host-family probes, got {host_count}"
        );
    }

    #[test]
    fn aggregator_contains_at_least_ten_path_family_probes() {
        // Pin the path family's contribution — anti-rig against a
        // regression that drops the path probes from the aggregator.
        let probes = all_probes(&ProbeSeeds::default());
        let path_count = probes
            .iter()
            .filter(|p| p.technique().starts_with("path."))
            .count();
        assert!(
            path_count >= 10,
            "expected >=10 path-family probes, got {path_count}"
        );
    }
}
