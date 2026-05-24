//! Hierarchical technique selection for `--only` / `--exclude` CLI flags.
//!
//! Selectors are slash-separated paths (`encoding/url`, `encoding/url/double`,
//! `grammar`). A selector matches any leaf whose path starts with it (so
//! `encoding/url` matches `encoding/url/single`, `encoding/url/double`, ...).
//! Every encoding `Strategy` enum variant has exactly one canonical leaf path.
//!
//! Scope (v0.1): toggles cover families that flow through the scan/evade
//! variant builder — `encoding/*` (strategy-level) and the `grammar` family
//! switch. Smuggling, content-type, and fingerprint are roadmap items and
//! intentionally not surfaced here yet.

use wafrift_encoding::encoding::Strategy;

/// Canonical hierarchical path for an encoding strategy.
pub fn strategy_path(strategy: Strategy) -> &'static str {
    match strategy {
        Strategy::CaseAlternation => "encoding/case/alternating",
        Strategy::RandomCase => "encoding/case/random",
        Strategy::WhitespaceInsertion => "encoding/whitespace/insert",
        Strategy::SpaceToPlus => "encoding/whitespace/space-plus",
        Strategy::SpaceToRandomBlank => "encoding/whitespace/space-random",
        Strategy::SpaceToComment => "encoding/whitespace/space-comment",
        Strategy::SpaceToDash => "encoding/whitespace/space-dash",
        Strategy::SpaceToHash => "encoding/whitespace/space-hash",
        Strategy::SqlCommentInsertion => "encoding/sql/comment",
        Strategy::MysqlVersionedComment => "encoding/sql/mysql-versioned-comment",
        Strategy::BetweenObfuscation => "encoding/sql/between-obfuscation",
        Strategy::UnmagicQuotes => "encoding/sql/unmagic-quotes",
        Strategy::UrlEncode => "encoding/url/single",
        Strategy::UrlEncodeLower => "encoding/url/lower",
        Strategy::DoubleUrlEncode => "encoding/url/double",
        Strategy::TripleUrlEncode => "encoding/url/triple",
        Strategy::PercentagePrefix => "encoding/url/percent-prefix",
        Strategy::UnicodeEncode => "encoding/unicode/escape",
        Strategy::IisUnicodeEncode => "encoding/unicode/iis-percent",
        Strategy::FullwidthEncode => "encoding/unicode/fullwidth",
        Strategy::HomoglyphEncode => "encoding/unicode/homoglyph",
        Strategy::OverlongUtf8 => "encoding/unicode/overlong-utf8",
        Strategy::OverlongUtf8More => "encoding/unicode/overlong-utf8-more",
        Strategy::JsonEncode => "encoding/json/escape",
        Strategy::HtmlEntityEncode => "encoding/html/hex-entity",
        Strategy::HtmlEntityDecimalEncode => "encoding/html/decimal-entity",
        Strategy::NullByte => "encoding/null-byte",
        Strategy::ChunkedSplit => "encoding/chunked-split",
        Strategy::ParameterPollution => "encoding/parameter-pollution",
        Strategy::Base64Encode => "encoding/base64/standard",
        Strategy::Base64UrlEncode => "encoding/base64/url",
        Strategy::HexEncode => "encoding/hex",
        Strategy::Utf7Encode => "encoding/utf7",
        Strategy::GzipEncode => "encoding/compression/gzip",
        Strategy::DeflateEncode => "encoding/compression/deflate",
        // `Strategy` is `#[non_exhaustive]`. New variants flag this sentinel
        // and the `every_strategy_is_mapped` test fails until a path is added.
        _ => "encoding/_unmapped",
    }
}

/// Family-level paths that the v0.1 filter recognizes.
///
/// `tamper/*` is recognised so `wafrift evade --only tamper/<name>`
/// validates instead of error-exiting on an unknown selector.  The
/// underlying tamper application currently runs only inside
/// `wafrift scan` (Step 3b — "Tamper probing"); a future revision
/// will fan tampers into `evade` as well.
const KNOWN_FAMILIES: &[&str] = &["encoding", "grammar", "tamper"];

/// Parsed filter built from comma-separated `--only` / `--exclude` lists.
#[derive(Debug, Default, Clone)]
pub struct TechniqueFilter {
    only: Vec<String>,
    exclude: Vec<String>,
}

impl TechniqueFilter {
    /// Build a filter. Empty `only` means "include everything by default".
    /// Returns `Err` listing any selectors that don't match a known family
    /// or leaf — fail-fast rather than silently drop.
    pub fn parse(only: &[String], exclude: &[String]) -> Result<Self, String> {
        let only = split_csv(only);
        let exclude = split_csv(exclude);
        let known = all_known_paths();
        let bad: Vec<_> = only
            .iter()
            .chain(exclude.iter())
            .filter(|sel| !is_known(sel, &known))
            .cloned()
            .collect();
        if !bad.is_empty() {
            return Err(format!(
                "unknown technique selector(s): {}\n  Tip: run `wafrift techniques list` to see available paths.",
                bad.join(", ")
            ));
        }
        // Contradiction guard (dogfood B7): a real contradiction is
        // when an `--exclude` selector COVERS (is ancestor of or
        // equal to) an `--only` selector — that drowns the only
        // and yields zero variants. `--only encoding/url
        // --exclude encoding/url/triple` is NOT a contradiction:
        // only is the ancestor, exclude just trims one leaf.
        // Previously we caught both directions, which rejected the
        // legitimate "include this subtree EXCEPT one leaf" compose
        // pattern.
        let overlap: Vec<_> = only
            .iter()
            .filter(|o| exclude.iter().any(|e| matches(e, o)))
            .cloned()
            .collect();
        if !overlap.is_empty() {
            return Err(format!(
                "contradictory --only/--exclude selectors: {} appear in both lists \
                 (no variant would ever be selected).\n  \
                 Tip: drop the selector from one of the two lists.",
                overlap.join(", ")
            ));
        }
        Ok(Self { only, exclude })
    }

    /// True if no selectors were supplied — caller can take a fast path.
    pub fn is_default(&self) -> bool {
        self.only.is_empty() && self.exclude.is_empty()
    }

    /// Whether a leaf path is selected.
    pub fn allows_path(&self, path: &str) -> bool {
        let included = if self.only.is_empty() {
            true
        } else {
            self.only.iter().any(|sel| matches(sel, path))
        };
        if !included {
            return false;
        }
        !self.exclude.iter().any(|sel| matches(sel, path))
    }

    /// Convenience: whether an encoding strategy is selected.
    pub fn allows_strategy(&self, strategy: Strategy) -> bool {
        self.allows_path(strategy_path(strategy))
    }

    /// Whether the `grammar` family is enabled. Used to gate grammar-aware
    /// mutations (when `false`, behavior matches the legacy `--encoding-only`).
    pub fn grammar_enabled(&self) -> bool {
        self.allows_path("grammar")
    }

    /// Apply `--only`/`--exclude` over a strategy list.
    pub fn filter_strategies(&self, strategies: Vec<Strategy>) -> Vec<Strategy> {
        if self.is_default() {
            return strategies;
        }
        strategies
            .into_iter()
            .filter(|s| self.allows_strategy(*s))
            .collect()
    }
}

fn split_csv(raw: &[String]) -> Vec<String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('/').to_string())
        .collect()
}

fn matches(selector: &str, leaf: &str) -> bool {
    if selector == leaf {
        return true;
    }
    leaf.starts_with(selector) && leaf.as_bytes().get(selector.len()) == Some(&b'/')
}

fn all_known_paths() -> Vec<&'static str> {
    let mut paths: Vec<&str> = KNOWN_FAMILIES.to_vec();
    for &s in wafrift_encoding::encoding::all_strategies() {
        paths.push(strategy_path(s));
    }
    // Tamper family — every registered tamper exposes a
    // `tamper/<name>` selector.  Names come from the
    // `wafrift_encoding::tamper::all_tamper_names()` static list
    // so adding a tamper is a one-line change in the registry; the
    // filter picks it up automatically and the renderer surfaces
    // it under `wafrift techniques list`.
    for name in wafrift_encoding::tamper::all_tamper_names() {
        paths.push(tamper_path_static(name));
    }
    paths
}

/// Returns a `'static` slash-prefixed path for a tamper name.
/// The tamper-name list is itself `&'static [&'static str]`, so
/// the prefix concatenation reduces to interning the result via
/// a one-time `Box::leak`.  Used only at filter parse time, so
/// the leak is bounded to one allocation per tamper per process
/// lifetime.
fn tamper_path_static(name: &'static str) -> &'static str {
    // SAFETY-FREE: cache results in a single OnceLock so the
    // leaked memory grows linearly with the number of tampers
    // (one entry each) and never per call.  Tampers are static so
    // the `&'static str` lifetime is honest.
    use std::sync::OnceLock;
    static CACHE: OnceLock<
        std::sync::Mutex<std::collections::HashMap<&'static str, &'static str>>,
    > = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().expect("tamper-path cache poisoned");
    if let Some(&path) = guard.get(name) {
        return path;
    }
    let leaked: &'static str = Box::leak(format!("tamper/{name}").into_boxed_str());
    guard.insert(name, leaked);
    leaked
}

fn is_known(selector: &str, known: &[&'static str]) -> bool {
    known.iter().any(|leaf| {
        *leaf == selector
            || (leaf.starts_with(selector) && leaf.as_bytes().get(selector.len()) == Some(&b'/'))
    })
}

/// Render the technique tree as plain text for `wafrift techniques list`.
pub fn render_tree() -> String {
    let mut out = String::new();
    out.push_str("grammar                        (grammar-aware payload mutations)\n");
    out.push_str("encoding\n");
    let mut paths: Vec<&str> = wafrift_encoding::encoding::all_strategies()
        .iter()
        .copied()
        .map(strategy_path)
        .collect();
    paths.sort_unstable();
    for p in paths {
        out.push_str("  ");
        out.push_str(p);
        out.push('\n');
    }
    // Tamper family — surfaced for visibility under `techniques
    // list` even though the tamper application currently runs
    // only inside `wafrift scan`.
    out.push_str("tamper                         (scan-only payload tampers)\n");
    let mut tamper_paths: Vec<String> = wafrift_encoding::tamper::all_tamper_names()
        .iter()
        .map(|n| format!("tamper/{n}"))
        .collect();
    tamper_paths.sort();
    for p in tamper_paths {
        out.push_str("  ");
        out.push_str(&p);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_allows_everything() {
        let f = TechniqueFilter::parse(&[], &[]).expect("parses");
        assert!(f.is_default());
        assert!(f.grammar_enabled());
        assert!(f.allows_strategy(Strategy::DoubleUrlEncode));
        assert!(f.allows_strategy(Strategy::OverlongUtf8));
    }

    #[test]
    fn only_family_keeps_subtree() {
        let f = TechniqueFilter::parse(&["encoding/url".into()], &[]).expect("parses");
        assert!(f.allows_strategy(Strategy::UrlEncode));
        assert!(f.allows_strategy(Strategy::DoubleUrlEncode));
        assert!(!f.allows_strategy(Strategy::OverlongUtf8));
        assert!(!f.grammar_enabled());
    }

    #[test]
    fn exclude_drops_specific_leaf() {
        let f = TechniqueFilter::parse(&[], &["encoding/url/double".into()]).expect("parses");
        assert!(f.allows_strategy(Strategy::UrlEncode));
        assert!(!f.allows_strategy(Strategy::DoubleUrlEncode));
        assert!(f.grammar_enabled());
    }

    #[test]
    fn only_plus_exclude_compose() {
        let f = TechniqueFilter::parse(&["encoding/url".into()], &["encoding/url/triple".into()])
            .expect("parses");
        assert!(f.allows_strategy(Strategy::UrlEncode));
        assert!(f.allows_strategy(Strategy::DoubleUrlEncode));
        assert!(!f.allows_strategy(Strategy::TripleUrlEncode));
    }

    #[test]
    fn exclude_swallowing_only_still_errors() {
        // --only encoding/url/double + --exclude encoding/url should
        // still fail: exclude is the ancestor and drowns only.
        let err = TechniqueFilter::parse(
            &["encoding/url/double".into()],
            &["encoding/url".into()],
        )
        .expect_err("rejected");
        assert!(err.contains("contradictory"), "got: {err}");
    }

    #[test]
    fn exact_match_in_both_lists_still_errors() {
        let err =
            TechniqueFilter::parse(&["encoding/url".into()], &["encoding/url".into()])
                .expect_err("rejected");
        assert!(err.contains("contradictory"), "got: {err}");
    }

    #[test]
    fn unknown_selector_fails_fast() {
        let err =
            TechniqueFilter::parse(&["encoding/totally-bogus".into()], &[]).expect_err("rejected");
        assert!(err.contains("unknown technique selector"));
    }

    #[test]
    fn comma_separated_lists_split() {
        let f =
            TechniqueFilter::parse(&["encoding/url,encoding/unicode".into()], &[]).expect("parses");
        assert!(f.allows_strategy(Strategy::DoubleUrlEncode));
        assert!(f.allows_strategy(Strategy::OverlongUtf8));
        assert!(!f.allows_strategy(Strategy::HtmlEntityEncode));
    }

    #[test]
    fn grammar_family_toggles_independently() {
        let f = TechniqueFilter::parse(&[], &["grammar".into()]).expect("parses");
        assert!(!f.grammar_enabled());
        assert!(f.allows_strategy(Strategy::UrlEncode));
    }

    #[test]
    fn every_strategy_is_mapped() {
        for &s in wafrift_encoding::encoding::all_strategies() {
            let path = strategy_path(s);
            assert_ne!(
                path, "encoding/_unmapped",
                "Strategy::{s:?} has no canonical path; add it to strategy_path()"
            );
        }
    }

    #[test]
    fn all_strategies_have_unique_paths() {
        use std::collections::HashSet;
        let paths: Vec<&str> = wafrift_encoding::encoding::all_strategies()
            .iter()
            .copied()
            .map(strategy_path)
            .collect();
        let unique: HashSet<&&str> = paths.iter().collect();
        assert_eq!(paths.len(), unique.len(), "duplicate path detected");
    }

    // ── Tamper-path wiring (added 2026-05) ─────────────────

    #[test]
    fn tamper_family_selector_is_recognized() {
        // `tamper` as a bare family must be a valid selector — it
        // shouldn't error out with "unknown selector".
        let f = TechniqueFilter::parse(&["tamper".into()], &[]).expect("parses tamper");
        assert!(!f.is_default());
    }

    #[test]
    fn tamper_leaf_selector_is_recognized() {
        // Every registered tamper produces a `tamper/<name>`
        // selector that must validate.
        for &name in wafrift_encoding::tamper::all_tamper_names() {
            let selector = format!("tamper/{name}");
            let f = TechniqueFilter::parse(std::slice::from_ref(&selector), &[])
                .unwrap_or_else(|e| panic!("tamper selector `{selector}` rejected: {e}"));
            assert!(!f.is_default(), "filter must register the selector");
        }
    }

    #[test]
    fn unknown_tamper_leaf_still_fails_fast() {
        // A typo'd selector under the tamper family should still
        // error out rather than silently match nothing.
        let r = TechniqueFilter::parse(&["tamper/nonexistent_tamper".into()], &[]);
        assert!(r.is_err(), "unknown tamper leaf must fail fast");
    }

    #[test]
    fn render_tree_includes_tamper_section() {
        let out = render_tree();
        assert!(
            out.contains("tamper"),
            "render_tree must include tamper family header"
        );
        // Every registered tamper must appear in the rendered output.
        for &name in wafrift_encoding::tamper::all_tamper_names() {
            let needle = format!("tamper/{name}");
            assert!(
                out.contains(&needle),
                "render_tree output must list `{needle}`"
            );
        }
    }

    #[test]
    fn render_tree_groups_have_distinct_headers() {
        let out = render_tree();
        assert!(out.contains("grammar"));
        assert!(out.contains("encoding"));
        assert!(out.contains("tamper"));
        // No accidental duplicate family headers.
        assert_eq!(out.matches("(scan-only payload tampers)").count(), 1);
    }

    #[test]
    fn tamper_paths_are_unique_across_known_set() {
        use std::collections::HashSet;
        let known = all_known_paths();
        let unique: HashSet<&&str> = known.iter().collect();
        assert_eq!(
            known.len(),
            unique.len(),
            "duplicate paths in known set: {known:?}"
        );
    }

    #[test]
    fn frontier_2026_tampers_are_recognised() {
        // Specific guard for the SIX frontier-2026 tampers shipped
        // in this release (keyword_comment_split was removed —
        // see encoding::tamper::tests::obsolete_keyword_comment_split_tamper_was_removed
        // for the parser-correctness rationale).
        for name in [
            "zero_width_inject",
            "postgres_dollar_quote",
            "mysql_versioned_comment_wrap",
            "bracket_confusable",
            "hex_literal_keyword",
            "bell_separator",
        ] {
            let selector = format!("tamper/{name}");
            let f = TechniqueFilter::parse(std::slice::from_ref(&selector), &[]);
            assert!(
                f.is_ok(),
                "frontier 2026 tamper `{selector}` is no longer registered"
            );
        }
    }

    #[test]
    fn tamper_path_static_caches_lookups() {
        // Internal property: calling tamper_path_static twice with
        // the same name returns the exact same `&'static str` (no
        // re-leak per call).  This keeps the leak bounded.
        let a = tamper_path_static("zero_width_inject");
        let b = tamper_path_static("zero_width_inject");
        assert_eq!(a.as_ptr(), b.as_ptr(), "tamper-path cache leaked twice");
    }
}
