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
const KNOWN_FAMILIES: &[&str] = &["encoding", "grammar"];

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
    for s in wafrift_encoding::encoding::all_strategies() {
        paths.push(strategy_path(s));
    }
    paths
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
        .into_iter()
        .map(strategy_path)
        .collect();
    paths.sort_unstable();
    for p in paths {
        out.push_str("  ");
        out.push_str(p);
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
        for s in wafrift_encoding::encoding::all_strategies() {
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
            .into_iter()
            .map(strategy_path)
            .collect();
        let unique: HashSet<&&str> = paths.iter().collect();
        assert_eq!(paths.len(), unique.len(), "duplicate path detected");
    }
}
