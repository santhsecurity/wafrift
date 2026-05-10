//! URL / query-string payload mutation — opt-in attack surface for
//! the proxy `--mutate-url` flag and the strategy engine's URL-aware
//! evade variants.
//!
//! Most production attacks live in the URL, not the request body:
//! `?id=1' OR 1=1--`, `?q=<script>alert(1)</script>`,
//! `?file=../../etc/passwd`. The default proxy pipeline only mutates
//! HTTP-layer artefacts (headers, body) which leaves this surface
//! uncovered. This module fills that gap when the operator opts in.
//!
//! Scope:
//! - mutates query parameter VALUES (not names — those drive routing)
//! - optionally mutates the path's last segment (rest is routing)
//! - never touches the host / scheme / port — those are pre-routing
//! - returns the URL unchanged when no `?` is present and path
//!   mutation is disabled
//!
//! Mutation strategies are intentionally a small fixed set chosen to
//! be effective against signature WAFs without requiring the heavier
//! grammar/encoding pipeline. Callers that want full pipeline
//! mutation should round-trip through `wafrift_strategy::evade` with
//! the parameter value lifted into the request body.

use std::borrow::Cow;

/// Knobs for [`mutate_url`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlMutateConfig {
    /// Mutate the query string. Default true.
    pub mutate_query_values: bool,
    /// Mutate the path's last segment (everything after the last `/`).
    /// Default false — disabled because changing path semantics is
    /// likely to break routing on most targets.
    pub mutate_last_path_segment: bool,
    /// Strategy to apply per value.
    pub strategy: UrlStrategy,
}

impl Default for UrlMutateConfig {
    fn default() -> Self {
        Self {
            mutate_query_values: true,
            mutate_last_path_segment: false,
            strategy: UrlStrategy::PercentEncodeAggressive,
        }
    }
}

/// Per-value mutation choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlStrategy {
    /// Percent-encode every byte that isn't alphanumeric. Most signatures
    /// match decoded payloads but verify by raw-byte regex — this
    /// breaks both checks at once.
    PercentEncodeAggressive,
    /// Double-percent-encode (`%` → `%25`, then percent-encode again).
    /// Bypasses URL-decode-then-match WAFs that decode exactly once.
    DoublePercentEncode,
    /// Mix in `+` for spaces, `0x2F` for `/`, etc. — non-canonical
    /// encodings that some upstream parsers normalise but signatures
    /// don't.
    NonCanonicalSpaces,
    /// Insert empty PHP-style array brackets `[]` after the param name
    /// to force HTTP Parameter Pollution path. Only meaningful when
    /// the *name* needs to change; otherwise no-op.
    Hpp,
}

impl UrlStrategy {
    /// Apply the strategy to a single decoded value, returning the
    /// mutated raw form (already URL-safe — caller does not re-encode).
    #[must_use]
    pub fn apply(self, value: &str) -> String {
        match self {
            Self::PercentEncodeAggressive => percent_encode_aggressive(value),
            Self::DoublePercentEncode => percent_encode_aggressive(&percent_encode_aggressive(value)),
            Self::NonCanonicalSpaces => non_canonical_spaces(value),
            Self::Hpp => value.to_string(),
        }
    }

    /// Stable name used for technique logging.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PercentEncodeAggressive => "url:percent_encode",
            Self::DoublePercentEncode => "url:double_percent",
            Self::NonCanonicalSpaces => "url:noncanon_spaces",
            Self::Hpp => "url:hpp",
        }
    }
}

/// Mutate `path_and_query` (no scheme/host) per `cfg`. Returns the
/// mutated string and a list of technique labels actually applied.
///
/// Inputs are accepted in either form:
///   `/path/segment?a=1&b=2`
///   `/path/segment`            (no query — query mutation is a no-op)
///   `?a=1`                     (no path — path mutation is a no-op)
///
/// Never panics, never returns empty for non-empty input.
#[must_use]
pub fn mutate_url(path_and_query: &str, cfg: &UrlMutateConfig) -> (String, Vec<&'static str>) {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (path_and_query.to_string(), None),
    };
    let mut techniques: Vec<&'static str> = Vec::new();

    let new_path = if cfg.mutate_last_path_segment {
        match mutate_last_segment(&path, cfg.strategy) {
            Some(p) => {
                techniques.push("url:path_segment");
                techniques.push(cfg.strategy.label());
                p
            }
            None => path,
        }
    } else {
        path
    };

    let new_query = if cfg.mutate_query_values {
        if let Some(q) = query.as_ref() {
            let (mq, applied) = mutate_query_string(q, cfg.strategy);
            if applied {
                techniques.push("url:query_values");
                techniques.push(cfg.strategy.label());
            }
            Some(mq)
        } else {
            query
        }
    } else {
        query
    };

    let result = match new_query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    (result, techniques)
}

fn mutate_last_segment(path: &str, strategy: UrlStrategy) -> Option<String> {
    let last_slash = path.rfind('/')?;
    let (head, tail) = path.split_at(last_slash + 1);
    if tail.is_empty() {
        return None;
    }
    let mutated = strategy.apply(tail);
    Some(format!("{head}{mutated}"))
}

/// Mutate every `name=value` pair, leaving `name` alone and mutating
/// `value`. Pairs without `=` (bare flags) are passed through.
fn mutate_query_string(query: &str, strategy: UrlStrategy) -> (String, bool) {
    let mut out = Vec::with_capacity(8);
    let mut applied = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((name, value)) = pair.split_once('=') {
            if value.is_empty() {
                out.push(format!("{name}="));
                continue;
            }
            let decoded = percent_decode_lossy(value);
            let mutated = strategy.apply(&decoded);
            out.push(format!("{name}={mutated}"));
            applied = true;
        } else {
            out.push(pair.to_string());
        }
    }
    (out.join("&"), applied)
}

/// Aggressive percent-encoding: every byte that is not `[A-Za-z0-9]`
/// is encoded. Drops the URL safe-list (`-._~`) intentionally — those
/// are the bytes signatures most often fail to canonicalise.
fn percent_encode_aggressive(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn non_canonical_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        match ch {
            ' ' => out.push('+'),
            '/' => out.push_str("%2F"),
            '\\' => out.push_str("%5C"),
            '<' => out.push_str("%3C"),
            '>' => out.push_str("%3E"),
            '\'' => out.push_str("%27"),
            '"' => out.push_str("%22"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            other => out.push(other),
        }
    }
    out
}

/// Decode `%xx` escapes lossily, treating invalid sequences as
/// literal. Returns `Cow::Borrowed` when nothing needed decoding.
fn percent_decode_lossy(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                hex_digit(bytes[i + 1]),
                hex_digit(bytes[i + 2]),
            )
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(strategy: UrlStrategy, mutate_path: bool) -> UrlMutateConfig {
        UrlMutateConfig {
            mutate_query_values: true,
            mutate_last_path_segment: mutate_path,
            strategy,
        }
    }

    // ── default-OFF semantics ──────────────────────────────────

    #[test]
    fn default_config_does_not_touch_path() {
        let c = UrlMutateConfig::default();
        assert!(!c.mutate_last_path_segment);
        let (out, _) = mutate_url("/admin/login?id=1", &c);
        assert!(out.starts_with("/admin/login?"), "path must stay verbatim, got {out}");
    }

    #[test]
    fn no_query_no_path_mutation_returns_input_unchanged() {
        let c = UrlMutateConfig::default();
        let (out, techniques) = mutate_url("/just/a/path", &c);
        assert_eq!(out, "/just/a/path");
        assert!(techniques.is_empty(), "no mutation must report no technique");
    }

    #[test]
    fn empty_value_pair_passes_through_unmutated() {
        let c = UrlMutateConfig::default();
        let (out, _) = mutate_url("/p?a=&b=2", &c);
        assert!(out.contains("a=&"), "empty value must stay empty");
    }

    #[test]
    fn bare_flag_param_passes_through() {
        let c = UrlMutateConfig::default();
        let (out, _) = mutate_url("/p?flag&other=1", &c);
        assert!(out.contains("flag&"));
    }

    // ── per-strategy correctness ───────────────────────────────

    #[test]
    fn percent_encode_aggressive_encodes_quotes_and_spaces() {
        let c = cfg(UrlStrategy::PercentEncodeAggressive, false);
        let (out, t) = mutate_url("/p?id=1' OR '1'='1", &c);
        // Every non-alphanumeric must be encoded.
        assert!(out.contains("id=1%27%20OR%20%271%27%3D%271"), "got {out}");
        assert!(t.contains(&"url:percent_encode"));
        assert!(t.contains(&"url:query_values"));
    }

    #[test]
    fn percent_encode_aggressive_skips_alphanumerics() {
        let c = cfg(UrlStrategy::PercentEncodeAggressive, false);
        let (out, _) = mutate_url("/p?q=ABCxyz123", &c);
        assert!(out.ends_with("q=ABCxyz123"), "alnum must not be encoded; got {out}");
    }

    #[test]
    fn double_percent_encode_doubles_each_byte() {
        let c = cfg(UrlStrategy::DoublePercentEncode, false);
        let (out, _) = mutate_url("/p?id='", &c);
        // "'" → %27 → %2527
        assert!(out.contains("id=%2527"), "got {out}");
    }

    #[test]
    fn non_canonical_spaces_swaps_known_chars() {
        let c = cfg(UrlStrategy::NonCanonicalSpaces, false);
        let (out, _) = mutate_url("/p?q=hello world<", &c);
        assert!(out.contains("q=hello+world%3C"), "got {out}");
    }

    // ── path-segment mutation ──────────────────────────────────

    #[test]
    fn path_segment_mutation_changes_last_segment_only_when_enabled() {
        let c = cfg(UrlStrategy::PercentEncodeAggressive, true);
        // Tail contains `.` (non-alphanumeric) so the strategy bites.
        let (out, t) = mutate_url("/api/v1/admin.php", &c);
        assert!(out.starts_with("/api/v1/"), "head must stay; got {out}");
        assert_ne!(out, "/api/v1/admin.php", "tail must change; got {out}");
        assert!(out.contains("admin%2Ephp"), "dot must be percent-encoded; got {out}");
        assert!(t.contains(&"url:path_segment"));
    }

    #[test]
    fn path_with_trailing_slash_is_not_mutated() {
        let c = cfg(UrlStrategy::PercentEncodeAggressive, true);
        let (out, t) = mutate_url("/api/v1/admin/", &c);
        // Empty tail after the trailing `/` → no mutation
        assert_eq!(out, "/api/v1/admin/");
        assert!(t.is_empty());
    }

    // ── round-tripping pre-encoded input ──────────────────────

    #[test]
    fn pre_encoded_query_value_is_decoded_then_re_mutated() {
        // Operator's input is `%27` (encoded `'`); we should decode
        // first and then apply the strategy so we don't end up
        // double-encoding accidentally on PercentEncodeAggressive.
        let c = cfg(UrlStrategy::PercentEncodeAggressive, false);
        let (out, _) = mutate_url("/p?q=%27OR%27", &c);
        // Decoded: `'OR'` → re-aggressive-encoded: `%27OR%27`
        assert!(out.contains("q=%27OR%27"));
    }

    // ── adversarial / robustness ──────────────────────────────

    #[test]
    fn does_not_panic_on_invalid_percent_escape() {
        let c = UrlMutateConfig::default();
        // %ZZ is invalid — must be treated as literal `%ZZ`
        let _ = mutate_url("/p?q=%ZZbad", &c);
    }

    #[test]
    fn does_not_panic_on_empty_input() {
        let c = UrlMutateConfig::default();
        let (out, _) = mutate_url("", &c);
        assert_eq!(out, "");
    }

    #[test]
    fn does_not_panic_on_trailing_question_mark() {
        let c = UrlMutateConfig::default();
        let (out, _) = mutate_url("/p?", &c);
        assert_eq!(out, "/p?");
    }

    #[test]
    fn handles_extremely_long_value() {
        let c = UrlMutateConfig::default();
        let long = "A".repeat(50_000);
        let (out, _) = mutate_url(&format!("/p?q={long}"), &c);
        // Alphanumeric → unchanged (50K A's)
        assert!(out.ends_with(&long), "alnum long string must pass through");
    }

    #[test]
    fn multiple_pairs_each_get_mutated_independently() {
        let c = cfg(UrlStrategy::PercentEncodeAggressive, false);
        let (out, _) = mutate_url("/p?a=1'&b=2\"&c=3", &c);
        assert!(out.contains("a=1%27"));
        assert!(out.contains("b=2%22"));
        assert!(out.contains("c=3"));
    }

    #[test]
    fn query_value_containing_equals_preserves_extra_equals() {
        let c = UrlMutateConfig::default();
        // `?key=base64==` is common (b64 padding)
        let (out, _) = mutate_url("/p?key=b64==", &c);
        // First `=` is the separator; "b64==" is the value
        assert!(out.starts_with("/p?key="));
    }
}
