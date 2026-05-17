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

/// Hard cap on the input size accepted by [`UrlStrategy::DoublePercentEncode`].
/// Two passes of aggressive percent-encoding can produce up to ~9×
/// the input length, so an unbounded input is a `DoS` vector. Real WAF
/// values are kilobytes at most; 1 MB is generous.
pub const MAX_DOUBLE_ENCODE_INPUT: usize = 1024 * 1024;

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
    /// to force HTTP Parameter Pollution path.
    ///
    /// **Audit (2026-05-10): NOT YET IMPLEMENTED.** `apply_bytes` only
    /// receives the value — the (name, value) pair lives one layer up
    /// in `mutate_query_string`. The current behaviour is a value
    /// pass-through, which is a stub. Selecting this strategy will
    /// log a `tracing::warn` but otherwise return the value unchanged
    /// so existing callers don't break. Real HPP needs a query-level
    /// mutator that operates on the pair list — track via a dedicated
    /// `query_pollute_pairs()` function rather than as a `UrlStrategy`
    /// variant.
    Hpp,
}

impl UrlStrategy {
    /// Apply the strategy to a single decoded value, returning the
    /// mutated raw form (already URL-safe — caller does not re-encode).
    #[must_use]
    pub fn apply(self, value: &str) -> String {
        self.apply_bytes(value.as_bytes())
    }

    /// Byte-clean variant of [`Self::apply`] for percent-encoding
    /// strategies. Lets callers run a non-UTF-8 byte sequence (e.g.
    /// the raw bytes from a percent-decode on `%FF%FE`) through the
    /// pipeline without it being silently rewritten to U+FFFD by
    /// `String::from_utf8_lossy`. Each strategy that only operates
    /// on bytes (`PercentEncodeAggressive`, `DoublePercentEncode`) is
    /// byte-pure here. Strategies that need character semantics
    /// (`NonCanonicalSpaces`) lossy-convert internally.
    #[must_use]
    pub fn apply_bytes(self, value: &[u8]) -> String {
        self.apply_bytes_with_label(value).0
    }

    /// Apply the strategy and return BOTH the encoded output AND the
    /// label that honestly describes what was done. For most strategies
    /// this is just `Self::label()`, but `DoublePercentEncode` silently
    /// downgrades to single-percent encoding above `MAX_DOUBLE_ENCODE_INPUT`
    /// (to avoid 9× output blowup) — pre-fix the technique log still
    /// reported `url:double_percent` even though only one pass ran,
    /// poisoning every WAF-decay statistic. Now the downgrade is
    /// surfaced via `url:double_percent_downgraded` so callers (and
    /// the gene-bank) see what actually shipped.
    ///
    /// Audit (2026-05-10).
    #[must_use]
    pub fn apply_bytes_with_label(self, value: &[u8]) -> (String, &'static str) {
        match self {
            Self::PercentEncodeAggressive => (
                percent_encode_aggressive_bytes(value),
                "url:percent_encode",
            ),
            Self::DoublePercentEncode => {
                // Two passes of aggressive percent-encoding can blow
                // up to roughly 9× the input size on worst-case
                // inputs (every byte → %XX → %25%XX). Cap the input
                // so a malicious caller can't OOM via a 100 MB
                // string asking for 900 MB of output.
                if value.len() > MAX_DOUBLE_ENCODE_INPUT {
                    return (
                        percent_encode_aggressive_bytes(value),
                        "url:double_percent_downgraded",
                    );
                }
                let first = percent_encode_aggressive_bytes(value);
                (
                    percent_encode_aggressive_bytes(first.as_bytes()),
                    "url:double_percent",
                )
            }
            Self::NonCanonicalSpaces => {
                let s = String::from_utf8_lossy(value);
                (non_canonical_spaces(&s), "url:noncanon_spaces")
            }
            Self::Hpp => {
                // Honest no-op label so the technique log doesn't claim
                // HPP was applied. See the Hpp variant docstring for
                // the architectural fix path.
                if std::str::from_utf8(value).is_err() {
                    // Lossy convert with a warn — a non-UTF-8 value
                    // would have been silently U+FFFD'd before.
                    tracing::warn!(
                        bytes = value.len(),
                        "UrlStrategy::Hpp dropped non-UTF-8 bytes; HPP transform NOT YET IMPLEMENTED"
                    );
                }
                (
                    String::from_utf8_lossy(value).into_owned(),
                    "url:hpp_unimplemented",
                )
            }
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
///   `/path?a=1#frag`           (fragment preserved verbatim)
///
/// Never panics, never returns empty for non-empty input.
#[must_use]
pub fn mutate_url(path_and_query: &str, cfg: &UrlMutateConfig) -> (String, Vec<&'static str>) {
    // Reject full URLs (with scheme://host/...) at the boundary —
    // mutate_url's contract is "path-and-query only". Pre-fix a full
    // URL got split on '?' such that the scheme + host leaked into
    // the "path" and got mutated, e.g. `https://example.com/p?q=1`
    // had `https://example.com/p` percent-encoded as the last path
    // segment. The caller almost certainly meant to pass the
    // path-and-query directly; pass-through is the safe behaviour.
    if path_and_query.starts_with("http://")
        || path_and_query.starts_with("https://")
        || path_and_query.starts_with("//")
    {
        return (path_and_query.to_string(), Vec::new());
    }

    // Split off any #fragment FIRST so query mutation can't encode the
    // '#' delimiter and destroy fragment routing. Pre-fix the
    // mutator turned `/p?q=1#frag` into `/p?q=1%23frag`, which the
    // upstream then treated as a single (broken) query value.
    let (without_frag, fragment) = match path_and_query.split_once('#') {
        Some((rest, frag)) => (rest, Some(frag)),
        None => (path_and_query, None),
    };

    let (path, query) = match without_frag.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (without_frag.to_string(), None),
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
            let (mq, label) = mutate_query_string(q, cfg.strategy);
            if let Some(honest_label) = label {
                techniques.push("url:query_values");
                // Use the honest label returned by apply_bytes_with_label
                // (may be a "_downgraded" variant) instead of the
                // nominal cfg.strategy.label(). Audit (2026-05-10).
                techniques.push(honest_label);
            }
            Some(mq)
        } else {
            query
        }
    } else {
        query
    };

    let mut result = match new_query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    if let Some(frag) = fragment {
        result.push('#');
        result.push_str(frag);
    }
    (result, techniques)
}

fn mutate_last_segment(path: &str, strategy: UrlStrategy) -> Option<String> {
    // Treat both literal '/' and percent-encoded slash (%2F or %2f)
    // as segment boundaries — otherwise an attacker who pre-encodes
    // a slash inside what looks like the last segment (e.g.
    // /a/b%2Fc) would have the WHOLE tail (b%2Fc) mutated, when the
    // logical last segment is `c`.
    let normalized_last_slash = {
        let lit = path.rfind('/');
        let pct_upper = path.rfind("%2F").map(|i| i + 2);
        let pct_lower = path.rfind("%2f").map(|i| i + 2);
        [lit, pct_upper, pct_lower].into_iter().flatten().max()?
    };
    let (head, tail) = path.split_at(normalized_last_slash + 1);
    if tail.is_empty() {
        return None;
    }
    // Decode pre-existing percent escapes BEFORE re-applying the
    // mutation strategy, into raw bytes (NOT through from_utf8_lossy)
    // so that `%FF%FE` and other non-UTF-8 byte sequences survive
    // the round-trip instead of being silently mangled into U+FFFD
    // sequences (`%EF%BF%BD`).
    let decoded = percent_decode_bytes(tail);
    let mutated = strategy.apply_bytes(&decoded);
    Some(format!("{head}{mutated}"))
}

/// Mutate every `name=value` pair, leaving `name` alone and mutating
/// `value`. Pairs without `=` (bare flags) are passed through.
///
/// Empty pairs (consecutive `&&` separators) are PRESERVED rather
/// than collapsed — some upstream frameworks (e.g. PHP, Rails 5+)
/// treat them as distinct empty parameters, so collapsing changes
/// the parsed parameter count.
///
/// `+` in a query value is interpreted as space per RFC 1866 form
/// encoding before the strategy is applied — otherwise `q=1+1`
/// would be mutated as if `+` were a literal plus sign.
/// Returns `(mutated_query, Some(honest_label))` if any pair was
/// mutated, or `(unchanged_query, None)` if not. The label tracks
/// per-input downgrades — e.g. `DoublePercentEncode` on an oversize
/// input returns `"url:double_percent_downgraded"` instead of the
/// nominal `"url:double_percent"`. Audit (2026-05-10).
fn mutate_query_string(query: &str, strategy: UrlStrategy) -> (String, Option<&'static str>) {
    let mut out = Vec::with_capacity(8);
    let mut last_label: Option<&'static str> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            out.push(String::new());
            continue;
        }
        if let Some((name, value)) = pair.split_once('=') {
            if value.is_empty() {
                out.push(format!("{name}="));
                continue;
            }
            let form_decoded = value.replace('+', " ");
            let decoded = percent_decode_bytes(&form_decoded);
            let (mutated, label) = strategy.apply_bytes_with_label(&decoded);
            let is_mutation = mutated.as_bytes() != value.as_bytes();
            let is_honest_noop = label.contains("unimplemented");
            if is_mutation || is_honest_noop {
                // If different inputs in the same query produce
                // different labels (one downgraded, others not),
                // PREFER the downgraded one — operators care most
                // about the worst case.
                if last_label
                    .is_none_or(|l| !l.contains("downgraded"))
                {
                    last_label = Some(label);
                }
            }
            out.push(format!("{name}={mutated}"));
        } else {
            out.push(pair.to_string());
        }
    }
    (out.join("&"), last_label)
}

/// Aggressive percent-encoding: every byte that is not `[A-Za-z0-9]`
/// is encoded. Drops the URL safe-list (`-._~`) intentionally — those
/// are the bytes signatures most often fail to canonicalise.
#[allow(dead_code)]
fn percent_encode_aggressive(s: &str) -> String {
    percent_encode_aggressive_bytes(s.as_bytes())
}

/// Byte-clean variant of [`percent_encode_aggressive`]. Used by the
/// byte-pipeline paths so non-UTF-8 input bytes (which a real
/// `%FF%FE`-style WAF-bypass payload contains) survive end-to-end
/// instead of being silently rewritten to U+FFFD.
fn percent_encode_aggressive_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for &b in bytes {
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
    // saturating_mul to avoid usize overflow on 32-bit targets when
    // someone hands us a ~2 GB string.
    let mut out = String::with_capacity(s.len().saturating_mul(3));
    // Pre-fix the `_ => out.push(other)` arm passed through `&`, `=`,
    // `%`, `#`, `+`, `?`, `\0`, control chars, etc. After percent-decode
    // had already turned `%26c%3Devil` into the literal bytes `&c=evil`,
    // this re-emitted them verbatim and the server then split the value
    // on `&` and `=` into THREE pairs — HTTP parameter injection. The
    // audit caught this as CRITICAL.
    //
    // Fix: percent-encode every byte that would be parsed as URL/form
    // structure or as an ASCII control. The cosmetic substitutions above
    // (` `→`+`, `/`→`%2F`, etc.) are kept for the WAF-bypass shape; the
    // dangerous bytes get the standard `%XX` form.
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
            // Structural URL / form delimiters — must always be encoded
            // so they cannot escape the value into a sibling pair.
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '%' => out.push_str("%25"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '+' => out.push_str("%2B"),
            ';' => out.push_str("%3B"),
            // Control chars (incl. NUL): %XX-encode exactly.
            other if (other as u32) < 0x20 || other as u32 == 0x7F => {
                use std::fmt::Write;
                let _ = write!(&mut out, "%{:02X}", other as u32);
            }
            other => out.push(other),
        }
    }
    out
}

/// Decode `%xx` escapes into raw bytes, treating invalid sequences
/// (lone `%`, `%G1`) as literal. Unlike [`percent_decode_lossy`],
/// this never round-trips through `from_utf8_lossy` so non-UTF-8
/// byte sequences (e.g. `%FF%FE`, overlong UTF-8 `%C0%AF`) survive
/// intact. The downstream encoders re-emit them as exact `%XX`
/// pairs instead of mangling them into `%EF%BF%BD` (U+FFFD), which
/// is what removes WAF-bypass vectors.
fn percent_decode_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Decode `%xx` escapes lossily, treating invalid sequences as
/// literal. Returns `Cow::Borrowed` when nothing needed decoding.
#[allow(dead_code)]
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
            && let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
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
        assert!(
            out.starts_with("/admin/login?"),
            "path must stay verbatim, got {out}"
        );
    }

    #[test]
    fn no_query_no_path_mutation_returns_input_unchanged() {
        let c = UrlMutateConfig::default();
        let (out, techniques) = mutate_url("/just/a/path", &c);
        assert_eq!(out, "/just/a/path");
        assert!(
            techniques.is_empty(),
            "no mutation must report no technique"
        );
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
        assert!(
            out.ends_with("q=ABCxyz123"),
            "alnum must not be encoded; got {out}"
        );
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
        assert!(
            out.contains("admin%2Ephp"),
            "dot must be percent-encoded; got {out}"
        );
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

    // ── HPP stub (NOT YET IMPLEMENTED) ────────────────────────

    #[test]
    fn hpp_strategy_is_honest_no_op() {
        // The Hpp variant is architecturally stubbed — it operates on
        // values but real HPP needs query-pair-level mutation. Verify
        // the honest no-op: value passes through unchanged and the
        // technique log reports `url:hpp_unimplemented`.
        let c = cfg(UrlStrategy::Hpp, false);
        let (out, t) = mutate_url("/p?q=test", &c);
        assert_eq!(out, "/p?q=test", "HPP stub must pass value through");
        assert!(
            t.contains(&"url:hpp_unimplemented"),
            "stub must report url:hpp_unimplemented, got {t:?}"
        );
    }

    #[test]
    fn hpp_strategy_label_is_stable() {
        assert_eq!(UrlStrategy::Hpp.label(), "url:hpp");
    }
}
