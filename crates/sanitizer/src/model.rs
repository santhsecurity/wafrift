//! Sanitizer behaviour model + the [`WafOracle`] adapter the learner drives.
//!
//! [`SanitizerModel`] describes *what* a
//! sanitizer allows and forbids; this module makes it *executable*:
//! [`SanitizerModel::sanitize`] simulates the sanitizer on an input string, and
//! [`SanitizerOracle`] wraps that simulation in the [`WafOracle`] contract so the
//! exact L*/SFA machinery that decompiles a server WAF can decompile a client
//! sanitizer. The membership question is the dual of the WAF's: **does an
//! executable XSS vector survive sanitization?** `Pass` = a bypass survived,
//! `Block` = the sanitizer neutralised it.
//!
//! Soundness: the simulation models the *common, real* matching semantics
//! (tag-name matching is case-insensitive, as DOMPurify/sanitize-html lowercase
//! before comparison), so a "bypass" it reports is a genuine structural gap in
//! the sanitizer's configuration (e.g. "forbids `script` but not `svg`+`onload`"),
//! not an artefact of a sloppy model. Every candidate is still flagged for live
//! scald DOM confirmation — never asserted as executed here.

use regex::Regex;
use std::sync::OnceLock;

use wafrift_types::Request;
use wafrift_wafmodel::{Outcome, Result as WafResult, WafOracle};

use crate::extract::SanitizerModel;

/// `<...>` tag matcher. Matches a complete `<...>` tag OR an **unterminated**
/// `<...` run at end-of-input: a real HTML parser (and DOMPurify) starts a tag on
/// a trailing `<script` even with no closing `>`, so the model must scrub it too
/// — otherwise a script-forbidding config would falsely "leak" a bare `<script`
/// (a fabricated bypass). A lone `<` in benign text still matches but carries an
/// empty tag name, so `scrub_tag` keeps it untouched.
fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]*(?:>|$)").expect("tag regex"))
}

/// An `on*=` event-handler attribute inside a tag value. The separator before
/// `on` is `[\s/]`: HTML treats `/` as an attribute separator, so `<svg/onload=>`
/// executes exactly like `<svg onload=>` and a real sanitizer strips both.
fn handler_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)[\s/]on[a-z0-9_]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)"#)
            .expect("handler regex")
    })
}

/// An executable event handler still present on a surviving tag (whitespace- or
/// slash-separated, matching real HTML attribute parsing).
fn exec_handler_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)<[a-z][^>]*[\s/]on[a-z0-9_]+\s*="#).expect("exec handler regex")
    })
}

/// Translate a JS regex source into something Rust's `regex` crate accepts,
/// best-effort. JS-only constructs (lookbehind, etc.) make `Regex::new` fail and
/// the caller skips that strip pattern — never a panic, never an unsound match.
fn js_to_rust_regex(src: &str) -> String {
    // `\/` (escaped slash, required in JS literals) is just `/` in Rust.
    src.replace("\\/", "/")
}

impl SanitizerModel {
    /// Is `tag_name` (already lowercased) permitted to survive?
    fn tag_allowed(&self, tag_name_lc: &str) -> bool {
        if self
            .forbidden_tags
            .iter()
            .any(|t| t.eq_ignore_ascii_case(tag_name_lc))
        {
            return false;
        }
        match &self.allowed_tags {
            Some(allow) => allow.iter().any(|t| t.eq_ignore_ascii_case(tag_name_lc)),
            None => true,
        }
    }

    /// Public reachability check: would a `<tag>` survive this sanitizer's
    /// allow/deny model? `true` means the tag is not forbidden and (if an
    /// allowlist exists) is on it. Used by [`crate::mxss`] to decide whether an
    /// mXSS trigger combination is reachable under the recovered config.
    #[must_use]
    pub fn tag_reachable(&self, tag: &str) -> bool {
        self.tag_allowed(&tag.to_ascii_lowercase())
    }

    /// Clean a single `<...>` tag: drop it entirely if its name is forbidden /
    /// not allowlisted; otherwise strip event handlers and neutralise blocked
    /// schemes within it, per the model.
    fn scrub_tag(&self, tag: &str) -> String {
        let name = tag_name_of(tag);
        let name_lc = name.to_ascii_lowercase();
        if !name_lc.is_empty() && !self.tag_allowed(&name_lc) {
            return String::new();
        }
        let mut cleaned = tag.to_string();
        if self.strips_event_handlers {
            cleaned = handler_re().replace_all(&cleaned, "").into_owned();
        }
        for scheme in &self.blocked_schemes {
            cleaned = neutralize_scheme(&cleaned, scheme);
        }
        cleaned
    }

    /// Compile this model's `strip_patterns` once. The membership hot path (the
    /// L*/SFA learner issues up to the per-round query budget of calls) must not
    /// recompile the same regexes on every query — doing so once turned a strict,
    /// no-bypass model carrying a single extracted strip regex into a multi-minute
    /// hang. Patterns that don't translate to Rust's `regex` engine are dropped;
    /// a dropped strip can only *keep* more of the input, so the model errs toward
    /// reporting a bypass (the sound direction — scald confirms in a real browser).
    #[must_use]
    pub fn compiled_strip_patterns(&self) -> Vec<Regex> {
        self.strip_patterns
            .iter()
            .filter_map(|pat| Regex::new(&js_to_rust_regex(pat)).ok())
            .collect()
    }

    /// Simulate the sanitizer on `input` using a pre-compiled strip-pattern set —
    /// the hot path ([`SanitizerOracle`]) compiles once and calls this per query.
    #[must_use]
    pub fn sanitize_with(&self, input: &str, strip_res: &[Regex]) -> String {
        let scrubbed =
            tag_re().replace_all(input, |caps: &regex::Captures| self.scrub_tag(&caps[0]));
        let mut out = scrubbed.into_owned();
        for re in strip_res {
            out = re.replace_all(&out, "").into_owned();
        }
        out
    }

    /// Simulate the sanitizer on `input`, returning the sanitized HTML. Compiles
    /// the strip patterns on the fly — fine for one-off calls; a learner's hot
    /// loop must use [`sanitize_with`](Self::sanitize_with) with a cached set.
    #[must_use]
    pub fn sanitize(&self, input: &str) -> String {
        self.sanitize_with(input, &self.compiled_strip_patterns())
    }

    /// Does an executable XSS vector survive sanitization of `input`? This is the
    /// oracle's membership predicate: `true` ⇒ a bypass survived.
    #[must_use]
    pub fn survives_executable(&self, input: &str) -> bool {
        is_executable_html(&self.sanitize(input))
    }

    /// [`survives_executable`](Self::survives_executable) with a pre-compiled
    /// strip set, for the membership hot path.
    #[must_use]
    pub fn survives_executable_with(&self, input: &str, strip_res: &[Regex]) -> bool {
        is_executable_html(&self.sanitize_with(input, strip_res))
    }
}

/// Lowercased tag name of a `<...>`/`</...>` token (empty if none).
fn tag_name_of(tag: &str) -> String {
    let inner = tag.trim_start_matches('<').trim_start_matches('/');
    inner
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Neutralise a dangerous URL scheme inside a tag by breaking its `:` so a
/// browser no longer parses it as that scheme. Models DOMPurify/sanitize-html
/// dropping `javascript:`/`data:` URLs.
fn neutralize_scheme(tag: &str, scheme: &str) -> String {
    // Case-insensitive replace of `scheme:` with a defanged form.
    let needle = format!("{scheme}:");
    let lower = tag.to_ascii_lowercase();
    let mut out = String::with_capacity(tag.len());
    let mut i = 0;
    while i < tag.len() {
        if lower[i..].starts_with(&needle) {
            out.push_str(&tag[i..i + scheme.len()]);
            out.push_str("%3a"); // defanged colon — no longer a live scheme
            i += needle.len();
        } else {
            // Advance one char (UTF-8 safe).
            let ch = tag[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Does `html` still carry a live, executable XSS vector in a markup sink? We
/// judge executability on the two **unambiguous** markup vectors — a surviving
/// `<script>` tag and a surviving `on*=` event handler on a tag. URL-scheme
/// execution (`javascript:` in `href`) depends on the specific tag/sink and is
/// modelled separately by defanging (`neutralize_scheme`) in `sanitize`; treating
/// a bare `javascript:` string as executable here would over-report (plain text
/// `javascript:` and `<b href=javascript:>` are both inert). scald confirms the
/// scheme vectors in a real browser; this detector stays sound by construction.
#[must_use]
pub fn is_executable_html(html: &str) -> bool {
    // A surviving <script> tag.
    if html.to_ascii_lowercase().contains("<script") {
        return true;
    }
    // A surviving event-handler attribute on any tag.
    exec_handler_re().is_match(html)
}

/// The [`WafOracle`] view of a sanitizer: classify a candidate input by whether
/// an executable vector survives the modelled sanitizer. `Pass` is a *bypass*.
#[derive(Debug, Clone)]
pub struct SanitizerOracle {
    model: SanitizerModel,
    /// Strip-pattern regexes compiled once at construction. The membership hot
    /// path must not recompile them per query — per-call `Regex::new` over a
    /// strict model's extracted strip regex was the multi-minute-hang root cause.
    strip_res: Vec<Regex>,
    queries: u64,
}

impl SanitizerOracle {
    /// Wrap an extracted model as a membership oracle, compiling its strip
    /// patterns once for the hot membership loop.
    #[must_use]
    pub fn new(model: SanitizerModel) -> Self {
        let strip_res = model.compiled_strip_patterns();
        Self {
            model,
            strip_res,
            queries: 0,
        }
    }

    /// The model being decompiled.
    #[must_use]
    pub fn model(&self) -> &SanitizerModel {
        &self.model
    }
}

impl WafOracle for SanitizerOracle {
    fn classify(&mut self, req: &Request) -> WafResult<Outcome> {
        self.queries += 1;
        let input = req
            .body_bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        Ok(
            if self.model.survives_executable_with(&input, &self.strip_res) {
                Outcome::Pass // an executable vector survived ⇒ bypass
            } else {
                Outcome::Block // sanitized away
            },
        )
    }

    fn queries(&self) -> u64 {
        self.queries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{SanitizerKind, SanitizerModel};

    fn dompurify(
        forbidden: &[&str],
        allowed: Option<&[&str]>,
        strip_handlers: bool,
    ) -> SanitizerModel {
        SanitizerModel {
            kind: SanitizerKind::DomPurify,
            allowed_tags: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
            forbidden_tags: forbidden.iter().map(|s| s.to_string()).collect(),
            forbidden_attrs: Vec::new(),
            strips_event_handlers: strip_handlers,
            blocked_schemes: Vec::new(),
            strip_patterns: Vec::new(),
            evidence: Vec::new(),
        }
    }

    // ── sanitize() ────────────────────────────────────────────────────────

    #[test]
    fn forbidden_script_tag_is_dropped() {
        let m = dompurify(&["script"], None, false);
        assert_eq!(m.sanitize("<script>alert(1)</script>hi"), "alert(1)hi");
    }

    #[test]
    fn forbid_is_case_insensitive_so_case_variation_does_not_bypass() {
        let m = dompurify(&["script"], None, false);
        // <ScRiPt> must also be dropped (real sanitizers lowercase) — NOT a bypass.
        assert!(!m.survives_executable("<ScRiPt>alert(1)</ScRiPt>"));
    }

    #[test]
    fn forbidding_script_but_not_svg_leaves_an_executable_handler() {
        // The classic misconfiguration: forbid script, no handler stripping →
        // <svg onload=...> survives and executes.
        let m = dompurify(&["script"], None, false);
        assert!(m.survives_executable("<svg onload=alert(1)>"));
    }

    #[test]
    fn handler_stripping_neutralizes_the_svg_vector() {
        let m = dompurify(&["script"], None, true);
        assert!(!m.survives_executable("<svg onload=alert(1)>"));
    }

    #[test]
    fn allowlist_drops_unlisted_executable_tags() {
        let m = dompurify(&[], Some(&["b", "i", "em"]), false);
        // <img> not in the allowlist → dropped → onerror can't fire.
        assert!(!m.survives_executable("<img src=x onerror=alert(1)>"));
        // Allowed <b> survives but carries no vector.
        assert_eq!(m.sanitize("<b>hi</b>"), "<b>hi</b>");
    }

    #[test]
    fn allowlisted_tag_with_handler_survives_when_handlers_not_stripped() {
        // <a> allowed, handlers NOT stripped → onmouseover survives = bypass.
        let m = dompurify(&[], Some(&["a"]), false);
        assert!(m.survives_executable("<a onmouseover=alert(1)>x</a>"));
        // Same config WITH handler stripping → no bypass.
        let m2 = dompurify(&[], Some(&["a"]), true);
        assert!(!m2.survives_executable("<a onmouseover=alert(1)>x</a>"));
    }

    #[test]
    fn blocked_javascript_scheme_is_defanged_in_output() {
        let mut m = dompurify(&[], Some(&["a"]), false);
        m.blocked_schemes = vec!["javascript".to_string()];
        let out = m.sanitize("<a href=javascript:alert(1)>x</a>");
        assert!(
            !out.to_ascii_lowercase().contains("javascript:"),
            "scheme must be defanged: {out}"
        );
        assert!(
            out.contains("%3a") || out.contains("%3A"),
            "defanged colon expected: {out}"
        );
    }

    #[test]
    fn custom_strip_pattern_removes_matches() {
        let mut m = SanitizerModel {
            kind: SanitizerKind::CustomRegexStrip,
            ..Default::default()
        };
        m.strip_patterns = vec!["<script[^>]*>".to_string()];
        // The strip removes the opening tag; nothing executable remains.
        assert!(!m.survives_executable("<script src=x>"));
    }

    // ── is_executable_html ────────────────────────────────────────────────

    #[test]
    fn executable_detector_flags_unambiguous_markup_vectors_only() {
        assert!(is_executable_html("<script>x</script>"));
        assert!(is_executable_html("<img src=x onerror=alert(1)>"));
        assert!(!is_executable_html("<b>safe</b> plain text"));
        assert!(!is_executable_html(
            "on its own this onload word is not a handler"
        ));
        // A bare scheme string is NOT executable in a markup sink (no over-report).
        assert!(!is_executable_html("javascript:alert(1)"));
        assert!(!is_executable_html("<b href=javascript:alert(1)>inert</b>"));
    }

    // ── Oracle ────────────────────────────────────────────────────────────

    #[test]
    fn oracle_passes_a_surviving_bypass_blocks_a_neutralized_input() {
        let m = dompurify(&["script"], None, false);
        let mut oracle = SanitizerOracle::new(m);
        let bypass = Request::post("https://s/", b"<svg onload=alert(1)>".to_vec());
        let blocked = Request::post("https://s/", b"<script>alert(1)</script>".to_vec());
        assert_eq!(oracle.classify(&bypass).unwrap(), Outcome::Pass);
        assert_eq!(oracle.classify(&blocked).unwrap(), Outcome::Block);
        assert_eq!(oracle.queries(), 2);
    }

    #[test]
    fn oracle_empty_body_is_block_not_panic() {
        let m = dompurify(&["script"], None, false);
        let mut oracle = SanitizerOracle::new(m);
        let empty = Request::post("https://s/", Vec::new());
        assert_eq!(oracle.classify(&empty).unwrap(), Outcome::Block);
    }

    // ── Property tests ────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// sanitize() never panics and is idempotent: sanitizing already-clean
        /// output does not resurrect a vector.
        #[test]
        fn prop_sanitize_idempotent_and_total(input in ".{0,200}") {
            let m = dompurify(&["script", "iframe"], None, true);
            let once = m.sanitize(&input);
            let twice = m.sanitize(&once);
            prop_assert_eq!(once, twice);
        }

        /// A sanitizer that strips handlers AND forbids script AND allowlists only
        /// inert tags must leave NO executable vector, for any input.
        #[test]
        fn prop_strict_config_admits_no_bypass(input in "[<>a-zA-Z0-9=/ '\"():;]{0,120}") {
            let m = dompurify(&["script", "svg", "img", "iframe", "math"], Some(&["b", "i", "em", "p"]), true);
            prop_assert!(!m.survives_executable(&input), "strict config leaked on {input:?}");
        }
    }
}
