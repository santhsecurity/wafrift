//! XSS payload oracle — validates that HTML/JS execution semantics survive transforms.
//!
//! XSS payloads have three critical structural elements:
//! 1. **A delivery mechanism** — an HTML tag or attribute injection point
//! 2. **An event trigger** — an event handler (`onerror`, `onload`, etc.)
//! 3. **An execution sink** — a JavaScript function call (`alert`, `eval`, etc.)
//!
//! If any of these three elements is destroyed by encoding, the payload is broken.

use crate::traits::PayloadOracle;
use serde::Deserialize;
use std::sync::OnceLock;

/// XSS-specific oracle that checks for structural element preservation.
pub struct XssOracle;

#[derive(Deserialize)]
struct XssRules {
    tag: Vec<TagPrefix>,
    event: Vec<NamedEntry>,
    exec_sink: Vec<NamedEntry>,
    js_uri_scheme: Vec<UriPrefix>,
    dangerous_sink: Vec<NamedEntry>,
}

#[derive(Deserialize)]
struct TagPrefix {
    prefix: String,
}
#[derive(Deserialize)]
struct UriPrefix {
    prefix: String,
}
#[derive(Deserialize)]
struct NamedEntry {
    name: String,
}

fn xss_rules() -> &'static XssRules {
    static RULES: OnceLock<XssRules> = OnceLock::new();
    RULES.get_or_init(|| {
        let raw = include_str!("../rules/xss/structure.toml");
        let mut rules: XssRules = toml::from_str(raw).expect("rules/xss/structure.toml must parse");
        // F134: every lookup uses `payload.to_ascii_lowercase().contains(needle)`,
        // so any rule whose `name` / `prefix` contains an upper-case letter is
        // dead — pre-fix this silently disabled the `setTimeout`, `setInterval`,
        // `Function`, and `innerHTML` exec_sink entries (and any future
        // mixed-case rule). Normalize at load so the TOML stays human-readable
        // and lookups stay O(n) `contains` against pre-lowered needles.
        for t in &mut rules.tag {
            t.prefix = t.prefix.to_ascii_lowercase();
        }
        for e in &mut rules.event {
            e.name = e.name.to_ascii_lowercase();
        }
        for s in &mut rules.exec_sink {
            s.name = s.name.to_ascii_lowercase();
        }
        for s in &mut rules.js_uri_scheme {
            s.prefix = s.prefix.to_ascii_lowercase();
        }
        for s in &mut rules.dangerous_sink {
            s.name = s.name.to_ascii_lowercase();
        }
        rules
    })
}

/// HTML tags that serve as XSS delivery mechanisms.
fn xss_tags() -> &'static [TagPrefix] {
    &xss_rules().tag
}
/// Event handlers that trigger JavaScript execution.
fn xss_events() -> &'static [NamedEntry] {
    &xss_rules().event
}
/// JavaScript execution sinks (any-of for "exec exists at all").
fn xss_exec_sinks() -> &'static [NamedEntry] {
    &xss_rules().exec_sink
}
/// URI schemes that execute JavaScript when followed.
fn js_uri_schemes() -> &'static [UriPrefix] {
    &xss_rules().js_uri_scheme
}
/// Dangerous sinks that indicate actual exploitation, not benign HTML.
fn dangerous_sinks() -> &'static [NamedEntry] {
    &xss_rules().dangerous_sink
}

/// Checks whether a payload contains at least one structural XSS element.
fn has_xss_structure(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    let has_tag = xss_tags().iter().any(|t| lower.contains(&t.prefix));
    let has_event = xss_events().iter().any(|e| lower.contains(&e.name));
    let has_exec = xss_exec_sinks().iter().any(|s| lower.contains(&s.name));
    let has_uri = js_uri_schemes().iter().any(|s| lower.contains(&s.prefix));

    // Check for a dangerous sink to avoid false positives on benign HTML
    let has_dangerous_sink = dangerous_sinks().iter().any(|s| lower.contains(&s.name));

    // Valid XSS requires either:
    // - URI scheme (javascript: or data: URI)
    // - tag + exec + dangerous_sink
    // - tag + event + dangerous_sink
    has_uri
        || (has_tag && has_exec && has_dangerous_sink)
        || (has_tag && has_event && has_dangerous_sink)
}

impl PayloadOracle for XssOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        has_xss_structure(transformed)
    }

    fn name(&self) -> &'static str {
        "XSS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_script_tag_valid() {
        let oracle = XssOracle;
        assert!(
            oracle.is_semantically_valid("<script>alert(1)</script>", "<script>alert(1)</script>",)
        );
    }

    #[test]
    fn img_onerror_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ));
    }

    #[test]
    fn svg_onload_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid("<svg onload=alert(1)>", "<svg onload=alert(1)>",));
    }

    #[test]
    fn javascript_uri_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid("javascript:alert(1)", "javascript:alert(1)",));
    }

    #[test]
    fn data_uri_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "data:text/html,<script>alert(1)</script>",
            "data:text/html,<script>alert(1)</script>",
        ));
    }

    #[test]
    fn broken_tag_invalid() {
        let oracle = XssOracle;
        // Encoding destroyed the tag structure
        assert!(!oracle.is_semantically_valid(
            "<script>alert(1)</script>",
            "%3Cscript%3Ealert%281%29%3C/script%3E",
        ));
    }

    #[test]
    fn case_alternation_preserves_structure() {
        let oracle = XssOracle;
        assert!(
            oracle.is_semantically_valid("<script>alert(1)</script>", "<ScRiPt>alert(1)</sCrIpT>",)
        );
    }

    #[test]
    fn empty_string_invalid() {
        let oracle = XssOracle;
        assert!(!oracle.is_semantically_valid("<script>alert(1)</script>", ""));
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = XssOracle;
        assert!(!oracle.is_semantically_valid("<script>alert(1)</script>", "hello world",));
    }

    #[test]
    fn event_handler_without_explicit_exec_valid() {
        let oracle = XssOracle;
        // Some event handlers have implicit execution context
        assert!(oracle.is_semantically_valid(
            "<img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ));
    }

    #[test]
    fn dom_clobber_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "<script>alert(1)</script>",
            "<form name=body><input name=innerHTML value='<img src=x onerror=alert(1)>'></form>",
        ));
    }

    #[test]
    fn constructor_chain_valid() {
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "<script>alert(1)</script>",
            "<img src=x onerror=constructor.constructor('alert(1)')()>",
        ));
    }

    // F134 regression: exec_sink rules with mixed-case names
    // (setTimeout, setInterval, Function, innerHTML) were dead — the
    // payload is lowercased before `contains` but the rule needles were
    // not, so the substring never appeared. Pin the live cases.

    #[test]
    fn settimeout_exec_sink_is_recognized() {
        // Tag + setTimeout + document.write (dangerous_sink) — pre-fix
        // has_exec was false because needle "setTimeout" doesn't appear
        // in the lowercased haystack "settimeout". With has_exec false
        // AND no event, the (tag && exec && dangerous_sink) and
        // (tag && event && dangerous_sink) branches both failed.
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "<script>setTimeout(document.write('x'),0)</script>",
            "<script>setTimeout(document.write('x'),0)</script>",
        ));
    }

    #[test]
    fn function_constructor_exec_sink_is_recognized() {
        let oracle = XssOracle;
        // `Function('...')()` — the `Function` exec_sink needle was
        // mixed-case in the TOML and never matched the lowered payload.
        assert!(oracle.is_semantically_valid(
            "<script>Function('alert(1)')()</script>",
            "<script>Function('document.write(1)')()</script>",
        ));
    }

    #[test]
    fn innerhtml_dangerous_sink_in_payload_matches() {
        // innerHTML appears in BOTH exec_sink and dangerous_sink. The
        // dangerous_sink TOML uses lowercase `innerhtml` so that branch
        // already worked — but pre-fix the exec_sink `innerHTML` was
        // dead. Pin that both paths now match a single payload.
        let oracle = XssOracle;
        assert!(oracle.is_semantically_valid(
            "<img src=x onerror=document.body.innerHTML='<b>x</b>'>",
            "<img src=x onerror=document.body.innerHTML='<b>x</b>'>",
        ));
    }
}
