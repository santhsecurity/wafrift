//! XSS payload oracle — validates that HTML/JS execution semantics survive transforms.
//!
//! XSS payloads have three critical structural elements:
//! 1. **A delivery mechanism** — an HTML tag or attribute injection point
//! 2. **An event trigger** — an event handler (`onerror`, `onload`, etc.)
//! 3. **An execution sink** — a JavaScript function call (`alert`, `eval`, etc.)
//!
//! If any of these three elements is destroyed by encoding, the payload is broken.

use crate::traits::PayloadOracle;

/// XSS-specific oracle that checks for structural element preservation.
pub struct XssOracle;

/// HTML tags that serve as XSS delivery mechanisms.
const XSS_TAGS: &[&str] = &[
    "<script",
    "<img",
    "<svg",
    "<body",
    "<iframe",
    "<details",
    "<video",
    "<audio",
    "<input",
    "<marquee",
    "<object",
    "<a ",
    "<div",
    "<form",
    "<select",
    "<textarea",
    "<embed",
    "<link",
    "<style",
    "<math",
    "<table",
    "<noscript",
];

/// Event handlers that trigger JavaScript execution.
const XSS_EVENTS: &[&str] = &[
    "onerror",
    "onload",
    "onclick",
    "onfocus",
    "onmouseover",
    "ontoggle",
    "onbegin",
    "onstart",
    "onmouseenter",
    "onanimationend",
    "onhashchange",
    "onpageshow",
    "onscroll",
    "onwheel",
    "onresize",
];

/// JavaScript execution sinks.
const XSS_EXEC_SINKS: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "constructor",
    "import(",
    "fetch(",
    "document.cookie",
    "window.name",
    "location",
    "innerHTML",
];

/// URI schemes that execute JavaScript.
const JS_URI_SCHEMES: &[&str] = &["javascript:", "data:text/html"];

/// Dangerous sinks that indicate actual exploitation, not benign HTML.
const DANGEROUS_SINKS: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "eval",
    "document.write",
    "document.location",
    "window.location",
    "innerhtml",
    "outerhtml",
    "srcdoc",
];

/// Checks whether a payload contains at least one structural XSS element.
fn has_xss_structure(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    // Check for tag-based delivery
    let has_tag = XSS_TAGS.iter().any(|tag| lower.contains(tag));

    // Check for event handler
    let has_event = XSS_EVENTS.iter().any(|evt| lower.contains(evt));

    // Check for execution sink
    let has_exec = XSS_EXEC_SINKS.iter().any(|sink| lower.contains(sink));

    // Check for URI scheme execution
    let has_uri = JS_URI_SCHEMES.iter().any(|scheme| lower.contains(scheme));

    // Check for a dangerous sink to avoid false positives on benign HTML
    let has_dangerous_sink = DANGEROUS_SINKS.iter().any(|sink| lower.contains(sink));

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
}
