//! SSTI (Server-Side Template Injection) payload oracle.
//!
//! Template injection payloads must preserve their template delimiters
//! and expression structure. If encoding destroys `{{`, `${`, `<%`, or
//! their closing counterparts, the template engine won't evaluate the
//! expression and the injection fails silently.
//!
//! # Validation strategy
//!
//! A valid SSTI payload must contain:
//! 1. **Matched delimiters** — `{{ ... }}`, `${ ... }`, `<% ... %>`, `#{ ... }`, `{% ... %}`
//! 2. **Expression content** — non-empty content between delimiters
//! 3. **Optional introspection markers** — `__class__`, `getClass()`, `system()`, etc.

use crate::traits::PayloadOracle;

/// SSTI-specific oracle that validates template expression structure.
pub struct SstiOracle;

/// Known template delimiter pairs: `(open, close)`.
const DELIMITER_PAIRS: &[(&str, &str)] = &[
    ("{{", "}}"),   // Jinja2, Twig, Mustache, Handlebars
    ("${", "}"),    // Freemarker, EL, Groovy
    ("<%", "%>"),   // ERB, JSP, ASP
    ("#{", "}"),    // Thymeleaf, PebbleJava
    ("{%", "%}"),   // Jinja2 control blocks, Django
    ("#set(", ")"), // Velocity
    ("{", "}"),     // Smarty (checked last to avoid matching JSON)
];

/// Introspection markers that indicate active exploitation (not just probe).
const INTROSPECTION_MARKERS: &[&str] = &[
    "__class__",
    "__mro__",
    "__subclasses__",
    "__import__",
    "__builtins__",
    "getClass()",
    "forName(",
    "getRuntime()",
    "exec(",
    "system(",
    "popen(",
    "subprocess",
    "Runtime",
    "ProcessBuilder",
    "range(",
    "lipsum",
    "cycler",
    "?new()",
    "?api",
    "Class.forName",
];

/// Checks whether a payload contains at least one valid template expression.
fn has_template_structure(payload: &str) -> bool {
    // Check each delimiter pair for matched occurrences with content between them
    for &(open, close) in DELIMITER_PAIRS {
        let mut search_start = 0;
        while let Some(start_pos) = payload[search_start..].find(open) {
            let absolute_start = search_start + start_pos;
            // Do not treat `{` inside `{{ ... }}` as a Smarty bare `{` opener.
            if open == "{" {
                if absolute_start > 0 && payload.as_bytes()[absolute_start - 1] == b'{' {
                    search_start = absolute_start + 1;
                    continue;
                }
                if absolute_start == 0 && payload.starts_with("{{") {
                    search_start = 1;
                    continue;
                }
            }
            let after_open = absolute_start + open.len();
            if let Some(close_pos) = payload[after_open..].find(close)
                && close_pos > 0
            {
                // For Smarty bare `{` `}`, avoid matching JSON-like structures
                if open == "{" && close == "}" {
                    let content = &payload[after_open..after_open + close_pos];
                    if looks_like_json(content) {
                        search_start = after_open;
                        continue;
                    }
                }
                return true;
            }
            search_start = after_open;
        }
    }

    false
}

/// Heuristic to avoid matching JSON objects as Smarty delimiters.
fn looks_like_json(content: &str) -> bool {
    // If the content looks like a JSON key-value pair or array, skip it.
    let trimmed = content.trim();
    trimmed.starts_with('"')
        || trimmed.starts_with('\'')
        || trimmed.parse::<f64>().is_ok()
        || (trimmed.contains(':') && trimmed.contains('"'))
}

/// Checks whether a payload retains introspection capabilities.
fn has_introspection(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    INTROSPECTION_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
}

impl PayloadOracle for SstiOracle {
    fn is_semantically_valid(&self, original: &str, transformed: &str) -> bool {
        let original_has_structure = has_template_structure(original);
        let transformed_has_structure = has_template_structure(transformed);

        // If the original had template structure, the transform must preserve it
        if original_has_structure && !transformed_has_structure {
            return false;
        }

        // If the original had introspection markers, check they survived
        let original_has_introspection = has_introspection(original);
        if original_has_introspection && !has_introspection(transformed) {
            return false;
        }

        // At minimum, the transformed payload must have template structure
        transformed_has_structure
    }

    fn name(&self) -> &'static str {
        "SSTI"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jinja2_expression_valid() {
        let oracle = SstiOracle;
        assert!(oracle.is_semantically_valid("{{7*7}}", "{{7*7}}"));
    }

    #[test]
    fn jinja2_introspection_valid() {
        let oracle = SstiOracle;
        assert!(
            oracle.is_semantically_valid("{{''.__class__.__mro__}}", "{{''.__class__.__mro__}}",)
        );
    }

    #[test]
    fn freemarker_expression_valid() {
        let oracle = SstiOracle;
        assert!(oracle.is_semantically_valid("${7*7}", "${7*7}"));
    }

    #[test]
    fn erb_expression_valid() {
        let oracle = SstiOracle;
        assert!(oracle.is_semantically_valid("<%= 7*7 %>", "<%= 7*7 %>"));
    }

    #[test]
    fn destroyed_delimiters_invalid() {
        let oracle = SstiOracle;
        // URL encoding destroys the delimiters
        assert!(!oracle.is_semantically_valid("{{7*7}}", "%7B%7B7*7%7D%7D",));
    }

    #[test]
    fn introspection_destroyed_invalid() {
        let oracle = SstiOracle;
        // Template structure preserved but introspection keywords mangled
        assert!(
            !oracle.is_semantically_valid("{{''.__class__.__mro__}}", "{{''.__c1ass__.__mr0__}}",)
        );
    }

    #[test]
    fn empty_delimiters_invalid() {
        let oracle = SstiOracle;
        assert!(!oracle.is_semantically_valid("{{7*7}}", "{{}}"));
    }

    #[test]
    fn velocity_expression_valid() {
        let oracle = SstiOracle;
        assert!(oracle.is_semantically_valid("#set($x=7*7)", "#set($x=7*7)",));
    }

    #[test]
    fn django_block_valid() {
        let oracle = SstiOracle;
        assert!(
            oracle.is_semantically_valid("{% for x in range(10) %}", "{% for x in range(10) %}",)
        );
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = SstiOracle;
        assert!(!oracle.is_semantically_valid("{{7*7}}", "hello world"));
    }

    #[test]
    fn probe_with_different_expression_valid() {
        let oracle = SstiOracle;
        // Different expression but same structure — valid transform
        assert!(oracle.is_semantically_valid("{{7*7}}", "{{7*'7'}}"));
    }
}
