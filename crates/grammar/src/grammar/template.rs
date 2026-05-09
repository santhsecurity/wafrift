//! Template injection grammar-aware payload mutation.
//!
//! Generates server-side template injection probes across multiple template
//! engines while preserving the same exploit class: expression evaluation,
//! control-flow execution, and runtime-introspection gadgets.
//!
//! # Supported Engines
//!
//! 1. Jinja2 - Python templating with expression evaluation
//! 2. Twig - PHP templating engine  
//! 3. Freemarker - Java templating with object construction
//! 4. Pebble - Java reflection-style expressions
//! 5. Velocity - Java assignment and class inspection
//! 6. ERB - Ruby evaluation and command execution
//! 7. Smarty - PHP template engine
//! 8. Thymeleaf - Java XML-based templating
//! 9. Pug - Node.js templating
//! 10. Nunjucks - JavaScript templating
//! 11. Mako - Python templating
//! 12. Blade - PHP Laravel templating
//! 13. Liquid - Ruby templating (Shopify)
//! 14. Handlebars - JavaScript templating
//! 15. EJS - Embedded JavaScript templating
//!
//! # Architecture
//!
//! Payloads are loaded from `rules/templates.toml` at compile time for
//! reliability and performance. The TOML structure allows adding new engines
//! without code changes.

use serde::Deserialize;
use std::collections::BTreeSet;

/// Template engine definition loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
struct Engine {
    /// Engine name (e.g., "jinja2", "twig")
    #[allow(dead_code)]
    name: String,
    /// Detection delimiters (e.g., ["{{", "}}"])
    delimiters: Vec<String>,
    /// Human-readable description
    #[allow(dead_code)]
    description: String,
    /// Category: python, java, php, ruby, javascript
    #[allow(dead_code)]
    category: String,
    /// List of payloads for this engine
    #[serde(default)]
    payloads: Vec<Payload>,
}

/// Individual payload definition.
#[derive(Debug, Clone, Deserialize)]
struct Payload {
    /// Payload type: expression, rce, control_flow, introspection, etc.
    #[allow(dead_code)]
    #[serde(rename = "type")]
    payload_type: String,
    /// The actual payload string
    payload: String,
    /// Human-readable description
    #[allow(dead_code)]
    description: String,
}

/// Polyglot payload definition.
#[derive(Debug, Clone, Deserialize)]
struct Polyglot {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    payload: String,
}

/// Root structure for templates.toml.
#[derive(Debug, Clone, Deserialize)]
struct TemplateRules {
    #[serde(default)]
    engine: Vec<Engine>,
    #[serde(default)]
    polyglot: Vec<Polyglot>,
}

impl Default for TemplateRules {
    fn default() -> Self {
        Self {
            engine: vec![Engine {
                name: "jinja2".into(),
                delimiters: vec!["{{".into(), "}}".into(), "{%".into(), "%}".into()],
                description: "Python Jinja2".into(),
                category: "python".into(),
                payloads: vec![Payload {
                    payload_type: "expression".into(),
                    payload: "{{7*7}}".into(),
                    description: "Basic arithmetic".into(),
                }],
            }],
            polyglot: vec![Polyglot {
                name: "polyglot_probe".into(),
                description: "Universal probe".into(),
                payload: "${{<%[%'\"}}%\\.".into(),
            }],
        }
    }
}

/// Compile-time embedded TOML rules for reliability.
const TEMPLATE_RULES_TOML: &str = include_str!("../../rules/templates.toml");

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static TemplateRules {
    use std::sync::OnceLock;
    static RULES: OnceLock<TemplateRules> = OnceLock::new();
    RULES.get_or_init(|| {
        toml::from_str(TEMPLATE_RULES_TOML).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "invalid TOML in rules/templates.toml");
            TemplateRules::default()
        })
    })
}

/// Generate semantic-preserving template-injection mutations for a candidate payload.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let mut results = BTreeSet::new();
    let rules = get_rules();

    // Add all engine payloads
    for engine in &rules.engine {
        for p in &engine.payloads {
            results.insert(p.payload.clone());
        }
    }

    // Add polyglot payloads
    for polyglot in &rules.polyglot {
        results.insert(polyglot.payload.clone());
    }

    // Context-aware mutations based on detected syntax
    if payload.contains("{{") {
        results.insert(payload.replace("{{", "{{7*7}}{{"));
    }
    if payload.contains("${") {
        results.insert(payload.replace("${", "${7*7}${"));
    }
    if payload.contains("<%") {
        results.insert(payload.replace("<%", "<%= 7*7 %><%"));
    }
    if payload.contains("#{") {
        results.insert(payload.replace("#{", "#{7*7}#{"));
    }
    if payload.contains("@{") {
        results.insert(payload.replace("@{", "@{7*7}@{"));
    }

    results.remove(payload);
    results.into_iter().collect()
}

/// Detect whether a payload looks like a template expression or template injection probe.
///
/// Checks delimiters for all supported engines:
/// - Jinja2/Twig/Nunjucks/Liquid: `{{`, `}}`, `{%`, `%}`
/// - Freemarker: `${`, `<#assign`, `>`
/// - Pebble/Blade: `{{`, `}}`
/// - Velocity: `#{`, `$`, `#set(`
/// - ERB/EJS: `<%`, `%>`, `<%=`
/// - Smarty: `{`, `}` (contextual)
/// - Thymeleaf: `th:`, `${`, `}`
/// - Pug: `#{`, `!{`, `- `
/// - Mako: `${`, `<%`, `%>`
/// - Handlebars: `{{{`, `}}}`
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    let rules = get_rules();

    // Check all engine delimiters
    for engine in &rules.engine {
        for delimiter in &engine.delimiters {
            if payload.contains(delimiter) {
                return true;
            }
        }
    }

    // Additional context-aware checks for ambiguous delimiters
    // Smarty: { followed by $ or specific keywords (not just any braces)
    if payload.contains("{$") || lower.contains("{php}") || lower.contains("{smarty") {
        return true;
    }

    // Thymeleaf namespace prefix
    if lower.contains("th:") || lower.contains("th-") {
        return true;
    }

    // Pug/Jade specific patterns
    if lower.contains("- require(") || lower.contains("= global.process") {
        return true;
    }

    // Blade directives
    if lower.contains("@php") || lower.contains("@endphp") || lower.contains("{!!") {
        return true;
    }

    // Mako specific patterns
    if lower.contains("<%!") || lower.contains("<%def") || lower.contains("<%namespace") {
        return true;
    }

    // Handlebars helpers
    if lower.contains("{{#") || lower.contains("{{/") || lower.contains("{{>") {
        return true;
    }

    // EJS specific patterns
    if lower.contains("<%-") || lower.contains("<%_") || lower.contains("_%>") {
        return true;
    }

    // Velocity-specific patterns beyond delimiters
    if lower.contains("$!{") || lower.contains("#macro") || lower.contains("#parse") {
        return true;
    }

    false
}

/// Get all supported engine names.
#[must_use]
pub fn supported_engines() -> Vec<&'static str> {
    let rules = get_rules();
    rules.engine.iter().map(|e| e.name.as_str()).collect()
}

/// Get payloads for a specific engine by name.
#[must_use]
pub fn get_engine_payloads(engine_name: &str) -> Vec<String> {
    let rules = get_rules();
    rules
        .engine
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(engine_name))
        .map(|e| e.payloads.iter().map(|p| p.payload.clone()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jinja_syntax() {
        assert!(detect_type("{{ user.name }}"));
        assert!(detect_type("{% if user %}"));
    }

    #[test]
    fn detects_twig_syntax() {
        assert!(detect_type("{{ 7*7 }}"));
        assert!(detect_type("{% for item in items %}"));
    }

    #[test]
    fn detects_freemarker_syntax() {
        assert!(detect_type("${user}"));
        assert!(detect_type("<#assign x=1>"));
    }

    #[test]
    fn detects_pebble_syntax() {
        assert!(detect_type("{{ user }}"));
    }

    #[test]
    fn detects_velocity_syntax() {
        assert!(detect_type("#{user}"));
        assert!(detect_type("#set($x=1)"));
        assert!(detect_type("$class.inspect"));
    }

    #[test]
    fn detects_erb_syntax() {
        assert!(detect_type("<%= 7*7 %>"));
        assert!(detect_type("<% if true %>"));
    }

    #[test]
    fn detects_smarty_syntax() {
        assert!(detect_type("{$user}"));
        assert!(detect_type("{php}echo 1{/php}"));
    }

    #[test]
    fn detects_thymeleaf_syntax() {
        assert!(detect_type("th:text=\"${user}\""));
        assert!(detect_type("th:value=\"${name}\""));
    }

    #[test]
    fn detects_pug_syntax() {
        assert!(detect_type("#{user}"));
        assert!(detect_type("!{html}"));
        assert!(detect_type("- console.log(1)"));
    }

    #[test]
    fn detects_nunjucks_syntax() {
        assert!(detect_type("{{ user }}"));
        assert!(detect_type("{% extends \"base.html\" %}"));
    }

    #[test]
    fn detects_mako_syntax() {
        assert!(detect_type("${user}"));
        assert!(detect_type("<% import os %>"));
    }

    #[test]
    fn detects_blade_syntax() {
        assert!(detect_type("{{ $user }}"));
        assert!(detect_type("@php echo 1; @endphp"));
        assert!(detect_type("{!! $html !!}"));
    }

    #[test]
    fn detects_liquid_syntax() {
        assert!(detect_type("{{ user }}"));
        assert!(detect_type("{% assign x = 1 %}"));
    }

    #[test]
    fn detects_handlebars_syntax() {
        assert!(detect_type("{{ user }}"));
        assert!(detect_type("{{{ unescaped }}}"));
        assert!(detect_type("{{#each items}}{{/each}}"));
    }

    #[test]
    fn detects_ejs_syntax() {
        assert!(detect_type("<%= user %>"));
        assert!(detect_type("<% if (true) { %>"));
        assert!(detect_type("<%- include('header') %>"));
    }

    #[test]
    fn rejects_plain_text() {
        assert!(!detect_type("ordinary content only"));
        assert!(!detect_type("Hello World"));
        assert!(!detect_type("No template here"));
    }

    #[test]
    fn generates_jinja_variants() {
        let mutations = mutate("{{user}}");
        assert!(mutations.iter().any(|item| item == "{{7*7}}"));
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("__class__.__mro__"))
        );
        assert!(mutations.iter().any(|item| item.contains("range(10)")));
    }

    #[test]
    fn generates_freemarker_variants() {
        let mutations = mutate("${user}");
        assert!(mutations.iter().any(|item| item == "${7*7}"));
        assert!(mutations.iter().any(|item| item.contains("<#assign")));
        assert!(mutations.iter().any(|item| item.contains("?new()")));
    }

    #[test]
    fn generates_pebble_variants() {
        let mutations = mutate("{{user}}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("getClass().forName"))
        );
    }

    #[test]
    fn generates_erb_variants() {
        let mutations = mutate("<%= user %>");
        assert!(mutations.iter().any(|item| item == "<%= 7*7 %>"));
        assert!(mutations.iter().any(|item| item.contains("system('id')")));
    }

    #[test]
    fn generates_smarty_variants() {
        let mutations = mutate("${user}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("{php}echo 'test';{/php}"))
        );
    }

    #[test]
    fn generates_velocity_variants() {
        let mutations = mutate("#{user}");
        assert!(mutations.iter().any(|item| item.contains("#set($x=7*7)")));
        assert!(mutations.iter().any(|item| item.contains("$class.inspect")));
    }

    #[test]
    fn generates_thymeleaf_variants() {
        let mutations = mutate("th:text\"");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("th:text=\"${7*7}\""))
        );
    }

    #[test]
    fn generates_pug_variants() {
        let mutations = mutate("#{user}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("require('child_process')"))
        );
    }

    #[test]
    fn generates_nunjucks_variants() {
        let mutations = mutate("{{user}}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("range.constructor"))
        );
    }

    #[test]
    fn generates_mako_variants() {
        let mutations = mutate("${user}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("__import__('os')"))
        );
    }

    #[test]
    fn generates_blade_variants() {
        let mutations = mutate("{{user}}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("@php") || item == "{{7*7}}")
        );
    }

    #[test]
    fn generates_liquid_variants() {
        let mutations = mutate("{{user}}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("inspect") || item == "{{7*7}}")
        );
    }

    #[test]
    fn generates_handlebars_variants() {
        let mutations = mutate("{{user}}");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("constructor") || item == "{{7*7}}")
        );
    }

    #[test]
    fn generates_ejs_variants() {
        let mutations = mutate("<%= user %>");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains("require('child_process')"))
        );
    }

    #[test]
    fn generates_polyglot_variant() {
        let mutations = mutate("{{user}}");
        assert!(mutations.iter().any(|item| item == "${{<%[%'\"}}%\\."));
    }

    #[test]
    fn empty_payload_returns_empty() {
        let mutations = mutate("");
        assert!(mutations.is_empty());
    }

    #[test]
    fn non_template_payload_returns_empty() {
        let mutations = mutate("hello world");
        assert!(mutations.is_empty());
    }

    #[test]
    fn supported_engines_listed() {
        let engines = supported_engines();
        assert!(engines.contains(&"jinja2"));
        assert!(engines.contains(&"twig"));
        assert!(engines.contains(&"freemarker"));
        assert!(engines.contains(&"velocity"));
        assert!(engines.contains(&"erb"));
        assert!(engines.contains(&"smarty"));
        assert!(engines.contains(&"thymeleaf"));
        assert!(engines.contains(&"pug"));
        assert!(engines.contains(&"nunjucks"));
        assert!(engines.contains(&"mako"));
        assert!(engines.contains(&"blade"));
        assert!(engines.contains(&"liquid"));
        assert!(engines.contains(&"handlebars"));
        assert!(engines.contains(&"ejs"));
    }

    #[test]
    fn get_engine_payloads_returns_correct_payloads() {
        let jinja_payloads = get_engine_payloads("jinja2");
        assert!(!jinja_payloads.is_empty());
        assert!(jinja_payloads.iter().any(|p| p.contains("7*7")));
        assert!(jinja_payloads.iter().any(|p| p.contains("__class__")));

        let unknown = get_engine_payloads("nonexistent");
        assert!(unknown.is_empty());
    }

    #[test]
    fn context_aware_mutations_work() {
        // Jinja-style context
        let jinja = mutate("{{user}}");
        assert!(jinja.iter().any(|p| p.contains("{{7*7}}{{")));

        // Freemarker-style context
        let freemarker = mutate("${user}");
        assert!(freemarker.iter().any(|p| p.contains("${7*7}${")));

        // ERB-style context
        let erb = mutate("<%= user %>");
        assert!(erb.iter().any(|p| p.contains("<%= 7*7 %><%")));

        // Velocity-style context
        let velocity = mutate("#{user}");
        assert!(velocity.iter().any(|p| p.contains("#{7*7}#{")));
    }
}
