//! Regression coverage for the 2026-05-10 swarm-audit findings:
//!   CRITICAL ssrf::detect_type fired on `// TODO`, `Chapter 127.5`,
//!     `Java 10.0`, `Version 192.168.something`, anything with `127.`
//!     inside a benign substring.
//!   CRITICAL template::detect_type fired on JSON, CSS, C, Python,
//!     Markdown — any string containing `{`, `}`, `#`, or `$` because
//!     Smarty / Velocity declare 1-char delimiters.
//!
//! Pre-fix every `assert!(!detect_type(...))` would have returned true.

use wafrift_grammar::grammar::{ssrf, template};

// ── ssrf detect_type FP fixes ───────────────────────────────────────

#[test]
fn ssrf_does_not_fire_on_doxygen_doc_comment() {
    assert!(!ssrf::detect_type("// TODO: refactor"));
    assert!(!ssrf::detect_type("// fix me later"));
}

#[test]
fn ssrf_does_not_fire_on_chapter_or_section_number() {
    assert!(!ssrf::detect_type("Chapter 127.5: how to scan"));
    assert!(!ssrf::detect_type("Section 10.4 and 10.5"));
}

#[test]
fn ssrf_does_not_fire_on_version_string() {
    assert!(!ssrf::detect_type("Java 10.0 release notes"));
    assert!(!ssrf::detect_type("Build 127.0 of nginx"));
    assert!(!ssrf::detect_type("Python 192.168.something"));
}

#[test]
fn ssrf_does_not_fire_on_localhost_substring_in_hostname() {
    // Pre-fix `localhost` matched anywhere; benign hosts that include
    // the word were flagged.
    assert!(!ssrf::detect_type("localhost-builds.example.com"));
    assert!(!ssrf::detect_type("my-localhost-mirror.io"));
}

#[test]
fn ssrf_still_fires_on_real_ssrf_payloads() {
    // Negative twin — the precision fix must not regress recall.
    assert!(ssrf::detect_type("http://127.0.0.1/admin"));
    assert!(ssrf::detect_type("http://localhost/internal"));
    assert!(ssrf::detect_type("http://169.254.169.254/latest/meta-data"));
    assert!(ssrf::detect_type("https://metadata.google.internal/"));
    assert!(ssrf::detect_type("//127.0.0.1/x"));
    assert!(ssrf::detect_type("file:///etc/passwd"));
    assert!(ssrf::detect_type("gopher://127.0.0.1:6379/_test"));
    assert!(ssrf::detect_type("127.0.0.1"));
}

// ── template detect_type FP fixes ───────────────────────────────────

#[test]
fn template_does_not_fire_on_plain_json() {
    assert!(!template::detect_type(r#"{"name": "alice", "id": 42}"#));
    assert!(!template::detect_type(r#"{"items":[{"x":1}]}"#));
}

#[test]
fn template_does_not_fire_on_css_block() {
    assert!(!template::detect_type("body { color: red; }"));
    assert!(!template::detect_type(".btn { background: #fff; }"));
}

#[test]
fn template_does_not_fire_on_c_or_python_code() {
    assert!(!template::detect_type("if (x) { return 1; }"));
    assert!(!template::detect_type("def foo(): return {'a': 1}"));
}

#[test]
fn template_does_not_fire_on_markdown_or_shell_var() {
    assert!(!template::detect_type("# Heading\nSome text $var"));
    assert!(!template::detect_type("$ ls /tmp/$user/"));
}

#[test]
fn template_still_fires_on_real_ssti_payloads() {
    // Negative twin — recall preserved on real SSTI.
    assert!(template::detect_type("{{7*7}}"), "jinja2 / twig");
    assert!(template::detect_type("{% if user %}{{ user }}{% endif %}"));
    assert!(template::detect_type("${7*7}"), "freemarker");
    assert!(template::detect_type("<%= 7*7 %>"), "erb");
    assert!(template::detect_type("{$smarty.version}"));
    assert!(template::detect_type("{php}phpinfo();{/php}"));
}
