/// A single probe in the differential analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    /// The probe payload to inject into a parameter.
    pub payload: String,
    /// What this probe is testing for.
    pub tests: ProbeTarget,
    /// Human-readable explanation.
    pub description: String,
    /// Whether this probe SHOULD be blocked by a well-configured WAF.
    pub expected_blocked: bool,
}

/// What aspect of WAF detection a probe is testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeTarget {
    /// Tests if the WAF blocks a specific SQL keyword.
    SqlKeyword(String),
    /// Tests if the WAF blocks SQL comparison operators.
    SqlOperator(String),
    /// Tests if the WAF blocks SQL comment syntax.
    SqlComment(String),
    /// Tests if the WAF blocks SQL string delimiters.
    SqlQuote,
    /// Tests if the WAF blocks a tautology pattern.
    SqlTautology(String),
    /// Tests if the WAF blocks XSS-related HTML tags.
    XssTag(String),
    /// Tests if the WAF blocks JavaScript event handlers.
    XssEvent(String),
    /// Tests if the WAF blocks JavaScript execution functions.
    XssExecFunction(String),
    /// Tests if the WAF blocks command injection separators.
    CmdSeparator(String),
    /// Tests if the WAF blocks specific shell commands.
    CmdCommand(String),
    /// Tests if the WAF blocks file path patterns.
    CmdPath(String),
    /// Baseline probe that should never be blocked.
    Baseline,
}

/// Generate the full set of differential analysis probes.
///
/// # SAFETY / authorization contract
///
/// Probe payloads are NOT inert. They contain genuinely exploitable
/// strings (`alert(1)`, `eval('x')`, `1=1`, `/etc/passwd`, `;`, `|`,
/// `||`) — that is the point: a WAF that doesn't block them is the
/// signal we're measuring. If the WAF fails to block AND the upstream
/// application is vulnerable, the probe IS the attack. Inert marker
/// strings (e.g. `wafrift_xss_probe_123`) don't trigger any WAF rule
/// and would defeat the purpose of differential probing.
///
/// **Caller responsibility.** Only call this against:
///   1. A WAF in front of a known-non-vulnerable backend you control
///      (the bench target's `kennethreitz/httpbin` fits — it
///      doesn't actually run JS, exec sh, or query SQL), OR
///   2. A target you have explicit written authorization to attack.
///
/// Wafrift cannot enforce this; the operator must.
#[must_use]
pub fn generate_probes() -> Vec<Probe> {
    let mut probes = Vec::new();
    probes.push(baseline_probe("test_value_12345", "baseline benign value"));
    probes.extend(sql_keyword_probes());
    probes.extend(sql_operator_probes());
    probes.extend(sql_comment_probes());
    probes.push(Probe {
        payload: "'".into(),
        tests: ProbeTarget::SqlQuote,
        description: "SQL single quote".into(),
        expected_blocked: true,
    });
    probes.extend(sql_tautology_probes());
    probes.extend(xss_tag_probes());
    probes.extend(xss_event_probes());
    probes.extend(xss_function_probes());
    probes.extend(command_separator_probes());
    probes.extend(command_name_probes());
    probes.extend(command_path_probes());
    probes
}

pub(crate) fn baseline_probe(payload: &str, description: &str) -> Probe {
    Probe {
        payload: payload.into(),
        tests: ProbeTarget::Baseline,
        description: description.into(),
        expected_blocked: false,
    }
}

pub(crate) fn sql_keyword_probes() -> Vec<Probe> {
    build_probes(
        &[
            "SELECT",
            "UNION",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "FROM",
            "WHERE",
            "ORDER BY",
            "GROUP BY",
            "HAVING",
            "SLEEP",
            "BENCHMARK",
            "WAITFOR",
        ],
        |keyword| Probe {
            payload: format!("test {keyword} value"),
            tests: ProbeTarget::SqlKeyword(keyword.to_string()),
            description: format!("SQL keyword: {keyword}"),
            expected_blocked: true,
        },
    )
}

pub(crate) fn sql_operator_probes() -> Vec<Probe> {
    build_probes(
        &[
            "=", "!=", "<>", "LIKE", "IN(", "BETWEEN", "IS NULL", "REGEXP",
        ],
        |operator| Probe {
            payload: format!("test{operator}test"),
            tests: ProbeTarget::SqlOperator(operator.to_string()),
            description: format!("SQL operator: {operator}"),
            expected_blocked: true,
        },
    )
}

pub(crate) fn sql_comment_probes() -> Vec<Probe> {
    build_probes(&["--", "#", "/***/", "-- -", "--+"], |comment| Probe {
        payload: format!("test{comment}test"),
        tests: ProbeTarget::SqlComment(comment.to_string()),
        description: format!("SQL comment: {comment}"),
        expected_blocked: true,
    })
}

pub(crate) fn sql_tautology_probes() -> Vec<Probe> {
    build_probes(
        &[
            "1=1",
            "1 LIKE 1",
            "'a'='a'",
            "1 BETWEEN 0 AND 2",
            "1 IN(1)",
            "true",
        ],
        |tautology| Probe {
            payload: tautology.to_string(),
            tests: ProbeTarget::SqlTautology(tautology.to_string()),
            description: format!("SQL tautology: {tautology}"),
            expected_blocked: true,
        },
    )
}

pub(crate) fn xss_tag_probes() -> Vec<Probe> {
    [
        ("script", "<script>", true),
        ("img", "<img src=x>", false),
        ("svg", "<svg>", false),
        ("iframe", "<iframe>", true),
        ("body", "<body>", false),
        ("details", "<details>", false),
        ("input", "<input>", false),
        ("marquee", "<marquee>", false),
        ("video", "<video>", false),
        ("object", "<object>", false),
        ("math", "<math>", false),
        ("style", "<style>", false),
    ]
    .into_iter()
    .map(|(name, payload, expected_blocked)| Probe {
        payload: payload.into(),
        tests: ProbeTarget::XssTag(name.into()),
        description: format!("XSS tag: {name}"),
        expected_blocked,
    })
    .collect()
}

pub(crate) fn xss_event_probes() -> Vec<Probe> {
    build_probes(
        &[
            "onerror",
            "onload",
            "onclick",
            "onfocus",
            "onmouseover",
            "ontoggle",
            "onbegin",
            "onstart",
            "onsubmit",
        ],
        |event| Probe {
            payload: format!("<x {event}=1>"),
            tests: ProbeTarget::XssEvent(event.to_string()),
            description: format!("XSS event: {event}"),
            expected_blocked: true,
        },
    )
}

pub(crate) fn xss_function_probes() -> Vec<Probe> {
    [
        ("alert", "alert(1)", true),
        ("confirm", "confirm(1)", false),
        ("prompt", "prompt(1)", false),
        ("eval", "eval('x')", true),
        ("Function", "Function('x')()", false),
        ("constructor", "[].constructor.constructor('x')()", false),
        ("setTimeout", "setTimeout('x')", false),
    ]
    .into_iter()
    .map(|(name, payload, expected_blocked)| Probe {
        payload: payload.into(),
        tests: ProbeTarget::XssExecFunction(name.into()),
        description: format!("XSS function: {name}"),
        expected_blocked,
    })
    .collect()
}

pub(crate) fn command_separator_probes() -> Vec<Probe> {
    build_probes(&[";", "|", "||", "&&", "`", "$("], |separator| Probe {
        payload: format!("test{separator}test"),
        tests: ProbeTarget::CmdSeparator(separator.to_string()),
        description: format!("CMD separator: {separator}"),
        expected_blocked: true,
    })
}

pub(crate) fn command_name_probes() -> Vec<Probe> {
    build_probes(
        &["cat", "ls", "id", "whoami", "wget", "curl", "ping", "nc"],
        |command| Probe {
            payload: command.to_string(),
            tests: ProbeTarget::CmdCommand(command.to_string()),
            description: format!("CMD command: {command}"),
            expected_blocked: false,
        },
    )
}

pub(crate) fn command_path_probes() -> Vec<Probe> {
    build_probes(
        &[
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/bin/sh",
        ],
        |path| Probe {
            payload: path.to_string(),
            tests: ProbeTarget::CmdPath(path.to_string()),
            description: format!("CMD path: {path}"),
            expected_blocked: true,
        },
    )
}

fn build_probes<T, F>(items: &[T], builder: F) -> Vec<Probe>
where
    T: Copy,
    F: Fn(T) -> Probe,
{
    items.iter().copied().map(builder).collect()
}

#[cfg(test)]
mod tests {
    use super::{ProbeTarget, generate_probes};

    #[test]
    fn generate_probes_has_baseline() {
        let probes = generate_probes();
        assert!(
            probes
                .iter()
                .any(|probe| probe.tests == ProbeTarget::Baseline)
        );
    }

    #[test]
    fn generate_probes_covers_all_categories() {
        let probes = generate_probes();
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::SqlKeyword(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::SqlOperator(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::SqlComment(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::SqlQuote))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::SqlTautology(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::XssTag(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::XssEvent(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::XssExecFunction(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::CmdSeparator(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::CmdCommand(_)))
        );
        assert!(
            probes
                .iter()
                .any(|probe| matches!(probe.tests, ProbeTarget::CmdPath(_)))
        );
    }

    #[test]
    fn generate_probes_has_many() {
        let probes = generate_probes();
        assert!(
            probes.len() >= 60,
            "expected 60+ probes, got {}",
            probes.len()
        );
    }

    #[test]
    fn probes_have_descriptions() {
        let probes = generate_probes();
        for probe in &probes {
            assert!(
                !probe.description.is_empty(),
                "probe should have description"
            );
            assert!(
                !probe.payload.is_empty() || probe.tests == ProbeTarget::Baseline,
                "probe should have payload"
            );
        }
    }

    #[test]
    fn sql_quote_expected_blocked() {
        let probes = generate_probes();
        let quote = probes
            .iter()
            .find(|p| matches!(p.tests, ProbeTarget::SqlQuote));
        assert!(quote.is_some());
        assert!(
            quote.unwrap().expected_blocked,
            "SQL quote should be expected blocked"
        );
    }
}
