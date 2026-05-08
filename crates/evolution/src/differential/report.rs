use super::analysis::DifferentialResult;

impl DifferentialResult {
    /// Generate a human-readable report of what the WAF blocks.
    #[must_use]
    pub fn report(&self) -> String {
        let mut lines = vec![
            "=== WAF Differential Analysis ===".to_string(),
            format!("Probes sent: {}", self.total_probes),
            format!(
                "Probes blocked: {} ({:.0}%)",
                self.total_blocked,
                if self.total_probes > 0 {
                    self.total_blocked as f64 / self.total_probes as f64 * 100.0
                } else {
                    0.0
                }
            ),
        ];
        if self.baseline_blocked {
            lines.push(
                "warning: baseline (benign) request was blocked; WAF may be over-aggressive".into(),
            );
        }
        append_section(
            &mut lines,
            "\nSQL Keywords blocked",
            &self.blocked_sql_keywords,
        );
        append_section(
            &mut lines,
            "SQL Operators blocked",
            &self.blocked_sql_operators,
        );
        append_section(
            &mut lines,
            "SQL Comments blocked",
            &self.blocked_sql_comments,
        );
        if self.blocks_sql_quotes {
            lines.push("SQL Quotes blocked: YES (single quotes trigger the WAF)".into());
        }
        append_section(
            &mut lines,
            "SQL Tautologies blocked",
            &self.blocked_tautologies,
        );
        append_section(&mut lines, "\nXSS Tags blocked", &self.blocked_xss_tags);
        append_section(&mut lines, "XSS Events blocked", &self.blocked_xss_events);
        append_section(
            &mut lines,
            "XSS Functions blocked",
            &self.blocked_xss_functions,
        );
        append_section(
            &mut lines,
            "\nCMD Separators blocked",
            &self.blocked_cmd_separators,
        );
        append_section(
            &mut lines,
            "CMD Commands blocked",
            &self.blocked_cmd_commands,
        );
        append_section(&mut lines, "CMD Paths blocked", &self.blocked_cmd_paths);
        lines.push("\n=== Gaps (what the WAF does NOT block) ===".into());
        append_gap_section(
            &mut lines,
            "SQL Keywords NOT blocked",
            &[
                "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "FROM", "WHERE",
                "ORDER BY", "HAVING",
            ],
            &self.blocked_sql_keywords,
        );
        append_gap_section(
            &mut lines,
            "XSS Tags NOT blocked",
            &[
                "script", "img", "svg", "iframe", "body", "details", "input", "marquee", "video",
                "object",
            ],
            &self.blocked_xss_tags,
        );
        lines.join("\n")
    }

    /// Suggest evasion strategies based on observed WAF behavior.
    #[must_use]
    pub fn suggest_evasions(&self) -> Vec<String> {
        let mut suggestions = Vec::new();
        if !self.blocked_sql_keywords.is_empty() && self.blocked_sql_comments.len() < 3 {
            suggestions.push(
                "SqlCommentInsertion — WAF blocks keywords but may not handle inline comments"
                    .into(),
            );
        }
        if self.blocked_xss_tags.iter().any(|tag| tag == "script")
            && !self.blocked_xss_tags.iter().any(|tag| tag == "details")
        {
            suggestions
                .push("XSS via <details ontoggle> — script blocked but details tag not".into());
        }
        if self.blocked_xss_tags.iter().any(|tag| tag == "script")
            && !self.blocked_xss_tags.iter().any(|tag| tag == "svg")
        {
            suggestions.push("XSS via <svg onload> — script blocked but SVG not".into());
        }
        if self
            .blocked_xss_functions
            .iter()
            .any(|function| function.contains("alert"))
            && !self
                .blocked_xss_functions
                .iter()
                .any(|function| function.contains("constructor"))
        {
            suggestions.push(
                "XSS via constructor chain — alert() blocked but prototype access not".into(),
            );
        }
        if self
            .blocked_cmd_separators
            .iter()
            .any(|separator| separator == ";")
            && !self
                .blocked_cmd_separators
                .iter()
                .any(|separator| separator == "|")
        {
            suggestions
                .push("CMD injection via pipe (|) — semicolons blocked but pipes not".into());
        }
        if !self.blocked_cmd_commands.is_empty() {
            suggestions.push(
                "CMD obfuscation (backslash, quotes, hex encoding) — command names blocked".into(),
            );
        }
        if self
            .blocked_tautologies
            .iter()
            .any(|tautology| tautology == "1=1")
            && !self
                .blocked_tautologies
                .iter()
                .any(|tautology| tautology.contains("BETWEEN"))
        {
            suggestions.push("SQL tautology via BETWEEN — 1=1 blocked but BETWEEN not".into());
        }
        if suggestions.is_empty() {
            suggestions.push(
                "WAF appears comprehensive — try Content-Type switching or encoding layering"
                    .into(),
            );
        }
        suggestions
    }
}

fn append_section(lines: &mut Vec<String>, label: &str, blocked: &[String]) {
    if !blocked.is_empty() {
        lines.push(format!("{label}: {}", blocked.join(", ")));
    }
}

fn append_gap_section(lines: &mut Vec<String>, label: &str, all: &[&str], blocked: &[String]) {
    let unblocked: Vec<&str> = all
        .iter()
        .copied()
        .filter(|candidate| {
            !blocked
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(candidate))
        })
        .collect();
    if !unblocked.is_empty() {
        lines.push(format!("{label}: {unblocked:?}"));
    }
}

#[cfg(test)]
mod tests {
    use crate::differential::DifferentialResult;

    #[test]
    fn report_includes_sections() {
        let mut result = DifferentialResult::new();
        result.blocked_sql_keywords.push("SELECT".into());
        result.blocked_xss_tags.push("script".into());
        result.total_probes = 10;
        result.total_blocked = 2;
        let report = result.report();
        assert!(report.contains("SELECT"));
        assert!(report.contains("script"));
        assert!(report.contains("Probes sent: 10"));
    }

    #[test]
    fn suggest_evasions_finds_gaps() {
        let mut result = DifferentialResult::new();
        result.blocked_sql_keywords.push("SELECT".into());
        result.blocked_sql_comments.push("--".into());
        assert!(!result.suggest_evasions().is_empty());
    }

    #[test]
    fn suggest_evasions_xss_tag_gap() {
        let mut result = DifferentialResult::new();
        result.blocked_xss_tags.push("script".into());
        let suggestions = result.suggest_evasions();
        let has_svg = suggestions
            .iter()
            .any(|suggestion| suggestion.contains("svg"));
        let has_details = suggestions
            .iter()
            .any(|suggestion| suggestion.contains("details"));
        assert!(has_svg || has_details, "should suggest unblocked tags");
    }

    #[test]
    fn suggest_evasions_cmd_separator_gap() {
        let mut result = DifferentialResult::new();
        result.blocked_cmd_separators.push(";".into());
        let has_pipe = result
            .suggest_evasions()
            .iter()
            .any(|suggestion| suggestion.contains("pipe") || suggestion.contains('|'));
        assert!(has_pipe, "should suggest pipe when semicolons blocked");
    }

    #[test]
    fn report_warns_on_baseline_blocked() {
        let mut result = DifferentialResult::new();
        result.baseline_blocked = true;
        let report = result.report();
        assert!(report.contains("warning"));
    }
}
