use super::probe::{Probe, ProbeTarget};

/// Results from a differential analysis run.
#[derive(Debug, Clone)]
pub struct DifferentialResult {
    /// Which SQL keywords trigger the WAF.
    pub blocked_sql_keywords: Vec<String>,
    /// Which SQL operators trigger the WAF.
    pub blocked_sql_operators: Vec<String>,
    /// Which SQL comment styles trigger the WAF.
    pub blocked_sql_comments: Vec<String>,
    /// Whether SQL string delimiters trigger the WAF.
    pub blocks_sql_quotes: bool,
    /// Which tautology patterns trigger the WAF.
    pub blocked_tautologies: Vec<String>,
    /// Which HTML tags trigger the WAF.
    pub blocked_xss_tags: Vec<String>,
    /// Which event handlers trigger the WAF.
    pub blocked_xss_events: Vec<String>,
    /// Which JS execution functions trigger the WAF.
    pub blocked_xss_functions: Vec<String>,
    /// Which command separators trigger the WAF.
    pub blocked_cmd_separators: Vec<String>,
    /// Which shell commands trigger the WAF.
    pub blocked_cmd_commands: Vec<String>,
    /// Which file paths trigger the WAF.
    pub blocked_cmd_paths: Vec<String>,
    /// Whether the benign baseline was blocked.
    pub baseline_blocked: bool,
    /// Total probes sent.
    pub total_probes: usize,
    /// Total probes blocked.
    pub total_blocked: usize,
}

impl DifferentialResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocked_sql_keywords: Vec::new(),
            blocked_sql_operators: Vec::new(),
            blocked_sql_comments: Vec::new(),
            blocks_sql_quotes: false,
            blocked_tautologies: Vec::new(),
            blocked_xss_tags: Vec::new(),
            blocked_xss_events: Vec::new(),
            blocked_xss_functions: Vec::new(),
            blocked_cmd_separators: Vec::new(),
            blocked_cmd_commands: Vec::new(),
            blocked_cmd_paths: Vec::new(),
            baseline_blocked: false,
            total_probes: 0,
            total_blocked: 0,
        }
    }

    /// Record a probe result.
    pub fn record(&mut self, probe: &Probe, was_blocked: bool) {
        self.total_probes += 1;
        if was_blocked {
            self.total_blocked += 1;
        }
        match &probe.tests {
            ProbeTarget::Baseline => self.baseline_blocked = was_blocked,
            ProbeTarget::SqlKeyword(keyword) => {
                if was_blocked && !self.blocked_sql_keywords.contains(keyword) {
                    self.blocked_sql_keywords.push(keyword.clone());
                }
            }
            ProbeTarget::SqlOperator(operator) => {
                if was_blocked && !self.blocked_sql_operators.contains(operator) {
                    self.blocked_sql_operators.push(operator.clone());
                }
            }
            ProbeTarget::SqlComment(comment) => {
                if was_blocked && !self.blocked_sql_comments.contains(comment) {
                    self.blocked_sql_comments.push(comment.clone());
                }
            }
            ProbeTarget::SqlQuote => self.blocks_sql_quotes = was_blocked,
            ProbeTarget::SqlTautology(tautology) => {
                if was_blocked && !self.blocked_tautologies.contains(tautology) {
                    self.blocked_tautologies.push(tautology.clone());
                }
            }
            ProbeTarget::XssTag(tag) => {
                if was_blocked && !self.blocked_xss_tags.contains(tag) {
                    self.blocked_xss_tags.push(tag.clone());
                }
            }
            ProbeTarget::XssEvent(event) => {
                if was_blocked && !self.blocked_xss_events.contains(event) {
                    self.blocked_xss_events.push(event.clone());
                }
            }
            ProbeTarget::XssExecFunction(function) => {
                if was_blocked && !self.blocked_xss_functions.contains(function) {
                    self.blocked_xss_functions.push(function.clone());
                }
            }
            ProbeTarget::CmdSeparator(separator) => {
                if was_blocked && !self.blocked_cmd_separators.contains(separator) {
                    self.blocked_cmd_separators.push(separator.clone());
                }
            }
            ProbeTarget::CmdCommand(command) => {
                if was_blocked && !self.blocked_cmd_commands.contains(command) {
                    self.blocked_cmd_commands.push(command.clone());
                }
            }
            ProbeTarget::CmdPath(path) => {
                if was_blocked && !self.blocked_cmd_paths.contains(path) {
                    self.blocked_cmd_paths.push(path.clone());
                }
            }
        }
    }
}
impl Default for DifferentialResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::DifferentialResult;
    use crate::differential::{ProbeTarget, generate_quick_probes};

    #[test]
    fn record_basic_results() {
        let probes = generate_quick_probes();
        let mut result = DifferentialResult::new();
        for probe in &probes {
            let blocked = match &probe.tests {
                ProbeTarget::SqlTautology(_) | ProbeTarget::SqlKeyword(_) => true,
                ProbeTarget::XssTag(tag) if tag == "script" => true,
                _ => false,
            };
            result.record(probe, blocked);
        }
        assert_eq!(result.total_probes, probes.len());
        assert!(result.total_blocked > 0);
        assert!(!result.baseline_blocked);
    }

    #[test]
    fn record_deduplicates() {
        let mut result = DifferentialResult::new();
        let probe = crate::differential::Probe {
            payload: "test".into(),
            tests: ProbeTarget::SqlKeyword("SELECT".into()),
            description: "test".into(),
            expected_blocked: true,
        };
        result.record(&probe, true);
        result.record(&probe, true);
        assert_eq!(result.blocked_sql_keywords.len(), 1);
        assert_eq!(result.blocked_sql_keywords[0], "SELECT");
    }

    #[test]
    fn default_impl_equivalent_to_new() {
        let first = DifferentialResult::new();
        let second = DifferentialResult::default();
        assert_eq!(first.total_probes, second.total_probes);
        assert_eq!(first.total_blocked, second.total_blocked);
    }
}
