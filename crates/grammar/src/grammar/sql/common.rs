//! Shared SQL grammar mutation types and helpers.

use serde::Deserialize;
use std::sync::OnceLock;

/// A single SQL mutation with metadata.
#[derive(Debug, Clone)]
pub struct SqlMutation {
    /// The mutated payload.
    pub payload: String,
    /// Human-readable description of what changed.
    pub description: String,
    /// Which mutation rules were applied.
    pub rules_applied: Vec<&'static str>,
}

/// SQL comment terminators.
pub(crate) const COMMENT_TERMINATORS: &[&str] =
    &["--", "-- ", "--+", "#", "/*", ";--", "-- -", ";#"];

/// Characters and sequences that can act as whitespace in SQL.
pub(crate) const WHITESPACE_ALTERNATIVES: &[&str] = &[
    " ", "\t", "\n", "/**/", "/**_***/", "+(+", "%0a", "%0d", "%0c", "%0b", "%a0",
];

// ──────────────────────────────────────────────
//  TOML-loaded operator alternatives
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for SQL operators.
const SQL_OPERATORS_TOML: &str = include_str!("../../../rules/sql/operators.toml");

/// OR alternative definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct OrAlternative {
    pattern: String,
    #[allow(dead_code)]
    description: String,
}

/// AND alternative definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct AndAlternative {
    pattern: String,
    #[allow(dead_code)]
    description: String,
}

/// Equality alternative definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct EqualityAlternative {
    pattern: String,
    #[allow(dead_code)]
    description: String,
}

/// Root structure for operators.toml.
#[derive(Debug, Clone, Deserialize)]
struct SqlOperatorRules {
    #[serde(default)]
    or_alternative: Vec<OrAlternative>,
    #[serde(default)]
    and_alternative: Vec<AndAlternative>,
    #[serde(default)]
    equality_alternative: Vec<EqualityAlternative>,
}

impl Default for SqlOperatorRules {
    fn default() -> Self {
        Self {
            or_alternative: vec![
                OrAlternative {
                    pattern: "OR".into(),
                    description: "Standard SQL OR".into(),
                },
                OrAlternative {
                    pattern: "||".into(),
                    description: "SQLite/Oracle OR".into(),
                },
            ],
            and_alternative: vec![
                AndAlternative {
                    pattern: "AND".into(),
                    description: "Standard SQL AND".into(),
                },
                AndAlternative {
                    pattern: "&&".into(),
                    description: "MySQL logical AND".into(),
                },
            ],
            equality_alternative: vec![
                EqualityAlternative {
                    pattern: "=".into(),
                    description: "Standard equality".into(),
                },
                EqualityAlternative {
                    pattern: " LIKE ".into(),
                    description: "LIKE operator".into(),
                },
                EqualityAlternative {
                    pattern: " REGEXP ".into(),
                    description: "REGEXP operator".into(),
                },
            ],
        }
    }
}

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static SqlOperatorRules {
    static RULES: OnceLock<SqlOperatorRules> = OnceLock::new();
    RULES.get_or_init(|| {
        toml::from_str(SQL_OPERATORS_TOML).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "invalid TOML in rules/sql/operators.toml");
            SqlOperatorRules::default()
        })
    })
}

/// Get logical `OR` alternatives across SQL dialects.
pub(crate) fn or_alternatives() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .or_alternative
            .iter()
            .map(|a| a.pattern.clone())
            .collect()
    })
}

/// Get logical `AND` alternatives across SQL dialects.
pub(crate) fn and_alternatives() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .and_alternative
            .iter()
            .map(|a| a.pattern.clone())
            .collect()
    })
}

/// Get equality-like alternatives that commonly bypass pattern matching.
pub(crate) fn equality_alternatives() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .equality_alternative
            .iter()
            .map(|a| a.pattern.clone())
            .collect()
    })
}

/// Extract the first single-quoted string value from a payload.
pub(crate) fn extract_quoted_string(payload: &str) -> Option<String> {
    let chars: Vec<char> = payload.chars().collect();
    let mut start = None;

    for (index, ch) in chars.iter().copied().enumerate() {
        if ch != '\'' {
            continue;
        }

        if let Some(open_index) = start {
            let value: String = chars[open_index + 1..index].iter().collect();
            if !value.is_empty() && value.len() <= 20 {
                return Some(value);
            }
            start = None;
        } else {
            start = Some(index);
        }
    }

    None
}
