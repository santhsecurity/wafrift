use wafrift_grammar::grammar::PayloadType;
use wafrift_oracle::SqlOracle;
use wafrift_oracle::oracle_for;
use wafrift_oracle::sql::{DatabaseDialect, is_valid_expression_injection, is_valid_query};
use wafrift_oracle::traits::PayloadOracle;

use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ldap::LdapOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::xss::XssOracle;

#[test]
fn test_sql_oracle_new() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SqlOracle::new(DatabaseDialect::PostgreSql);
    assert_eq!(oracle.dialect, DatabaseDialect::PostgreSql);
    assert_eq!(oracle.name(), "SQL");
    Ok(())
}

#[test]
fn test_sql_oracle_generic() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SqlOracle::generic();
    assert_eq!(oracle.dialect, DatabaseDialect::Generic);
    assert_eq!(oracle.name(), "SQL");
    Ok(())
}

#[test]
fn test_oracle_for() -> Result<(), Box<dyn std::error::Error>> {
    assert!(oracle_for(PayloadType::Sql).is_some());
    assert!(oracle_for(PayloadType::Xss).is_some());
    assert!(oracle_for(PayloadType::TemplateInjection).is_some());
    assert!(oracle_for(PayloadType::CommandInjection).is_some());
    assert!(oracle_for(PayloadType::PathTraversal).is_some());
    assert!(oracle_for(PayloadType::Ldap).is_some());
    assert!(oracle_for(PayloadType::Ssrf).is_some());

    assert!(oracle_for(PayloadType::Unknown).is_none());
    Ok(())
}

#[test]
fn test_is_valid_expression_injection() -> Result<(), Box<dyn std::error::Error>> {
    assert!(is_valid_expression_injection(
        "1 OR 1=1",
        DatabaseDialect::Generic
    ));
    assert!(!is_valid_expression_injection(
        "1 OR OR 1=1",
        DatabaseDialect::Generic
    ));
    Ok(())
}

#[test]
fn test_is_valid_query() -> Result<(), Box<dyn std::error::Error>> {
    assert!(is_valid_query(
        "SELECT * FROM users",
        DatabaseDialect::Generic
    ));
    assert!(!is_valid_query(
        "SELECT * FROM users WHERE",
        DatabaseDialect::Generic
    ));
    Ok(())
}

#[test]
fn test_cmdi_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = CmdiOracle;
    assert_eq!(oracle.name(), "CMDI");
    assert!(oracle.is_semantically_valid("orig", "; id"));
    assert!(!oracle.is_semantically_valid("orig", "id"));
    Ok(())
}

#[test]
fn test_ldap_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = LdapOracle;
    assert_eq!(oracle.name(), "LDAP");
    // A real filter-break injection is valid.
    assert!(oracle.is_semantically_valid("(uid=x)", "*)(|(uid=*"));
    // ANTI-RIG: a standalone benign equality filter is NOT an
    // injection (the previous assertion asserted it was — the rig).
    assert!(!oracle.is_semantically_valid("orig", "(uid=admin)"));
    // No filter structure at all is likewise not an injection.
    assert!(!oracle.is_semantically_valid("orig", "uid=admin"));
    Ok(())
}

#[test]
fn test_path_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = PathOracle;
    assert_eq!(oracle.name(), "PathTraversal");
    assert!(oracle.is_semantically_valid("orig", "../etc/passwd"));
    assert!(!oracle.is_semantically_valid("orig", "etc/passwd"));
    Ok(())
}

#[test]
fn test_ssrf_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SsrfOracle;
    assert_eq!(oracle.name(), "SSRF");
    assert!(oracle.is_semantically_valid("orig", "http://127.0.0.1"));
    assert!(!oracle.is_semantically_valid("orig", "127.0.0.1"));
    Ok(())
}

#[test]
fn test_ssti_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SstiOracle;
    assert_eq!(oracle.name(), "SSTI");
    assert!(oracle.is_semantically_valid("{{7*7}}", "{{7*7}}"));
    assert!(!oracle.is_semantically_valid("{{7*7}}", "7*7"));
    Ok(())
}

#[test]
fn test_xss_oracle() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = XssOracle;
    assert_eq!(oracle.name(), "XSS");
    assert!(oracle.is_semantically_valid("orig", "<script>alert(1)</script>"));
    assert!(!oracle.is_semantically_valid("orig", "alert(1)"));
    Ok(())
}
