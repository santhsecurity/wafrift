use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ldap::LdapOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::traits::PayloadOracle;
use wafrift_oracle::xss::XssOracle;

#[test]
fn test_cmdi_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = CmdiOracle;
    let payload = "; id";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "; id\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![b';', b' ', b'i', b'd', 0xFF];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "; id ".to_string() + &"A".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}

#[test]
fn test_ldap_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = LdapOracle;
    let payload = "(uid=admin)";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "(uid=admin)\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![
        b'(', b'u', b'i', b'd', b'=', b'a', b'd', b'm', b'i', b'n', b')', 0xFF,
    ];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "(uid=admin)".to_string() + &" ".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}

#[test]
fn test_path_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = PathOracle;
    let payload = "../etc/passwd";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "../etc/passwd\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![
        b'.', b'.', b'/', b'e', b't', b'c', b'/', b'p', b'a', b's', b's', b'w', b'd', 0xFF,
    ];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "../etc/passwd".to_string() + &"A".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}

#[test]
fn test_ssrf_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SsrfOracle;
    let payload = "http://127.0.0.1";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "http://127.0.0.1\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![
        b'h', b't', b't', b'p', b':', b'/', b'/', b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.',
        b'1', 0xFF,
    ];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "http://127.0.0.1/".to_string() + &"A".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}

#[test]
fn test_ssti_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = SstiOracle;
    let payload = "{{7*7}}";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "{{7*7}}\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![b'{', b'{', b'7', b'*', b'7', b'}', b'}', 0xFF];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "{{7*7}}".to_string() + &" ".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}

#[test]
fn test_xss_adversarial() -> Result<(), Box<dyn std::error::Error>> {
    let oracle = XssOracle;
    let payload = "<script>alert(1)</script>";

    // Empty input
    assert!(!oracle.is_semantically_valid(payload, ""));

    // Null bytes
    assert!(oracle.is_semantically_valid(payload, "<script>alert(1)</script>\x00"));

    // Invalid UTF-8 bytes
    let invalid_utf8 = vec![
        b'<', b's', b'c', b'r', b'i', b'p', b't', b'>', b'a', b'l', b'e', b'r', b't', b'(', b'1',
        b')', b'<', b'/', b's', b'c', b'r', b'i', b'p', b't', b'>', 0xFF,
    ];
    let invalid_str = String::from_utf8_lossy(&invalid_utf8);
    assert!(oracle.is_semantically_valid(payload, &invalid_str));

    // Huge input (simulate ~1MB)
    let huge = "<script>alert(1)</script>".to_string() + &" ".repeat(1024 * 1024);
    assert!(oracle.is_semantically_valid(payload, &huge));

    Ok(())
}
