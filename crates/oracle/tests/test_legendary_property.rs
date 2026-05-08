use proptest::prelude::*;
use wafrift_grammar::grammar::PayloadType;
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::ldap::LdapOracle;
use wafrift_oracle::oracle_for;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::traits::PayloadOracle;
use wafrift_oracle::xss::XssOracle;

proptest! {
    #[test]
    fn test_cmdi_oracle_does_not_panic(s in ".*") {
        let oracle = CmdiOracle;
        let _ = oracle.is_semantically_valid("; id", &s);
    }

    #[test]
    fn test_ldap_oracle_does_not_panic(s in ".*") {
        let oracle = LdapOracle;
        let _ = oracle.is_semantically_valid("(uid=admin)", &s);
    }

    #[test]
    fn test_path_oracle_does_not_panic(s in ".*") {
        let oracle = PathOracle;
        let _ = oracle.is_semantically_valid("../etc/passwd", &s);
    }

    #[test]
    fn test_ssrf_oracle_does_not_panic(s in ".*") {
        let oracle = SsrfOracle;
        let _ = oracle.is_semantically_valid("http://127.0.0.1", &s);
    }

    #[test]
    fn test_ssti_oracle_does_not_panic(s in ".*") {
        let oracle = SstiOracle;
        let _ = oracle.is_semantically_valid("{{7*7}}", &s);
    }

    #[test]
    fn test_xss_oracle_does_not_panic(s in ".*") {
        let oracle = XssOracle;
        let _ = oracle.is_semantically_valid("<script>alert(1)</script>", &s);
    }

    #[test]
    fn test_oracle_for_does_not_panic(payload_type_u8 in 0u8..255u8) {
        // Try all payload types implicitly
        let payload_types = [
            PayloadType::Unknown,
            PayloadType::Sql,
            PayloadType::Xss,
            PayloadType::TemplateInjection,
            PayloadType::CommandInjection,
            PayloadType::PathTraversal,
            PayloadType::Ldap,
            PayloadType::Ssrf,
        ];

        let payload_type = payload_types[(payload_type_u8 as usize) % payload_types.len()];
        let _ = oracle_for(payload_type);
    }
}
