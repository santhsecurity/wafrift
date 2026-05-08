use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::ssti::SstiOracle;
use wafrift_oracle::traits::PayloadOracle;

#[test]
fn ssrf_rejects_malformed_bracket_url() {
    let oracle = SsrfOracle;
    assert!(!oracle.is_semantically_valid("http://127.0.0.1", "http://[127.0.0.1",));
}

#[test]
fn ssti_accepts_smarty_style_brace_expression() {
    let oracle = SstiOracle;
    assert!(oracle.is_semantically_valid("{7*7}", "{7*7}"));
}
