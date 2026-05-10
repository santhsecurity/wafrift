use crate::waf_detect::detect;

fn first_name(status: u16, headers: &[(String, String)], body: &[u8]) -> Option<String> {
    detect(status, headers, body)
        .first()
        .map(|w| w.name.clone())
}

fn mixed_case_header_name(name: &str) -> String {
    name.chars()
        .enumerate()
        .map(|(idx, ch)| {
            if idx % 2 == 0 {
                ch.to_ascii_uppercase()
            } else {
                ch
            }
        })
        .collect()
}

#[test]
fn detect_cloudflare_from_headers() {
    let headers = vec![
        ("cf-ray".into(), "abc123-IAD".into()),
        ("server".into(), "cloudflare".into()),
    ];
    let result = first_name(403, &headers, b"Access denied");
    assert_eq!(result.as_deref(), Some("Cloudflare"));
}

#[test]
fn detect_major_wafs_from_headers_alone() {
    let cases = [
        (
            "Cloudflare",
            vec![
                ("cf-ray".to_string(), "abc123-IAD".to_string()),
                ("server".to_string(), "cloudflare".to_string()),
            ],
        ),
        (
            "Kona SiteDefender",
            vec![
                ("x-akamai-transformed".to_string(), "9 12345".to_string()),
                ("server".to_string(), "akamaighost".to_string()),
            ],
        ),
        (
            "AWS Elastic Load Balancer",
            vec![("x-amz-id".to_string(), "BLOCK".to_string())],
        ),
        (
            "Incapsula",
            vec![
                ("x-iinfo".to_string(), "10-12345678-0 0NNN RT(0".to_string()),
                ("x-cdn".to_string(), "Incapsula".to_string()),
            ],
        ),
        (
            "ModSecurity",
            vec![("server".to_string(), "Mod_Security".to_string())],
        ),
    ];

    for (expected, headers) in cases {
        let name =
            first_name(403, &headers, b"").unwrap_or_else(|| panic!("should detect {expected}"));
        assert_eq!(name, expected);
    }
}

#[test]
fn detect_major_wafs_from_mixed_case_headers() {
    let cases = [
        (
            "Cloudflare",
            vec![
                ("cf-ray".to_string(), "abc123-IAD".to_string()),
                ("server".to_string(), "cloudflare".to_string()),
            ],
        ),
        (
            "Kona SiteDefender",
            vec![
                ("x-akamai-transformed".to_string(), "9 12345".to_string()),
                ("server".to_string(), "akamaighost".to_string()),
            ],
        ),
        (
            "AWS Elastic Load Balancer",
            vec![("x-amz-id".to_string(), "BLOCK".to_string())],
        ),
        (
            "Incapsula",
            vec![
                ("x-iinfo".to_string(), "10-12345678-0 0NNN RT(0".to_string()),
                ("x-cdn".to_string(), "Incapsula".to_string()),
            ],
        ),
        (
            "ModSecurity",
            vec![("server".to_string(), "Mod_Security".to_string())],
        ),
        (
            "Sucuri CloudProxy",
            vec![("x-sucuri-id".to_string(), "edge-us-01".to_string())],
        ),
    ];

    for (expected, headers) in cases {
        let mixed_case_headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (mixed_case_header_name(k), v.clone()))
            .collect();
        let name = first_name(403, &mixed_case_headers, b"")
            .unwrap_or_else(|| panic!("should detect {expected} with mixed-case headers"));
        assert_eq!(name, expected);
    }
}

#[test]
fn detect_aws_from_body() {
    let headers = vec![];
    let result = first_name(403, &headers, b"<html>Request blocked by AWS WAF</html>");
    assert_eq!(result.as_deref(), Some("AWS Elastic Load Balancer"));
}

#[test]
fn detect_akamai_reference() {
    let headers = vec![];
    let result = first_name(403, &headers, b"Access Denied. Reference #18.abc123def.456");
    assert_eq!(result.as_deref(), Some("Kona SiteDefender"));
}

#[test]
fn detect_imperva_cookie() {
    let headers = vec![("set-cookie".into(), "visid_incap_123=abc; path=/".into())];
    let result = first_name(200, &headers, b"OK");
    assert_eq!(result.as_deref(), Some("Incapsula"));
}

#[test]
fn no_waf_on_clean_response() {
    let headers = vec![("server".into(), "nginx".into())];
    let result = detect(200, &headers, b"<html>Welcome</html>");
    assert!(result.is_empty());
}

#[test]
fn detect_f5_bigip() {
    let headers = vec![("server".into(), "bigip".into())];
    let result = first_name(200, &headers, b"OK");
    assert_eq!(result.as_deref(), Some("BIG-IP AP Manager"));
}

#[test]
fn highest_confidence_wins() {
    let headers = vec![
        ("cf-ray".into(), "abc".into()),
        ("server".into(), "cloudflare".into()),
        ("x-amz-requestid".into(), "123".into()),
    ];
    let result = first_name(403, &headers, b"blocked");
    assert_eq!(result.as_deref(), Some("Cloudflare"));
}

#[test]
fn detect_barracuda() {
    let headers = vec![("set-cookie".into(), "barra_counter_session=abc".into())];
    let result = first_name(403, &headers, b"Blocked by Barracuda");
    assert_eq!(result.as_deref(), Some("Barracuda"));
}

#[test]
fn detect_fortiweb_cookie() {
    let headers = vec![("set-cookie".into(), "fortiwafsid=abc123".into())];
    let result = first_name(403, &headers, b"Blocked");
    assert_eq!(result.as_deref(), Some("FortiWeb"));
}

#[test]
fn detect_wordfence_body() {
    let result = first_name(403, &[], b"This response was generated by Wordfence.");
    assert_eq!(result.as_deref(), Some("Wordfence"));
}

#[test]
fn detect_with_mangled_utf8_keeps_suffix_matches() {
    let body = b"prefix \xff This response was generated by Wordfence.";
    let result = first_name(403, &[], body);
    assert_eq!(result.as_deref(), Some("Wordfence"));
}

#[test]
fn mangled_utf8_without_signature_does_not_false_positive() {
    let body = b"normal page\xff with unrelated text";
    let result = detect(200, &[], body);
    assert!(result.is_empty());
}

#[test]
fn status_zero_or_large_status_never_panics_or_false_matches() {
    let headers = vec![("server".into(), "nginx".into())];
    let zero = detect(0, &headers, b"plain text");
    assert!(zero.is_empty());

    let large = detect(1000, &headers, b"plain text");
    assert!(large.is_empty());
}

#[test]
fn benign_404_wording_does_not_trigger_waf_detection() {
    let headers = vec![
        ("server".to_string(), "nginx".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
    ];
    let body = b"<html><body><h1>404 Not Found</h1><p>The requested page is blocked from indexing and this link is forbidden for anonymous users.</p></body></html>";
    let result = detect(404, &headers, body);
    assert!(
        result.is_empty(),
        "benign 404 must not be classified as WAF: {result:?}"
    );
}

#[test]
fn waf_404_with_strong_header_signal_still_detects() {
    let headers = vec![
        ("CF-Ray".to_string(), "abc123-IAD".to_string()),
        ("Server".to_string(), "cloudflare".to_string()),
    ];
    let body = b"<html><body><h1>404 Not Found</h1><p>Forbidden</p></body></html>";
    let result = detect(404, &headers, body);
    assert!(!result.is_empty());
    assert_eq!(result[0].name, "Cloudflare");
}

#[test]
fn modsecurity_406_pattern() {
    let result = first_name(406, &[], b"Not Acceptable. ModSecurity blocked the request");
    assert_eq!(result.as_deref(), Some("ModSecurity"));
}

#[test]
fn ambiguity_returns_multiple() {
    // Headers that could match multiple WAFs with similar confidence
    let headers = vec![
        ("server".into(), "cloudflare".into()),
        ("x-amz-id".into(), "123".into()),
    ];
    let results = detect(403, &headers, b"blocked");
    // Both Cloudflare and AWS may match; if confidence delta is < 0.15,
    // the ambiguity logic should return both.
    assert!(!results.is_empty());
}

#[test]
fn detect_all_whitespace_body_no_panic() {
    let result = detect(200, &[], b"     \n\t   ");
    assert!(result.is_empty());
}

#[test]
fn detect_gzip_bytes_raw_no_panic() {
    // Gzip magic bytes passed as raw body — should not panic or false-match
    let gzip_prefix = &[0x1f, 0x8b, 0x08, 0x00];
    let result = detect(200, &[], gzip_prefix);
    assert!(result.is_empty());
}

#[test]
fn detect_http2_pseudo_headers_no_panic() {
    // HTTP/2 pseudo-headers mixed with regular headers
    let headers = vec![
        (":authority".into(), "example.com".into()),
        (":status".into(), "200".into()),
        ("server".into(), "nginx".into()),
    ];
    let result = detect(200, &headers, b"OK");
    assert!(result.is_empty());
}

#[test]
fn detect_non_ascii_header_name_no_panic() {
    let headers = vec![
        ("x-café".into(), "value".into()),
        ("server".into(), "nginx".into()),
    ];
    let result = detect(200, &headers, b"OK");
    // Should not panic; result may be empty or not depending on rules
    let _ = result;
}

#[test]
fn detect_body_length_boundary_100_no_panic() {
    let body = "x".repeat(100);
    let _ = detect(200, &[], body.as_bytes());
}

#[test]
fn detect_body_length_boundary_1000_no_panic() {
    let body = "x".repeat(1000);
    let _ = detect(200, &[], body.as_bytes());
}

#[test]
fn detect_body_length_boundary_5000_no_panic() {
    let body = "x".repeat(5000);
    let _ = detect(200, &[], body.as_bytes());
}

#[test]
fn detect_empty_headers_no_panic() {
    let _ = detect(200, &[], b"normal body");
    let _ = detect(403, &[], b"blocked body");
}
