use wafrift_proxy::extract_host_from_header;

#[test]
fn test_extract_host_from_header_ipv6() {
    assert_eq!(extract_host_from_header("[::1]:8080"), "::1");
    assert_eq!(extract_host_from_header("[2001:db8::1]"), "2001:db8::1");
}

#[test]
fn test_extract_host_from_header_ipv4() {
    assert_eq!(extract_host_from_header("192.168.1.1:80"), "192.168.1.1");
    assert_eq!(extract_host_from_header("10.0.0.1"), "10.0.0.1");
}

#[test]
fn test_extract_host_from_header_domain() {
    assert_eq!(extract_host_from_header("example.com:443"), "example.com");
    assert_eq!(extract_host_from_header("localhost"), "localhost");
}
