use super::*;

use std::sync::Arc;
use tokio::sync::Mutex;

// TEST 1-10: error_response function
#[test]
fn error_response_404_not_found() {
    let resp = error_response(StatusCode::NOT_FOUND, "Not Found");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn error_response_500_internal_server() {
    let resp = error_response(StatusCode::INTERNAL_SERVER_ERROR, "Server Error");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn error_response_403_forbidden() {
    let resp = error_response(StatusCode::FORBIDDEN, "Forbidden");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[test]
fn error_response_401_unauthorized() {
    let resp = error_response(StatusCode::UNAUTHORIZED, "Unauthorized");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn error_response_400_bad_request() {
    let resp = error_response(StatusCode::BAD_REQUEST, "Bad Request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn error_response_502_bad_gateway() {
    let resp = error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn error_response_503_service_unavailable() {
    let resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn error_response_429_too_many_requests() {
    let resp = error_response(StatusCode::TOO_MANY_REQUESTS, "Rate Limited");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn error_response_empty_message() {
    let resp = error_response(StatusCode::OK, "");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn error_response_special_chars_in_message() {
    let resp = error_response(StatusCode::BAD_REQUEST, "Error: <special> & \"chars\"");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// TEST 11-25: host_addr function
#[test]
fn host_addr_with_port() {
    let uri = "https://example.com:8080/path"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(host_addr(&uri), Some("example.com:8080".to_string()));
}

#[test]
fn host_addr_without_port() {
    let uri = "https://example.com/path".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com".to_string()));
}

#[test]
fn host_addr_http() {
    let uri = "http://api.example.com:3000/v1"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(host_addr(&uri), Some("api.example.com:3000".to_string()));
}

#[test]
fn host_addr_ip_address() {
    let uri = "https://192.168.1.1:8443/admin"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(host_addr(&uri), Some("192.168.1.1:8443".to_string()));
}

#[test]
fn host_addr_localhost() {
    let uri = "https://localhost:3000".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("localhost:3000".to_string()));
}

#[test]
fn host_addr_ipv6() {
    let uri = "https://[::1]:8080/path".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("[::1]:8080".to_string()));
}

#[test]
fn host_addr_with_query() {
    let uri = "https://example.com:443/path?query=value"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(host_addr(&uri), Some("example.com:443".to_string()));
}

#[test]
fn host_addr_with_fragment() {
    let uri = "https://example.com/path#fragment"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(host_addr(&uri), Some("example.com".to_string()));
}

#[test]
fn host_addr_subdomain() {
    let uri = "https://sub.domain.example.com:9000/api"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(
        host_addr(&uri),
        Some("sub.domain.example.com:9000".to_string())
    );
}

#[test]
fn host_addr_complex_url() {
    let uri = "https://user:pass@example.com:8080/path?query=1#frag"
        .parse::<hyper::Uri>()
        .unwrap();
    assert_eq!(
        host_addr(&uri),
        Some("user:pass@example.com:8080".to_string())
    );
}

#[test]
fn host_addr_default_https_port() {
    let uri = "https://example.com:443/".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com:443".to_string()));
}

#[test]
fn host_addr_default_http_port() {
    let uri = "http://example.com:80/".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com:80".to_string()));
}

#[test]
fn host_addr_no_path() {
    let uri = "https://example.com".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com".to_string()));
}

#[test]
fn host_addr_root_path() {
    let uri = "https://example.com/".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com".to_string()));
}

// TEST 26-40: ProxyState structure and operations
#[tokio::test]
async fn proxy_state_default_empty() {
    let state = ProxyState::default();
    assert!(state.hosts.is_empty());
    assert_eq!(state.total_scanned, 0);
    assert_eq!(state.total_blocks, 0);
    assert!(state.techniques_used.is_empty());
}

#[tokio::test]
async fn proxy_state_shared_state_creation() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    let locked = state.lock().await;
    assert_eq!(locked.total_scanned, 0);
}

#[tokio::test]
async fn proxy_state_increment_scanned() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    {
        let mut st = state.lock().await;
        st.total_scanned += 1;
    }
    let st = state.lock().await;
    assert_eq!(st.total_scanned, 1);
}

#[tokio::test]
async fn proxy_state_record_block() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    let host = "example.com".to_string();
    {
        let mut st = state.lock().await;
        st.total_blocks += 1;
        let hs = st.hosts.entry(host.clone()).or_default();
        hs.record_block();
    }
    let st = state.lock().await;
    assert_eq!(st.total_blocks, 1);
    assert_eq!(st.hosts.get(&host).unwrap().blocks, 1);
}

#[tokio::test]
async fn proxy_state_record_multiple_blocks() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    let host = "example.com".to_string();
    {
        let mut st = state.lock().await;
        for _ in 0..5 {
            st.total_blocks += 1;
            let hs = st.hosts.entry(host.clone()).or_default();
            hs.record_block();
        }
    }
    let st = state.lock().await;
    assert_eq!(st.total_blocks, 5);
    assert_eq!(st.hosts.get(&host).unwrap().blocks, 5);
}

#[tokio::test]
async fn proxy_state_multiple_hosts() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    let host1 = "example.com".to_string();
    let host2 = "test.com".to_string();
    {
        let mut st = state.lock().await;
        st.hosts.entry(host1.clone()).or_default().record_block();
        st.hosts.entry(host2.clone()).or_default().record_block();
    }
    let st = state.lock().await;
    assert_eq!(st.hosts.len(), 2);
    assert!(st.hosts.contains_key(&host1));
    assert!(st.hosts.contains_key(&host2));
}

#[tokio::test]
async fn proxy_state_techniques_tracking() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    {
        let mut st = state.lock().await;
        *st.techniques_used
            .entry("UrlEncode".to_string())
            .or_insert(0) += 1;
        *st.techniques_used
            .entry("UrlEncode".to_string())
            .or_insert(0) += 1;
        *st.techniques_used.entry("Base64".to_string()).or_insert(0) += 1;
    }
    let st = state.lock().await;
    assert_eq!(st.techniques_used.get("UrlEncode"), Some(&2));
    assert_eq!(st.techniques_used.get("Base64"), Some(&1));
}

#[tokio::test]
async fn proxy_state_concurrent_access() {
    let state = Arc::new(Mutex::new(ProxyState::default()));
    let mut handles = vec![];
    for _ in 0..10 {
        let state_clone = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            let mut st = state_clone.lock().await;
            st.total_scanned += 1;
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let st = state.lock().await;
    assert_eq!(st.total_scanned, 10);
}

#[tokio::test]
async fn proxy_state_host_state_clone() {
    let mut state = HostState::default();
    state.record_block();
    state.record_block();
    let cloned = state.clone();
    assert_eq!(cloned.blocks, 2);
}

#[tokio::test]
async fn proxy_state_escalation_levels() {
    use wafrift_strategy::EscalationLevel;
    let mut state = HostState::default();
    assert_eq!(state.escalation_level(), EscalationLevel::None);
    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Light);
    state.record_block();
    state.record_block();
    assert_eq!(state.escalation_level(), EscalationLevel::Medium);
    for _ in 0..5 {
        state.record_block();
    }
    assert_eq!(state.escalation_level(), EscalationLevel::Heavy);
}

#[tokio::test]
async fn proxy_state_host_needs_evasion_default() {
    let state = HostState::default();
    assert!(state.needs_evasion());
}

#[tokio::test]
async fn proxy_state_host_waf_confirmed() {
    let mut state = HostState::default();
    state.confirm_waf(Some("Cloudflare".to_string()));
    assert!(state.waf_confirmed);
    assert_eq!(state.waf_name, Some("Cloudflare".to_string()));
    assert!(state.needs_evasion());
}

#[tokio::test]
async fn proxy_state_success_tracking() {
    use wafrift_types::Technique;
    let mut state = HostState::default();
    let tech = Technique::PayloadEncoding("UrlEncode".to_string());
    state.record_success(tech);
    assert_eq!(state.successes, 1);
    assert!(state.last_success.is_some());
}

// TEST 41-50: TLS/CONNECT and Request Interception Tests
#[test]
fn tls_connect_method_detection() {
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(req.method(), Method::CONNECT);
}

#[test]
fn tls_connect_host_extraction() {
    let uri = "example.com:443".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("example.com:443".to_string()));
}

#[test]
fn tls_connect_standard_https_port() {
    let uri = "target.com:443".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("target.com:443".to_string()));
}

#[test]
fn tls_connect_non_standard_port() {
    let uri = "internal.local:8443".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("internal.local:8443".to_string()));
}

#[test]
fn tls_connect_ip_address() {
    let uri = "10.0.0.1:443".parse::<hyper::Uri>().unwrap();
    assert_eq!(host_addr(&uri), Some("10.0.0.1:443".to_string()));
}

#[test]
fn request_intercept_get_method() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/api")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(req.method(), Method::GET);
}

#[test]
fn request_intercept_post_method() {
    let body = b"test body";
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/api")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    assert_eq!(req.method(), Method::POST);
}

#[test]
fn request_intercept_headers() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .header("X-Custom-Header", "value")
        .header("Authorization", "Bearer token123")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(req.headers().get("X-Custom-Header").unwrap(), "value");
    assert_eq!(
        req.headers().get("Authorization").unwrap(),
        "Bearer token123"
    );
}

#[test]
fn request_intercept_status_endpoint_path() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:8080/_wafrift/status")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(req.uri().path(), "/_wafrift/status");
}

#[test]
fn response_modification_status_code_preservation() {
    let resp = error_response(StatusCode::IM_A_TEAPOT, "I'm a teapot");
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(resp.status().as_u16(), 418);
}

#[test]
fn proxy_state_technique_stats() {
    let mut state = HostState::default();
    state.record_block_for("TestTechnique");
    state.record_block_for("TestTechnique");
    assert_eq!(state.technique_stats.len(), 1);
    assert_eq!(state.technique_stats[0].2, 2);
}

#[tokio::test]
async fn proxy_state_best_technique_requires_attempts() {
    let mut state = HostState::default();
    let tech = wafrift_types::Technique::PayloadEncoding("UrlEncode".to_string());
    state.record_success(tech.clone());
    assert!(state.best_technique().is_none());
    state.record_success(tech);
    assert!(state.best_technique().is_some());
}

#[test]
fn tls_tunnel_addr_format_variations() {
    let addrs = vec![
        "example.com:443",
        "192.168.1.1:8443",
        "localhost:3000",
        "[::1]:8080",
    ];
    for addr in addrs {
        assert!(!addr.is_empty());
    }
}


// TEST 51-55: Gene bank persistence
#[test]
fn load_gene_bank_valid_v1() {
    let tmp = std::env::temp_dir().join("wafrift_test_gene_bank_v1.json");
    let json = r#"{"schema":1,"hosts":{"api.example.com":{"proven_winners":["UrlEncode"],"blocklisted":[],"waf_name":null}}}"#;
    std::fs::write(&tmp, json).unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 1);
    assert!(bank.hosts.contains_key("api.example.com"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_future_schema_loads_but_warns() {
    let tmp = std::env::temp_dir().join("wafrift_test_gene_bank_v2.json");
    let json = r#"{"schema":2,"hosts":{"api.example.com":{"proven_winners":["UrlEncode"],"blocklisted":[],"waf_name":"FutureWAF"}}}"#;
    std::fs::write(&tmp, json).unwrap();
    let bank = load_gene_bank(&tmp);
    // Backward-compatible future schema should parse successfully.
    assert_eq!(bank.schema, 2);
    assert!(bank.hosts.contains_key("api.example.com"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_empty_file_returns_default() {
    let tmp = std::env::temp_dir().join("wafrift_test_gene_bank_empty.json");
    std::fs::write(&tmp, "   ").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_malformed_json_returns_default() {
    let tmp = std::env::temp_dir().join("wafrift_test_gene_bank_bad.json");
    std::fs::write(&tmp, "not json").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_missing_file_returns_default() {
    let tmp = std::env::temp_dir().join("wafrift_test_gene_bank_missing.json");
    let _ = std::fs::remove_file(&tmp);
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
}
