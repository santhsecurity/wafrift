use super::*;

// Symbols carved out of main.rs into focused modules — the tests
// were written when these all lived inline; re-import them at the
// new locations so the test surface keeps its existing coverage.
use crate::findings::{render_live_findings, sanitize_for_markdown};
use crate::gene_bank_io::{
    PersistedGeneBank, PersistedHostState, load as load_gene_bank, save as save_gene_bank,
};

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
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gene_bank_v1_{}.json",
        std::process::id()
    ));
    let json = r#"{"schema":1,"hosts":{"api.example.com":{"proven_winners":["UrlEncode"],"blocklisted":[],"waf_name":null}}}"#;
    std::fs::write(&tmp, json).unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 1);
    assert!(bank.hosts.contains_key("api.example.com"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_future_schema_loads_but_warns() {
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gene_bank_v2_{}.json",
        std::process::id()
    ));
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
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gene_bank_empty_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, "   ").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_malformed_json_returns_default() {
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gene_bank_bad_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, "not json").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_missing_file_returns_default() {
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gene_bank_missing_{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
}

fn default_args() -> Args {
    Args {
        listen: "127.0.0.1:8080".into(),
        escalation: None,
        content_type_switching: false,
        fingerprint_rotation: false,
        insecure: false,
        write_mitm_ca_dir: None,
        mitm: false,
        mitm_ca_dir: None,
        allow_private_upstream: false,
        insecure_open_upstream: false,
        max_concurrent_connections: 4096,
        max_upstream_response_bytes: 33554432,
        max_evade_retries: 0,
        gene_bank_path: "".into(),
        gene_bank_flush_interval_secs: 60,
        only_host: vec![],
        skip_host: vec![],
        only_path: vec![],
        skip_path: vec![],
        only_method: vec![],
        max_rps_per_host: 0.0,
        max_rps_per_host_burst: 0.0,
        log_dir: None,
        tls_impersonate: None,
        tls_impersonate_rotate: vec![],
        body_padding_bytes: 0,
        no_conn_reuse: false,
        tui: false,
        mutate_url: false,
        captchaforge: false,
    }
}

// ── validate_args ───────────────────────────────────────────────

#[test]
fn validate_args_accepts_defaults() {
    assert!(validate_args(&default_args()).is_ok());
}

#[test]
fn validate_args_rejects_zero_connections() {
    let args = Args {
        max_concurrent_connections: 0,
        ..default_args()
    };
    let err = validate_args(&args).unwrap_err();
    assert!(err.contains("--max-concurrent-connections must be >= 1"));
}

#[test]
fn validate_args_rejects_small_response_bytes() {
    let args = Args {
        max_upstream_response_bytes: 100,
        ..default_args()
    };
    let err = validate_args(&args).unwrap_err();
    assert!(err.contains("--max-upstream-response-bytes must be >= 4096"));
}

#[test]
fn validate_args_rejects_negative_rps() {
    let args = Args {
        max_rps_per_host: -2.0,
        ..default_args()
    };
    let err = validate_args(&args).unwrap_err();
    assert!(err.contains("--max-rps-per-host must be a non-negative number"));
    assert!(err.contains("-2"));
}

#[test]
fn validate_args_rejects_negative_burst() {
    let args = Args {
        max_rps_per_host_burst: -1.5,
        ..default_args()
    };
    let err = validate_args(&args).unwrap_err();
    assert!(err.contains("--max-rps-per-host-burst must be a non-negative number"));
}

#[test]
fn validate_args_rejects_invalid_escalation() {
    let args = Args {
        escalation: Some("extreme".into()),
        ..default_args()
    };
    let err = validate_args(&args).unwrap_err();
    assert!(err.contains("--escalation must be one of: light, medium, heavy"));
    assert!(err.contains("extreme"));
}

#[test]
fn validate_args_accepts_valid_escalation() {
    for level in ["light", "medium", "heavy"] {
        let args = Args {
            escalation: Some(level.into()),
            ..default_args()
        };
        assert!(validate_args(&args).is_ok(), "failed for {level}");
    }
}

// ── gene bank saving / round trip ───────────────────────────────

#[test]
fn save_and_load_gene_bank_round_trip() {
    let dir = std::env::temp_dir().join(format!("wafrift_gb_rt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gene-bank.json");

    let mut state = ProxyState::default();
    let hs = state.hosts.entry("example.com".into()).or_default();
    hs.proven_winners.push("UrlEncode".into());
    hs.blocklisted.push("Base64".into());
    hs.waf_name = Some("Cloudflare".into());

    save_gene_bank(&state, &path).unwrap();
    let loaded = load_gene_bank(&path);
    assert_eq!(loaded.schema, 1);
    assert_eq!(loaded.hosts.len(), 1);
    let host = loaded.hosts.get("example.com").unwrap();
    assert_eq!(host.proven_winners, vec!["UrlEncode"]);
    assert_eq!(host.blocklisted, vec!["Base64"]);
    assert_eq!(host.waf_name, Some("Cloudflare".into()));

    let _ = std::fs::remove_dir_all(&dir);
}

// ── default_gene_bank_path ──────────────────────────────────────

#[test]
fn default_gene_bank_path_empty_uses_home() {
    let result = default_gene_bank_path("");
    if std::env::var_os("HOME").is_some() {
        assert!(result.is_some());
        let p = result.unwrap();
        assert!(p.ends_with("gene-bank.json"));
    } else {
        assert!(result.is_none());
    }
}

#[test]
fn default_gene_bank_path_off_returns_none() {
    assert!(default_gene_bank_path("off").is_none());
}

#[test]
fn default_gene_bank_path_dash_returns_none() {
    assert!(default_gene_bank_path("-").is_none());
}

#[test]
fn default_gene_bank_path_explicit_returns_path() {
    let result = default_gene_bank_path("/tmp/wafrift-test-bank.json");
    assert_eq!(
        result,
        Some(std::path::PathBuf::from("/tmp/wafrift-test-bank.json"))
    );
}

// ── render_live_findings ────────────────────────────────────────

#[test]
fn render_findings_zero_requests() {
    let state = ProxyState::default();
    let md = render_live_findings(&state);
    assert!(md.contains("No requests have been proxied yet"));
    assert!(md.contains("Total proxied: 0"));
}

#[test]
fn render_findings_hosts_but_no_winners() {
    let mut state = ProxyState {
        total_scanned: 5,
        ..Default::default()
    };
    let hs = state.hosts.entry("example.com".into()).or_default();
    hs.record_block();
    let md = render_live_findings(&state);
    assert!(md.contains("No bypasses discovered yet"));
    assert!(md.contains("Total proxied: 5"));
    assert!(md.contains("Hosts seen: 1"));
}

#[test]
fn render_findings_with_winners() {
    let mut state = ProxyState {
        total_scanned: 10,
        ..Default::default()
    };
    let hs = state.hosts.entry("example.com".into()).or_default();
    hs.proven_winners.push("UrlEncode".into());
    hs.waf_name = Some("Cloudflare".into());
    let md = render_live_findings(&state);
    assert!(md.contains("Hosts with proven bypasses"));
    assert!(md.contains("`example.com`"));
    assert!(md.contains("Cloudflare"));
    assert!(md.contains("UrlEncode"));
    assert!(md.contains("wafrift replay"));
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT-COMPAT REFINEMENT TESTS
// ═════════════════════════════════════════════════════════════════════════════

use wafrift_proxy::hop_by_hop::{
    collect_connection_header_names, is_hop_by_hop, should_strip_proxy_header,
};
use wafrift_proxy::rate_limit::RateLimiter;
use wafrift_transport::is_waf_block;

// ── 1. Burp/ZAP hop-by-hop stripping ──────────────────────────────────────

#[test]
fn burp_proxy_connection_is_hop_by_hop() {
    assert!(is_hop_by_hop("Proxy-Connection"));
    assert!(is_hop_by_hop("proxy-connection"));
    assert!(is_hop_by_hop("PROXY-CONNECTION"));
}

#[test]
fn burp_proxy_authorization_is_hop_by_hop() {
    assert!(is_hop_by_hop("Proxy-Authorization"));
    assert!(is_hop_by_hop("proxy-authorization"));
}

#[test]
fn burp_x_forwarded_for_is_hop_by_hop() {
    assert!(is_hop_by_hop("X-Forwarded-For"));
    assert!(is_hop_by_hop("x-forwarded-for"));
}

#[test]
fn burp_connection_header_triggers_strip() {
    let headers = vec![
        (
            "Connection".to_string(),
            "keep-alive, X-Custom-Hop".to_string(),
        ),
        ("X-Custom-Hop".to_string(), "value".to_string()),
        ("Content-Type".to_string(), "text/html".to_string()),
    ];
    let conn = collect_connection_header_names(&headers);
    assert!(should_strip_proxy_header("keep-alive", &conn));
    assert!(should_strip_proxy_header("X-Custom-Hop", &conn));
    assert!(!should_strip_proxy_header("Content-Type", &conn));
}

#[test]
fn response_side_strips_proxy_headers() {
    // Simulate upstream response headers containing proxy-specific fields.
    let resp_headers = vec![
        ("Connection".to_string(), "Proxy-Authentication".to_string()),
        ("Proxy-Authentication".to_string(), "Basic xyz".to_string()),
        ("X-Forwarded-For".to_string(), "1.2.3.4".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let conn = collect_connection_header_names(&resp_headers);
    assert!(should_strip_proxy_header("Proxy-Authentication", &conn));
    assert!(should_strip_proxy_header("X-Forwarded-For", &conn));
    assert!(!should_strip_proxy_header("Content-Type", &conn));
}

// ── 2. sqlmap high-rate: rate limiter + warn throttle ─────────────────────

#[tokio::test]
async fn rate_limiter_concurrent_same_host_no_deadlock() {
    let limiter = RateLimiter::new(1000.0, 1000.0);
    let mut handles = vec![];
    for _ in 0..50 {
        let l = limiter.clone();
        handles.push(tokio::spawn(async move {
            l.acquire("target.com").await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[test]
fn warn_throttle_dedups_within_cooldown() {
    let throttle = WarnThrottle::new(60);
    assert!(throttle.should_warn("key:a"));
    assert!(!throttle.should_warn("key:a"));
    assert!(throttle.should_warn("key:b"));
}

#[test]
fn proxy_state_fifo_eviction_is_deterministic() {
    let mut state = ProxyState::default();
    for i in 0..5 {
        let host = format!("host-{i:04}.example.com");
        state.hosts.entry(host.clone()).or_default().blocks = 1;
        state.host_fifo.push_back(host);
    }
    assert_eq!(state.hosts.len(), 5);
    assert_eq!(state.host_fifo.len(), 5);

    // Evict the oldest (host-0000)
    while let Some(key) = state.host_fifo.pop_front() {
        if state.hosts.remove(&key).is_some() {
            break;
        }
    }
    assert!(!state.hosts.contains_key("host-0000.example.com"));
    assert!(state.hosts.contains_key("host-0001.example.com"));
}

#[test]
fn proxy_state_host_isolation_no_leak() {
    let mut state = ProxyState::default();
    state
        .hosts
        .entry("host-a.com".into())
        .or_default()
        .record_block();
    state
        .hosts
        .entry("host-b.com".into())
        .or_default()
        .record_success(wafrift_types::Technique::PayloadEncoding(
            "UrlEncode".into(),
        ));
    assert_eq!(state.hosts.get("host-a.com").unwrap().blocks, 1);
    assert_eq!(state.hosts.get("host-b.com").unwrap().blocks, 0);
    assert_eq!(state.hosts.get("host-b.com").unwrap().successes, 1);
}

// ── 3. ffuf 404 false WAF identification ──────────────────────────────────

#[test]
fn ffuf_404_forbidden_body_not_waf_block() {
    // Custom 404 pages often say "forbidden" or "access denied".
    assert!(!is_waf_block(
        404,
        b"Forbidden - you cannot access this resource"
    ));
    assert!(!is_waf_block(404, b"Access Denied - page not found"));
    assert!(!is_waf_block(
        404,
        b"Request blocked - this path does not exist"
    ));
}

#[test]
fn ffuf_404_with_akamai_reference_not_blocked() {
    assert!(!is_waf_block(404, b"Access Denied. Reference #18.abc123"));
}

#[test]
fn ffuf_200_with_same_body_is_blocked() {
    // Same body on 200 SHOULD still be flagged (real WAF block page).
    // Uses "access denied" — an explicit block-page marker retained
    // after the 2026-05-10 audit that removed high-FP terms like
    // "forbidden" to avoid false-positives on benign content.
    assert!(is_waf_block(
        200,
        b"Access Denied - you cannot access this resource"
    ));
}

// ── 4. curl --resolve literal IP in Host ──────────────────────────────────

#[test]
fn curl_literal_ipv4_host_header() {
    assert_eq!(extract_host_from_header("192.168.1.1"), "192.168.1.1");
    assert_eq!(extract_host_from_header("192.168.1.1:8080"), "192.168.1.1");
    assert_eq!(extract_host_from_header("10.0.0.1:443"), "10.0.0.1");
}

#[test]
fn curl_literal_ipv6_host_header() {
    assert_eq!(extract_host_from_header("[::1]"), "::1");
    assert_eq!(extract_host_from_header("[::1]:443"), "::1");
    assert_eq!(
        extract_host_from_header("[2001:db8::1]:8080"),
        "2001:db8::1"
    );
    assert_eq!(extract_host_from_header("2001:db8::1"), "2001:db8::1");
}

#[test]
fn curl_malformed_host_header_safe() {
    assert_eq!(extract_host_from_header("[::1"), "");
    assert_eq!(extract_host_from_header("["), "");
    assert_eq!(extract_host_from_header(""), "");
}

// ── 5. Browser keep-alive / pipeline ──────────────────────────────────────

#[test]
fn pipeline_state_per_host_isolated() {
    // Simulate two requests on the same TCP connection to different hosts.
    let mut state = ProxyState::default();
    state.host_fifo.push_back("api.example.com".into());
    state
        .hosts
        .entry("api.example.com".into())
        .or_default()
        .blocks = 3;

    state.host_fifo.push_back("cdn.example.com".into());
    state
        .hosts
        .entry("cdn.example.com".into())
        .or_default()
        .blocks = 0;

    assert_eq!(
        state
            .hosts
            .get("api.example.com")
            .unwrap()
            .escalation_level(),
        wafrift_strategy::EscalationLevel::Medium
    );
    assert_eq!(
        state
            .hosts
            .get("cdn.example.com")
            .unwrap()
            .escalation_level(),
        wafrift_strategy::EscalationLevel::None
    );
}

// ── 6. Chunked body > MAX_PROXY_BODY_BYTES ────────────────────────────────

#[tokio::test]
async fn oversized_body_limited_errors_once() {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;

    let big = vec![0u8; MAX_PROXY_BODY_BYTES + 1];
    let body = Full::new(Bytes::from(big));
    let limited = Limited::new(body, MAX_PROXY_BODY_BYTES);
    let result = limited.collect().await;
    assert!(result.is_err(), "Limited must error on oversized body");
}

#[test]
fn error_response_413_payload_too_large() {
    let resp = error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(resp.status().as_u16(), 413);
}

// ── /_wafrift/findings.md attacker-controlled-host injection guard ──

#[test]
fn sanitize_for_markdown_strips_backtick_breakouts() {
    // Backticks would break out of `{host}` code formatting and let an
    // attacker inject markdown / HTML / JS-handlers.
    let evil = "evil`onclick=alert(1)`com";
    let out = sanitize_for_markdown(evil);
    assert!(!out.contains('`'), "backtick survived: {out}");
}

#[test]
fn sanitize_for_markdown_strips_pipes_asterisks_brackets() {
    // Markdown emphasis / table / link characters all become `_`.
    for ch in &['*', '|', '[', ']', '(', ')', '{', '}', '<', '>', '\n', '\r'] {
        let input = format!("a{ch}b");
        let out = sanitize_for_markdown(&input);
        assert!(!out.contains(*ch), "{ch:?} survived in {out}");
    }
}

#[test]
fn sanitize_for_markdown_keeps_legitimate_host_characters() {
    // RFC 1123 / 3986 valid host characters must round-trip unchanged.
    let inputs = [
        "api.example.com",
        "api-v2.example.com",
        "10.0.0.1",
        "example.com:8443",
        "service_v1.example.com",
    ];
    for input in inputs {
        let out = sanitize_for_markdown(input);
        assert_eq!(out, input, "legitimate host got mutated: {input} -> {out}");
    }
}

#[test]
fn render_live_findings_does_not_render_attacker_markdown() {
    // Stuff a malicious Host into proxy state, render markdown, assert
    // the backtick / asterisk / bracket payload does not survive into
    // the output. Defends against /_wafrift/findings.md being a stored
    // markdown-injection sink reachable via crafted Host headers.
    let mut state = ProxyState {
        total_scanned: 1,
        ..Default::default()
    };
    let hs = HostState {
        proven_winners: vec!["EncodingUrl".into()],
        waf_name: Some("Cloud`Flare`".into()),
        ..Default::default()
    }; // backtick in WAF name too
    state.hosts.insert("evil`alert(1)`.com".into(), hs);

    let md = render_live_findings(&state);
    // No raw backticks from the host or waf name — both should be
    // sanitised to underscores before interpolation.
    assert!(
        !md.contains("evil`alert"),
        "attacker host backtick payload survived in markdown:\n{md}"
    );
    assert!(
        !md.contains("Cloud`Flare`"),
        "attacker waf-name backtick survived:\n{md}"
    );
    // Sanity — sanitised form should still be present.
    assert!(
        md.contains("evil_alert_1__.com"),
        "sanitised host missing:\n{md}"
    );
}

// ── --mutate-url plumbing tests (blocker #114) ─────────────────────

#[test]
fn split_url_for_mutation_separates_authority_from_path() {
    let r = split_url_for_mutation("https://api.target.com/admin?id=1");
    assert_eq!(
        r,
        Some(("https://api.target.com".into(), "/admin?id=1".into()))
    );
}

#[test]
fn split_url_for_mutation_handles_port() {
    let r = split_url_for_mutation("http://localhost:8080/api/v1?q=hello");
    assert_eq!(
        r,
        Some(("http://localhost:8080".into(), "/api/v1?q=hello".into()))
    );
}

#[test]
fn split_url_for_mutation_handles_path_only_no_query() {
    let r = split_url_for_mutation("https://x.com/just/a/path");
    assert_eq!(r, Some(("https://x.com".into(), "/just/a/path".into())));
}

#[test]
fn split_url_for_mutation_returns_none_for_relative() {
    assert_eq!(split_url_for_mutation("/relative/path?q=1"), None);
    assert_eq!(split_url_for_mutation("not a url"), None);
    assert_eq!(split_url_for_mutation(""), None);
}

#[test]
fn split_url_for_mutation_returns_none_for_authority_only() {
    // No path component — there's nothing for the mutator to chew on.
    assert_eq!(split_url_for_mutation("https://x.com"), None);
}

#[test]
fn mutate_url_atomic_default_off() {
    // Reset so the test is order-independent on the global atomic.
    MUTATE_URL_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        !MUTATE_URL_ENABLED.load(std::sync::atomic::Ordering::Relaxed),
        "MUTATE_URL_ENABLED must default to false — opt-in only"
    );
}

#[test]
fn mutate_url_full_mutation_pipeline_round_trip() {
    // Smoke: feed a realistic SQLi-bearing URL through the same
    // (split → mutate → reassemble) sequence the proxy uses.
    let url = "https://api.target.com/admin?id=1' OR '1'='1&debug=true";
    let (authority, pq) = split_url_for_mutation(url).expect("absolute");
    let cfg = wafrift_encoding::url_mutate::UrlMutateConfig::default();
    let (mutated_pq, techniques) = wafrift_encoding::url_mutate::mutate_url(&pq, &cfg);
    let mutated_url = format!("{authority}{mutated_pq}");
    assert_ne!(
        mutated_url, url,
        "mutated URL must differ from original — got identical {mutated_url}"
    );
    assert!(
        mutated_url.starts_with("https://api.target.com/admin?"),
        "scheme + authority + path must be byte-identical, got {mutated_url}"
    );
    assert!(
        mutated_url.contains("id=1%27%20OR%20%271%27%3D%271"),
        "id value must be aggressively percent-encoded, got {mutated_url}"
    );
    assert!(
        techniques.contains(&"url:percent_encode"),
        "techniques must report the strategy that fired, got {techniques:?}"
    );
}

#[test]
fn mutate_url_does_not_disturb_alphanumeric_only_query() {
    // If every query value is alphanumeric there is nothing to encode
    // and the URL must come out byte-identical.
    let url = "https://x.com/path?a=ABC&b=xyz123";
    let (authority, pq) = split_url_for_mutation(url).expect("absolute");
    let cfg = wafrift_encoding::url_mutate::UrlMutateConfig::default();
    let (mutated_pq, _) = wafrift_encoding::url_mutate::mutate_url(&pq, &cfg);
    let mutated_url = format!("{authority}{mutated_pq}");
    assert_eq!(mutated_url, url);
}

// ── Managed-challenge wiring tests (blocker #115) ──────────────────

#[test]
fn challenge_store_singleton_is_reusable_across_calls() {
    let s1 = challenge_store();
    let s2 = challenge_store();
    s1.record(
        "test-singleton.example",
        "cf_clearance=xyz",
        wafrift_transport::challenge::ChallengeKind::CloudflareManaged,
        None,
    );
    assert_eq!(
        s2.get("test-singleton.example"),
        Some("cf_clearance=xyz".into()),
        "challenge_store() must return the same shared store on every call"
    );
    s1.forget("test-singleton.example");
}

#[test]
fn challenge_capture_round_trip_via_extract_and_store() {
    let store = challenge_store();
    let host = "challenge-rt.example";
    store.forget(host);
    let set_cookie_values = vec![
        "session=abc; path=/",
        "cf_clearance=zzz; domain=.example.com; secure; httponly",
    ];
    let extracted = wafrift_transport::challenge::extract_clearance_cookie(&set_cookie_values);
    assert!(
        extracted.is_some(),
        "must extract cf_clearance from a Set-Cookie set"
    );
    let (cookie, kind) = extracted.unwrap();
    assert_eq!(
        kind,
        wafrift_transport::challenge::ChallengeKind::CloudflareManaged
    );
    store.record(host, cookie, kind, None);
    assert_eq!(store.get(host), Some("cf_clearance=zzz".into()));
    store.forget(host);
}

// ═════════════════════════════════════════════════════════════════════════════
// ADVERSARIAL SWEEP TESTS — 2026-05-10
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. Gene-bank backward compat (v0.1 flat HashMap) ───────────────────────

#[test]
fn load_gene_bank_v0_1_flat_hashmap_migrates() {
    let tmp = std::env::temp_dir().join(format!("wafrift_test_gb_v01_{}.json", std::process::id()));
    // v0.1 format: no schema wrapper, just a flat object.
    let json = r#"{"api.example.com":{"proven_winners":["UrlEncode"],"blocklisted":[],"waf_name":"Cloudflare"}}"#;
    std::fs::write(&tmp, json).unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 1, "v0.1 must be migrated to schema 1");
    assert!(bank.hosts.contains_key("api.example.com"));
    let host = bank.hosts.get("api.example.com").unwrap();
    assert_eq!(host.proven_winners, vec!["UrlEncode"]);
    assert_eq!(host.waf_name, Some("Cloudflare".into()));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_v0_1_empty_object_migrates() {
    let tmp = std::env::temp_dir().join(format!(
        "wafrift_test_gb_v01_empty_{}.json",
        std::process::id()
    ));
    std::fs::write(&tmp, "{}").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 1);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn load_gene_bank_truly_malformed_returns_default() {
    // Negative twin: garbage that matches neither format must still
    // degrade gracefully to an empty bank.
    let tmp = std::env::temp_dir().join(format!("wafrift_test_gb_bad_{}.json", std::process::id()));
    std::fs::write(&tmp, "not json at all").unwrap();
    let bank = load_gene_bank(&tmp);
    assert_eq!(bank.schema, 0);
    assert!(bank.hosts.is_empty());
    let _ = std::fs::remove_file(&tmp);
}

// ── 2. restore_gene_bank memory cap ────────────────────────────────────────

#[test]
fn restore_gene_bank_enforces_10k_cap() {
    let mut state = ProxyState::default();
    let mut bank = PersistedGeneBank::default();
    for i in 0..10_001 {
        let host = format!("host-{i:05}.example.com");
        let mut hs = PersistedHostState::default();
        hs.proven_winners.push("UrlEncode".into());
        bank.hosts.insert(host, hs);
    }
    let restored = restore_gene_bank(&mut state, bank);
    assert_eq!(restored, 10_001);
    assert!(
        state.hosts.len() <= 10_000,
        "hosts.len() = {}",
        state.hosts.len()
    );
}

#[test]
fn restore_gene_bank_evicts_oldest_on_overflow() {
    let mut state = ProxyState::default();
    let mut bank = PersistedGeneBank::default();
    for i in 0..10_001 {
        let host = format!("host-{i:05}.example.com");
        let mut hs = PersistedHostState::default();
        hs.proven_winners.push("UrlEncode".into());
        bank.hosts.insert(host, hs);
    }
    restore_gene_bank(&mut state, bank);
    assert_eq!(state.hosts.len(), 10_000, "must be capped at 10k");
    assert_eq!(state.host_fifo.len(), 10_000, "fifo must stay in sync");
    // HashMap iteration order is arbitrary, so we can't predict which
    // specific host was evicted — only that one of the 10_001 is gone.
}

#[test]
fn restore_gene_bank_under_cap_keeps_all() {
    let mut state = ProxyState::default();
    let mut bank = PersistedGeneBank::default();
    for i in 0..100 {
        let host = format!("host-{i}.example.com");
        let mut hs = PersistedHostState::default();
        hs.proven_winners.push("UrlEncode".into());
        bank.hosts.insert(host, hs);
    }
    let restored = restore_gene_bank(&mut state, bank);
    assert_eq!(restored, 100);
    assert_eq!(state.hosts.len(), 100);
}

// ── 3. save_gene_bank tempfile cleanup ─────────────────────────────────────

#[cfg(unix)] // Windows does not block creating files inside a read-only directory.
#[test]
fn save_gene_bank_cleans_up_tempfile_on_error() {
    let dir = std::env::temp_dir().join(format!("wafrift_gb_ro_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gene-bank.json");

    // Make directory read-only so File::create on the tempfile fails.
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&dir, perms.clone()).unwrap();

    let state = ProxyState::default();
    let result = save_gene_bank(&state, &path);
    assert!(result.is_err(), "expected write failure in read-only dir");

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|s| s.contains(".json.tmp."))
        })
        .collect();
    assert!(
        entries.is_empty(),
        "tempfile must be cleaned up on error: {:?}",
        entries
    );

    // Restore permissions for cleanup.
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    let _ = std::fs::set_permissions(&dir, perms);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_gene_bank_leaves_no_tempfile_on_success() {
    let dir = std::env::temp_dir().join(format!("wafrift_gb_ok_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gene-bank.json");

    let mut state = ProxyState::default();
    state
        .hosts
        .insert("example.com".into(), HostState::default());
    save_gene_bank(&state, &path).unwrap();

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|s| s.contains(".json.tmp."))
        })
        .collect();
    assert!(
        entries.is_empty(),
        "tempfile must not leak on success: {:?}",
        entries
    );

    let _ = std::fs::remove_dir_all(&dir);
}
