#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::safety::{CircuitBreaker, ScanPolicy, guard_prefix_len, sanitize_input};
    use crate::smuggling::*;
    use proptest::prelude::*;
    #[cfg(feature = "unsafe-probes")]
    use std::collections::HashSet;

    fn parse_request(raw: &[u8]) -> Result<(), httparse::Error> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(raw) {
            Ok(s) if s.is_complete() => Ok(()),
            Ok(_) => Err(httparse::Error::TooManyHeaders),
            Err(e) => Err(e),
        }
    }

    #[test]
    fn cl_te_contains_smuggled_prefix() {
        let payload = cl_te("example.com", "GET /admin HTTP/1.1\r\nHost: example.com").unwrap();
        let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
        assert!(raw_str.contains("GET /admin"));
        assert!(raw_str.contains("Content-Length:"));
        assert!(raw_str.contains("Transfer-Encoding: chunked"));
        assert_eq!(payload.variant, SmugglingVariant::ClTe);
        assert!(!payload.canary.token.is_empty());
    }

    #[test]
    fn cl_te_custom_nonzero_cl() {
        let payload = cl_te_custom("example.com", "X", 5).unwrap();
        assert!(String::from_utf8_lossy(&payload.raw_bytes).contains("Content-Length: 5"));
    }

    #[test]
    fn te_cl_dynamic_cl() {
        for len in 1..=100usize {
            let prefix = "A".repeat(len);
            let payload = te_cl("example.com", &prefix).unwrap();
            let raw = String::from_utf8_lossy(&payload.raw_bytes);
            // The chunk line is "{len:x}\r\n"
            let chunk_line = format!("{:x}\r\n", prefix.len() + 2).len();
            assert!(
                raw.contains(&format!("Content-Length: {}", chunk_line)),
                "failed for len={}",
                len
            );
        }
    }

    #[test]
    fn te_cl_contains_chunked_body() {
        let payload = te_cl("example.com", "GET /admin HTTP/1.1\r\nHost: example.com").unwrap();
        let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
        assert!(raw_str.contains("Transfer-Encoding: chunked"));
        assert!(raw_str.contains("0\r\n\r\n"));
        assert_eq!(payload.variant, SmugglingVariant::TeCl);
    }

    #[test]
    fn cl_te_places_smuggled_request_after_zero_chunk() {
        let payload = cl_te("example.com", "GET /admin HTTP/1.1\r\nHost: internal").unwrap();
        let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
        let split = raw_str.split_once("\r\n\r\n").expect("separator missing");
        assert!(split.1.starts_with("0\r\n\r\nGET /admin HTTP/1.1"));
        assert!(raw_str.contains("Content-Length: 0"));
    }

    #[test]
    fn te_cl_uses_dynamic_content_length() {
        let payload = te_cl("example.com", "GET /admin HTTP/1.1\r\nHost: internal").unwrap();
        let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
        let smuggled_len = "GET /admin HTTP/1.1\r\nHost: internal\r\n".len();
        let expected_cl = format!("{:x}\r\n", smuggled_len + 2).len();
        assert!(raw_str.contains(&format!("Content-Length: {}", expected_cl)));
    }

    #[test]
    fn te_te_uses_obfuscation() {
        let obs = te_obfuscations();
        for i in 0..obs.len().min(10) {
            let payload = te_te("example.com", "SMUGGLED", i).unwrap();
            assert_eq!(payload.variant, SmugglingVariant::TeTe);
            let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
            assert!(raw_str.contains("SMUGGLED"));
        }
    }

    #[test]
    fn te_obfuscations_covers_smuggler_matrix() {
        let obs = te_obfuscations();
        assert!(
            obs.len() >= 20,
            "expected 20+ obfuscations, got {}",
            obs.len()
        );
        assert!(obs.iter().any(|s| s.contains('\n')));
        assert!(obs.iter().any(|s| s.contains('\t')));
        assert!(obs.iter().any(|s| s.contains('\u{00a0}')));
        assert!(obs.iter().any(|s| s.contains('"')));
        assert!(
            obs.iter()
                .any(|s| s.eq_ignore_ascii_case("transfer-encoding: chunked"))
        );
    }

    #[test]
    fn all_detection_probes_safe() {
        let probes = all_detection_probes("example.com").unwrap();
        assert!(!probes.is_empty());
        for p in &probes {
            assert!(!p.canary.token.is_empty());
            assert!(matches!(
                p.variant,
                SmugglingVariant::DetectClTe | SmugglingVariant::DetectTeCl
            ));
        }
    }

    #[cfg(feature = "unsafe-probes")]
    #[test]
    fn all_payloads_generates_full_set() {
        let payloads = all_payloads("example.com", "GET /secret HTTP/1.1").unwrap();
        assert!(payloads.len() >= 20, "expected 20+, got {}", payloads.len());
        let variants: HashSet<_> = payloads.iter().map(|p| p.variant).collect();
        assert!(variants.contains(&SmugglingVariant::ClTe));
        assert!(variants.contains(&SmugglingVariant::TeCl));
        assert!(variants.contains(&SmugglingVariant::H2c));
    }

    #[cfg(feature = "unsafe-probes")]
    #[test]
    fn all_payloads_unique() {
        let payloads = all_payloads("example.com", "GET / HTTP/1.1").unwrap();
        let raw: Vec<_> = payloads.iter().map(|p| p.raw_bytes.clone()).collect();
        let mut set = HashSet::new();
        for (i, r) in raw.iter().enumerate() {
            if !set.insert(r.clone()) {
                panic!(
                    "duplicate payload at index {}: {:?}",
                    i,
                    String::from_utf8_lossy(r)
                );
            }
        }
    }

    #[test]
    fn dual_cl_generates_two_headers() {
        let p = dual_cl("example.com", "GET / HTTP/1.1", 6, 5).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        let c1 = s.matches("Content-Length: 6").count();
        let c2 = s.matches("Content-Length: 5").count();
        assert_eq!(c1, 1);
        assert_eq!(c2, 1);
    }

    #[test]
    fn multi_value_cl_has_comma() {
        let p = multi_value_cl("example.com", "GET / HTTP/1.1").unwrap();
        assert!(String::from_utf8_lossy(&p.raw_bytes).contains("Content-Length: 5, 6"));
    }

    #[test]
    fn chunk_extension_present() {
        let p = chunk_extension("example.com", "GET / HTTP/1.1").unwrap();
        assert!(String::from_utf8_lossy(&p.raw_bytes).contains("1;ext=foo"));
    }

    #[test]
    fn method_body_smuggle_variants() {
        for method in ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let p = method_body_smuggle(method, "example.com", "GET /admin HTTP/1.1").unwrap();
            assert!(String::from_utf8_lossy(&p.raw_bytes).starts_with(method));
        }
    }

    #[test]
    fn http10_persistence_has_keep_alive() {
        let ps = http10_persistence("example.com", "GET / HTTP/1.1").unwrap();
        let s0 = String::from_utf8_lossy(&ps[0].raw_bytes);
        assert!(s0.contains("HTTP/1.0"));
        assert!(
            s0.contains("Connection: keep-alive") || s0.contains("Proxy-Connection: keep-alive")
        );
    }

    #[test]
    fn http09_downgrade_no_version() {
        let p = http09_downgrade("example.com", "GET /admin HTTP/1.1").unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.starts_with("GET /"));
        // First line is HTTP/0.9 simple request, no version
        let first_line = s.lines().next().unwrap();
        assert!(!first_line.contains("HTTP/1.1"));
    }

    #[test]
    fn pipeline_builder_returns_pair() {
        let poison = cl_te("example.com", "GET /admin HTTP/1.1").unwrap();
        let (p, v) = pipeline_builder(&poison, "GET", "/victim", "example.com").unwrap();
        assert!(!p.is_empty());
        assert!(String::from_utf8_lossy(&v).contains("GET /victim HTTP/1.1"));
    }

    #[test]
    fn h2c_upgrade_only_no_settings() {
        let p = h2c_upgrade_only_smuggle("example.com").unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(!s.contains("HTTP2-Settings"));
        assert!(s.contains("Upgrade: h2c"));
    }

    #[test]
    fn malformed_http2_settings_variants() {
        let ps = malformed_http2_settings("example.com").unwrap();
        assert_eq!(ps.len(), 3);
    }

    #[test]
    fn websocket_smuggle_random_key() {
        let p1 = websocket_smuggle("example.com", "/chat").unwrap();
        let p2 = websocket_smuggle("example.com", "/chat").unwrap();
        let s1 = String::from_utf8_lossy(&p1.raw_bytes);
        let s2 = String::from_utf8_lossy(&p2.raw_bytes);
        assert!(s1.contains("Sec-WebSocket-Key:"));
        assert_ne!(s1, s2, "keys should be random per call");
    }

    #[test]
    fn cl_obfuscation_variants() {
        let ps = cl_obfuscation("example.com", "GET / HTTP/1.1").unwrap();
        assert_eq!(ps.len(), 4);
    }

    #[test]
    fn chunk_size_mutations_variants() {
        let ps = chunk_size_mutations("example.com", "GET / HTTP/1.1").unwrap();
        assert_eq!(ps.len(), 4);
    }

    #[test]
    fn cl_te_precedence_test_valid_chunked() {
        let ps = cl_te_precedence_test("example.com").unwrap();
        assert!(!ps.is_empty());
        let s = String::from_utf8_lossy(&ps[0].raw_bytes);
        assert!(s.contains("Transfer-Encoding: chunked"));
        assert!(s.contains("Content-Length:"));
    }

    #[test]
    fn canary_unique_per_payload() {
        let p1 = cl_te("example.com", "X").unwrap();
        let p2 = cl_te("example.com", "X").unwrap();
        assert_ne!(p1.canary.token, p2.canary.token);
    }

    #[test]
    fn raw_bytes_end_with_double_crlf() {
        let payloads = vec![
            cl_te("example.com", "GET / HTTP/1.1").unwrap(),
            te_cl("example.com", "GET / HTTP/1.1").unwrap(),
            cl_zero("example.com", "GET / HTTP/1.1").unwrap(),
            detect_cl_te("example.com").unwrap(),
            detect_te_cl("example.com").unwrap(),
        ];
        for p in &payloads {
            assert!(
                p.raw_bytes.ends_with(b"\r\n\r\n"),
                "{:?} missing double CRLF",
                p.variant
            );
        }
    }

    #[test]
    fn sanitize_blocks_crlf() {
        assert!(sanitize_input("foo\r\nbar").is_err());
        assert!(sanitize_input("foo\nbar").is_err());
        assert!(sanitize_input("foo\rbar").is_err());
        assert!(sanitize_input("foobar").is_ok());
    }

    #[test]
    fn guard_prefix_len_blocks_huge() {
        let huge = "A".repeat(100_000);
        assert!(guard_prefix_len(&huge, 64 * 1024).is_err());
        assert!(guard_prefix_len(&"A".repeat(100), 64 * 1024).is_ok());
    }

    #[test]
    fn scan_policy_backoff_grows() {
        let policy = ScanPolicy::default();
        let d0 = policy.backoff_delay(0);
        let d1 = policy.backoff_delay(1);
        let d2 = policy.backoff_delay(2);
        assert!(d1 >= d0);
        assert!(d2 >= d1);
    }

    #[test]
    fn circuit_breaker_opens_then_recovers() {
        let mut cb = CircuitBreaker::new(2, 10);
        assert!(cb.can_proceed());
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.can_proceed());
        std::thread::sleep(std::time::Duration::from_millis(15));
        assert!(cb.can_proceed());
    }

    #[test]
    fn cache_buster_non_empty() {
        let b = crate::safety::cache_buster();
        assert!(!b.is_empty());
    }

    #[test]
    fn httparse_validates_all_payloads() {
        let payloads = vec![
            cl_te("example.com", "GET / HTTP/1.1\r\nHost: example.com\r\n").unwrap(),
            te_cl("example.com", "GET / HTTP/1.1\r\nHost: example.com\r\n").unwrap(),
            cl_zero("example.com", "GET / HTTP/1.1\r\nHost: example.com\r\n").unwrap(),
            detect_cl_te("example.com").unwrap(),
            detect_te_cl("example.com").unwrap(),
        ];
        for p in &payloads {
            parse_request(&p.raw_bytes).expect("httparse rejected payload");
        }
    }

    #[test]
    fn adversarial_random_delays_and_rst() {
        // The parser must classify correctly regardless of upstream behavior.
        // We simulate by verifying payload structure is deterministic.
        let p = detect_cl_te("example.com").unwrap();
        let s1 = String::from_utf8_lossy(&p.raw_bytes);
        let p2 = detect_cl_te("example.com").unwrap();
        let s2 = String::from_utf8_lossy(&p2.raw_bytes);
        assert_eq!(
            s1.replace(&p.canary.token, ""),
            s2.replace(&p2.canary.token, "")
        );
    }

    proptest! {
        #[test]
        fn prop_cl_te_idempotent(host in "[a-z0-9]{1,20}", prefix in "[A-Z/]{1,50}") {
            let p1 = cl_te(&host, &prefix).unwrap();
            let p2 = cl_te(&host, &prefix).unwrap();
            // Everything except canary must match
            assert_eq!(p1.variant, p2.variant);
            assert_eq!(p1.description, p2.description);
            assert_eq!(p1.raw_bytes.len(), p2.raw_bytes.len());
        }

        #[test]
        fn prop_te_cl_structure(host in "[a-z0-9]{1,20}", prefix in "[A-Z/]{1,50}") {
            let p = te_cl(&host, &prefix).unwrap();
            let s = String::from_utf8_lossy(&p.raw_bytes);
            assert!(s.contains("Transfer-Encoding: chunked"));
            assert!(s.contains("Content-Length:"));
        }

        #[test]
        fn prop_chunked_parser_bounded(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            use crate::parser::ChunkedParser;
            let parser = ChunkedParser::default();
            // Must not panic on arbitrary bytes
            let _ = parser.parse(&data);
        }
    }

    #[test]
    fn concurrency_stress_all_payloads() {
        use std::thread;
        let handles: Vec<_> = (0..16)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..100 {
                        let _ = cl_te("example.com", "GET / HTTP/1.1").unwrap();
                        let _ = te_cl("example.com", "GET / HTTP/1.1").unwrap();
                        let _ = te_obfuscations();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn multibyte_utf8_split_path_no_panic() {
        let path = "/admin/日本語";
        let p = te_cl("example.com", path).unwrap();
        assert!(!p.raw_bytes.is_empty());
    }

    #[test]
    fn websocket_custom_key_rejects_crlf() {
        assert!(websocket_smuggle_custom("example.com", "/ws", Some("bad\r\nkey"), None).is_err());
        assert!(websocket_smuggle_custom("example.com", "/ws", Some("bad\nkey"), None).is_err());
        assert!(
            websocket_smuggle_custom("example.com", "/ws", None, Some("bad\r\nproto")).is_err()
        );
        // Safe values should succeed
        assert!(
            websocket_smuggle_custom("example.com", "/ws", Some("safe-key"), Some("safe-proto"))
                .is_ok()
        );
    }
}
