#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::h2_evasion::*;
    use std::collections::HashSet;

    #[test]
    fn crlf_injection_contains_crlf() {
        let evasion = crlf_in_pseudo_headers("/search", "X-Injected", "true");
        let path = evasion
            .pseudo_headers
            .iter()
            .find(|(n, _)| n == ":path")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(path.contains("\r\n"));
        assert!(path.contains("X-Injected: true"));
    }

    #[test]
    fn crlf_request_smuggle_has_two_requests() {
        let evasion = crlf_request_smuggle("/api/search", "/admin");
        let path = evasion
            .pseudo_headers
            .iter()
            .find(|(n, _)| n == ":path")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(path.contains("GET /admin"));
        assert!(path.contains("Host:"));
    }

    #[test]
    fn crlf_in_regular_header_present() {
        let evasion = crlf_in_regular_header("user-agent", "Mozilla/5.0");
        let val = evasion
            .headers
            .iter()
            .find(|(n, _)| n == "user-agent")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(val.contains("\r\n"));
    }

    #[test]
    fn crlf_in_header_name_present() {
        let evasion = crlf_in_header_name("x", "foo: bar");
        assert!(evasion.headers.iter().any(|(n, _)| n.contains("\r\n")));
    }

    #[test]
    fn authority_host_mismatch_has_both() {
        let evasion = authority_host_mismatch("safe.example.com", "malicious.internal");
        assert!(
            evasion
                .pseudo_headers
                .iter()
                .any(|(n, v)| n == ":authority" && v == "safe.example.com")
        );
        assert!(
            evasion
                .headers
                .iter()
                .any(|(n, v)| n == "host" && v == "malicious.internal")
        );
    }

    #[test]
    fn mixed_case_headers_produced() {
        let variants = mixed_case_headers();
        assert!(!variants.is_empty());
        assert!(variants.iter().any(|e| {
            e.headers
                .iter()
                .any(|(n, _)| n.chars().any(char::is_uppercase))
        }));
    }

    #[test]
    fn continuation_split_separates_headers() {
        let split = split_header_to_continuation("X-Payload", "malicious_value");
        assert!(!split.headers_frame.is_empty());
        assert!(!split.continuation_frames.is_empty());
        assert!(!split.headers_frame.iter().any(|(n, _)| n == "X-Payload"));
        assert!(
            split.continuation_frames[0]
                .iter()
                .any(|(n, _)| n == "X-Payload")
        );
    }

    #[test]
    fn split_path_across_frames_multibyte_safe() {
        let path = "/admin/日本語/dashboard?action=delete";
        let split = split_path_across_frames(path);
        assert!(!split.description.is_empty());
        assert!(!split.continuation_frames.is_empty());
        let first = split
            .headers_frame
            .iter()
            .find(|(n, _)| n == ":path")
            .map(|(_, v)| v.clone())
            .unwrap();
        let second = split.continuation_frames[0]
            .iter()
            .find(|(n, _)| n == ":path")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(format!("{first}{second}"), path);
    }

    #[test]
    fn split_pseudo_after_regular_has_regular_first() {
        let split = split_pseudo_after_regular();
        assert!(split.headers_frame.iter().any(|(n, _)| n == "x-regular"));
        assert!(
            split.continuation_frames[0]
                .iter()
                .any(|(n, _)| n == ":path")
        );
    }

    #[test]
    fn padding_configurations_has_variants() {
        let configs = padding_configurations();
        assert!(configs.len() >= 4);
        assert!(configs.iter().any(|c| c.data_padding == 255));
        assert!(configs.iter().any(|c| c.inject_priority_frames));
        assert!(configs.iter().any(|c| c.malformed));
    }

    #[test]
    fn all_evasions_non_empty() {
        let evasions = all_evasions("/api/v1/search", "example.com");
        assert!(
            evasions.len() >= 20,
            "expected 20+ evasions, got {}",
            evasions.len()
        );
    }

    #[test]
    fn all_evasions_cover_all_flaws() {
        let evasions = all_evasions("/", "example.com");
        let flaws: HashSet<_> = evasions.iter().map(|e| e.target_flaw).collect();
        assert!(flaws.contains(&H2TargetFlaw::ProtocolDowngrade));
        assert!(flaws.contains(&H2TargetFlaw::PseudoHeaderMismatch));
        assert!(flaws.contains(&H2TargetFlaw::LaxHeaderValidation));
        assert!(flaws.contains(&H2TargetFlaw::MethodOverride));
    }

    #[test]
    fn method_override_has_override_headers() {
        let evasion = method_override("/api", "example.com", "POST");
        assert_eq!(evasion.target_flaw, H2TargetFlaw::MethodOverride);
        assert!(
            evasion
                .headers
                .iter()
                .any(|(n, v)| n == "x-http-method-override" && v == "POST")
        );
        assert!(
            evasion
                .pseudo_headers
                .iter()
                .any(|(n, v)| n == ":method" && v == "GET")
        );
    }

    #[test]
    fn method_anomaly_connect_and_pri() {
        let c = method_anomaly("/", "example.com", "CONNECT");
        assert!(
            c.pseudo_headers
                .iter()
                .any(|(n, v)| n == ":method" && v == "CONNECT")
        );
        let p = method_anomaly("/", "example.com", "PRI");
        assert!(
            p.pseudo_headers
                .iter()
                .any(|(n, v)| n == ":method" && v == "PRI")
        );
    }

    #[test]
    fn scheme_confusion_sends_wrong_scheme() {
        let evasion = scheme_confusion("/api", "example.com");
        assert!(
            evasion
                .pseudo_headers
                .iter()
                .any(|(n, v)| n == ":scheme" && v == "http")
        );
    }

    #[test]
    fn exotic_scheme_variants() {
        let evasions = exotic_scheme("/", "example.com");
        assert_eq!(evasions.len(), 4);
        assert!(evasions.iter().any(|e| {
            e.pseudo_headers
                .iter()
                .any(|(n, v)| n == ":scheme" && v == "ftp")
        }));
    }

    #[test]
    fn duplicate_pseudo_header_has_two_paths() {
        let evasion = duplicate_pseudo_header("/admin", "example.com");
        let path_count = evasion
            .pseudo_headers
            .iter()
            .filter(|(n, _)| n == ":path")
            .count();
        assert_eq!(path_count, 2);
    }

    #[test]
    fn duplicate_method_scheme_authority() {
        assert_eq!(
            duplicate_method("example.com")
                .pseudo_headers
                .iter()
                .filter(|(n, _)| n == ":method")
                .count(),
            2
        );
        assert_eq!(
            duplicate_scheme("example.com")
                .pseudo_headers
                .iter()
                .filter(|(n, _)| n == ":scheme")
                .count(),
            2
        );
        assert_eq!(
            duplicate_authority("example.com")
                .pseudo_headers
                .iter()
                .filter(|(n, _)| n == ":authority")
                .count(),
            2
        );
    }

    #[test]
    fn empty_authority_empty() {
        let evasion = empty_authority("/");
        assert!(
            evasion
                .pseudo_headers
                .iter()
                .any(|(n, v)| n == ":authority" && v.is_empty())
        );
    }

    #[test]
    fn missing_authority_omits() {
        let evasion = missing_authority("/");
        assert!(
            !evasion
                .pseudo_headers
                .iter()
                .any(|(n, _)| n == ":authority")
        );
    }

    #[test]
    fn invalid_path_chars_variants() {
        let evasions = invalid_path_chars();
        assert_eq!(evasions.len(), 3);
        assert!(
            evasions
                .iter()
                .any(|e| e.pseudo_headers.iter().any(|(_, v)| v.contains('\x00')))
        );
        assert!(
            evasions
                .iter()
                .any(|e| e.pseudo_headers.iter().any(|(_, v)| v.contains(' ')))
        );
    }

    #[test]
    fn status_in_request_present() {
        let evasion = status_in_request("/");
        assert!(
            evasion
                .pseudo_headers
                .iter()
                .any(|(n, v)| n == ":status" && v == "200")
        );
    }

    #[test]
    fn pseudo_header_reordering_variants() {
        let evasions = pseudo_header_reordering("/", "example.com");
        assert_eq!(evasions.len(), 2);
        for e in &evasions {
            assert!(e.pseudo_headers.iter().any(|(n, _)| n == ":method"));
            assert!(e.pseudo_headers.iter().any(|(n, _)| n == ":path"));
        }
    }

    #[test]
    fn regular_header_before_pseudo_present() {
        let evasion = regular_header_before_pseudo();
        assert_eq!(evasion.pseudo_headers[0].0, "x-regular");
    }

    #[test]
    fn h2_cl_has_content_length() {
        let evasion = h2_cl("example.com");
        assert!(
            evasion
                .headers
                .iter()
                .any(|(n, v)| n == "content-length" && v == "6")
        );
    }

    #[test]
    fn h2_te_has_transfer_encoding() {
        let evasion = h2_te("example.com");
        assert!(
            evasion
                .headers
                .iter()
                .any(|(n, v)| n == "transfer-encoding" && v == "chunked")
        );
    }

    #[test]
    fn alpn_h2c_present() {
        let evasion = alpn_h2c();
        assert!(
            evasion
                .headers
                .iter()
                .any(|(n, v)| n == "alpn-protocol" && v == "h2c")
        );
    }

    #[test]
    fn settings_bombardment_variants() {
        let frames = settings_bombardment();
        assert!(!frames.is_empty());
        assert!(frames.iter().any(|f| f.setting_id == 4));
        assert!(frames.iter().any(|f| f.value == u32::MAX));
    }

    #[test]
    fn window_update_desync_variants() {
        let ids = window_update_desync();
        assert!(!ids.is_empty());
    }

    #[test]
    fn rst_stream_injection_variants() {
        let ids = rst_stream_injection();
        assert!(!ids.is_empty());
    }

    #[test]
    fn goaway_injection_variants() {
        let ids = goaway_injection();
        assert!(!ids.is_empty());
    }

    #[test]
    fn invalid_stream_ids_variants() {
        let ids = invalid_stream_ids();
        assert!(ids.iter().any(|i| i.id == 0));
        assert!(ids.iter().any(|i| i.id % 2 == 0 && i.id != 0));
    }

    #[test]
    fn flag_manipulations_variants() {
        let flags = flag_manipulations();
        assert!(flags.iter().any(|f| !f.end_stream));
        assert!(flags.iter().any(|f| !f.end_headers));
    }

    #[test]
    fn hpack_table_manipulations_extreme() {
        let tables = hpack_table_manipulations();
        assert!(tables.iter().any(|t| t.table_size == u32::MAX));
    }

    #[test]
    fn evasion_descriptions_non_empty() {
        let evasions = all_evasions("/test", "example.com");
        for e in &evasions {
            assert!(!e.description.is_empty());
            assert!(!e.name.is_empty());
        }
    }

    #[test]
    fn crlf_targets_protocol_downgrade() {
        let evasion = crlf_in_pseudo_headers("/", "X-Test", "1");
        assert_eq!(evasion.target_flaw, H2TargetFlaw::ProtocolDowngrade);
    }

    #[test]
    fn double_host_targets_pseudo_mismatch() {
        let evasion = double_host("a.com", "b.com");
        assert_eq!(evasion.target_flaw, H2TargetFlaw::PseudoHeaderMismatch);
    }
}
