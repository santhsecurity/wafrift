#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::h2_evasion::*;
    use std::collections::HashSet;

    #[test]
    fn crlf_injection_contains_crlf() {
        let evasion = crlf_in_pseudo_headers("/search", "X-Injected", "true").unwrap();
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
        let evasion = crlf_request_smuggle("/api/search", "/admin").unwrap();
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
        let evasion = authority_host_mismatch("safe.example.com", "malicious.internal").unwrap();
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
    fn authority_host_mismatch_rejects_crlf_host() {
        // A host containing CRLF would silently produce an empty-host probe
        // before the fix (unwrap_or_default). Now it propagates the error.
        let err = authority_host_mismatch("safe.com", "evil.com\r\nX-Injected: 1");
        assert!(err.is_err(), "CRLF in target_host must be rejected");
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
        let evasions = all_evasions("/api/v1/search", "example.com").unwrap();
        assert!(
            evasions.len() >= 20,
            "expected 20+ evasions, got {}",
            evasions.len()
        );
    }

    #[test]
    fn all_evasions_cover_all_flaws() {
        let evasions = all_evasions("/", "example.com").unwrap();
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
        let evasions = all_evasions("/test", "example.com").unwrap();
        for e in &evasions {
            assert!(!e.description.is_empty());
            assert!(!e.name.is_empty());
        }
    }

    #[test]
    fn crlf_targets_protocol_downgrade() {
        let evasion = crlf_in_pseudo_headers("/", "X-Test", "1").unwrap();
        assert_eq!(evasion.target_flaw, H2TargetFlaw::ProtocolDowngrade);
    }

    #[test]
    fn double_host_targets_pseudo_mismatch() {
        let evasion = double_host("a.com", "b.com").unwrap();
        assert_eq!(evasion.target_flaw, H2TargetFlaw::PseudoHeaderMismatch);
    }

    // ── #95 SPCA stream-priority topology tests ───────────────────────────

    #[test]
    fn spca_circular_produces_loop() {
        let topo = spca_circular_priority(4);
        assert_eq!(topo.frames.len(), 4, "4 streams → 4 PRIORITY frames");
        // Each stream_id must appear exactly once as stream_id.
        let stream_ids: Vec<u32> = topo.frames.iter().map(|f| f.stream_id).collect();
        assert_eq!(stream_ids, vec![1, 3, 5, 7]);
        // depends_on forms a ring: 1→3, 3→5, 5→7, 7→1
        assert_eq!(topo.frames[0].depends_on, 3);
        assert_eq!(topo.frames[1].depends_on, 5);
        assert_eq!(topo.frames[2].depends_on, 7);
        assert_eq!(topo.frames[3].depends_on, 1, "last must wrap back to first");
    }

    #[test]
    fn spca_circular_n_less_than_2_is_empty() {
        let topo = spca_circular_priority(0);
        assert!(topo.frames.is_empty());
        let topo = spca_circular_priority(1);
        assert!(topo.frames.is_empty());
    }

    #[test]
    fn spca_circular_large_n() {
        let topo = spca_circular_priority(32);
        assert_eq!(topo.frames.len(), 32);
        // All stream ids are odd.
        assert!(topo.frames.iter().all(|f| f.stream_id % 2 == 1));
        // All depends_on values are odd (from the same set).
        assert!(topo.frames.iter().all(|f| f.depends_on % 2 == 1));
        // The last frame wraps back to stream 1.
        assert_eq!(topo.frames[31].depends_on, 1);
    }

    #[test]
    fn spca_orphan_has_correct_ids() {
        let topo = spca_orphan_dependency(5, 999);
        assert_eq!(topo.frames.len(), 1);
        assert_eq!(topo.frames[0].stream_id, 5);
        assert_eq!(topo.frames[0].depends_on, 999);
        assert_eq!(topo.frames[0].weight, 1);
        assert_eq!(topo.target_flaw, H2TargetFlaw::StreamIdValidation);
    }

    #[test]
    fn spca_exclusive_weight_storm_produces_16_frames() {
        let topo = spca_exclusive_weight_storm();
        assert_eq!(topo.frames.len(), 16);
        // All frames must be exclusive.
        assert!(topo.frames.iter().all(|f| f.exclusive));
        // All depend on root (stream 0).
        assert!(topo.frames.iter().all(|f| f.depends_on == 0));
        // Even-indexed frames have weight=0.
        assert!(topo.frames.iter().enumerate().all(|(i, f)| {
            if i % 2 == 0 {
                f.weight == 0
            } else {
                f.weight == 255
            }
        }));
    }

    #[test]
    fn spca_deep_chain_depth_honoured() {
        let topo = spca_deep_dependency_chain(10);
        assert_eq!(topo.frames.len(), 10);
        // Linear chain: each frame depends on the previous frame's stream_id.
        assert_eq!(topo.frames[0].depends_on, 0); // root
        assert_eq!(topo.frames[1].depends_on, topo.frames[0].stream_id);
        assert_eq!(topo.frames[9].depends_on, topo.frames[8].stream_id);
    }

    #[test]
    fn spca_deep_chain_cap_at_512() {
        let topo = spca_deep_dependency_chain(999);
        assert_eq!(topo.frames.len(), 512, "cap at 512 frames");
    }

    #[test]
    fn priority_frame_to_bytes_length_correct() {
        let f = H2PriorityFrame {
            stream_id: 1,
            exclusive: false,
            depends_on: 0,
            weight: 15,
            description: "test".into(),
        };
        let bytes = priority_frame_to_bytes(&f);
        // HTTP/2 frame header (9 bytes) + PRIORITY payload (5 bytes) = 14
        assert_eq!(bytes.len(), 14);
        // Type byte at offset 3 must be 0x02 (PRIORITY).
        assert_eq!(bytes[3], 0x02);
        // Length field (bytes 0..3) must encode 5.
        let length = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        assert_eq!(length, 5);
        // Weight at last byte.
        assert_eq!(bytes[13], 15);
    }

    #[test]
    fn priority_frame_exclusive_bit_set() {
        let f = H2PriorityFrame {
            stream_id: 3,
            exclusive: true,
            depends_on: 1,
            weight: 0,
            description: "excl".into(),
        };
        let bytes = priority_frame_to_bytes(&f);
        // The dependency field starts at byte 9. The MSB of byte 9 is the
        // exclusive flag.
        assert!(bytes[9] & 0x80 != 0, "exclusive bit must be set");
    }

    #[test]
    fn priority_frame_exclusive_bit_clear() {
        let f = H2PriorityFrame {
            stream_id: 3,
            exclusive: false,
            depends_on: 1,
            weight: 0,
            description: "not-excl".into(),
        };
        let bytes = priority_frame_to_bytes(&f);
        assert!(bytes[9] & 0x80 == 0, "exclusive bit must be clear");
    }

    #[test]
    fn spca_priority_update_frame_non_empty() {
        let frame = spca_priority_update_frame(1, 3, true);
        assert!(!frame.is_empty());
        // Frame type at byte 3 must be 0x10 (PRIORITY_UPDATE provisional).
        assert_eq!(frame[3], 0x10);
        // Payload should include "u=3,i".
        let payload_start = 13; // 9-byte header + 4-byte prioritized-stream-id
        let payload = &frame[payload_start..];
        let payload_str = std::str::from_utf8(payload).expect("ascii payload");
        assert!(payload_str.contains("u=3"), "urgency must be embedded");
        assert!(
            payload_str.contains(",i"),
            "incremental flag must be present"
        );
    }

    #[test]
    fn spca_priority_update_without_incremental() {
        let frame = spca_priority_update_frame(5, 7, false);
        let payload = &frame[13..];
        let s = std::str::from_utf8(payload).unwrap();
        assert_eq!(s, "u=7");
    }

    // ── Round 28: UTF-8 boundary safety in N-way continuation split ──

    #[test]
    fn continuation_split_does_not_panic_on_multibyte_payload() {
        let s = split_payload_across_n_continuations("x-evil", "🎉🎉", 3);
        let mut rebuilt = String::new();
        for frame in &s.continuation_frames {
            for (_, v) in frame {
                rebuilt.push_str(v);
            }
        }
        assert_eq!(rebuilt, "🎉🎉", "reconstructed payload must match input");
    }

    #[test]
    fn continuation_split_preserves_ascii_payload_round_trip() {
        let s = split_payload_across_n_continuations("x-payload", "abcdefghij", 5);
        let mut rebuilt = String::new();
        for frame in &s.continuation_frames {
            for (_, v) in frame {
                rebuilt.push_str(v);
            }
        }
        assert_eq!(rebuilt, "abcdefghij");
    }

    #[test]
    fn continuation_split_handles_single_wide_codepoint_with_tight_n() {
        let s = split_payload_across_n_continuations("x-single", "🎉", 8);
        let mut rebuilt = String::new();
        for frame in &s.continuation_frames {
            for (_, v) in frame {
                rebuilt.push_str(v);
            }
        }
        assert_eq!(rebuilt, "🎉");
    }

    #[test]
    fn continuation_split_emits_at_most_n_frames() {
        let s = split_payload_across_n_continuations("x-many", "🎉🎉🎉", 10);
        assert!(
            s.continuation_frames.len() <= 10,
            "got {} frames, expected at most 10",
            s.continuation_frames.len()
        );
    }
}
