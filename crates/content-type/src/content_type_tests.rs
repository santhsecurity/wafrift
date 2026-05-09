#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::content_type::{
        ContentTypeTechnique, generate_variants, generate_variants_from_body, parse_form_body,
        xml_safe_name,
    };

    #[test]
    fn parse_form_body_basic() {
        let body = b"user=admin&pass=secret";
        let params = parse_form_body(body);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("user".into(), "admin".into()));
    }

    #[test]
    fn parse_form_body_empty() {
        assert!(parse_form_body(b"").is_empty());
    }

    #[test]
    fn generate_all_variants() {
        let params = vec![
            ("username".into(), "admin".into()),
            ("password".into(), "' OR 1=1--".into()),
        ];
        let variants = generate_variants(&params);
        assert!(
            variants.len() >= 10,
            "Should generate at least 10 variants, got {}",
            variants.len()
        );
    }

    #[test]
    fn multipart_variant_has_boundary() {
        let params = vec![("q".into(), "test".into())];
        let variants = generate_variants(&params);
        let multipart = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::Multipart)
            .unwrap();
        assert!(multipart.content_type.contains("boundary="));
        assert!(multipart.body.windows(2).any(|w| w == b"\r\n"));
    }

    #[test]
    fn quoted_boundary_has_quotes() {
        let params = vec![("q".into(), "test".into())];
        let variants = generate_variants(&params);
        let quoted = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::MultipartQuotedBoundary)
            .unwrap();
        assert!(quoted.content_type.contains("boundary=\""));
    }

    #[test]
    fn json_variant_is_valid_json() {
        let params = vec![("user".into(), "admin".into())];
        let variants = generate_variants(&params);
        let json_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json_var.body).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn json_with_comments_generated() {
        let params = vec![("user".into(), "admin".into())];
        let variants = generate_variants(&params);
        let json_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::JsonWithComments)
            .unwrap();
        let body_str = String::from_utf8_lossy(&json_var.body);
        assert!(body_str.contains("// wafrift padding"));
    }

    #[test]
    fn json_unicode_escape_handles_polyglot_payload() {
        let payload = "{\"a\":1}</script><svg/onload=alert(1)>";
        let params = vec![("q".into(), payload.into())];
        let variants = generate_variants(&params);
        let json_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::JsonUnicodeEscape)
            .unwrap();
        let body_str = String::from_utf8_lossy(&json_var.body);
        assert!(body_str.contains("\\u003c"));
        assert!(body_str.contains("svg"));
    }

    #[test]
    fn xml_cdata_wraps_payload() {
        let params = vec![("q".into(), "' OR 1=1--".into())];
        let variants = generate_variants(&params);
        let xml_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::XmlCdata)
            .unwrap();
        let body_str = String::from_utf8_lossy(&xml_var.body);
        assert!(body_str.contains("<![CDATA[' OR 1=1--]]>"));
    }

    #[test]
    fn xml_cdata_escapes_cdata_end() {
        let params = vec![("q".into(), "payload]]>injection".into())];
        let variants = generate_variants(&params);
        let xml_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::XmlCdata)
            .unwrap();
        let body_str = String::from_utf8_lossy(&xml_var.body);
        // cdata_escape correctly splits `]]>` to prevent early CDATA termination.
        // It does not silently drop payload characters.
        assert!(
            !body_str.contains("<![CDATA[payload]]>injection]]>"),
            "Raw ]]> from payload should not appear inside CDATA: {body_str}"
        );
        assert!(
            body_str.contains("payload]]]]><![CDATA[>injection"),
            "Payload should be properly escaped: {body_str}"
        );
    }

    #[test]
    fn xml_safe_name_sanitises() {
        assert_eq!(xml_safe_name("user[name]"), "user_name_");
        assert_eq!(xml_safe_name("123field"), "_23field");
        assert_eq!(xml_safe_name(""), "_");
        assert_eq!(xml_safe_name("valid_name-1.0"), "valid_name-1.0");
    }

    #[test]
    fn duplicate_boundary_has_two() {
        let params = vec![("q".into(), "test".into())];
        let variants = generate_variants(&params);
        let dup = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::MultipartDuplicateBoundary)
            .unwrap();
        assert_eq!(dup.content_type.matches("boundary=").count(), 2);
    }

    #[test]
    fn xml_namespace_has_prefix() {
        let params = vec![("q".into(), "test".into())];
        let variants = generate_variants(&params);
        let ns = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::XmlNamespace)
            .unwrap();
        let body_str = String::from_utf8_lossy(&ns.body);
        assert!(body_str.contains("ns:q"));
        assert!(body_str.contains("xmlns:ns"));
    }

    #[test]
    fn mixed_content_type_generated() {
        let params = vec![("q".into(), "test".into())];
        let variants = generate_variants(&params);
        let mixed = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::MixedContentType);
        assert!(
            mixed.is_some(),
            "MixedContentType variant should be generated"
        );
        let mixed = mixed.unwrap();
        assert!(mixed.content_type.contains("charset=application/json"));
        assert!(mixed.content_type.contains("boundary="));
    }

    #[test]
    fn mixed_content_type_keeps_multipart_body_for_mime_sniffing_edges() {
        let params = vec![("file".into(), "GIF89a<script>alert(1)</script>".into())];
        let variants = generate_variants(&params);
        let mixed = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::MixedContentType)
            .unwrap();
        let body_str = String::from_utf8_lossy(&mixed.body);
        assert!(body_str.contains("GIF89a<script>alert(1)</script>"));
        assert!(body_str.contains("Content-Disposition: form-data; name=\"file\""));
    }

    #[test]
    fn payload_preserved_in_all_variants() {
        let payload = "' UNION SELECT * FROM users--";
        let params = vec![("q".into(), payload.into())];
        let variants = generate_variants(&params);
        for variant in &variants {
            let body_str = String::from_utf8_lossy(&variant.body);
            assert!(
                body_str.contains(payload)
                    || body_str.contains("UNION") // Case may change but keywords preserved
                    || body_str.contains("\\u") // Unicode-escaped
                    || body_str.contains("CDATA"), // CDATA-wrapped
                "Payload missing from {:?} variant: {}",
                variant.technique,
                body_str
            );
        }
    }

    #[test]
    fn from_body_works() {
        let body = b"user=admin&pass=test";
        let variants = generate_variants_from_body(body);
        assert!(!variants.is_empty());
    }

    #[test]
    fn parse_form_body_rejects_oversized() {
        let huge = vec![b'A'; super::MAX_FORM_BODY_SIZE + 1];
        assert!(parse_form_body(&huge).is_empty());
    }

    #[test]
    fn parse_form_body_accepts_max_size() {
        let body = vec![b'a'; super::MAX_FORM_BODY_SIZE];
        // No '=' delimiters → empty result, but must not panic or allocate huge vecs.
        assert!(parse_form_body(&body).is_empty());
    }

    #[test]
    fn multipart_boundary_avoids_collision() {
        // Payload that contains the static boundary prefix.
        let payload = "----WafriftBoundary0000000000000000";
        let params = vec![("field".into(), payload.into())];
        let variants = generate_variants(&params);
        for variant in &variants {
            if matches!(
                variant.technique,
                ContentTypeTechnique::Multipart
                    | ContentTypeTechnique::MultipartQuotedBoundary
                    | ContentTypeTechnique::MultipartWhitespaceBoundary
                    | ContentTypeTechnique::MultipartDuplicateBoundary
                    | ContentTypeTechnique::MultipartCharsetPrefix
                    | ContentTypeTechnique::MixedContentType
            ) {
                let ct = &variant.content_type;
                let boundary = ct
                    .split("boundary=")
                    .nth(1)
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim();
                let body_str = String::from_utf8_lossy(&variant.body);
                // Every occurrence of the boundary in the body must be a
                // framework delimiter (preceded by "--" and either at start
                // or after \r\n). If the payload contained the boundary,
                // we would see an embedded occurrence.
                for (idx, _) in body_str.match_indices(boundary) {
                    let before = &body_str[..idx];
                    assert!(
                        before.ends_with("--")
                            && (before.len() == 2 || before.ends_with("\r\n--")),
                        "boundary embedded in payload at position {idx} for {:?}: {body_str}",
                        variant.technique
                    );
                }
            }
        }
    }

    #[test]
    fn xml_special_chars_in_namespace_variant() {
        let params = vec![("q".into(), "<script>alert(1)</script>".into())];
        let variants = generate_variants(&params);
        let ns = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::XmlNamespace)
            .unwrap();
        let body_str = String::from_utf8_lossy(&ns.body);
        // XSS payload should be XML-escaped, not raw
        assert!(body_str.contains("&lt;script&gt;"));
        assert!(!body_str.contains("<script>"));
    }

    #[test]
    fn xml_cdata_preserves_polyglot_payload_verbatim() {
        let payload = "<svg><script>alert(1)</script></svg>{\"a\":1}";
        let params = vec![("q".into(), payload.into())];
        let variants = generate_variants(&params);
        let xml_var = variants
            .iter()
            .find(|v| v.technique == ContentTypeTechnique::XmlCdata)
            .unwrap();
        let body_str = String::from_utf8_lossy(&xml_var.body);
        assert!(body_str.contains(payload));
        assert!(body_str.contains("<![CDATA["));
    }

    #[test]
    fn generate_variants_from_body_rejects_non_form_plaintext() {
        let variants = generate_variants_from_body(b"plain text with no equals sign");
        assert!(variants.is_empty());
    }

    // Generated adversarial content-type tests

    #[test]
    fn adversarial_content_type_test_auto_0() {
        let repeat_str = "A".to_string();
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[0 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_1() {
        let repeat_str = "A".repeat(101);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[1 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_2() {
        let repeat_str = "A".repeat(201);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[2 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_3() {
        let repeat_str = "A".repeat(301);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[3 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_4() {
        let repeat_str = "A".repeat(401);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[4 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_5() {
        let repeat_str = "A".repeat(501);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[5 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_6() {
        let repeat_str = "A".repeat(601);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[6 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_7() {
        let repeat_str = "A".repeat(701);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[7 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_8() {
        let repeat_str = "A".repeat(801);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[8 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_9() {
        let repeat_str = "A".repeat(901);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[9 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_10() {
        let repeat_str = "A".repeat(1001);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[10 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_11() {
        let repeat_str = "A".repeat(1101);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[11 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_12() {
        let repeat_str = "A".repeat(1201);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[12 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_13() {
        let repeat_str = "A".repeat(1301);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[13 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_14() {
        let repeat_str = "A".repeat(1401);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[14 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_15() {
        let repeat_str = "A".repeat(1501);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[15 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_16() {
        let repeat_str = "A".repeat(1601);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[16 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_17() {
        let repeat_str = "A".repeat(1701);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[17 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_18() {
        let repeat_str = "A".repeat(1801);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[18 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_19() {
        let repeat_str = "A".repeat(1901);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[19 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_20() {
        let repeat_str = "A".repeat(2001);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[20 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_21() {
        let repeat_str = "A".repeat(2101);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[21 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_22() {
        let repeat_str = "A".repeat(2201);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[22 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_23() {
        let repeat_str = "A".repeat(2301);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[23 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_24() {
        let repeat_str = "A".repeat(2401);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[24 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_25() {
        let repeat_str = "A".repeat(2501);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[25 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_26() {
        let repeat_str = "A".repeat(2601);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[26 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_27() {
        let repeat_str = "A".repeat(2701);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[27 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_28() {
        let repeat_str = "A".repeat(2801);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[28 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    #[test]
    fn adversarial_content_type_test_auto_29() {
        let repeat_str = "A".repeat(2901);
        let payloads: Vec<&str> = vec![
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &repeat_str,
            "{\"key\": \"value\"}",
        ];
        let payload = payloads[29 % payloads.len()];
        let body = format!("user=admin&pass={payload}");
        let variants = generate_variants_from_body(body.as_bytes());
        if !payload.is_empty() {
            assert!(!variants.is_empty());
        }
    }

    /// JSON variants must be parseable as strict JSON. Earlier versions
    /// emitted `\u{:04x}` for code points >= U+10000 (a single 5+ digit
    /// escape), which is invalid JSON. RFC 8259 requires a UTF-16
    /// surrogate pair for supplementary-plane characters.
    #[test]
    fn json_unicode_escape_supplementary_plane_is_valid_json() {
        // U+1F600 GRINNING FACE — supplementary plane.
        let params = vec![("emoji".to_string(), "\u{1F600}".to_string())];
        let variants = generate_variants(&params);
        let json = variants
            .iter()
            .find(|v| matches!(v.technique, ContentTypeTechnique::JsonUnicodeEscape))
            .expect("JsonUnicodeEscape variant must exist");
        let body_str = std::str::from_utf8(&json.body).expect("body is utf-8");
        // Must contain the surrogate pair, not a single ὠ0.
        assert!(
            body_str.contains("\\ud83d\\ude00"),
            "expected UTF-16 surrogate pair \\ud83d\\ude00, body = {body_str}"
        );
        // Must parse as strict JSON.
        let parsed: serde_json::Value =
            serde_json::from_slice(&json.body).expect("JSON variant must be strict-valid JSON");
        assert_eq!(
            parsed.get("emoji").and_then(|v| v.as_str()),
            Some("\u{1F600}"),
            "round-trip: parsed value should equal original char"
        );
    }

    #[test]
    fn json_unicode_escape_bmp_char_uses_4hex_form() {
        let params = vec![("v".to_string(), "©".to_string())]; // U+00A9
        let variants = generate_variants(&params);
        let json = variants
            .iter()
            .find(|v| matches!(v.technique, ContentTypeTechnique::JsonUnicodeEscape))
            .expect("JsonUnicodeEscape variant must exist");
        let body_str = std::str::from_utf8(&json.body).unwrap();
        assert!(body_str.contains("\\u00a9"));
        let parsed: serde_json::Value = serde_json::from_slice(&json.body).unwrap();
        assert_eq!(parsed.get("v").and_then(|v| v.as_str()), Some("©"));
    }

    /// CR/LF in form values must NOT escape the multipart part header
    /// section. Previously these survived raw and let an attacker
    /// inject a fake part with a chosen Content-Disposition. The fix
    /// strips CR/LF from values; the smuggled "boundary" no longer
    /// appears as a real boundary because the only \r\n separators
    /// remaining are the framework-emitted ones.
    #[test]
    fn multipart_strips_crlf_from_value() {
        let params = vec![(
            "field".to_string(),
            "innocent\r\nContent-Disposition: form-data; name=\"smuggled\"\r\n\r\nattacker".to_string(),
        )];
        let variants = generate_variants(&params);
        let mp = variants
            .iter()
            .find(|v| matches!(v.technique, ContentTypeTechnique::Multipart))
            .expect("multipart variant must exist");
        let body_str = std::str::from_utf8(&mp.body).unwrap();
        // No raw CR/LF remain inside the value region. A clean single-
        // part multipart has exactly 5 CR/LFs (boundary, CD header,
        // header/body separator, body, closing boundary). Any
        // surviving CR/LF inside the value would push this above 5.
        let crlf_count = body_str.matches("\r\n").count();
        assert_eq!(
            crlf_count, 5,
            "expected 5 framework CR/LF (no smuggled CR/LF in value), got {crlf_count}; body = {body_str}"
        );
        // Parse the multipart properly: extract the boundary token and
        // count parts. There must be exactly ONE part (only the legit
        // `field`, never a `smuggled` one). Substring counting on
        // "Content-Disposition" would be misleading because the smuggled
        // string survives as inert data inside the value.
        let boundary_line = body_str
            .lines()
            .next()
            .expect("body must start with boundary line");
        // Boundary is the line minus the leading "--".
        assert!(boundary_line.starts_with("--"));
        let boundary = &boundary_line[2..];
        // A "part" begins right after each boundary occurrence (excluding the closing one).
        let part_count = body_str
            .matches(&format!("--{boundary}\r\n"))
            .count();
        assert_eq!(
            part_count, 1,
            "expected exactly 1 part (no smuggled part); body = {body_str}"
        );
    }

    #[test]
    fn multipart_escapes_quotes_in_name() {
        let params = vec![("a\"b".to_string(), "v".to_string())];
        let variants = generate_variants(&params);
        let mp = variants
            .iter()
            .find(|v| matches!(v.technique, ContentTypeTechnique::Multipart))
            .expect("multipart variant must exist");
        let body_str = std::str::from_utf8(&mp.body).unwrap();
        // Quote in name must be backslash-escaped per RFC 7578 §4.2.
        assert!(
            body_str.contains(r#"name="a\"b""#),
            "embedded quote must be escaped, body = {body_str}"
        );
    }
}
