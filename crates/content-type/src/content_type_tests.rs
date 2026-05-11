#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::content_type::{
        ContentTypeTechnique, MAX_FORM_BODY_SIZE, generate_variants, generate_variants_from_body,
        parse_form_body, unique_boundary, xml_safe_name,
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
        let huge = vec![b'A'; MAX_FORM_BODY_SIZE + 1];
        assert!(parse_form_body(&huge).is_empty());
    }

    #[test]
    fn parse_form_body_accepts_max_size() {
        let body = vec![b'a'; MAX_FORM_BODY_SIZE];
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
                        before.ends_with("--") && (before.len() == 2 || before.ends_with("\r\n--")),
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

    /// Adversarial coverage replacing 30 hand-generated smoke-alarm
    /// tests (`auto_0..auto_29`) flagged by the 2026-05-10 audit. Each
    /// of the originals only asserted `!variants.is_empty()` — they
    /// passed regardless of whether the bodies were valid multipart
    /// framing, parseable JSON, or well-formed XML. This replacement
    /// drives the same payload set through `generate_variants_from_body`
    /// AND validates the body shape per Content-Type variant.
    #[test]
    fn adversarial_payloads_produce_structurally_valid_variants() {
        let medium = "A".repeat(2901);
        let payloads: &[&str] = &[
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "DROP TABLE users;",
            &medium,
            "{\"key\": \"value\"}",
        ];

        for payload in payloads {
            let body = format!("user=admin&pass={payload}");
            let variants = generate_variants_from_body(body.as_bytes());
            assert!(
                !variants.is_empty(),
                "no variants for payload: {payload:?}"
            );

            for v in &variants {
                let ct = &v.content_type;
                let body_str = std::str::from_utf8(&v.body)
                    .expect("variant body must be valid UTF-8 for these payloads");

                if ct.starts_with("multipart/form-data") {
                    // Boundary param must be present.
                    assert!(
                        ct.contains("boundary="),
                        "multipart Content-Type missing boundary param: {ct:?}"
                    );
                    // Body must contain the user param's name field.
                    assert!(
                        body_str.contains(r#"name="user""#),
                        "multipart body missing user= field"
                    );
                    // Body must contain the pass field.
                    assert!(
                        body_str.contains(r#"name="pass""#),
                        "multipart body missing pass= field"
                    );
                    // Multipart must end with `--<boundary>--\r\n`.
                    assert!(
                        body_str.ends_with("--\r\n"),
                        "multipart body must end with --boundary--\\r\\n"
                    );
                } else if ct == "application/json" {
                    // Either strict JSON OR JSON-with-comments
                    // (JsonWithComments variant). For the comments
                    // variant, strip `//` lines before parsing.
                    let stripped: String = body_str
                        .lines()
                        .filter(|line| !line.trim_start().starts_with("//"))
                        .collect::<Vec<&str>>()
                        .join("\n");
                    let parsed: serde_json::Value = serde_json::from_str(&stripped)
                        .unwrap_or_else(|e| panic!(
                            "JSON variant failed to parse: {e} ; body={body_str:?}"
                        ));
                    assert!(
                        parsed.get("user").is_some() || parsed.get("pass").is_some(),
                        "JSON variant missing expected fields: {body_str:?}"
                    );
                } else if ct == "application/xml" {
                    // Must contain BOTH a user element and a pass
                    // element. Tag name may be plain or namespaced.
                    assert!(
                        body_str.contains("user>") || body_str.contains("user "),
                        "XML variant missing user element: {body_str:?}"
                    );
                    assert!(
                        body_str.contains("pass>") || body_str.contains("pass "),
                        "XML variant missing pass element: {body_str:?}"
                    );
                    // Must declare the XML preamble.
                    assert!(
                        body_str.starts_with("<?xml "),
                        "XML variant missing <?xml preamble: {body_str:?}"
                    );
                }
            }
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
            "innocent\r\nContent-Disposition: form-data; name=\"smuggled\"\r\n\r\nattacker"
                .to_string(),
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
        let part_count = body_str.matches(&format!("--{boundary}\r\n")).count();
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

    #[test]
    fn unique_boundary_avoids_collision_with_payload_content() {
        // unique_boundary's contract: never return a value that already
        // appears (preceded by --) in any of the supplied strings, so a
        // multipart parser cannot mis-frame on attacker-controlled input.
        let candidate = unique_boundary(&["benign content with no boundary"]);
        assert!(candidate.starts_with("----WafriftBoundary"));

        // Adversarial: feed the just-issued boundary back in. The helper
        // must produce a different value (or at least one whose framing
        // marker is not in the input).
        let payload = format!("--{candidate}");
        let fresh = unique_boundary(&[&payload]);
        let fresh_needle = format!("--{fresh}");
        assert!(
            !payload.contains(&fresh_needle),
            "unique_boundary returned {fresh:?} which collides with input {payload:?}"
        );
    }

    #[test]
    fn unique_boundary_two_calls_differ() {
        // Independent calls return distinct boundaries — important so a
        // future caller that cached one boundary across requests would
        // not silently make framing predictable.
        let a = unique_boundary(&["x"]);
        let b = unique_boundary(&["x"]);
        assert_ne!(a, b);
    }
}
