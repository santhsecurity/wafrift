//! Browser fingerprint profiles for TLS/HTTP evasion.
//!
//! WAFs use TLS fingerprinting (JA3/JA4) and HTTP/2 settings to detect
//! automated tools. This module provides profiles that mimic real browsers.

/// A browser profile for fingerprint evasion.
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    /// Profile name.
    pub name: &'static str,
    /// User-Agent string.
    pub user_agent: &'static str,
    /// Accept header.
    pub accept: &'static str,
    /// Accept-Language header.
    pub accept_language: &'static str,
    /// Accept-Encoding header.
    pub accept_encoding: &'static str,
    /// Sec-Fetch-* headers for modern browsers.
    pub sec_fetch_site: &'static str,
    pub sec_fetch_mode: &'static str,
    pub sec_fetch_dest: &'static str,
}

/// Built-in browser profiles.
pub const PROFILES: &[BrowserProfile] = &[
    BrowserProfile {
        name: "chrome-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
    BrowserProfile {
        name: "chrome-mac",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
    BrowserProfile {
        name: "firefox-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
    BrowserProfile {
        name: "firefox-linux",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
    BrowserProfile {
        name: "safari-mac",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
    BrowserProfile {
        name: "edge-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    },
];

/// Select a random browser profile using the global thread RNG.
///
/// Non-deterministic: two calls in the same process may return different
/// profiles. Use [`seeded_profile`] when reproducibility is required.
#[must_use]
pub fn random_profile_from(context: &[u8]) -> Option<&'static BrowserProfile> {
    if PROFILES.is_empty() {
        return None;
    }
    let h = fnv1a_profile_hash(context);
    Some(&PROFILES[(h as usize) % PROFILES.len()])
}

/// Select a browser profile. Returns a stable deterministic pick (first profile).
///
/// Callers that need per-host variation should use `random_profile_from`.
#[must_use]
pub fn random_profile() -> Option<&'static BrowserProfile> {
    PROFILES.first()
}

/// Select a browser profile deterministically from `seed`.
///
/// Given the same `seed` this always returns the same profile, regardless
/// of how many times the process has called `random_profile`. Used by
/// `bench-waf --seed` to make two identical invocations produce the same
/// User-Agent header and therefore byte-identical JSON output.
#[must_use]
pub fn seeded_profile(seed: u64) -> Option<&'static BrowserProfile> {
    if PROFILES.is_empty() {
        return None;
    }
    // Mix the seed through a cheap bijection (splitmix64 finalizer) so
    // seeds 0, 1, 2 … don't all map to the same low-index profiles.
    let mixed = seed
        .wrapping_add(0x9e37_79b9_7f4a_7c15)
        .wrapping_mul(0x6eed_0e9d_a4d9_4a4f);
    let idx = (mixed as usize) % PROFILES.len();
    Some(&PROFILES[idx])
}

/// Apply a browser profile to a request's headers.
pub fn apply_profile(headers: &mut Vec<(String, String)>, profile: &BrowserProfile) {
    // Remove existing headers that we're replacing
    headers.retain(|(k, _)| {
        let lower = k.to_ascii_lowercase();
        lower != "user-agent"
            && lower != "accept"
            && lower != "accept-language"
            && lower != "accept-encoding"
            && !lower.starts_with("sec-fetch")
    });

    headers.push(("User-Agent".into(), profile.user_agent.into()));
    headers.push(("Accept".into(), profile.accept.into()));
    headers.push(("Accept-Language".into(), profile.accept_language.into()));
    headers.push(("Accept-Encoding".into(), profile.accept_encoding.into()));
    headers.push(("Sec-Fetch-Site".into(), profile.sec_fetch_site.into()));
    headers.push(("Sec-Fetch-Mode".into(), profile.sec_fetch_mode.into()));
    headers.push(("Sec-Fetch-Dest".into(), profile.sec_fetch_dest.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_populated() {
        assert!(PROFILES.len() >= 6);
    }

    #[test]
    fn random_profile_returns_valid() {
        let profile = random_profile().expect("PROFILES array is empty");
        assert!(!profile.user_agent.is_empty());
        assert!(!profile.accept.is_empty());
    }

    #[test]
    fn apply_profile_sets_headers() {
        let mut headers = vec![("User-Agent".into(), "old".into())];
        apply_profile(&mut headers, &PROFILES[0]);
        let ua = headers.iter().find(|(k, _)| k == "User-Agent").unwrap();
        assert!(ua.1.contains("Chrome"));
        // Old UA should be removed
        assert_eq!(headers.iter().filter(|(k, _)| k == "User-Agent").count(), 1);
    }

    #[test]
    fn each_profile_has_unique_ua() {
        let uas: Vec<&str> = PROFILES.iter().map(|p| p.user_agent).collect();
        let unique: std::collections::HashSet<&&str> = uas.iter().collect();
        assert_eq!(uas.len(), unique.len(), "Duplicate User-Agent found");
    }

    #[test]
    fn apply_profile_replaces_all_fingerprint_headers() {
        let mut headers = vec![
            ("user-agent".into(), "old-ua".into()),
            ("accept".into(), "old-accept".into()),
            ("accept-language".into(), "old-lang".into()),
            ("accept-encoding".into(), "old-enc".into()),
            ("sec-fetch-site".into(), "old-site".into()),
            ("sec-fetch-mode".into(), "old-mode".into()),
            ("sec-fetch-dest".into(), "old-dest".into()),
            ("other-header".into(), "keep-me".into()),
        ];
        apply_profile(&mut headers, &PROFILES[0]);

        // All fingerprint headers replaced exactly once
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("accept"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-site"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-mode"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-dest"))
                .count(),
            1
        );

        // Non-fingerprint header preserved
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "other-header" && v == "keep-me")
        );
    }

    #[test]
    fn apply_profile_case_insensitive_replacement() {
        let mut headers = vec![
            ("USER-AGENT".into(), "old".into()),
            ("Accept".into(), "old".into()),
            ("sec-FETCH-MODE".into(), "old".into()),
        ];
        apply_profile(&mut headers, &PROFILES[0]);
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("accept"))
                .count(),
            1
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-mode"))
                .count(),
            1
        );
    }

    #[test]
    fn apply_profile_adds_missing_headers() {
        let mut headers = vec![("other".into(), "value".into())];
        apply_profile(&mut headers, &PROFILES[0]);
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
        assert!(headers.iter().any(|(k, _)| k == "Accept"));
        assert!(headers.iter().any(|(k, _)| k == "Accept-Language"));
        assert!(headers.iter().any(|(k, _)| k == "Accept-Encoding"));
        assert!(headers.iter().any(|(k, _)| k == "Sec-Fetch-Site"));
        assert!(headers.iter().any(|(k, _)| k == "Sec-Fetch-Mode"));
        assert!(headers.iter().any(|(k, _)| k == "Sec-Fetch-Dest"));
    }
}
