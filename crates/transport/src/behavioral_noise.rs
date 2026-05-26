//! #117 Behavioral noise injection — anti-AWS-Bot-Control / anti-Cloudflare-Bot-Management.
//!
//! AWS Bot Control, Cloudflare Bot Management, and Akamai Bot Manager classify
//! traffic using ML models trained on:
//!
//! - **TLS fingerprint** (JA3/JA4) — handled by `StealthClient`
//! - **HTTP header order and values** — handled by `wafrift-fingerprint`
//! - **Behavioral signals** present in headers that real browsers emit:
//!   - `Accept-Language` (locale → known browser × OS × geography)
//!   - `Referer` (organic navigation chain)
//!   - `User-Agent` (consistent build version)
//!   - `Sec-Fetch-*` (CORS preflight vs navigation intent)
//!   - `Cookie` (session coherence)
//!   - Timing jitter between requests (Poisson-like inter-arrival times)
//!
//! This module synthesizes realistic behavioral noise at the HTTP header
//! level. It does NOT control TCP/IP timing (that requires transport-level
//! cooperation outside this crate's scope), but it does produce a
//! `TimingProfile` that callers can use to insert `tokio::time::sleep`
//! delays that match real browser inter-request distributions.
//!
//! # Usage
//!
//! ```no_run
//! # use wafrift_transport::behavioral_noise::{BehavioralProfile, NoiseInjector};
//! let profile = BehavioralProfile::chrome_us();
//! let mut injector = NoiseInjector::new(profile, 42);
//!
//! // Mutate a header set in place.
//! let mut headers: Vec<(String, String)> = vec![
//!     ("user-agent".into(), "wafrift/0.2".into()),
//! ];
//! injector.inject(&mut headers);
//! // headers now has realistic Accept-Language, Sec-Fetch-*, Referer, etc.
//! ```

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ── Browser locale profiles ───────────────────────────────────────────────

/// A behavioral browser profile describing the realistic header set a
/// specific browser+OS+locale combination would emit.
#[derive(Debug, Clone)]
pub struct BehavioralProfile {
    pub name: &'static str,
    /// Accept-Language header values, weighted by population share.
    pub accept_language_variants: Vec<(&'static str, f64)>,
    /// User-Agent strings for this browser family.
    pub user_agent_pool: Vec<&'static str>,
    /// Referer base URLs for organic navigation simulations.
    pub referer_pool: Vec<&'static str>,
    /// Inter-request timing: (mean_ms, std_ms) for a log-normal distribution.
    pub timing: (f64, f64),
    /// Sec-Fetch-Mode values typical for this browser.
    pub sec_fetch_mode: Vec<&'static str>,
    /// Whether to include Sec-CH-UA headers (only Chromium-family).
    pub emit_client_hints: bool,
    /// Client hints string.
    pub sec_ch_ua: Option<&'static str>,
}

impl BehavioralProfile {
    /// Chrome 131 on Windows 11, US locale.
    #[must_use]
    pub fn chrome_us() -> Self {
        Self {
            name: "chrome_131_win11_us",
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.70),
                ("en-US,en;q=0.9,es;q=0.8", 0.10),
                ("en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7", 0.05),
                ("en-US,en;q=0.9,fr;q=0.8", 0.05),
                ("en-US,en;q=0.9,de;q=0.8", 0.05),
                ("en-US,en;q=0.8", 0.05),
            ],
            user_agent_pool: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.204 Safari/537.36",
            ],
            referer_pool: vec![
                "https://www.google.com/",
                "https://www.bing.com/",
                "https://duckduckgo.com/",
                "https://www.google.com/search?q=site",
                "",
            ],
            timing: (850.0, 320.0), // ms
            sec_fetch_mode: vec!["navigate", "cors", "no-cors", "same-origin"],
            emit_client_hints: true,
            sec_ch_ua: Some(r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#),
        }
    }

    /// Firefox 133 on Windows 11, European mixed locale.
    #[must_use]
    pub fn firefox_eu() -> Self {
        Self {
            name: "firefox_133_win11_eu",
            accept_language_variants: vec![
                ("de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", 0.30),
                ("fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", 0.20),
                ("es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7", 0.15),
                ("it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7", 0.10),
                ("nl-NL,nl;q=0.9,en;q=0.8", 0.10),
                ("en-GB,en;q=0.9", 0.15),
            ],
            user_agent_pool: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
            ],
            referer_pool: vec![
                "https://www.google.de/",
                "https://www.google.fr/",
                "https://www.google.es/",
                "https://duckduckgo.com/",
                "https://search.yahoo.com/",
                "",
            ],
            timing: (1100.0, 450.0),
            sec_fetch_mode: vec!["navigate", "cors", "same-origin"],
            emit_client_hints: false,
            sec_ch_ua: None,
        }
    }

    /// Safari 17.5 on macOS 14 Sonoma, US locale.
    #[must_use]
    pub fn safari_us() -> Self {
        Self {
            name: "safari_17_5_macos14_us",
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.80),
                ("en-US,en;q=0.9,es;q=0.8", 0.10),
                ("en-US,en;q=0.9,fr;q=0.8", 0.05),
                ("en-US,en;q=0.9,zh-TW;q=0.8", 0.05),
            ],
            user_agent_pool: vec![
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            ],
            referer_pool: vec![
                "https://www.google.com/",
                "https://www.bing.com/",
                "",
                "https://t.co/",
                "https://l.instagram.com/",
            ],
            timing: (750.0, 280.0),
            sec_fetch_mode: vec!["navigate", "same-origin"],
            emit_client_hints: false,
            sec_ch_ua: None,
        }
    }

    /// Mobile Chrome 131 on Android 14, global mixed locale.
    #[must_use]
    pub fn chrome_android() -> Self {
        Self {
            name: "chrome_131_android14",
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.40),
                ("zh-CN,zh;q=0.9", 0.20),
                ("hi-IN,hi;q=0.9,en;q=0.8", 0.10),
                ("pt-BR,pt;q=0.9,en;q=0.8", 0.10),
                ("ar,en;q=0.9", 0.10),
                ("ru-RU,ru;q=0.9,en;q=0.8", 0.10),
            ],
            user_agent_pool: vec![
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
            ],
            referer_pool: vec![
                "https://www.google.com/",
                "https://m.facebook.com/",
                "https://t.co/",
                "https://l.instagram.com/",
                "",
            ],
            timing: (1200.0, 600.0), // mobile users are slower
            sec_fetch_mode: vec!["navigate", "cors"],
            emit_client_hints: true,
            sec_ch_ua: Some(r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#),
        }
    }
}

// ── Timing profile ────────────────────────────────────────────────────────

/// Recommended inter-request timing for one request in a sequence.
///
/// The values are drawn from a log-normal distribution parameterized by the
/// profile's `timing` (mean, std) in milliseconds. Log-normal is the correct
/// distribution for human think-time (it is right-skewed and always positive).
#[derive(Debug, Clone, Copy)]
pub struct TimingProfile {
    /// Recommended sleep before this request, in milliseconds.
    pub sleep_ms: u64,
    /// Whether this request is marked as "burst" (below the mean — fast path).
    pub is_burst: bool,
}

// ── Noise injector ────────────────────────────────────────────────────────

/// Stateful behavioral noise injector.
///
/// Maintains a simulated navigation state (referer chain, session cookie
/// prefix) across successive calls so the injected headers form a coherent
/// organic browsing session rather than uncorrelated random values.
#[derive(Debug, Clone)]
pub struct NoiseInjector {
    profile: BehavioralProfile,
    rng: StdRng,
    /// Simulated current page URL (used to build organic referer chains).
    current_url: Option<String>,
    /// Request counter in the current "session".
    request_count: u32,
    /// Sampled user-agent for this session (stays stable across requests).
    session_user_agent: String,
    /// Sampled Accept-Language for this session (stays stable).
    session_accept_language: String,
}

impl NoiseInjector {
    #[must_use]
    pub fn new(profile: BehavioralProfile, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let ua = sample_weighted_str(&profile.user_agent_pool, &mut rng);
        let al = sample_accept_language(&profile.accept_language_variants, &mut rng);
        Self {
            profile,
            rng,
            current_url: None,
            request_count: 0,
            session_user_agent: ua,
            session_accept_language: al,
        }
    }

    /// Inject behavioral noise headers into `headers`.
    ///
    /// Existing headers with the same name are replaced; new headers are
    /// appended. The injection is additive — attack headers already in the
    /// set are untouched.
    pub fn inject(&mut self, headers: &mut Vec<(String, String)>) {
        self.request_count += 1;

        // User-Agent — stable for the session.
        set_header(headers, "user-agent", &self.session_user_agent.clone());

        // Accept-Language — stable for the session.
        set_header(headers, "accept-language", &self.session_accept_language.clone());

        // Accept — match browser defaults.
        if !headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "accept") {
            let accept = self.realistic_accept();
            headers.push(("accept".into(), accept));
        }

        // Referer — build organic navigation chain.
        let referer = self.sample_referer();
        if !referer.is_empty() {
            set_header(headers, "referer", &referer);
        }

        // Sec-Fetch-* — CORS / navigation intent.
        self.inject_sec_fetch(headers);

        // Client hints — Chromium-only.
        if self.profile.emit_client_hints {
            if let Some(ua_hint) = self.profile.sec_ch_ua {
                set_header(headers, "sec-ch-ua", ua_hint);
                set_header(headers, "sec-ch-ua-mobile", "?0");
                set_header(headers, "sec-ch-ua-platform", self.platform_hint());
            }
        }

        // Cache-Control — organic mix.
        if self.request_count == 1 || self.rng.gen_bool(0.15) {
            set_header(headers, "cache-control", "max-age=0");
        }

        // Accept-Encoding — always present in real browsers.
        if !headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "accept-encoding") {
            headers.push(("accept-encoding".into(), "gzip, deflate, br, zstd".into()));
        }
    }

    /// Generate a timing recommendation for the next request.
    #[must_use]
    pub fn next_timing(&mut self) -> TimingProfile {
        let (mean, std) = self.profile.timing;
        // Log-normal: sample normal, exponentiate.
        let sigma = (((std / mean).powi(2) + 1.0).ln()).sqrt();
        let mu = (mean).ln() - sigma.powi(2) / 2.0;
        // Box-Muller for normal sample (no external dep).
        let u1: f64 = self.rng.r#gen::<f64>().max(f64::EPSILON);
        let u2: f64 = self.rng.r#gen::<f64>();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample_ms = (mu + sigma * z).exp().clamp(50.0, 8000.0);
        let sleep_ms = sample_ms as u64;
        TimingProfile {
            sleep_ms,
            is_burst: sample_ms < mean * 0.5,
        }
    }

    fn realistic_accept(&mut self) -> String {
        // Different browsers have different Accept header values.
        if self.session_user_agent.contains("Firefox") {
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()
        } else if self.session_user_agent.contains("Safari") && !self.session_user_agent.contains("Chrome") {
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()
        } else {
            // Chrome / Chromium family.
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".into()
        }
    }

    fn sample_referer(&mut self) -> String {
        // 70% chance of a referer after the first request.
        if self.request_count == 1 {
            // First request: may come from search or direct.
            let pool = &self.profile.referer_pool;
            return sample_weighted_str(pool, &mut self.rng);
        }
        if self.rng.gen_bool(0.70) {
            if let Some(cur) = &self.current_url {
                return cur.clone();
            }
        }
        sample_weighted_str(&self.profile.referer_pool, &mut self.rng)
    }

    fn inject_sec_fetch(&mut self, headers: &mut Vec<(String, String)>) {
        let mode = sample_weighted_str(&self.profile.sec_fetch_mode, &mut self.rng);
        let dest = match mode.as_str() {
            "navigate" => "document",
            "cors" => "empty",
            "no-cors" => "image",
            "same-origin" => "empty",
            _ => "document",
        };
        let site = if self.current_url.is_some() && self.rng.gen_bool(0.6) {
            "same-origin"
        } else {
            "cross-site"
        };
        set_header(headers, "sec-fetch-mode", &mode);
        set_header(headers, "sec-fetch-dest", dest);
        set_header(headers, "sec-fetch-site", site);
        // sec-fetch-user: only on user-initiated navigations.
        if mode == "navigate" && self.rng.gen_bool(0.8) {
            set_header(headers, "sec-fetch-user", "?1");
        }
    }

    fn platform_hint(&self) -> &'static str {
        let ua = &self.session_user_agent;
        if ua.contains("Android") { "\"Android\"" }
        else if ua.contains("iPhone") || ua.contains("iPad") { "\"iOS\"" }
        else if ua.contains("Macintosh") { "\"macOS\"" }
        else { "\"Windows\"" }
    }

    /// Update the simulated current URL (for referer chain maintenance).
    pub fn set_current_url(&mut self, url: impl Into<String>) {
        self.current_url = Some(url.into());
    }

    /// Current request count in this session.
    #[must_use]
    pub fn request_count(&self) -> u32 {
        self.request_count
    }

    /// Profile name.
    #[must_use]
    pub fn profile_name(&self) -> &'static str {
        self.profile.name
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    for (n, v) in headers.iter_mut() {
        if n.to_ascii_lowercase() == name {
            *v = value.to_string();
            return;
        }
    }
    headers.push((name.to_string(), value.to_string()));
}

fn sample_weighted_str<S: AsRef<str>>(pool: &[S], rng: &mut StdRng) -> String {
    if pool.is_empty() {
        return String::new();
    }
    let idx = rng.gen_range(0..pool.len());
    pool[idx].as_ref().to_string()
}

fn sample_accept_language(variants: &[(&'static str, f64)], rng: &mut StdRng) -> String {
    if variants.is_empty() {
        return "en-US,en;q=0.9".to_string();
    }
    let total: f64 = variants.iter().map(|(_, w)| w).sum();
    let mut r = rng.r#gen::<f64>() * total;
    for (lang, weight) in variants {
        r -= weight;
        if r <= 0.0 {
            return lang.to_string();
        }
    }
    variants.last().unwrap().0.to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_injector() -> NoiseInjector {
        NoiseInjector::new(BehavioralProfile::chrome_us(), 0xDEAD_BEEF)
    }

    #[test]
    fn inject_adds_user_agent() {
        let mut injector = make_injector();
        let mut headers: Vec<(String, String)> = Vec::new();
        injector.inject(&mut headers);
        assert!(
            headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "user-agent"),
            "user-agent must be injected"
        );
    }

    #[test]
    fn inject_adds_accept_language() {
        let mut injector = make_injector();
        let mut headers = Vec::new();
        injector.inject(&mut headers);
        assert!(headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "accept-language"));
    }

    #[test]
    fn inject_adds_accept_encoding() {
        let mut injector = make_injector();
        let mut headers = Vec::new();
        injector.inject(&mut headers);
        assert!(headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "accept-encoding"));
    }

    #[test]
    fn inject_adds_sec_fetch_mode() {
        let mut injector = make_injector();
        let mut headers = Vec::new();
        injector.inject(&mut headers);
        assert!(headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "sec-fetch-mode"));
    }

    #[test]
    fn inject_chrome_emits_client_hints() {
        let mut injector = make_injector();
        let mut headers = Vec::new();
        injector.inject(&mut headers);
        assert!(
            headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "sec-ch-ua"),
            "Chrome profile must emit sec-ch-ua"
        );
    }

    #[test]
    fn inject_firefox_no_client_hints() {
        let mut injector = NoiseInjector::new(BehavioralProfile::firefox_eu(), 42);
        let mut headers = Vec::new();
        injector.inject(&mut headers);
        assert!(
            !headers.iter().any(|(n, _)| n.to_ascii_lowercase() == "sec-ch-ua"),
            "Firefox profile must NOT emit sec-ch-ua"
        );
    }

    #[test]
    fn inject_does_not_overwrite_attack_headers() {
        let mut injector = make_injector();
        let mut headers = vec![
            ("x-attack-payload".to_string(), "' OR 1=1--".to_string()),
        ];
        injector.inject(&mut headers);
        // Attack header must be preserved.
        assert!(
            headers.iter().any(|(n, v)| n == "x-attack-payload" && v == "' OR 1=1--"),
            "attack headers must survive injection"
        );
    }

    #[test]
    fn inject_replaces_existing_user_agent() {
        let mut injector = make_injector();
        let mut headers = vec![("user-agent".to_string(), "wafrift-bot/1.0".to_string())];
        injector.inject(&mut headers);
        let ua = headers
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == "user-agent")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_ne!(ua, "wafrift-bot/1.0", "old UA must be replaced");
        assert!(
            ua.contains("Mozilla"),
            "new UA must be browser-like: {ua}"
        );
    }

    #[test]
    fn inject_user_agent_is_stable_across_calls() {
        let mut injector = make_injector();
        let mut h1 = Vec::new();
        let mut h2 = Vec::new();
        injector.inject(&mut h1);
        injector.inject(&mut h2);
        let ua1 = h1.iter().find(|(n, _)| n.to_ascii_lowercase() == "user-agent").unwrap().1.clone();
        let ua2 = h2.iter().find(|(n, _)| n.to_ascii_lowercase() == "user-agent").unwrap().1.clone();
        assert_eq!(ua1, ua2, "UA must be stable within a session");
    }

    #[test]
    fn inject_accept_language_is_stable() {
        let mut injector = make_injector();
        let mut h1 = Vec::new();
        let mut h2 = Vec::new();
        injector.inject(&mut h1);
        injector.inject(&mut h2);
        let al1 = h1.iter().find(|(n, _)| n.to_ascii_lowercase() == "accept-language").unwrap().1.clone();
        let al2 = h2.iter().find(|(n, _)| n.to_ascii_lowercase() == "accept-language").unwrap().1.clone();
        assert_eq!(al1, al2, "Accept-Language must be stable within a session");
    }

    #[test]
    fn timing_is_positive_and_capped() {
        let mut injector = make_injector();
        for _ in 0..20 {
            let timing = injector.next_timing();
            assert!(timing.sleep_ms >= 50, "sleep must be >= 50ms");
            assert!(timing.sleep_ms <= 8000, "sleep must be <= 8000ms");
        }
    }

    #[test]
    fn request_count_increments() {
        let mut injector = make_injector();
        assert_eq!(injector.request_count(), 0);
        let mut h = Vec::new();
        injector.inject(&mut h);
        assert_eq!(injector.request_count(), 1);
        injector.inject(&mut h);
        assert_eq!(injector.request_count(), 2);
    }

    #[test]
    fn set_current_url_affects_referer() {
        let mut injector = make_injector();
        injector.set_current_url("https://target.example.com/page");
        // After the first request, subsequent ones have 70% referer from current_url.
        // Do 30 second-request injections and check that referer appears sometimes.
        let mut h = Vec::new();
        injector.inject(&mut h); // request 1
        let mut saw_referer = false;
        for _ in 0..30 {
            let mut hh = Vec::new();
            injector.inject(&mut hh);
            if let Some((_, v)) = hh.iter().find(|(n, _)| n.to_ascii_lowercase() == "referer") {
                if v.contains("target.example.com") {
                    saw_referer = true;
                    break;
                }
            }
        }
        assert!(saw_referer, "current_url should appear as referer in some requests");
    }

    #[test]
    fn safari_profile_constructs() {
        let profile = BehavioralProfile::safari_us();
        assert_eq!(profile.name, "safari_17_5_macos14_us");
        assert!(!profile.emit_client_hints);
        assert!(profile.sec_ch_ua.is_none());
    }

    #[test]
    fn android_profile_constructs() {
        let profile = BehavioralProfile::chrome_android();
        assert!(profile.emit_client_hints);
        assert!(!profile.user_agent_pool.is_empty());
        assert!(profile.user_agent_pool.iter().any(|ua| ua.contains("Android")));
    }

    #[test]
    fn all_profiles_have_non_empty_ua_pool() {
        for profile in [
            BehavioralProfile::chrome_us(),
            BehavioralProfile::firefox_eu(),
            BehavioralProfile::safari_us(),
            BehavioralProfile::chrome_android(),
        ] {
            assert!(!profile.user_agent_pool.is_empty(), "{} has empty UA pool", profile.name);
        }
    }

    #[test]
    fn accept_language_weighted_sampling_is_stable() {
        // Sampling with the same seed must be deterministic.
        let mut rng1 = StdRng::seed_from_u64(99);
        let mut rng2 = StdRng::seed_from_u64(99);
        let variants = &BehavioralProfile::chrome_us().accept_language_variants;
        let s1 = sample_accept_language(variants, &mut rng1);
        let s2 = sample_accept_language(variants, &mut rng2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn profile_name_is_accessible() {
        let injector = make_injector();
        assert_eq!(injector.profile_name(), "chrome_131_win11_us");
    }
}
