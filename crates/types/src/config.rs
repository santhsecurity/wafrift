//! Evasion configuration — knobs for the strategy engine.
//!
//! One struct, one job: controls which evasion layers are enabled
//! and how aggressively the engine escalates.

use serde::{Deserialize, Serialize};

/// Evasion configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Enable payload encoding transformations.
    pub encoding_enabled: bool,
    /// Enable Content-Type switching (form → JSON, XML, multipart).
    pub content_type_switching: bool,
    /// Enable browser fingerprint rotation (User-Agent, Accept, etc.).
    pub fingerprint_rotation: bool,
    /// Enable header obfuscation (case mixing, tab separators, folding).
    pub header_obfuscation: bool,
    /// Enable grammar-aware payload mutation (SQL/XSS/CMD transforms).
    pub grammar_mutations: bool,
    /// Enable request smuggling metadata generation.
    pub smuggling_enabled: bool,
    /// Enable HTTP/2 evasion metadata generation.
    pub h2_evasion_enabled: bool,
    /// Maximum evasion retry attempts before giving up.
    pub max_attempts: u32,
    /// Disable TLS verification (`danger_accept_invalid_certs`).
    pub insecure_tls: bool,
    /// Proxies for round-robin IP rotation.
    #[serde(default)]
    pub proxies: Vec<String>,
    /// Manual origin bypass mapping from Host to IP.
    #[serde(default)]
    pub origin_bypass: std::collections::HashMap<String, std::net::IpAddr>,
    /// Body padding (bytes) — pre-pend N bytes of inert filler to
    /// JSON / form / multipart bodies so the malicious payload sits
    /// past cloud-WAF inspection windows (Cloudflare Pro 8 KB, AWS
    /// WAF 16 KB). 0 disables padding entirely. Anything below
    /// `wafrift_evolution::body_padding::MIN_USEFUL_PAD` is silently
    /// skipped at strategy time.
    #[serde(default)]
    pub body_padding_bytes: usize,
    /// Mutate URL/query-param payload bytes (off by default).
    ///
    /// When true, the evade pipeline applies the same encoding +
    /// grammar mutations to query-string parameter VALUES (not
    /// names) and to the path's last segment. This is the canonical
    /// attack surface for SQLi-in-`?id=` / XSS-in-`?q=` etc — most
    /// production attacks live in URL parameters, not request bodies.
    ///
    /// **Off by default** because mutating the URL changes upstream
    /// routing semantics (e.g. cache keys, log entries, downstream
    /// handler dispatch). Operators must opt in via
    /// `wafrift-proxy --mutate-url` (or set this field via TOML).
    #[serde(default)]
    pub mutate_url: bool,

    /// Allow upstream targets that fall in the bogon set
    /// (loopback / RFC1918 / CGN / Teredo / IMDS / etc.).
    ///
    /// Off by default — wafrift-transport's `EvasionClient` rejects
    /// literal-IP requests to these ranges as a defence-in-depth
    /// against accidental SSRF. Set true when targeting a lab
    /// upstream on 127.0.0.1 / 192.168.x or when running tests
    /// against a wiremock instance bound to loopback. Audit
    /// (2026-05-10).
    #[serde(default)]
    pub allow_private_upstream: bool,

    /// Weight for the ensemble sub-score dilution component in evolutionary
    /// fitness scoring (`--dilution-weight`). Range `[0.0, 1.0]`.
    ///
    /// When `> 0`, the evolution engine blends a dilution-plausibility
    /// score (from `wafrift-wafmodel::ensemble_dilution`) into the oracle
    /// fitness at submission time:
    ///   `final_fitness = oracle_fitness * (1 - w) + dilution_score * w`
    ///
    /// Only active when the target WAF fingerprint shows a multi-rule-group
    /// ensemble (Cloudflare Managed Rules, AWS Core Rule Set). On non-ensemble
    /// WAFs this field has no effect regardless of value.
    ///
    /// Default `0.0` (disabled) — callers opt in explicitly via CLI or TOML.
    #[serde(default)]
    pub dilution_weight: f64,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: true,
            fingerprint_rotation: true,
            header_obfuscation: true,
            grammar_mutations: true,
            smuggling_enabled: true,
            h2_evasion_enabled: true,
            max_attempts: 5,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
            body_padding_bytes: 0,
            mutate_url: false,
            allow_private_upstream: false,
            dilution_weight: 0.0,
        }
    }
}

impl EvasionConfig {
    /// Create a minimal config with only encoding enabled.
    #[must_use]
    pub fn encoding_only() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: false,
            fingerprint_rotation: false,
            header_obfuscation: false,
            grammar_mutations: false,
            smuggling_enabled: false,
            h2_evasion_enabled: false,
            max_attempts: 3,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
            body_padding_bytes: 0,
            mutate_url: false,
            allow_private_upstream: false,
            dilution_weight: 0.0,
        }
    }

    /// Create a maximum-aggression config with everything enabled.
    #[must_use]
    pub fn maximum() -> Self {
        Self {
            encoding_enabled: true,
            content_type_switching: true,
            fingerprint_rotation: true,
            header_obfuscation: true,
            grammar_mutations: true,
            smuggling_enabled: true,
            h2_evasion_enabled: true,
            max_attempts: 10,
            insecure_tls: false,
            proxies: Vec::new(),
            origin_bypass: std::collections::HashMap::new(),
            // Default to AWS-WAF-default-tier (16 KB) — covers
            // Cloudflare Pro (8 KB), AWS WAF default, Akamai default.
            body_padding_bytes: 16 * 1024,
            // maximum() is opt-in aggression — flip URL mutation on
            // too. Operators reaching for `maximum()` already accept
            // the routing-semantics tradeoffs.
            mutate_url: true,
            // maximum() is for offensive testing on lab infra, where
            // loopback / RFC1918 targets are normal. Stays false in
            // production via the default; flips true here.
            allow_private_upstream: true,
            // maximum() enables dilution scoring at the recommended
            // operational weight. Callers that don't want it use default().
            dilution_weight: 0.3,
        }
    }

    /// Maximum permitted `body_padding_bytes`. Requests padded beyond this
    /// (256 MiB) would exhaust memory on the sending host before reaching
    /// the WAF.
    pub const MAX_BODY_PADDING_BYTES: usize = 256 * 1024 * 1024;

    /// Maximum permitted `max_attempts`. Values above this would effectively
    /// make the retry loop infinite for any non-trivial target.
    pub const MAX_ATTEMPTS: u32 = 10_000;

    /// Validate the configuration for conflicts or missing dependencies.
    pub fn validate(&self) -> Result<(), String> {
        if self.insecure_tls {
            tracing::warn!(
                "TLS certificate validation is disabled (--insecure-tls). Do not use in production."
            );
        }

        if self.grammar_mutations && !self.encoding_enabled {
            tracing::warn!(
                "Grammar mutations are enabled but encoding is disabled. Mutations may require encoding to bypass effectively."
            );
        }

        if self.max_attempts == 0 {
            return Err("max_attempts must be greater than 0".to_string());
        }
        if self.max_attempts > Self::MAX_ATTEMPTS {
            return Err(format!(
                "max_attempts {} exceeds maximum allowed value {}",
                self.max_attempts,
                Self::MAX_ATTEMPTS,
            ));
        }

        if self.body_padding_bytes > Self::MAX_BODY_PADDING_BYTES {
            return Err(format!(
                "body_padding_bytes {} exceeds maximum allowed value {} (256 MiB)",
                self.body_padding_bytes,
                Self::MAX_BODY_PADDING_BYTES,
            ));
        }

        if !self.dilution_weight.is_finite() {
            return Err(format!(
                "dilution_weight must be finite, got {}",
                self.dilution_weight
            ));
        }
        if self.dilution_weight < 0.0 || self.dilution_weight > 1.0 {
            return Err(format!(
                "dilution_weight {} is out of range [0.0, 1.0]",
                self.dilution_weight
            ));
        }

        self.validate_proxies()?;

        Ok(())
    }

    /// Validate the format of proxies.
    fn validate_proxies(&self) -> Result<(), String> {
        for proxy in &self.proxies {
            if !proxy.starts_with("http://")
                && !proxy.starts_with("https://")
                && !proxy.starts_with("socks5://")
                && !proxy.starts_with("socks5h://")
            {
                return Err(format!(
                    "Invalid proxy URL '{proxy}': must start with http://, https://, socks5://, or socks5h://"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_all_enabled() {
        let config = EvasionConfig::default();
        assert!(config.encoding_enabled);
        assert!(config.content_type_switching);
        assert!(config.fingerprint_rotation);
        assert!(config.header_obfuscation);
        assert!(config.grammar_mutations);
        assert!(config.smuggling_enabled);
        assert!(config.h2_evasion_enabled);
        assert_eq!(config.max_attempts, 5);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn encoding_only_config() {
        let config = EvasionConfig::encoding_only();
        assert!(config.encoding_enabled);
        assert!(!config.content_type_switching);
        assert!(!config.grammar_mutations);
    }

    #[test]
    fn maximum_config() {
        let config = EvasionConfig::maximum();
        assert!(config.grammar_mutations);
        assert_eq!(config.max_attempts, 10);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = EvasionConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let deserialized: EvasionConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.max_attempts, config.max_attempts);
    }

    // ── validate() bounds checks ─────────────────────────────────

    #[test]
    fn validate_rejects_max_attempts_zero() {
        let mut cfg = EvasionConfig::default();
        cfg.max_attempts = 0;
        assert!(cfg.validate().is_err(), "max_attempts=0 must be rejected");
    }

    #[test]
    fn validate_rejects_max_attempts_above_ceiling() {
        let mut cfg = EvasionConfig::default();
        cfg.max_attempts = EvasionConfig::MAX_ATTEMPTS + 1;
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("max_attempts"),
            "error must mention field, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_max_attempts_at_ceiling() {
        let mut cfg = EvasionConfig::default();
        cfg.max_attempts = EvasionConfig::MAX_ATTEMPTS;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_body_padding_above_ceiling() {
        let mut cfg = EvasionConfig::default();
        cfg.body_padding_bytes = EvasionConfig::MAX_BODY_PADDING_BYTES + 1;
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("body_padding_bytes"),
            "error must mention field, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_body_padding_at_ceiling() {
        let mut cfg = EvasionConfig::default();
        cfg.body_padding_bytes = EvasionConfig::MAX_BODY_PADDING_BYTES;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_dilution_weight_nan() {
        let mut cfg = EvasionConfig::default();
        cfg.dilution_weight = f64::NAN;
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("dilution_weight"),
            "error must mention field, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_dilution_weight_inf() {
        let mut cfg = EvasionConfig::default();
        cfg.dilution_weight = f64::INFINITY;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("dilution_weight"));
        cfg.dilution_weight = f64::NEG_INFINITY;
        let err2 = cfg.validate().unwrap_err();
        assert!(err2.contains("dilution_weight"));
    }

    #[test]
    fn validate_rejects_dilution_weight_out_of_range() {
        let mut cfg = EvasionConfig::default();
        cfg.dilution_weight = 1.1;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("dilution_weight"), "got: {err}");
        cfg.dilution_weight = -0.1;
        let err2 = cfg.validate().unwrap_err();
        assert!(err2.contains("dilution_weight"), "got: {err2}");
    }

    #[test]
    fn validate_accepts_dilution_weight_boundary_values() {
        let mut cfg = EvasionConfig::default();
        cfg.dilution_weight = 0.0;
        assert!(cfg.validate().is_ok());
        cfg.dilution_weight = 1.0;
        assert!(cfg.validate().is_ok());
        cfg.dilution_weight = 0.5;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_invalid_proxy_scheme() {
        let mut cfg = EvasionConfig::default();
        cfg.proxies = vec!["ftp://bad.proxy:21".to_string()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_proxy_schemes() {
        let mut cfg = EvasionConfig::default();
        for scheme in &[
            "http://proxy:8080",
            "https://proxy:8443",
            "socks5://proxy:1080",
            "socks5h://proxy:1080",
        ] {
            cfg.proxies = vec![(*scheme).to_string()];
            assert!(
                cfg.validate().is_ok(),
                "scheme {scheme} should be accepted"
            );
        }
    }

    #[test]
    fn maximum_config_passes_validate() {
        assert!(EvasionConfig::maximum().validate().is_ok());
    }

    #[test]
    fn encoding_only_config_passes_validate() {
        assert!(EvasionConfig::encoding_only().validate().is_ok());
    }
}
