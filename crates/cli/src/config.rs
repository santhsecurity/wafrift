//! TOML configuration file support for `WafRift`.
//!
//! Config files are loaded in priority order (CLI flags > env vars > file):
//!   1. `.wafrift.toml` in the current directory
//!   2. `~/.config/wafrift/config.toml`
//!
//! Any field left unset in the config file uses compiled defaults.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default User-Agent used by every wafrift HTTP client when the
/// operator hasn't set one in `.wafrift.toml`. Browser-shaped because
/// most WAF Core Rule Set bundles block non-browser UAs (ModSecurity
/// PL2+ fires rule 913100/913110 on `reqwest/*`, `curl/*`,
/// `python-requests/*` before any payload-inspection ever runs).
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

/// Operator-configured UA installed once at startup by `main()` from
/// `WafRiftConfig::http.user_agent`. `None` means "use the default";
/// `Some(String)` is the operator's override. Read via
/// [`shared_user_agent`] from every command's HTTP-client builder so
/// the config flag actually changes the wire bytes — the field used
/// to be parsed-and-ignored.
static CONFIGURED_USER_AGENT: OnceLock<Option<String>> = OnceLock::new();

/// Install the operator's configured User-Agent at startup.
/// Idempotent — subsequent calls are no-ops. `None` means "use the
/// browser default"; `Some(s)` overrides it for every wafrift
/// HTTP-client builder.
pub fn install_user_agent(ua: Option<String>) {
    let _ = CONFIGURED_USER_AGENT.set(ua);
}

/// Pure resolver: configured override wins, default otherwise.
/// Factored out from [`shared_user_agent`] so unit tests can
/// exercise the resolution logic without touching the process-wide
/// OnceLock (which is order-dependent across tests in the same
/// binary — a test contract bug we hit on the first commit of
/// this wiring). The runtime path stays thin: `shared_user_agent`
/// is one OnceLock lookup + this resolver.
#[must_use]
pub(crate) fn resolve_user_agent(configured: Option<&str>) -> String {
    configured
        .map(str::to_owned)
        .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string())
}

/// Resolve the User-Agent every wafrift HTTP client should send.
/// Pulls the operator-configured value (set by `main()` from
/// `.wafrift.toml`'s `http.user_agent`) and falls back to
/// [`DEFAULT_USER_AGENT`] otherwise. Returns an owned String because
/// `reqwest::ClientBuilder::user_agent` takes anything convertible to
/// a HeaderValue and we want the configured-string path to not require
/// `Box::leak` for `&'static str`.
#[must_use]
pub fn shared_user_agent() -> String {
    resolve_user_agent(CONFIGURED_USER_AGENT.get().and_then(|o| o.as_deref()))
}

/// Map a config `scan.level` string onto the CLI `Level` enum. Unknown
/// values return `None` (keep the existing value) rather than silently
/// snapping to a default the operator didn't write.
fn parse_config_level(s: &str) -> Option<crate::Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "light" => Some(crate::Level::Light),
        "medium" => Some(crate::Level::Medium),
        "heavy" => Some(crate::Level::Heavy),
        _ => None,
    }
}

/// Operational configuration (Tier A) — runtime behavior tuning.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WafRiftConfig {
    /// Default scan settings.
    pub scan: ScanConfig,
    /// HTTP transport settings.
    pub http: HttpConfig,
    /// Output settings.
    pub output: OutputConfig,
}

/// Scan-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Default evasion intensity: "light", "medium", or "heavy".
    pub level: String,
    /// Default query parameter name for injection.
    pub param: String,
    /// Delay between requests in milliseconds.
    pub delay_ms: u64,
    /// Apply encoding only (no grammar mutations).
    pub encoding_only: bool,
    /// Concurrency level for parallel variant firing.
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            level: String::from("heavy"),
            param: String::from("q"),
            delay_ms: 50,
            encoding_only: false,
            concurrency: 8,
        }
    }
}

/// HTTP transport configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Browser fingerprint to impersonate.
    pub stealth_browser: Option<String>,
    /// Disable TLS certificate verification.
    pub insecure: bool,
    /// Custom User-Agent header.
    pub user_agent: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            stealth_browser: None,
            insecure: false,
            user_agent: None,
            timeout_secs: 30,
        }
    }
}

/// Output configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Default output format: "text" or "json".
    pub format: String,
    /// Include layer report in JSON output.
    pub report_layers: bool,
    /// Suppress human-readable output.
    pub quiet: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: String::from("text"),
            report_layers: false,
            quiet: false,
        }
    }
}

impl WafRiftConfig {
    /// Load configuration from the standard search paths.
    ///
    /// Search order:
    /// 1. `.wafrift.toml` in the current working directory
    /// 2. `~/.config/wafrift/config.toml`
    ///
    /// Returns `Default` if no config file is found.
    pub fn load() -> Self {
        // Try current directory first.
        let cwd_config = PathBuf::from(".wafrift.toml");
        if let Ok(config) = Self::load_from(&cwd_config) {
            return config;
        }

        // Try XDG / home config.
        if let Some(config_dir) = dirs::config_dir() {
            let home_config = config_dir.join("wafrift").join("config.toml");
            if let Ok(config) = Self::load_from(&home_config) {
                return config;
            }
        }

        Self::default()
    }

    /// Overlay this config onto parsed `scan` arguments with correct
    /// precedence: **CLI flag > config file > compiled default**.
    ///
    /// Correctness hinges on `clap`'s `ValueSource`: a field is only
    /// overridden by config when clap reports the value came from the
    /// compiled default (or the arg is absent), never when the operator
    /// actually typed it. This is what makes `.wafrift.toml` real
    /// instead of the documented-but-ignored stub the scaffold warned
    /// about.
    #[must_use]
    pub fn apply_to_scan(
        &self,
        mut args: crate::ScanArgs,
        m: Option<&clap::ArgMatches>,
    ) -> crate::ScanArgs {
        use clap::parser::ValueSource;
        // True when the operator did NOT explicitly set this arg.
        let from_default = |name: &str| {
            m.is_none_or(|m| !matches!(m.value_source(name), Some(ValueSource::CommandLine)))
        };
        if from_default("delay_ms") {
            args.delay_ms = self.scan.delay_ms;
        }
        if from_default("param") {
            args.param.clone_from(&self.scan.param);
        }
        if from_default("encoding_only") {
            args.encoding_only = self.scan.encoding_only;
        }
        if from_default("format") {
            args.format.clone_from(&self.output.format);
        }
        if from_default("insecure") {
            args.insecure = self.http.insecure;
        }
        if from_default("level")
            && let Some(level) = parse_config_level(&self.scan.level)
        {
            args.level = level;
        }
        if from_default("stealth_browser") && args.stealth_browser.is_none() {
            args.stealth_browser.clone_from(&self.http.stealth_browser);
        }
        // The clap arg name uses kebab-case (`report-layers`) but
        // ValueSource lookups always go through the underlying field
        // name — match `ScanArgs.report_layers`. Pre-fix this field was
        // documented and parsed but never applied; a user setting
        // `output.report_layers = true` in `.wafrift.toml` got no
        // layer-report in their JSON. Honest behaviour now matches
        // the docs.
        if from_default("report_layers") {
            args.report_layers = self.output.report_layers;
        }
        // `scan.concurrency`, `http.timeout_secs`, `output.quiet` were
        // documented config fields with no apply path — operators set
        // them in `.wafrift.toml` and got no effect. Now wired to the
        // matching ScanArgs flags (added 2026-05). 0 = scan-side
        // dynamic default (keeps every pre-flag invocation behaving
        // identically), so an unset config field keeps the existing
        // behaviour.
        if from_default("concurrency") {
            args.concurrency = self.scan.concurrency;
        }
        if from_default("timeout_secs") {
            args.timeout_secs = self.http.timeout_secs;
        }
        if from_default("quiet") {
            args.quiet = self.output.quiet;
        }
        args
    }

    /// Load configuration from a specific file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config at {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = WafRiftConfig::default();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
        assert!(!config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 8);
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn parse_toml_config() {
        let toml_str = r#"
[scan]
level = "light"
param = "id"
delay_ms = 100
encoding_only = true
concurrency = 4

[http]
insecure = true
stealth_browser = "chrome"
user_agent = "WafRift/1.0"
timeout_secs = 60

[output]
format = "json"
report_layers = true
quiet = true
"#;
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.level, "light");
        assert_eq!(config.scan.param, "id");
        assert_eq!(config.scan.delay_ms, 100);
        assert!(config.scan.encoding_only);
        assert_eq!(config.scan.concurrency, 4);
        assert!(config.http.insecure);
        assert_eq!(config.http.stealth_browser.as_deref(), Some("chrome"));
        assert_eq!(config.http.user_agent.as_deref(), Some("WafRift/1.0"));
        assert_eq!(config.http.timeout_secs, 60);
        assert_eq!(config.output.format, "json");
        assert!(config.output.report_layers);
        assert!(config.output.quiet);
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r"
[scan]
delay_ms = 200
";
        let config: WafRiftConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.scan.delay_ms, 200);
        // Everything else should use defaults.
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert!(!config.http.insecure);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let config: WafRiftConfig = toml::from_str("").unwrap();
        assert_eq!(config.scan.level, "heavy");
        assert_eq!(config.scan.param, "q");
        assert_eq!(config.scan.delay_ms, 50);
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = WafRiftConfig::load_from(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_user_agent_defaults_when_none() {
        assert_eq!(resolve_user_agent(None), DEFAULT_USER_AGENT);
    }

    #[test]
    fn resolve_user_agent_uses_configured_when_some() {
        let got = resolve_user_agent(Some("WafRift-Test/9.9"));
        assert_eq!(got, "WafRift-Test/9.9");
        // And critically NOT the default — would prove an off-by-one
        // in `unwrap_or_else` that flipped Some/None branches.
        assert_ne!(got, DEFAULT_USER_AGENT);
    }

    #[test]
    fn default_user_agent_is_browser_shaped() {
        // CRS PL2+ blocks non-browser UAs (`reqwest/*`, `curl/*`,
        // `python-requests/*` trigger rule 913100/913110) before any
        // payload inspection. Pin a browser-signature substring so
        // an accidental "Wafrift/1.0" baked into the default would
        // fail CI rather than silently get every default install
        // blocked at PL2.
        assert!(
            DEFAULT_USER_AGENT.contains("Mozilla"),
            "DEFAULT_USER_AGENT must be browser-shaped: got {DEFAULT_USER_AGENT:?}"
        );
        assert!(
            DEFAULT_USER_AGENT.contains("Chrome") || DEFAULT_USER_AGENT.contains("Safari"),
            "DEFAULT_USER_AGENT must look like a real browser, not a generic Mozilla token"
        );
    }

    // ── ScanArgs config-wiring contract gates ──
    // Each `[output] / [scan] / [http]` field documented in the
    // README must have an apply path. Before 2026-05 the wiring was
    // partial: `report_layers`, `concurrency`, `timeout_secs`, and
    // `quiet` were parsed-and-ignored. These tests pin the wiring so
    // the contract can't regress silently again.

    fn default_scan_args() -> crate::ScanArgs {
        crate::ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            payload: "x".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Heavy,
            encoding_only: false,
            delay_ms: 50,
            format: "text".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: 200,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: 5,
            exploit_cap: 500,
            variants_cap: 0,
<<<<<<< HEAD
=======
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: "127.0.0.1:1055".into(),
            egress_challenge_threshold: 3,
            egress_cooldown_secs: 300,
            i_have_permission: None,
            graphql: false,
            custom_rules: None,
>>>>>>> Maximally use existing infra: wire hunt corpus + custom_rules
        }
    }

    #[test]
    fn apply_to_scan_wires_report_layers() {
        let mut cfg = WafRiftConfig::default();
        cfg.output.report_layers = true;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert!(
            args.report_layers,
            "output.report_layers must flow to ScanArgs.report_layers"
        );
    }

    #[test]
    fn apply_to_scan_wires_concurrency() {
        let mut cfg = WafRiftConfig::default();
        cfg.scan.concurrency = 16;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert_eq!(
            args.concurrency, 16,
            "scan.concurrency must flow to ScanArgs.concurrency"
        );
    }

    #[test]
    fn apply_to_scan_wires_timeout_secs() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.timeout_secs = 120;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert_eq!(
            args.timeout_secs, 120,
            "http.timeout_secs must flow to ScanArgs.timeout_secs"
        );
    }

    #[test]
    fn apply_to_scan_wires_quiet() {
        let mut cfg = WafRiftConfig::default();
        cfg.output.quiet = true;
        let args = cfg.apply_to_scan(default_scan_args(), None);
        assert!(args.quiet, "output.quiet must flow to ScanArgs.quiet");
    }
}
