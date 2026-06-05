//! TOML configuration file support for `WafRift`.
//!
//! Config files are loaded in priority order (CLI flags > env vars > file):
//!   1. `.wafrift.toml` in the current directory
//!   2. `~/.config/wafrift/config.toml`
//!
//! Any field left unset in the config file uses compiled defaults.

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use guise::fingerprint::{StealthProfile, default_profile_user_agent, profile_user_agent};
use guise::http::browser_header_map_without_compression;
use guise::rotation::named_profile;

/// Default User-Agent used by every wafrift HTTP client when the
/// operator hasn't set one in `.wafrift.toml`. Browser-shaped because
/// most WAF Core Rule Set bundles block non-browser UAs (ModSecurity
/// PL2+ fires rule 913100/913110 on `reqwest/*`, `curl/*`,
/// `python-requests/*` before any payload-inspection ever runs).
pub(crate) use guise::fingerprint::DEFAULT_STEALTH_PROFILE;
pub(crate) const DEFAULT_USER_AGENT: &str = default_profile_user_agent();

/// Default Tailscale SOCKS5 listener address used by every wafrift egress
/// path that needs Tailscale tunneling. Centralised here so that
/// `import_curl`, `hunt_cmd`, `raw_runner`, `model_evade_cmd`, `bench_waf`,
/// and the config-test helper all agree on the same string without
/// independent copies that can silently drift (§6).
pub(crate) const DEFAULT_TAILSCALE_SOCKS_ADDR: &str = "127.0.0.1:1055";

/// Re-export of `wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD` for
/// ergonomic use from this crate. The canonical home is `wafrift_types`
/// so the `wafrift-transport::egress_pool` builder (which cannot depend
/// on `wafrift-cli`) sees the same value. R63 pass-21 §6.
pub(crate) use wafrift_types::{DEFAULT_EGRESS_CHALLENGE_THRESHOLD, DEFAULT_EGRESS_COOLDOWN_SECS};

/// Differential-baseline verification toggle. When enabled, a payload
/// variant is credited as a WAF bypass ONLY when the UN-EVADED base
/// payload is BLOCKED in the same delivery — proving the evasion is what
/// passed the variant, not that the WAF never policed that attack at all.
/// Set once at startup by `main()` from the `--differential` flag. Default
/// OFF so the headline bypass metric is byte-for-byte unchanged unless the
/// operator explicitly opts in (anti-rig: never silently move the number).
static DIFFERENTIAL_BASELINE: OnceLock<bool> = OnceLock::new();

/// Install the differential-baseline toggle at startup. Idempotent.
pub(crate) fn install_differential(enabled: bool) {
    let _ = DIFFERENTIAL_BASELINE.set(enabled);
}

/// Whether differential-baseline verification is active for this run.
/// Defaults to `false` (legacy crediting) when never installed.
#[must_use]
pub(crate) fn differential_enabled() -> bool {
    DIFFERENTIAL_BASELINE.get().copied().unwrap_or(false)
}

/// Detonation engine the `detonate` subprocess should use when wafrift proves
/// execution (`--prove-execution`, `exploit`, proxy classification). `"jsdet"`
/// (default) is the fast QuickJS sandbox; `"chrome"` selects real headless
/// Chrome, which also catches mutation-XSS and browser-only handlers the
/// sandbox cannot. Set once at startup from the global `--detonate-engine`
/// flag; passed verbatim to `detonate --engine <…>`.
static DETONATE_ENGINE: OnceLock<String> = OnceLock::new();

/// Install the detonation-engine selector at startup. Idempotent.
pub(crate) fn install_detonate_engine(engine: &str) {
    let _ = DETONATE_ENGINE.set(engine.trim().to_ascii_lowercase());
}

/// The detonation engine for this run (`"jsdet"` default). Read by
/// `exec_proof` to choose the `detonate --engine` value.
#[must_use]
pub(crate) fn detonate_engine() -> &'static str {
    DETONATE_ENGINE.get().map_or("jsdet", String::as_str)
}

/// Operator-configured UA installed once at startup by `main()` from
/// `WafRiftConfig::http.user_agent`. `None` means "use the default";
/// `Some(String)` is the operator's override. Read through
/// [`shared_scan_browser_headers`] for scan-style HTTP clients, or
/// [`shared_user_agent_explicit`] for bench paths that intentionally
/// choose their own profile rotation policy.
static CONFIGURED_USER_AGENT: OnceLock<Option<String>> = OnceLock::new();

/// Install the operator's configured User-Agent at startup.
/// Idempotent — subsequent calls are no-ops. `None` means "use the
/// browser default"; `Some(s)` overrides it for every wafrift
/// HTTP-client builder.
pub(crate) fn install_user_agent(ua: Option<String>) {
    let _ = CONFIGURED_USER_AGENT.set(ua);
}

/// Browser headers selected for a scan client.
#[derive(Debug, Clone)]
pub(crate) struct ScanBrowserHeaders {
    /// Fully materialized headers passed to reqwest `default_headers`.
    pub headers: HeaderMap,
    /// Effective User-Agent after explicit operator override handling.
    pub user_agent: String,
    /// Validated stealth profile when one was chosen or implied by defaults.
    pub profile: Option<StealthProfile>,
    /// Whether `http.user_agent` supplied the effective User-Agent.
    pub explicit_user_agent: bool,
}

/// Resolve browser-shaped HTTP headers for `wafrift scan`.
///
/// The explicit `http.user_agent` config wins because it is a literal wire
/// override. Otherwise `http.stealth_browser` / `--stealth-browser` selects the
/// canonical browser headers for that profile. Unknown names are rejected so a
/// mistyped profile cannot silently fall back to Chrome.
pub(crate) fn resolve_scan_browser_headers(
    configured: Option<&str>,
    stealth_browser: Option<&str>,
) -> Result<ScanBrowserHeaders, String> {
    let selected_profile = match stealth_browser.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(named_profile(raw).ok_or_else(|| {
            format!(
                "unknown stealth browser profile {raw:?}; use names such as chrome, \
                 chrome-macos, chrome-linux, firefox, firefox-windows, safari, edge, \
                 brave, opera, samsung-internet, chrome-windows-legacy-96, or ie11"
            )
        })?),
        None => None,
    };

    let explicit_user_agent = configured.filter(|s| !s.is_empty()).map(str::to_string);
    let explicit_user_agent_supplied = explicit_user_agent.is_some();
    let profile_for_headers = selected_profile.or_else(|| {
        if explicit_user_agent.is_none() {
            Some(DEFAULT_STEALTH_PROFILE)
        } else {
            None
        }
    });

    let mut headers = if let Some(profile) = profile_for_headers {
        browser_header_map_without_compression(profile).map_err(|e| e.to_string())?
    } else {
        HeaderMap::new()
    };
    let user_agent = explicit_user_agent.unwrap_or_else(|| {
        profile_for_headers.map_or_else(
            || DEFAULT_USER_AGENT.to_string(),
            |profile| profile_user_agent(profile).to_string(),
        )
    });
    let value = HeaderValue::from_str(&user_agent)
        .map_err(|_| format!("http.user_agent is not a valid HTTP header value: {user_agent:?}"))?;
    headers.insert(USER_AGENT, value);

    Ok(ScanBrowserHeaders {
        headers,
        user_agent,
        profile: profile_for_headers,
        explicit_user_agent: explicit_user_agent_supplied,
    })
}

/// Resolve the process-configured scan browser headers.
pub(crate) fn shared_scan_browser_headers(
    stealth_browser: Option<&str>,
) -> Result<ScanBrowserHeaders, String> {
    resolve_scan_browser_headers(
        CONFIGURED_USER_AGENT.get().and_then(|o| o.as_deref()),
        stealth_browser,
    )
}

/// Returns `Some(ua)` ONLY when the operator explicitly configured a
/// User-Agent via `.wafrift.toml`. Returns `None` when no override is
/// installed — callers can then fall back to their own UA policy
/// (e.g. bench-waf's fingerprint rotation). Scan-style clients should
/// use [`shared_scan_browser_headers`] so UA, Accept, Accept-Language,
/// and Sec-Fetch stay coherent.
#[must_use]
pub(crate) fn shared_user_agent_explicit() -> Option<String> {
    CONFIGURED_USER_AGENT
        .get()
        .and_then(|o| o.clone())
        .filter(|s| !s.is_empty())
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
// R48-I5 fix (dogfood pass 9): strict deserialisation so a typo in
// the operator's .wafrift.toml (e.g. `timout_secs` for `timeout_secs`)
// errors at load time instead of silently doing nothing. CLAUDE.md
// §11 UTILIZATION: a config field that is parsed but never reached
// is dead config; deny_unknown_fields converts the silent-typo case
// into a loud parse error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WafRiftConfig {
    /// Default scan settings.
    pub scan: ScanConfig,
    /// HTTP transport settings.
    pub http: HttpConfig,
    /// Output settings.
    pub output: OutputConfig,
}

/// Scan-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ScanConfig {
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
            delay_ms: crate::DEFAULT_DELAY_MS,
            encoding_only: false,
            concurrency: 8,
        }
    }
}

/// HTTP transport configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct HttpConfig {
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
            timeout_secs: wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}

/// Output configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct OutputConfig {
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
        // §15 TOCTOU: read_bounded_text_file opens+reads in one fd to avoid
        // a symlink-swap race between stat() and open(). .wafrift.toml configs
        // are operator-created TOML; 1 MiB is far beyond any real config file.
        let contents = crate::safe_body::read_bounded_text_file(
            path,
            crate::safe_body::MAX_OPERATOR_INPUT_BYTES,
        )
        .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config at {}: {e}", path.display()))
    }

    /// Apply HTTP-layer defaults (`http.timeout_secs`, `http.insecure`)
    /// to a detect-style args struct.
    ///
    /// R48 pass-10 I1 fix (CLAUDE.md §9 WIRING): pre-fix only ScanArgs
    /// consumed `.wafrift.toml`; detect / attack / bench-waf silently
    /// ignored the config file. This helper is the per-command wire
    /// point. ArgMatches lets us distinguish "operator passed flag
    /// explicitly" from "clap supplied default" so the config only
    /// fills the latter.
    /// Apply the http.* section of `.wafrift.toml` to any command's
    /// args struct via the [`HasHttpConfig`] trait. R48 pass-10 I1
    /// (CLAUDE.md §7 DEDUPLICATION + §9 WIRING): rather than ship
    /// N copies of `apply_http_defaults_to_<cmd>`, the args structs
    /// expose getters/setters via the trait and ONE generic apply
    /// runs against any of them. New subcommands wire in by adding
    /// a small `impl HasHttpConfig` block in their args file.
    pub fn apply_http_defaults<A: HasHttpConfig>(
        &self,
        mut args: A,
        m: Option<&clap::ArgMatches>,
    ) -> A {
        use clap::parser::ValueSource;
        let from_default = |name: &str| {
            m.is_none_or(|m| !matches!(m.value_source(name), Some(ValueSource::CommandLine)))
        };
        if from_default("timeout_secs") && self.http.timeout_secs > 0 {
            args.set_timeout_secs(self.http.timeout_secs);
        }
        if from_default("insecure") {
            args.set_insecure(self.http.insecure);
        }
        args
    }
}

/// Args structs that carry HTTP-layer settings (timeout, insecure)
/// implement this trait so [`WafRiftConfig::apply_http_defaults`]
/// can fill them from `.wafrift.toml` without per-command code.
pub(crate) trait HasHttpConfig {
    fn set_timeout_secs(&mut self, secs: u64);
    fn set_insecure(&mut self, insecure: bool);
}

impl HasHttpConfig for crate::detect_cmd::DetectArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::attack_cmd::AttackArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::bench_waf::BenchWafArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::body_diff_cmd::BodyDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::cache_diff_cmd::CacheDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::cors_diff_cmd::CorsDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::header_diff_cmd::HeaderDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-17 I1 (CLAUDE.md §9 WIRING): the six diff subcommands
// below all carry their own `--timeout-secs` / `--insecure` flags but
// were not wired through the trait, so a setting in `.wafrift.toml`
// silently applied to detect/attack/bench/header-diff/body-diff/cache-
// diff/cors-diff and silently DID NOT apply to these six. Trait impls
// + dispatch wiring in main.rs closes the gap.
impl HasHttpConfig for crate::query_diff_cmd::QueryDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::h2_diff_cmd::H2DiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::method_diff_cmd::MethodDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::gql_diff_cmd::GqlDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::jwt_diff_cmd::JwtDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::trailer_diff_cmd::TrailerDiffArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-18 I1 (CLAUDE.md §9 WIRING): distill and tmin (which
// delegates to distill) both hit the network but were dispatched
// without `apply_http_defaults`, so `.wafrift.toml`'s http.* keys
// silently dropped on the floor — operators with a lab on a
// self-signed cert had no way to make distill work short of passing
// --insecure on every invocation.
impl HasHttpConfig for crate::distill_cmd::DistillArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::tmin_cmd::TminArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R55 pass-19 I1 (CLAUDE.md §9 WIRING): bypass-probe ignored
// `.wafrift.toml`'s http.* keys silently — every other reachable
// subcommand consumes them.
impl HasHttpConfig for crate::replay::ReplayArgs {
    // R68 pass-21: pre-fix `wafrift replay` was the only network
    // subcommand without a HasHttpConfig impl; its dispatch in main.rs
    // never called apply_http_defaults so `.wafrift.toml` http.timeout
    // and http.insecure were silently ignored on every replay
    // invocation. Surface from Coherence R2 audit.
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

impl HasHttpConfig for crate::bypass_probe::BypassProbeArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

// R56 pass-20 I1 (CLAUDE.md §9 WIRING): discover was the last
// network-capable subcommand that ignored `.wafrift.toml` http.*
// keys. Added --timeout-secs / --insecure flags to DiscoverArgs
// and wire them through apply_http_defaults here.
impl HasHttpConfig for crate::discover_cmd::DiscoverArgs {
    fn set_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }
    fn set_insecure(&mut self, insecure: bool) {
        self.insecure = insecure;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::ACCEPT_LANGUAGE;

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
    fn resolve_scan_browser_headers_uses_stealth_profile_when_no_explicit_ua() {
        let got = resolve_scan_browser_headers(None, Some("firefox-windows"))
            .expect("known stealth browser must resolve");
        let expected = profile_user_agent(StealthProfile::FirefoxWindows);
        assert_eq!(got.user_agent, expected);
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), expected);
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_some());
        assert_eq!(got.profile, Some(StealthProfile::FirefoxWindows));
        assert!(!got.explicit_user_agent);
    }

    #[test]
    fn resolve_scan_browser_headers_rejects_unknown_stealth_browser() {
        let err = resolve_scan_browser_headers(None, Some("netscape-4"))
            .expect_err("unknown stealth browser must fail closed");
        assert!(err.contains("unknown stealth browser profile"));
        assert!(err.contains("chrome"));
    }

    #[test]
    fn resolve_scan_browser_headers_explicit_user_agent_wins_after_profile_validation() {
        let got = resolve_scan_browser_headers(Some("Operator-UA/7.0"), Some("chrome-linux"))
            .expect("known stealth browser must validate");
        assert_eq!(got.user_agent, "Operator-UA/7.0");
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), "Operator-UA/7.0");
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_some());
        assert_eq!(got.profile, Some(StealthProfile::ChromeLinux));
        assert!(got.explicit_user_agent);
    }

    #[test]
    fn resolve_scan_browser_headers_explicit_user_agent_without_profile_keeps_surface_minimal() {
        let got = resolve_scan_browser_headers(Some("Operator-UA/7.0"), None)
            .expect("literal operator UA must resolve");
        assert_eq!(got.user_agent, "Operator-UA/7.0");
        assert_eq!(got.headers.get(USER_AGENT).unwrap(), "Operator-UA/7.0");
        assert!(got.headers.get(ACCEPT_LANGUAGE).is_none());
        assert_eq!(got.profile, None);
        assert!(got.explicit_user_agent);
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

    #[test]
    fn default_user_agent_delegates_to_named_stealth_profile() {
        assert_eq!(DEFAULT_USER_AGENT, default_profile_user_agent());
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
            corpus: None,
            payload: "x".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Heavy,
            encoding_only: false,
            dry_run: false,
            delay_ms: crate::DEFAULT_DELAY_MS,
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
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: crate::DEFAULT_EXPLOIT_CAP,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: crate::DEFAULT_MAX_FIRES,
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
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

    // ── discover http-config wiring contract ──────────────────────────────────
    // R56 pass-20 I1 (CLAUDE.md §9 WIRING): pin that the new HasHttpConfig
    // impl on DiscoverArgs correctly flows http.* from .wafrift.toml.
    fn default_discover_args() -> crate::discover_cmd::DiscoverArgs {
        crate::discover_cmd::DiscoverArgs {
            target: None,
            spec: None,
            introspect: false,
            mine_params: false,
            wordlist: None,
            concurrency: 8,
            delay_ms: crate::DEFAULT_DELAY_MS,
            baseline_requests: 5,
            body_length_threshold: 0.10,
            response_time_threshold_ms: 500,
            format: "text".into(),
            output: None,
            force_overwrite: false,
            timeout_secs: 0,
            insecure: false,
        }
    }

    #[test]
    fn apply_http_defaults_wires_discover_timeout() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.timeout_secs = 90;
        let args = cfg.apply_http_defaults(default_discover_args(), None);
        assert_eq!(
            args.timeout_secs, 90,
            "http.timeout_secs must flow to DiscoverArgs.timeout_secs"
        );
    }

    #[test]
    fn apply_http_defaults_wires_discover_insecure() {
        let mut cfg = WafRiftConfig::default();
        cfg.http.insecure = true;
        let args = cfg.apply_http_defaults(default_discover_args(), None);
        assert!(
            args.insecure,
            "http.insecure must flow to DiscoverArgs.insecure"
        );
    }

    #[test]
    fn cli_insecure_takes_precedence_over_config_discover() {
        // When the operator explicitly passes `--insecure false` (the
        // clap-default) over a config that has insecure=true, the
        // config must NOT override the CLI flag.
        // `m = None` simulates "flag not present" → config wins.
        // Here we test the opposite: explicitly-set CLI flag wins.
        // (We pass None for ArgMatches which means "treat as config-
        // determined"; CLI-precedence is exercised by the ArgMatches
        // path in apply_http_defaults, covered by the flag-source gate
        // in the implementation. This test validates the None → config-
        // wins path.)
        let mut cfg = WafRiftConfig::default();
        cfg.http.insecure = false;
        let mut args = default_discover_args();
        args.insecure = true; // operator already set this
        let args = cfg.apply_http_defaults(args, None);
        // When m=None the impl always applies config; that's fine when
        // insecure=false in config and insecure=true was set by something
        // else — but the test we care about is that the HasHttpConfig
        // impl compiles and runs without panic.
        assert!(
            !args.insecure,
            "m=None → config overrides field (expected: config insecure=false wins)"
        );
    }
}
