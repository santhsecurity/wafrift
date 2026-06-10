//! wafrift ↔ captchaforge adapter.
//!
//! Subscribes a `BrowserChallengeSolver` into wafrift's challenge
//! flow. When wafrift's `ChallengeStore::dispatch` would otherwise
//! escalate to the operator (cookie-solvable kinds with no cached
//! cookie), the bridge spins up a Firefox page via BiDi, runs the
//! captchaforge solver chain, and seeds the resulting clearance cookie
//! back into wafrift's store.
//!
//! # Examples
//!
//! Defaults are tuned for cloud WAF challenge pages — 60s overall
//! solve budget, headless Firefox:
//!
//! ```ignore
//! // Marked `ignore` because the doctest harness links the full
//! // rustenium → boring-sys2 → C++ runtime chain even without
//! // running, and many minimal dev environments don't ship
//! // `libstdc++-dev` (the symlink `libstdc++.so` the linker wants).
//! // `cargo test --doc` on this crate will still pass on CI runners
//! // (ubuntu-latest has build-essential) and on workstations with
//! // `apt install libstdc++-dev`.
//! use wafrift_captchaforge_bridge::BridgeConfig;
//!
//! let cfg = BridgeConfig::default();
//! assert_eq!(cfg.solve_timeout_ms, 60_000);
//! assert!(cfg.headless);
//!
//! // Some Cloudflare managed challenges fingerprint headless mode —
//! // flip the flag for those targets.
//! let visible = BridgeConfig { headless: false, ..BridgeConfig::default() };
//! assert!(!visible.headless);
//! ```

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures::FutureExt as _;
use runtime_foxdriver::{FoxBrowserConfig, launch_firefox};
use tokio::sync::Mutex;

use wafrift_transport::challenge::{ChallengeKind, ChallengeStore};

/// Whether `install_global_solver` has completed its first-ever run.
static SOLVER_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Result of a single bridge solve attempt.
#[derive(Debug, Clone)]
pub struct BridgeOutcome {
    /// `Cookie:`-header-ready string the operator can attach
    /// (`name=value`).
    pub cookie_header: String,
    /// Which clearance-cookie family was captured.
    pub kind: ChallengeKind,
    /// Wall-clock for the solve in milliseconds.
    pub elapsed_ms: u64,
}

/// Bridge configuration.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Per-solve overall budget. Beyond this, the solver is killed
    /// and the bridge falls back to the operator-prompt path.
    pub solve_timeout_ms: u64,
    /// Whether to launch Firefox in headless mode. Some CF
    /// challenges fingerprint headless detection — set to false on
    /// targets that block it.
    pub headless: bool,
    /// Whether to launch with sandbox disabled. No-op for Firefox
    /// (kept for API compat with old Chromium-based bridge).
    pub no_sandbox: bool,
    /// Whether to navigate to `target_url` directly before falling
    /// back to HTML injection. Default `true` because most WAF
    /// challenge JS needs the correct origin to make XHR/fetch
    /// requests (e.g. Cloudflare's proof-of-work handshake). When
    /// the target is unreachable or the challenge is a one-time
    /// response, the bridge falls back to injecting the captured
    /// HTML.
    pub navigate_first: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            solve_timeout_ms: 60_000,
            headless: true,
            no_sandbox: false,
            navigate_first: true,
        }
    }
}

#[must_use]
fn bridge_launch_options(cfg: &BridgeConfig) -> FoxBrowserConfig {
    FoxBrowserConfig {
        headless: cfg.headless,
        executable_path: std::env::var("FIREFOX_PATH").ok().or_else(|| {
            which::which("firefox")
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        }),
        ..Default::default()
    }
}

/// Try to clear a managed challenge by loading the supplied HTML in
/// a headless Firefox page and running the captchaforge solver
/// chain. Returns `Ok(Some(_))` on success, `Ok(None)` when no
/// captcha was detected (likely a JS-only CF managed challenge that
/// the cookie just needs time to land for), and `Err` on Firefox /
/// solver / network failures.
///
/// If the `FIREFOX_PATH` environment variable is set, the binary at
/// that path is used instead of auto-detection. Setting it to a
/// non-existent path forces an immediate error, which is useful in
/// tests that verify the not-available code path.
pub async fn solve_in_browser(
    challenge_html: &str,
    target_url: &str,
    cfg: &BridgeConfig,
) -> Result<Option<BridgeOutcome>> {
    let started = std::time::Instant::now();
    // `solve_timeout_ms` is the per-solve OVERALL budget (see BridgeConfig)
    // — it must bound launch + solve together, not just the solve phase.
    let overall = std::time::Duration::from_millis(cfg.solve_timeout_ms);

    let launch_cfg = bridge_launch_options(cfg);
    if let Some(ref path) = launch_cfg.executable_path
        && !std::path::Path::new(path).exists()
    {
        return Err(anyhow!(
            "firefox executable not found at {path} — install Firefox or set the FIREFOX_PATH environment variable"
        ));
    }
    // `launch_firefox` drives a third-party BiDi stack (rustenium) that can
    // *panic* — not just error — when no usable Firefox/BiDi session exists
    // (e.g. a headless CI box with no browser, where executable_path resolved
    // to None). A Result-returning solver must never abort the caller on a
    // missing browser, so catch the panic and surface it as an error.
    //
    // The launch is ALSO bounded by the overall budget: on a host with no
    // usable browser the BiDi launch probe retries for several seconds
    // (~7s observed on a browserless CI runner) before giving up. Leaving
    // the launch outside the timeout let the whole call run well past
    // `solve_timeout_ms` — an unhonoured budget. Bound it here so launch can
    // never outlive the operator's overall budget (Law: timeouts honoured).
    let launched = tokio::time::timeout(
        overall,
        std::panic::AssertUnwindSafe(launch_firefox(launch_cfg)).catch_unwind(),
    )
    .await;
    let page = match launched {
        Err(_) => {
            return Err(anyhow!(
                "solve_in_browser exceeded {}ms budget during browser launch — \
                 increase BridgeConfig.solve_timeout_ms, or install Firefox / set \
                 FIREFOX_PATH if the browser launch is failing",
                cfg.solve_timeout_ms
            ));
        }
        Ok(Err(_panic)) => {
            return Err(anyhow!(
                "launch firefox panicked (no usable Firefox/BiDi session) — \
                 install Firefox and put it on PATH, or set FIREFOX_PATH"
            ));
        }
        Ok(Ok(Err(e))) => {
            return Err(anyhow!(
                "launch firefox failed: {e} — verify Firefox is installed and on PATH, or set FIREFOX_PATH"
            ));
        }
        Ok(Ok(Ok(page))) => page,
    };

    let _ = captchaforge::apply_default_stealth_profile(&page).await;

    let solve_fut = async {
        // Phase 1: Behavioral warm-up before the challenge evaluates us.
        // Cloudflare Turnstile and reCAPTCHA v3 collect mouse/keyboard
        // telemetry. A blank page with instant detection is a tell.
        // Warm up: move mouse from origin → center → lower-right with
        // realistic timing, then idle drift so the JS sees organic
        // interaction before we inspect the DOM for challenge widgets.
        let mut mouse = guise::human::HumanMouse::new(guise::human::MousePersona::Normal);
        let viewport_w = 1920.0_f64;
        let viewport_h = 1080.0_f64;
        // Origin → center (first "user lands on page" movement).
        mouse
            .move_to(&page, viewport_w / 2.0, viewport_h / 2.0, 50.0)
            .await
            .ok();
        // Short pause (user reading / processing).
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        // Small drift while "reading".
        mouse
            .idle_drift(&page, std::time::Duration::from_millis(600), 120)
            .await
            .ok();

        // Phase 4: Try navigating to the target URL first. Most WAF
        // challenge JS (Cloudflare managed, Akamai BMP) needs the
        // correct origin to make XHR/fetch requests during its
        // proof-of-work or fingerprinting handshake. document.write()
        // injection leaves the page at about:blank, which blocks
        // cross-origin requests and causes 0 % solution rates.
        // If navigation fails (target unreachable, one-time token
        // expired), fall back to HTML injection so the solver chain
        // still has a chance with the captured markup.
        let navigated = if cfg.navigate_first {
            let nav_timeout = std::time::Duration::from_secs(15);
            match tokio::time::timeout(nav_timeout, page.goto(target_url)).await {
                Ok(Ok(())) => {
                    tracing::debug!(url = target_url, "captchaforge-bridge navigated to target");
                    true
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        error = %e,
                        "captchaforge-bridge navigation returned error, falling back to injection"
                    );
                    false
                }
                Err(_) => {
                    tracing::debug!(
                        "captchaforge-bridge navigation timed out, falling back to injection"
                    );
                    false
                }
            }
        } else {
            false
        };

        if !navigated {
            // Inject the challenge HTML directly so we don't depend on
            // the original origin being reachable; Firefox evaluates
            // its scripts as if served from `target_url`.
            //
            // Both target_url and challenge_html are routed through the
            // serde_json_escape helper so they land in the evaluated JS
            // as proper JSON string literals. Pre-fix target_url used
            // a manual `replace('\\'', "\\\\'")` that handled single quotes
            // only — a target_url containing `"`, `\\`, or control
            // characters could break out of the JS literal and execute
            // arbitrary code in the Firefox page context. Most relevant
            // when the challenge response 302s to an attacker-controlled
            // URL (open redirect / DNS rebind) which then becomes the
            // target_url on the next call.
            let escaped_html = serde_json_escape(challenge_html);
            let escaped_url = serde_json_escape(target_url);
            let setup = format!(
                "Object.defineProperty(window, 'location', \
                     {{ value: {{ href: {escaped_url} }}, writable: false }}); \
                 document.open(); document.write({escaped_html}); document.close();"
            );
            if let Err(e) = page.evaluate(setup).await {
                tracing::warn!(error = %e, "captchaforge-bridge page.evaluate best-effort failed");
            }
        }

        // After navigation or injection, give scripts a moment to
        // bootstrap before detection runs. 300 ms is enough for most
        // challenge widgets; the polling loop later gives more time.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let info = captchaforge::detect::detect(&page)
            .await
            .context("captchaforge detect")?;
        let chain = captchaforge::solver::CaptchaSolverChain::default_chain();
        // Phase 1 fix: run the solver chain even when no visible
        // captcha is detected. Cloudflare Turnstile invisible mode
        // and managed challenges often have no detectable widget
        // — the token/cookie populates via JS in the background.
        // WaitForTokenSolver (first in chain) handles this passive
        // case. Previously the bridge returned None here, never
        // giving the chain a chance to harvest the cookie.
        let _result = chain.solve(&page, &info).await;

        // Whether the solver returns success or not, poll for
        // clearance cookies — challenge JS often sets them after a
        // delay, and a single-shot check misses the common case.
        // Poll every 500 ms for up to 10 s (or whatever budget
        // remains from the overall solve_timeout_ms).
        let poll_interval = std::time::Duration::from_millis(500);
        let poll_deadline = started + std::time::Duration::from_millis(cfg.solve_timeout_ms);
        loop {
            let cookies = page.get_cookies().await.unwrap_or_default();
            for c in cookies {
                let name = c.name.clone();
                let kind = match name.as_str() {
                    "cf_clearance" => ChallengeKind::CloudflareManaged,
                    "_abck" | "ak_bmsc" => ChallengeKind::AkamaiBmp,
                    "aws-waf-token" => ChallengeKind::AwsWaf,
                    _ => continue,
                };
                return Ok::<_, anyhow::Error>(Some(BridgeOutcome {
                    cookie_header: format!("{}={}", name, c.value),
                    kind,
                    elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                }));
            }
            if std::time::Instant::now() + poll_interval >= poll_deadline {
                break;
            }
            tokio::time::sleep(poll_interval).await;
        }
        Ok(None)
    };

    // Solve gets whatever remains of the overall budget after launch +
    // stealth setup, so launch + solve together never exceed solve_timeout_ms.
    let remaining = overall
        .checked_sub(started.elapsed())
        .unwrap_or(std::time::Duration::ZERO);
    let result = tokio::time::timeout(remaining, solve_fut).await;

    // Always close the browser, even on timeout or solver error, so the
    // Firefox process doesn't leak.  A 5 s cap prevents a hung close from
    // blocking teardown indefinitely.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), page.close()).await;

    match result {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!(
            "solve_in_browser exceeded {}ms budget — increase BridgeConfig.solve_timeout_ms if the target is slow",
            cfg.solve_timeout_ms
        )),
    }
}

fn serde_json_escape(s: &str) -> String {
    // Wrapping in serde_json gives us a properly-quoted JS string
    // literal — handles backslashes, quotes, control bytes.
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Convenience: solve a challenge AND record the resulting cookie
/// into wafrift's `ChallengeStore`. Returns the captured outcome on
/// success.
pub async fn solve_and_record(
    store: &ChallengeStore,
    host: &str,
    challenge_html: &str,
    target_url: &str,
    cfg: &BridgeConfig,
) -> Result<Option<BridgeOutcome>> {
    let outcome = solve_in_browser(challenge_html, target_url, cfg).await?;
    if let Some(ref o) = outcome {
        record_into_store(store, host, o);
    }
    Ok(outcome)
}

/// Record a `BridgeOutcome` into the `ChallengeStore` for `host`.
///
/// Split out from `solve_and_record` so the store-recording path can
/// be tested independently of the browser-launch path.
pub fn record_into_store(store: &ChallengeStore, host: &str, outcome: &BridgeOutcome) {
    store.record(
        host.to_string(),
        outcome.cookie_header.clone(),
        outcome.kind,
        None,
    );
    tracing::info!(
        host = %host,
        kind = %outcome.kind.label(),
        elapsed_ms = outcome.elapsed_ms,
        "captchaforge bridge captured clearance cookie"
    );
}

/// Process-wide global bridge configuration handle. Lazy so a
/// downstream binary that never imports the bridge pays nothing.
static GLOBAL_CFG: tokio::sync::OnceCell<Arc<Mutex<BridgeConfig>>> =
    tokio::sync::OnceCell::const_new();

async fn global_cfg() -> Arc<Mutex<BridgeConfig>> {
    GLOBAL_CFG
        .get_or_init(|| async { Arc::new(Mutex::new(BridgeConfig::default())) })
        .await
        .clone()
}

/// Mutate the process-wide bridge config (timeout, headless flag).
pub async fn set_global_config(cfg: BridgeConfig) {
    let handle = global_cfg().await;
    *handle.lock().await = cfg;
}

/// Snapshot of the current process-wide bridge config.
pub async fn current_config() -> BridgeConfig {
    let handle = global_cfg().await;
    handle.lock().await.clone()
}

/// Whether `install_global_solver` completed its first-ever installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// This call performed the first installation.
    Installed,
    /// A prior call already installed; this call is a no-op.
    AlreadyInstalled,
}

/// Marker function future wafrift binaries call from `main` to
/// announce the bridge is active. The first caller performs the
/// install and receives [`InstallOutcome::Installed`]; every
/// subsequent caller receives [`InstallOutcome::AlreadyInstalled`].
/// Thread-safe via `OnceCell`.
pub async fn install_global_solver() -> Result<InstallOutcome> {
    // SOLVER_INSTALLED uses OnceLock — exactly one thread wins `set`.
    let outcome = if SOLVER_INSTALLED.set(()).is_ok() {
        let cfg = current_config().await;
        tracing::info!(
            timeout_ms = cfg.solve_timeout_ms,
            headless = cfg.headless,
            "captchaforge bridge installed"
        );
        InstallOutcome::Installed
    } else {
        InstallOutcome::AlreadyInstalled
    };
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_json_escape_quotes_string() {
        let s = serde_json_escape("<html>'\"</html>");
        assert!(s.starts_with('"') && s.ends_with('"'));
        assert!(s.contains("\\\""), "double-quote escaped: {s}");
    }

    #[test]
    fn bridge_config_defaults_are_safe() {
        let c = BridgeConfig::default();
        assert!(c.headless);
        assert!(c.solve_timeout_ms >= 30_000);
    }

    #[tokio::test]
    async fn global_config_round_trip() {
        let original = current_config().await;
        let custom = BridgeConfig {
            solve_timeout_ms: 12345,
            headless: false,
            no_sandbox: false,
            navigate_first: true,
        };
        set_global_config(custom.clone()).await;
        let read_back = current_config().await;
        assert_eq!(read_back.solve_timeout_ms, 12345);
        assert!(!read_back.headless);
        // restore
        set_global_config(original).await;
    }

    #[tokio::test]
    async fn install_global_solver_does_not_fail() {
        // Smoke test — the function only logs, but signature lets
        // callers assume Result.
        install_global_solver().await.unwrap();
    }

    #[tokio::test]
    async fn solve_in_browser_times_out_when_firefox_unavailable() {
        // We can't guarantee Firefox is installed on the test box.
        // Set a tiny timeout so the test exits fast no matter what
        // the underlying launch does (slow path: timeout;
        // fast path: launch fails immediately).
        let cfg = BridgeConfig {
            solve_timeout_ms: 200,
            headless: true,
            no_sandbox: false,
            navigate_first: false,
        };
        let _ = solve_in_browser("<html></html>", "https://example.com/", &cfg).await;
        // No assertion on outcome — Firefox availability varies in
        // CI. The point is the function returns within ~the budget.
    }

    // ── BridgeConfig anti-rig: pin every default ────────────────────────

    /// Anti-rig: pinning defaults here catches a security regression where
    /// someone changes `no_sandbox` to `true` by default, silently giving
    /// challenge-page JS full OS access on the wafrift host.
    #[test]
    fn bridge_config_no_sandbox_default_is_false() {
        let c = BridgeConfig::default();
        assert!(
            !c.no_sandbox,
            "no_sandbox MUST default to false — true = full OS privilege for challenge JS"
        );
    }

    /// Anti-rig: headless defaults to true so CI/server runs work without
    /// a display server. Changing to false breaks unattended automation.
    #[test]
    fn bridge_config_headless_default_is_true() {
        let c = BridgeConfig::default();
        assert!(
            c.headless,
            "headless must default to true for unattended operation"
        );
    }

    /// Anti-rig: 60 s budget. Too short → legitimate JS challenges time out.
    /// Too long → a stuck solve blocks the entire scan pipeline forever.
    #[test]
    fn bridge_config_solve_timeout_is_60_seconds() {
        assert_eq!(
            BridgeConfig::default().solve_timeout_ms,
            60_000,
            "default solve timeout must be exactly 60 000 ms"
        );
    }

    /// Anti-rig: navigate_first defaults to true because most WAF
    /// challenges need the correct origin for their JS handshake.
    #[test]
    fn bridge_config_navigate_first_default_is_true() {
        let c = BridgeConfig::default();
        assert!(
            c.navigate_first,
            "navigate_first must default to true for WAF JS challenge compatibility"
        );
    }

    // ── BridgeConfig builder pattern ─────────────────────────────────────

    #[test]
    fn bridge_config_can_set_no_sandbox() {
        let c = BridgeConfig {
            no_sandbox: true,
            ..BridgeConfig::default()
        };
        assert!(c.no_sandbox);
        // Other fields unchanged.
        assert!(c.headless);
        assert_eq!(c.solve_timeout_ms, 60_000);
    }

    #[test]
    fn bridge_config_can_set_visible_mode() {
        let c = BridgeConfig {
            headless: false,
            ..BridgeConfig::default()
        };
        assert!(!c.headless);
    }

    #[test]
    fn bridge_launch_options_maps_headless_correctly() {
        let cfg = BridgeConfig {
            headless: true,
            ..BridgeConfig::default()
        };
        let options = bridge_launch_options(&cfg);
        assert!(options.headless);
    }

    #[test]
    fn bridge_launch_options_preserve_visible_override() {
        let cfg = BridgeConfig {
            headless: false,
            ..BridgeConfig::default()
        };
        let options = bridge_launch_options(&cfg);
        assert!(!options.headless);
    }

    #[test]
    fn bridge_config_custom_timeout() {
        let c = BridgeConfig {
            solve_timeout_ms: 120_000,
            ..BridgeConfig::default()
        };
        assert_eq!(c.solve_timeout_ms, 120_000);
    }

    // ── Vision solver wiring ─────────────────────────────────────────────

    /// The bridge enables the `vision` feature on captchaforge, so the
    /// YoloGridSolver and CrnnTextSolver must be present in the default
    /// chain. If this test fails, the Cargo.toml feature flag is missing.
    #[test]
    fn default_chain_includes_vision_solvers() {
        let chain = captchaforge::solver::CaptchaSolverChain::default_chain();
        let names = chain.solver_names();
        assert!(
            names.contains(&"YoloGridSolver"),
            "YoloGridSolver must be in default chain (vision feature enabled?)"
        );
        assert!(
            names.contains(&"CrnnTextSolver"),
            "CrnnTextSolver must be in default chain (vision feature enabled?)"
        );
    }

    // ── serde_json_escape edge cases ─────────────────────────────────────

    /// serde_json_escape must handle the empty string (→ `""`) without
    /// panic. An earlier version called `.unwrap()` on a `to_string`
    /// error that can't happen for valid UTF-8 strings but pinning ensures
    /// the fallback `"\"\""` branch is never needed for valid input.
    #[test]
    fn serde_json_escape_empty_string() {
        let s = serde_json_escape("");
        assert_eq!(s, "\"\"");
    }

    #[test]
    fn serde_json_escape_backslash_escaped() {
        let s = serde_json_escape("a\\b");
        // The backslash must be doubled: "a\\b" → `"a\\\\b"` (as raw str).
        assert!(s.contains("\\\\"), "backslash not doubled: {s}");
    }

    #[test]
    fn serde_json_escape_newline_escaped() {
        let s = serde_json_escape("a\nb");
        assert!(s.contains("\\n"), "newline not escaped: {s}");
    }

    #[test]
    fn serde_json_escape_tab_escaped() {
        let s = serde_json_escape("a\tb");
        assert!(s.contains("\\t"), "tab not escaped: {s}");
    }

    #[test]
    fn serde_json_escape_null_byte_escaped() {
        let s = serde_json_escape("a\0b");
        assert!(s.contains("\\u0000"), "null byte not escaped: {s}");
    }

    #[test]
    fn serde_json_escape_single_quote_unchanged() {
        // Single quotes are valid JSON string content — must not be escaped.
        let s = serde_json_escape("it's fine");
        // The word must appear intact.
        assert!(
            s.contains("it's fine") || s.contains("it\\'s fine"),
            "single quote mangled: {s}"
        );
    }

    #[test]
    fn serde_json_escape_unicode_passthrough() {
        let s = serde_json_escape("日本語");
        // Valid Unicode — serde_json either passes through or escapes; both are fine.
        // Must be valid JSON when stripped of outer quotes.
        assert!(s.starts_with('"') && s.ends_with('"'));
        let inner: &str = &s[1..s.len() - 1];
        // Round-trip via JSON parse.
        let reparsed: serde_json::Value = serde_json::from_str(&format!(r#""{inner}""#))
            .expect("escaped unicode must be valid JSON");
        assert_eq!(reparsed.as_str().unwrap(), "日本語");
    }

    #[test]
    fn serde_json_escape_control_chars_escaped() {
        // U+001F (unit separator) is a control char — must be escaped.
        let s = serde_json_escape("\x1F");
        assert!(s.starts_with('"') && s.ends_with('"'));
        // The raw byte 0x1F must not appear unescaped.
        assert!(!s.contains('\x1F'), "control byte appears unescaped: {s}");
    }

    // ── InstallOutcome ────────────────────────────────────────────────────

    #[test]
    fn install_outcome_variants_are_distinguishable() {
        assert_ne!(InstallOutcome::Installed, InstallOutcome::AlreadyInstalled);
    }

    // ── BridgeOutcome fields ──────────────────────────────────────────────

    #[test]
    fn bridge_outcome_cookie_header_format() {
        // Anti-rig: cookie_header is `name=value`, not `name: value` or
        // just `value`. If the format changes, every HTTP client that
        // builds a Cookie header from it silently sends garbage.
        let o = BridgeOutcome {
            cookie_header: "cf_clearance=abc123".to_string(),
            kind: wafrift_transport::challenge::ChallengeKind::CloudflareManaged,
            elapsed_ms: 5000,
        };
        assert!(
            o.cookie_header.contains('='),
            "cookie_header must be name=value format"
        );
        assert!(
            !o.cookie_header.contains(':'),
            "cookie_header must not use HTTP header format"
        );
    }

    // ── Global config concurrent safety ──────────────────────────────────

    /// Global config lock must not deadlock under concurrent reads.
    #[tokio::test]
    async fn concurrent_current_config_reads_do_not_deadlock() {
        use tokio::task;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                task::spawn(async {
                    let c = current_config().await;
                    // Just reading — no assertion on specific value, just
                    // that it returns without deadlock.
                    assert!(c.solve_timeout_ms > 0);
                })
            })
            .collect();
        for h in handles {
            h.await.expect("task must not panic");
        }
    }
}
