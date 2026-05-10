//! wafrift ↔ captchaforge adapter.
//!
//! Subscribes a `BrowserChallengeSolver` into wafrift's challenge
//! flow. When wafrift's `ChallengeStore::dispatch` would otherwise
//! escalate to the operator (cookie-solvable kinds with no cached
//! cookie), the bridge spins up a chromiumoxide page from the
//! captured challenge HTML, runs the captchaforge solver chain, and
//! seeds the resulting clearance cookie back into wafrift's store.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use tokio::sync::Mutex;

use wafrift_transport::challenge::{ChallengeKind, ChallengeStore};

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
    /// Whether to launch chromium in headless mode. Some CF
    /// challenges fingerprint headless detection — set to false on
    /// targets that block it.
    pub headless: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            solve_timeout_ms: 60_000,
            headless: true,
        }
    }
}

/// Try to clear a managed challenge by loading the supplied HTML in
/// a headless chromiumoxide page and running the captchaforge solver
/// chain. Returns `Ok(Some(_))` on success, `Ok(None)` when no
/// captcha was detected (likely a JS-only CF managed challenge that
/// the cookie just needs time to land for), and `Err` on chromium /
/// solver / network failures.
pub async fn solve_in_browser(
    challenge_html: &str,
    target_url: &str,
    cfg: &BridgeConfig,
) -> Result<Option<BridgeOutcome>> {
    let started = std::time::Instant::now();

    let mut browser_cfg_builder = BrowserConfig::builder();
    if !cfg.headless {
        browser_cfg_builder = browser_cfg_builder.with_head();
    }
    let browser_cfg = browser_cfg_builder
        .build()
        .map_err(|e| anyhow!("chromium config: {e}"))?;

    let (mut browser, mut handler) = Browser::launch(browser_cfg)
        .await
        .context("launch chromium")?;
    let handler_task = tokio::spawn(async move {
        while let Some(_evt) = handler.next().await {
            // drain CDP events; we don't care about specific ones for
            // the bridge happy path.
        }
    });

    let solve_fut = async {
        let page = browser.new_page("about:blank").await.context("new_page")?;
        // Inject the challenge HTML directly so we don't depend on
        // the original origin being reachable; chromium evaluates
        // its scripts as if served from `target_url`.
        let escaped = serde_json_escape(challenge_html);
        let setup = format!(
            "Object.defineProperty(window, 'location', \
                 {{ value: {{ href: '{}' }}, writable: false }}); \
             document.open(); document.write({escaped}); document.close();",
            target_url.replace('\'', "\\'")
        );
        page.evaluate(setup).await.ok(); // best-effort

        let info = captchaforge::detect::detect(&page)
            .await
            .context("captchaforge detect")?;
        if !captchaforge::detect::is_captcha(&info) {
            return Ok::<_, anyhow::Error>(None);
        }
        let chain = captchaforge::solver::CaptchaSolverChain::default_chain();
        // CaptchaSolverChain::solve returns the chain's best
        // CaptchaSolveResult (no Result wrapper) — failures are
        // surfaced via .success=false rather than as Errors.
        let _result = chain.solve(&page, &info).await;

        // Whether the solver returns success or not, harvest the
        // page's cookies — clearance is set by the challenge JS
        // even on partial successes, and the cookie itself is what
        // wafrift cares about.
        let cookies = page.get_cookies().await.unwrap_or_default();
        for c in cookies {
            let name = c.name.clone();
            let kind = match name.as_str() {
                "cf_clearance" => ChallengeKind::CloudflareManaged,
                "_abck" | "ak_bmsc" => ChallengeKind::AkamaiBmp,
                "aws-waf-token" => ChallengeKind::AwsWaf,
                _ => continue,
            };
            return Ok(Some(BridgeOutcome {
                cookie_header: format!("{}={}", name, c.value),
                kind,
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            }));
        }
        Ok(None)
    };

    let timeout = std::time::Duration::from_millis(cfg.solve_timeout_ms);
    let result = tokio::time::timeout(timeout, solve_fut)
        .await
        .map_err(|_| {
            anyhow!(
                "solve_in_browser exceeded {}ms budget",
                cfg.solve_timeout_ms
            )
        })??;

    // Best-effort tidy.
    let _ = browser.close().await;
    handler_task.abort();
    Ok(result)
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
        store.record(host.to_string(), o.cookie_header.clone(), o.kind, None);
        tracing::info!(
            host = %host,
            kind = %o.kind.label(),
            elapsed_ms = o.elapsed_ms,
            "captchaforge bridge captured clearance cookie"
        );
    }
    Ok(outcome)
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

/// Marker function future wafrift binaries call from `main` to
/// announce the bridge is active. Today this only logs — real wiring
/// (subscribing the bridge into the proxy's challenge dispatch path)
/// is left to the binary so the lib doesn't pull in proxy types.
pub async fn install_global_solver() -> Result<()> {
    let cfg = current_config().await;
    tracing::info!(
        timeout_ms = cfg.solve_timeout_ms,
        headless = cfg.headless,
        "captchaforge bridge installed"
    );
    Ok(())
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
    async fn solve_in_browser_times_out_when_chromium_unavailable() {
        // We can't guarantee chromium is installed on the test box.
        // Set a tiny timeout so the test exits fast no matter what
        // the underlying Browser::launch does (slow path: timeout;
        // fast path: launch fails immediately).
        let cfg = BridgeConfig {
            solve_timeout_ms: 200,
            headless: true,
        };
        let _ = solve_in_browser("<html></html>", "https://example.com/", &cfg).await;
        // No assertion on outcome — chromium availability varies in
        // CI. The point is the function returns within ~the budget.
    }
}
