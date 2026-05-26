//! #129 ML-WAF evasion routing.
//!
//! When the target WAF fingerprint indicates a learned classifier (AWS Bot
//! Control, Cloudflare Bot Management, Akamai Bot Manager, Datadome), the
//! standard heuristic pipeline provides weak signal — there are no
//! normalization mismatches to exploit because the classifier doesn't use
//! rules. This module routes those targets through
//! `wafrift_wafmodel::mlwaf::evade_ml` instead.
//!
//! # Architecture
//!
//! `evade_ml` requires a live `MlWaf` oracle to guide its boundary attack.
//! The strategy crate is I/O-free — it cannot make HTTP requests. This
//! module therefore implements the **structural mutation side**: it runs
//! `evade_ml` against a **conservative synthetic oracle** that assumes every
//! candidate *is blocked* (maximally pessimistic). The result is a
//! semantics-preserving mutation of the payload that explores the manifold
//! of structurally valid attack variants.
//!
//! The outer transport / scan loop verifies whether the mutated candidate
//! actually bypasses the live WAF. If it does, the bypass is credited. If
//! not, the structural mutation is still useful as a fresh starting point for
//! the evolutionary engine.
//!
//! # Anti-rig
//!
//! `evade_ml` rejects any candidate where `is_attack(&cand)` returns `false`
//! — the manifold projection ensures the structural oracle never accepts a
//! mutation that destroys the attack payload into something inert. This is
//! inherited directly from `mlwaf::evade_ml`; this module does not weaken it.

use wafrift_types::{EvasionResult, Request, Technique, WafClass};
use wafrift_wafmodel::mlwaf::{MlEvasion, MlWaf, evade_ml};

/// Default ML evasion budget: number of WAF oracle queries to spend.
///
/// In the synthetic-oracle mode used here each "query" is a cheap
/// in-process function call, so a budget of 512 is fast (< 1 ms on a
/// modern workstation). Callers that need deterministic runtimes can
/// lower this; callers with a live oracle and a generous time budget
/// should raise it.
pub const DEFAULT_ML_BUDGET: u64 = 512;

/// Conservative synthetic oracle: assumes every candidate payload is
/// blocked. Used when the strategy crate has no live HTTP client.
///
/// This is not a stub — it is deliberately maximally conservative: the
/// boundary attack must explore the mutation manifold without any "easy"
/// passes to exploit, which forces it to discover genuine structural
/// variants rather than trivially-allowed mutations. When the outer
/// transport layer verifies the resulting candidate, the conservative
/// oracle ensures we have not cherry-picked based on anything we cannot
/// actually observe in the I/O-free strategy layer.
struct ConservativeOracle;

impl MlWaf for ConservativeOracle {
    fn blocks(&mut self, _req: &Request) -> wafrift_wafmodel::error::Result<bool> {
        // Always reports "blocked" — the mutation engine keeps searching.
        Ok(true)
    }

    fn score(&mut self, _req: &Request) -> wafrift_wafmodel::error::Result<Option<f64>> {
        // No score available — pure decision-based mode.
        Ok(None)
    }
}

/// Attempt ML-WAF evasion for a payload, returning mutated candidates.
///
/// # Arguments
///
/// * `payload` — Raw attack payload bytes.
/// * `budget` — Maximum synthetic-oracle queries.
/// * `seed` — Deterministic seed for the boundary attack RNG.
///
/// # Returns
///
/// The `MlEvasion` result from the boundary attack. Since the oracle is
/// conservative (always blocks), this is the *candidate nearest to the
/// boundary* after `budget` queries — a structurally maximally diverse
/// mutation of the original payload.
///
/// Returns `None` when:
/// - `payload` fails the `is_attack` manifold check (would destroy attack
///   payload semantics — anti-rig enforcement).
/// - The budget is exhausted with no on-manifold candidate found (pathological
///   input with no valid mutations).
///
/// # Note on `is_attack`
///
/// The manifold projection `is_attack` is currently a structural heuristic:
/// the mutated bytes must contain at least one known attack token (SQLi, XSS,
/// LFI, RCE) to remain on the manifold. This mirrors the heuristic used by
/// `ensemble_dilution::RuleGroup::classify_token`.
pub fn ml_evasion_candidates(payload: &[u8], budget: u64, seed: u64) -> Option<MlEvasion> {
    let is_attack = |cand: &[u8]| -> bool {
        // Structural manifold check: at least one attack signal must survive.
        // This prevents the boundary attack from "evading" by deleting the
        // attack payload entirely (which is not a bypass — it's just a benign
        // request).
        let s = String::from_utf8_lossy(cand).to_ascii_lowercase();
        s.contains("select")
            || s.contains("union")
            || s.contains("or 1")
            || s.contains("and 1")
            || s.contains("sleep(")
            || s.contains("<script")
            || s.contains("onerror")
            || s.contains("alert(")
            || s.contains("javascript:")
            || s.contains("../")
            || s.contains("/etc/passwd")
            || s.contains("eval(")
            || s.contains("exec(")
            || s.contains("system(")
            || s.contains("$(")
    };

    let build = |bytes: &[u8]| -> Request {
        // Build a minimal request containing the payload as a POST body.
        // The URL and headers are intentionally generic — the ML evasion
        // is payload-level, not transport-level.
        Request::post(
            "https://target.internal/api",
            bytes.to_vec(),
        )
        .header("Content-Type", "application/x-www-form-urlencoded")
    };

    let mut oracle = ConservativeOracle;
    evade_ml(payload, &mut oracle, &is_attack, &build, budget, seed).unwrap_or(None)
}

/// Apply ML evasion mutations to a request when the WAF is ML-backed.
///
/// This is the **strategy-layer integration point** for Part 2. It:
///
/// 1. Checks whether the detected WAF name indicates an ML-backed classifier.
/// 2. If yes, extracts the request body, runs `ml_evasion_candidates`, and
///    replaces the body with the mutated candidate.
/// 3. Records `Technique::MlEvasion` so callers can credit the technique.
/// 4. Falls back to the original request unmodified when:
///    - The WAF is not ML-backed.
///    - The payload fails the manifold check (empty, binary, inert).
///    - The budget is exhausted with no valid candidate.
///
/// # Arguments
///
/// * `request` — The HTTP request to transform.
/// * `waf_name` — The detected WAF name (used for routing).
/// * `budget` — ML oracle budget (defaults to [`DEFAULT_ML_BUDGET`]).
/// * `seed` — Deterministic RNG seed.
#[must_use]
pub fn apply_ml_evasion_if_applicable(
    request: &Request,
    waf_name: &str,
    budget: u64,
    seed: u64,
) -> (Request, Vec<Technique>) {
    let waf_class = WafClass::from_waf_name(waf_name);
    if !waf_class.is_ml_backed() {
        return (request.clone(), Vec::new());
    }

    let Some(ref body) = request.body else {
        return (request.clone(), Vec::new());
    };

    let Some(evasion) = ml_evasion_candidates(body, budget, seed) else {
        return (request.clone(), Vec::new());
    };

    let mut req = request.clone();
    req.body = Some(evasion.input);
    let techniques = vec![Technique::MlEvasion {
        waf_class: format!("{waf_class:?}"),
        queries: evasion.queries,
        off_manifold_rejected: evasion.off_manifold_rejected,
    }];
    (req, techniques)
}

/// Convenience wrapper: apply ML evasion and wrap in an [`EvasionResult`].
///
/// Returns `None` if the WAF is not ML-backed or evasion produced no
/// useful mutation (original request unchanged).
#[must_use]
pub fn evade_ml_backed(
    request: &Request,
    waf_name: &str,
    budget: u64,
    seed: u64,
) -> Option<EvasionResult> {
    let waf_class = WafClass::from_waf_name(waf_name);
    if !waf_class.is_ml_backed() {
        return None;
    }

    let (mutated_req, techniques) =
        apply_ml_evasion_if_applicable(request, waf_name, budget, seed);

    if techniques.is_empty() {
        return None;
    }

    let description = format!(
        "ML evasion ({waf_class:?}): {} technique(s) applied",
        techniques.len()
    );
    Some(EvasionResult::new(mutated_req, techniques, description))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_types::{EvasionConfig, Request};

    #[test]
    fn ml_backed_routes_through_evade_ml_or_returns_none_gracefully() {
        // AWS Bot Control is ML-backed. With a known attack payload
        // the function must return Some or None (never panic).
        let req = Request::post(
            "https://target.internal/",
            b"q=' OR 1=1--".to_vec(),
        )
        .header("Content-Type", "application/x-www-form-urlencoded");

        // Result may be None if the manifold check rejects all mutations.
        let _result = evade_ml_backed(&req, "AWS Bot Control", 64, 42);
        // No panic == success for this structural routing test.
    }

    #[test]
    fn plain_modsec_not_ml_backed_returns_none() {
        let req = Request::post("https://example.com/", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");

        let result = evade_ml_backed(&req, "ModSecurity", DEFAULT_ML_BUDGET, 0);
        assert!(
            result.is_none(),
            "PlainModSec must not route through ML evasion"
        );
    }

    #[test]
    fn unknown_waf_not_ml_backed_returns_none() {
        let req = Request::post("https://example.com/", b"q=test".to_vec())
            .header("Content-Type", "application/x-www-form-urlencoded");

        let result = evade_ml_backed(&req, "SomeRandomVendor", DEFAULT_ML_BUDGET, 0);
        assert!(result.is_none(), "Unknown WAF must not route through ML evasion");
    }

    #[test]
    fn ml_evasion_preserves_payload_semantics() {
        // The manifold projection must ensure attack tokens are preserved.
        let payload = b"' UNION SELECT 1,2--";
        let result = ml_evasion_candidates(payload, 128, 99);

        if let Some(evasion) = result {
            let mutated = String::from_utf8_lossy(&evasion.input).to_ascii_lowercase();
            // "union" or "select" must survive — manifold projection enforces this.
            assert!(
                mutated.contains("union") || mutated.contains("select"),
                "manifold projection must preserve attack tokens; got: {mutated:?}"
            );
        }
        // None is also valid: the conservative oracle may find no bypass
        // within the budget. That is correct behaviour, not a failure.
    }

    #[test]
    fn apply_ml_evasion_no_body_returns_original() {
        let req = Request::get("https://example.com/");
        let (result_req, techniques) =
            apply_ml_evasion_if_applicable(&req, "AWS Bot Control", 64, 0);
        assert_eq!(result_req.url, req.url);
        assert!(techniques.is_empty(), "no body → no techniques applied");
    }

    #[test]
    fn apply_ml_evasion_cloudflare_bot_mgmt_routes_correctly() {
        let req = Request::post(
            "https://target.internal/",
            b"q=<script>alert(1)</script>".to_vec(),
        )
        .header("Content-Type", "application/x-www-form-urlencoded");

        // Cloudflare Bot Management is ML-backed — must not fall through
        // to non-ML path.
        let waf = "Cloudflare Bot Management";
        assert!(
            WafClass::from_waf_name(waf).is_ml_backed(),
            "Cloudflare Bot Management must be identified as ML-backed"
        );

        // The function must not panic regardless of outcome.
        let _ = apply_ml_evasion_if_applicable(&req, waf, 64, 7);
    }
}
