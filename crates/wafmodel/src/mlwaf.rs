//! Constrained black-box evasion of **ML-WAFs**.
//!
//! Regex-WAFs are decompiled (P1) and solved (P2). The next-generation
//! threat is a learned classifier — Cloudflare/AWS/Fastly ML-WAFs —
//! where there is no rule to learn and no normalization to mismatch.
//! The paradigm-correct tool there is a *decision-based boundary
//! attack* (HopSkipJump-family): perturb a blocked attack toward the
//! decision boundary using only the WAF's block/allow answers.
//!
//! The crucial twist nobody else has: the perturbation must keep the
//! input a **working attack**. That is a hard manifold constraint, and
//! the projection-onto-feasible operator *is wafrift's soundness
//! oracle*. Every candidate is projected back onto the executable-
//! attack manifold (rejected if it stops being an attack) — so a
//! "bypass" can never be won by mutating the payload into something
//! inert. Anti-rig is structural: leaving the manifold is not a
//! success, it is a discarded sample.

use crate::error::Result;
use wafrift_types::Request;

/// An ML-WAF: a decision, and optionally a continuous score that lets
/// the boundary attack descend instead of blind-search.
pub trait MlWaf {
    /// `true` ⇒ the request is blocked.
    fn blocks(&mut self, req: &Request) -> Result<bool>;
    /// Optional anomaly score (higher = more likely blocked). `None`
    /// ⇒ decision-only WAF (the realistic black-box threat model).
    fn score(&mut self, _req: &Request) -> Result<Option<f64>> {
        Ok(None)
    }
}

/// Deterministic SplitMix64 (reproducible adversarial search).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Semantics-preserving *proposals* (liberal — validity is enforced by
/// the manifold projection, not by the mutator). For HTML/JS XSS:
/// tag/attribute names are case-insensitive, and benign intra-tag
/// whitespace / comments do not change execution.
fn propose(input: &[u8], rng: &mut Rng) -> Vec<u8> {
    if input.is_empty() {
        return input.to_vec();
    }
    let mut v = input.to_vec();
    match rng.below(3) {
        // Flip the case of one ASCII letter.
        0 => {
            for _ in 0..4 {
                let i = rng.below(v.len());
                if v[i].is_ascii_alphabetic() {
                    v[i] ^= 0x20;
                    break;
                }
            }
        }
        // Insert a benign whitespace byte.
        1 => {
            let i = rng.below(v.len());
            v.insert(i, b' ');
        }
        // Insert an HTML comment (inert between tags / attributes).
        _ => {
            let i = rng.below(v.len());
            for (k, b) in b"<!---->".iter().enumerate() {
                v.insert(i + k, *b);
            }
        }
    }
    v
}

/// Outcome of an ML-WAF evasion search.
#[derive(Debug, Clone)]
pub struct MlEvasion {
    /// The evading input — bypasses the ML-WAF *and* is still an attack.
    pub input: Vec<u8>,
    /// ML-WAF queries spent.
    pub queries: u64,
    /// Candidates rejected by the manifold projection (never counted
    /// as progress — the anti-rig ledger).
    pub off_manifold_rejected: u64,
}

/// Decision-based boundary attack constrained to the executable-attack
/// manifold.
///
/// `is_attack` is the projection-onto-feasible operator (wafrift's
/// soundness oracle): a candidate that is not a working attack is
/// discarded, never accepted to "win". If `score` is available the
/// search descends it (HopSkipJump-style); otherwise it is a
/// manifold-constrained randomized boundary walk with restarts.
///
/// Returns `None` iff no on-manifold input within `budget` queries
/// bypasses the WAF — e.g. an ML-WAF that blocks the *entire* attack
/// manifold (correctly reported, never fabricated).
pub fn evade_ml<W, F, B>(
    start: &[u8],
    waf: &mut W,
    is_attack: &F,
    build: &B,
    budget: u64,
    seed: u64,
) -> Result<Option<MlEvasion>>
where
    W: MlWaf,
    F: Fn(&[u8]) -> bool,
    B: Fn(&[u8]) -> Request,
{
    // The start MUST be on the manifold and blocked, else the search
    // is meaningless (anti-rig: no vacuous "bypass").
    if !is_attack(start) {
        return Ok(None);
    }
    let mut rng = Rng(seed);
    let mut queries = 0u64;
    let mut off = 0u64;

    let start_req = build(start);
    if !waf.blocks(&start_req)? {
        queries += 1;
        // Already passes and is an attack — trivially evading.
        return Ok(Some(MlEvasion {
            input: start.to_vec(),
            queries,
            off_manifold_rejected: 0,
        }));
    }
    queries += 1;

    let mut best = start.to_vec();
    let mut best_score = waf.score(&start_req)?;
    if let Some(s) = best_score {
        queries += 1;
        best_score = Some(s);
    }

    while queries < budget {
        // Restart from `best` (the closest-to-boundary on-manifold
        // point found so far) with a fresh perturbation.
        let cand = propose(&best, &mut rng);
        // Manifold projection: reject anything that is not a working
        // attack. This is the hard constraint — and the anti-rig.
        if !is_attack(&cand) {
            off += 1;
            continue;
        }
        let req = build(&cand);
        let blocked = waf.blocks(&req)?;
        queries += 1;
        if !blocked {
            return Ok(Some(MlEvasion {
                input: cand,
                queries,
                off_manifold_rejected: off,
            }));
        }
        // Still blocked: keep it only if it moved us closer to the
        // boundary (lower score). With no score, accept with a small
        // probability to keep exploring (constrained boundary walk).
        if let Ok(Some(sc)) = waf.score(&req) {
            queries += 1;
            if best_score.is_none_or(|b| sc < b) {
                best = cand;
                best_score = Some(sc);
            }
        } else if rng.below(4) == 0 {
            best = cand;
        }
    }
    Ok(None)
}
