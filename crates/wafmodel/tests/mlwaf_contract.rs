//! Truth contract for ML-WAF constrained evasion.
//!
//! The decisive anti-rig property: a "bypass" is only ever an input
//! that (a) the ML-WAF passes AND (b) is still a working attack. The
//! manifold projection is enforced on every accepted candidate, and an
//! ML-WAF that blocks the entire attack manifold yields `None` — never
//! a fabricated off-manifold "win".

use wafrift_types::Request;
use wafrift_wafmodel::{MlWaf, Result, evade_ml};

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

/// Executable-attack manifold: HTML is case-insensitive, so the
/// lowercased form containing a live sink token means it executes.
fn is_attack(x: &[u8]) -> bool {
    let lc = x.to_ascii_lowercase();
    lc.windows(7).any(|w| w == b"<script") || lc.windows(8).any(|w| w == b"onerror=")
}

/// A *brittle* ML-WAF: its features key on the EXACT-CASE literals
/// (the realistic failure mode of a classifier trained on raw tokens).
struct BrittleMl {
    expose_score: bool,
}
impl BrittleMl {
    fn raw_score(req: &Request) -> f64 {
        let b = req.body_bytes().unwrap_or(&[]);
        let f1 = b.windows(7).any(|w| w == b"<script");
        let f2 = b.windows(8).any(|w| w == b"onerror=");
        let f3 = b.windows(11).any(|w| w == b"javascript:");
        0.6 * f64::from(u8::from(f1))
            + 0.6 * f64::from(u8::from(f2))
            + 0.6 * f64::from(u8::from(f3))
    }
}
impl MlWaf for BrittleMl {
    fn blocks(&mut self, req: &Request) -> Result<bool> {
        Ok(Self::raw_score(req) >= 0.5)
    }
    fn score(&mut self, req: &Request) -> Result<Option<f64>> {
        Ok(self.expose_score.then(|| Self::raw_score(req)))
    }
}

/// A *robust* ML-WAF: its feature is case-insensitive — i.e. it keys
/// on the manifold itself. Nothing on the attack manifold can evade
/// it; the only "bypass" would be to stop attacking.
struct RobustMl;
impl MlWaf for RobustMl {
    fn blocks(&mut self, req: &Request) -> Result<bool> {
        Ok(is_attack(req.body_bytes().unwrap_or(&[])))
    }
}

#[test]
fn score_guided_boundary_attack_finds_an_on_manifold_bypass() {
    let start = b"<script>alert(1)</script>";
    assert!(is_attack(start));
    let mut waf = BrittleMl { expose_score: true };
    let ev = evade_ml(start, &mut waf, &is_attack, &body, 5_000, 42)
        .unwrap()
        .expect("a brittle exact-case ML-WAF must be evadable on-manifold");

    // The evading input is genuinely NOT the original …
    assert_ne!(ev.input, start);
    // … it is STILL a working attack (manifold preserved) …
    assert!(
        is_attack(&ev.input),
        "winner left the attack manifold (rigged!)"
    );
    // … and the ML-WAF actually passes it.
    let mut check = BrittleMl { expose_score: true };
    assert!(!check.blocks(&body(&ev.input)).unwrap());
}

#[test]
fn decision_only_boundary_walk_also_succeeds() {
    // No score exposed — the realistic black-box ML-WAF. The manifold-
    // constrained randomized walk must still find a bypass.
    let start = b"<script>alert(1)</script>";
    let mut waf = BrittleMl {
        expose_score: false,
    };
    let ev = evade_ml(start, &mut waf, &is_attack, &body, 40_000, 7)
        .unwrap()
        .expect("decision-only brittle ML-WAF is still evadable");
    assert!(is_attack(&ev.input));
    let mut check = BrittleMl {
        expose_score: false,
    };
    assert!(!check.blocks(&body(&ev.input)).unwrap());
}

#[test]
fn an_ml_waf_covering_the_whole_manifold_yields_none_not_a_fabrication() {
    // RobustMl blocks anything on the manifold. The ONLY way to make
    // it pass is to leave the manifold — which the projection forbids.
    // The honest result is None, and crucially the search must have
    // *tried and rejected* off-manifold candidates rather than cheat.
    let start = b"<script>alert(1)</script>";
    let mut waf = RobustMl;
    let out = evade_ml(start, &mut waf, &is_attack, &body, 3_000, 1).unwrap();
    assert!(
        out.is_none(),
        "a manifold-covering ML-WAF must yield None, never an off-manifold fake: {out:?}"
    );
}

#[test]
fn non_attack_start_is_rejected_no_vacuous_bypass() {
    // If the seed is not even an attack, there is nothing to evade —
    // must return None rather than declare a meaningless success.
    let mut waf = BrittleMl { expose_score: true };
    let out = evade_ml(b"hello world", &mut waf, &is_attack, &body, 1000, 0).unwrap();
    assert!(out.is_none());
}
