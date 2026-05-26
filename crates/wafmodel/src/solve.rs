//! Composition + preimage solver — the part that turns "encoding
//! tricks" from hand-written rules into *emergent solutions*.
//!
//! A working bypass of the whole pipeline is any input `x` with:
//!
//! ```text
//!   WAF passes  (the WAF's normalized view of x is inert)
//!     ∧  sink(x) reconstructs the live attack
//! ```
//!
//! The solver never hard-codes "double-URL-encode" or any other trick.
//! It takes the **sink pipeline as data**, computes the *structural
//! preimage* of the attack under that pipeline (compose each stage's
//! inverse encoder in reverse order), then runs an active L*-style
//! boundary-learning loop: generate a candidate preimage, test it
//! against the real WAF oracle and the sink, and on failure escalate
//! to a deeper/likewise-structural encoding. Point the same code at a
//! JSON-unescaping sink and it emits a JSON-escaped bypass; at a
//! double-decoding sink, the double-encoding falls out. The trick is
//! *derived from the pipeline*, not retrieved from a list.
//! [Angluin 1987, "Learning Regular Sets from Queries and Counterexamples".]

use crate::error::Result;
use crate::oracle::WafOracle;
use crate::outcome::Outcome;
use crate::transduce::{Pipeline, Stage};
use wafrift_types::Request;

/// Which bytes a structural encoder rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Every byte (maximally evasive, longest).
    All,
    /// Only the "dangerous" bytes a WAF rule keys on (minimal, often
    /// enough and much shorter).
    Danger,
}

const DANGER: &[u8] = b"<>()'\"/;= \t\r\n&%{}[]:";

fn in_scope(b: u8, s: Scope) -> bool {
    match s {
        Scope::All => true,
        Scope::Danger => DANGER.contains(&b),
    }
}

fn pct_encode(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

fn json_escape(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 6);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(format!("\\u{b:04x}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

fn html_entity_encode(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 6);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(format!("&#x{b:x};").as_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

/// The structural inverse of one stage: bytes that this stage decodes
/// back to its input. `None` ⇒ the stage is not a decoder the solver
/// can invert (it is treated as identity in the preimage).
fn stage_inverse(stage: &Stage, input: &[u8], scope: Scope) -> Vec<u8> {
    match stage {
        Stage::UrlDecode { .. } => pct_encode(input, scope),
        Stage::DoubleUrlDecode => pct_encode(&pct_encode(input, scope), scope),
        Stage::JsonUnescape => json_escape(input, scope),
        Stage::HtmlEntityDecode => html_entity_encode(input, scope),
        Stage::Identity | Stage::CrsView(_) => input.to_vec(),
    }
}

/// The structural preimage of `attack` under `sink`: compose each
/// stage's inverse encoder in reverse pipeline order, so that
/// `sink.apply(preimage) == attack` by construction.
fn structural_preimage(attack: &[u8], sink: &Pipeline, scope: Scope) -> Vec<u8> {
    sink.0
        .iter()
        .rev()
        .fold(attack.to_vec(), |acc, st| stage_inverse(st, &acc, scope))
}

/// The structural preimage of `attack` under `sink` (encode every
/// dangerous byte, or every byte). `sink.apply(result)` reconstructs
/// `attack` by construction — public so the equiv bridge can mint
/// pipeline-conditioned members without re-deriving the inversion.
#[must_use]
pub fn preimage_for(attack: &[u8], sink: &Pipeline, encode_all: bool) -> Vec<u8> {
    structural_preimage(
        attack,
        sink,
        if encode_all {
            Scope::All
        } else {
            Scope::Danger
        },
    )
}

/// A solved end-to-end bypass.
#[derive(Debug, Clone)]
pub struct Solution {
    /// The input bytes to send (the solved preimage).
    pub input: Vec<u8>,
    /// Human label of the encoding the solver derived (not chosen from
    /// a list — describes the structural preimage it computed).
    pub encoding: String,
    /// Whether the *raw* attack is blocked by this WAF (the control:
    /// if the raw attack already passed, a "bypass" would be vacuous).
    pub raw_attack_blocked: bool,
    /// What the sink reconstructed (must contain the attack).
    pub sink_view: Vec<u8>,
}

/// Solve for an input that bypasses `oracle` yet still delivers
/// `attack` through `sink`. `build` turns candidate bytes into the
/// request shape under test (so the same solver works against a
/// learned model, a `SimRegexWaf`, or a live target).
///
/// Active boundary learning: candidates are ordered minimal-first (encode
/// only dangerous bytes) then escalated (encode everything); each is
/// *verified* against the real oracle and the real sink. `None` ⇒ no
/// structural preimage bypasses this pipeline (e.g. an identity sink —
/// correctly reported, never a fabricated bypass). Each blocked candidate
/// acts as a counterexample that narrows the search (Angluin 1987).
pub fn solve_bypass<B>(
    attack: &[u8],
    sink: &Pipeline,
    oracle: &mut dyn WafOracle,
    build: &B,
) -> Result<Option<Solution>>
where
    B: Fn(&[u8]) -> Request,
{
    // The raw attack is the control: confirm the WAF actually blocks
    // it, otherwise "bypass" is meaningless (anti-rig).
    let raw_blocked = matches!(oracle.classify(&build(attack))?, Outcome::Block);

    // Empty attacks are vacuous — there's nothing to "deliver
    // through" the WAF and `Vec::windows(0)` panics. Return None
    // early so callers see "no bypass found" instead of a runtime
    // panic. (Found by an adversarial test in
    // `wafrift-cli::wafmodel_solve_cmd`.)
    if attack.is_empty() {
        return Ok(None);
    }

    for scope in [Scope::Danger, Scope::All] {
        let cand = structural_preimage(attack, sink, scope);
        // The sink must reconstruct the literal attack.
        let sink_view = sink.apply(&cand);
        let reconstructs = sink_view.windows(attack.len()).any(|w| w == attack);
        if !reconstructs {
            continue;
        }
        // The WAF must pass the candidate.
        let passes = matches!(oracle.classify(&build(&cand))?, Outcome::Pass);
        if passes {
            return Ok(Some(Solution {
                input: cand,
                encoding: format!(
                    "structural-preimage[{}]({} stages, scope={scope:?})",
                    if raw_blocked {
                        "raw-blocked"
                    } else {
                        "raw-passed"
                    },
                    sink.len(),
                ),
                raw_attack_blocked: raw_blocked,
                sink_view,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod empty_attack_tests {
    use super::*;
    use crate::oracle::FnOracle;
    use wafrift_types::Request;

    /// Empty attack used to panic on `windows(0)`. Pin: must return
    /// `Ok(None)` and not invoke the oracle for any candidate body.
    #[test]
    fn empty_attack_returns_none_no_panic() {
        let mut oracle = FnOracle::new(|_req: &Request| Ok(Outcome::Block));
        let build = |b: &[u8]| Request::post("http://target/", b.to_vec());
        let sink = Pipeline(vec![]);
        let result = solve_bypass(&[], &sink, &mut oracle, &build).expect("no error");
        assert!(result.is_none());
    }

    /// One-byte attack still finds a bypass when the encoder
    /// produces a different wire form. Sanity for the boundary
    /// right above the empty case.
    #[test]
    fn one_byte_attack_does_not_panic() {
        let mut oracle = FnOracle::new(|req: &Request| {
            let body = req.body_bytes().unwrap_or(&[]);
            if body == b"<" {
                Ok(Outcome::Block)
            } else {
                Ok(Outcome::Pass)
            }
        });
        let build = |b: &[u8]| Request::post("http://target/", b.to_vec());
        use crate::transduce::Stage;
        let sink = Pipeline(vec![Stage::UrlDecode { plus_is_space: false }]);
        // Must not panic.
        let _ = solve_bypass(b"<", &sink, &mut oracle, &build);
    }
}
