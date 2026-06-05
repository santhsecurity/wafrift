//! Zero-downstream-change bridge: solver/preimage output expressed as
//! the **canonical [`EquivPayload`]** the rest of the ecosystem
//! already consumes.
//!
//! scald's terminal evasion tier is a loop over
//! `wafrift_grammar::grammar::equiv` members:
//!
//! ```ignore
//! for m in xss_delivered(payload, max) {
//!     let req = m.delivery.to_request(target, &m.payload);
//!     // … send, check marker …
//! }
//! ```
//!
//! Everything this module produces is the *same* `EquivPayload` type
//! with the *same* `DeliveryShape`, so that loop body is **unchanged**:
//! a consumer adds these members to the same iteration and its
//! per-member handling, request building, and marker check are
//! untouched.
//!
//! Why a bridge and not a new `xss_delivered` tier: a normalization-
//! mismatch payload is *not* directly browser-executable (it executes
//! only after the origin's decode), so it cannot pass
//! `xss::still_executes_xss` — and weakening that anti-rig oracle to
//! admit it would be exactly the rigging the project forbids. These
//! members are sound *relative to a declared decoding sink* (the same
//! soundness model scald's existing double-URL tier uses: a member
//! that the origin does not decode simply never verifies — no false
//! positive). Each member's payload, run through its declared sink,
//! reconstructs the attack — asserted in the contract tests.

use crate::solve::{Solution, preimage_for};
use crate::transduce::{Pipeline, Stage};
use wafrift_grammar::grammar::equiv::{DeliveryShape, Dialect, EquivPayload};

/// A canonical decoding sink and its stable rule tag.
struct NamedSink {
    tag: &'static str,
    pipeline: Pipeline,
}

fn default_sinks() -> Vec<NamedSink> {
    vec![
        NamedSink {
            tag: "norm_mismatch_double_url",
            pipeline: Pipeline(vec![Stage::DoubleUrlDecode]),
        },
        NamedSink {
            tag: "norm_mismatch_json_unescape",
            pipeline: Pipeline(vec![Stage::JsonUnescape]),
        },
        NamedSink {
            tag: "norm_mismatch_html_entity",
            pipeline: Pipeline(vec![Stage::HtmlEntityDecode]),
        },
        // Origin Unicode-normalization sinks. Unlike the three above (whose
        // preimage is an ASCII `%XX`/`\uXXXX`/`&#x;` form), these emit a
        // non-ASCII homoglyph form that an NFKC-normalizing / best-fit-coercing
        // origin folds back to the attack. A member is emitted only when its
        // preimage actually differs from the attack (see the skip-degenerate
        // guard in `norm_mismatch_members`): best-fit no-ops on a quote/dash/
        // slash-free attack, so it self-selects to the SQLi-class payloads.
        //
        // The LAYERED composite (url-decode∘normalize) is deliberately NOT a
        // default offline member: on an attack the normalizer cannot fold it
        // degenerates to a plain url-encode under a misleading tag. The live
        // `solve_bypass` CEGIS path escalates to the composite preimage when a
        // real decompiled WAF blocks the bare homoglyph (proven in
        // solve_contract's `solver_composes_url_decode_and_nfkc`).
        NamedSink {
            tag: "norm_mismatch_nfkc",
            pipeline: Pipeline(vec![Stage::NfkcNormalize]),
        },
        NamedSink {
            tag: "norm_mismatch_bestfit",
            pipeline: Pipeline(vec![Stage::BestFitDownconvert]),
        },
    ]
}

/// Normalization-mismatch members for `attack`, one per canonical
/// decoding sink, as query-delivered [`EquivPayload`]s. Consume them
/// through the identical `m.delivery.to_request(t, &m.payload)` path.
///
/// Each member's `payload`, decoded by the sink its `rules` tag names,
/// reconstructs `attack` — so against an origin that performs that
/// decode the live attack lands at the sink, and against one that does
/// not it stays inert (never a false positive).
#[must_use]
pub fn norm_mismatch_members(attack: &str, param: &str) -> Vec<EquivPayload> {
    let mut out = Vec::new();
    let mut seen_payloads = std::collections::HashSet::new();
    for ns in default_sinks() {
        let pre = preimage_for(attack.as_bytes(), &ns.pipeline, false);
        // Skip-degenerate guard: a sink that produced no change (no byte the
        // sink decodes / no codepoint it folds appears in the attack — e.g.
        // best-fit on a quote-free XSS attack) yields the raw attack, which is
        // not an evasion. Emitting it would be unsound (the WAF sees the attack
        // directly) and would trip the anti-rig `payload != attack` contract.
        if pre == attack.as_bytes() {
            continue;
        }
        // Lossless: the percent/JSON/HTML preimages are ASCII; the NFKC/best-
        // fit preimages are valid-UTF-8 homoglyph forms (built char-by-char),
        // so `from_utf8_lossy` never substitutes here.
        let payload = String::from_utf8_lossy(&pre).into_owned();
        // Dedup by payload: a composite sink can coincide byte-for-byte with a
        // single-stage one (e.g. when the outer layer is a no-op for this
        // attack). Keep the first (most specific tag wins by sink order) and
        // never emit two members the operator would see as identical.
        if !seen_payloads.insert(payload.clone()) {
            continue;
        }
        out.push(EquivPayload {
            payload,
            delivery: DeliveryShape::Query {
                param: param.to_string(),
            },
            dialect: Dialect::Generic,
            rules: vec![ns.tag],
        });
    }
    out
}

/// Turn a fully-verified solver [`Solution`] (bypassed a *specific*
/// decompiled WAF) into a canonical member for the same consumption
/// path. The `audit` flow uses this so a solved bypass flows straight
/// into the existing delivery machinery.
///
/// R54 pass-16 I5 fix (CLAUDE.md §15 AUDIT): pre-fix used
/// `from_utf8_lossy(&sol.input).into_owned()` which silently replaces
/// non-UTF-8 bytes with U+FFFD — the candidate the operator delivered
/// would then differ from the bytes the solver actually computed and
/// the oracle would compare against the original attack rather than
/// the mutilated version. Now: drop non-UTF-8 solutions with a
/// tracing warn so the gap is visible. A future revision should
/// thread `Vec<u8>` through `EquivPayload.payload` to preserve byte-
/// level fidelity.
#[must_use]
pub fn solution_member(sol: &Solution, param: &str) -> Option<EquivPayload> {
    let payload = match std::str::from_utf8(&sol.input) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!(
                bytes = sol.input.len(),
                "solver returned non-UTF-8 bypass candidate; \
                 dropping (lossy conversion would mangle the bytes \
                 the oracle compared against)"
            );
            return None;
        }
    };
    Some(EquivPayload {
        payload,
        delivery: DeliveryShape::Query {
            param: param.to_string(),
        },
        dialect: Dialect::Generic,
        rules: vec!["solver_bypass"],
    })
}

/// The decoding sink a member's rule tag declares (so a verifier can
/// confirm reconstruction). `None` for tags this module did not mint.
#[must_use]
pub fn sink_for_tag(tag: &str) -> Option<Pipeline> {
    default_sinks()
        .into_iter()
        .find(|ns| ns.tag == tag)
        .map(|ns| ns.pipeline)
}
