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
    for ns in default_sinks() {
        let pre = preimage_for(attack.as_bytes(), &ns.pipeline, false);
        // Lossless: structural preimages of ASCII attacks are ASCII.
        let payload = String::from_utf8_lossy(&pre).into_owned();
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
#[must_use]
pub fn solution_member(sol: &Solution, param: &str) -> EquivPayload {
    EquivPayload {
        payload: String::from_utf8_lossy(&sol.input).into_owned(),
        delivery: DeliveryShape::Query {
            param: param.to_string(),
        },
        dialect: Dialect::Generic,
        rules: vec!["solver_bypass"],
    }
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
