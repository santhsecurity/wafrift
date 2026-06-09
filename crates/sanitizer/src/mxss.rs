//! Mutation-XSS (mXSS) candidate detection.
//!
//! The L*/SFA miner judges a payload executable by whether `<script>` or an
//! `on*=` handler survives the modelled sanitizer. That misses **mutation XSS**:
//! the sanitizer removes every handler it can see, but the browser *re-parses*
//! the serialized output through a different path (HTML foreign content, MathML /
//! SVG integration points, `<noscript>` scripting-state toggles, `<template>`
//! adoption) and script comes back to life. Confirming an mXSS bypass needs a
//! real browser — scald — not an in-process model.
//!
//! What this module *can* do statically is flag, from the recovered allow/deny
//! model, every known mXSS **trigger combination** whose two tags are both
//! reachable. That is a precise, Tier-B-driven advisory: "this config leaves the
//! mXSS door open via `<svg><style>` — confirm in a live DOM." Proposed, never
//! asserted executed — exactly the contract the rest of the decompiler honours.

use serde::{Deserialize, Serialize};

use crate::extract::SanitizerModel;

/// The Tier-B mXSS trigger table (the data file is the single source).
const MXSS_TOML: &str = include_str!("../rules/mxss_combinations.toml");

/// One mXSS trigger combination from the Tier-B table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxssCombination {
    /// Foreign-content / mode-switching root element.
    pub root: String,
    /// Raw-text / re-parse child element reachable under `root`.
    pub child: String,
    /// The parsing differential exploited.
    pub class: String,
    /// Operator-facing explanation and a representative payload shape.
    pub note: String,
}

/// An mXSS combination found reachable under a specific sanitizer model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxssCandidate {
    /// The reachable root tag.
    pub root: String,
    /// The reachable child tag.
    pub child: String,
    /// The parsing-differential class.
    pub class: String,
    /// Why this combination is dangerous (from the Tier-B note).
    pub note: String,
}

/// The embedded Tier-B mXSS combinations, parsed from the data file.
/// Panics only if the shipped data file is malformed (asserted by tests).
#[must_use]
pub fn mxss_combinations() -> Vec<MxssCombination> {
    load_mxss_combinations(MXSS_TOML)
        .expect("embedded mXSS combination data file must be valid (asserted in tests)")
}

/// Parse a Tier-B mXSS table: `[[mxss]] root=.. child=.. class=.. note=..`.
/// Fails closed on an empty table (a silently-empty set would suppress every
/// advisory).
pub fn load_mxss_combinations(src: &str) -> Result<Vec<MxssCombination>, String> {
    #[derive(Deserialize)]
    struct Table {
        #[serde(default)]
        mxss: Vec<MxssCombination>,
    }
    let table: Table =
        toml::from_str(src).map_err(|e| format!("parsing mXSS combination TOML: {e}"))?;
    if table.mxss.is_empty() {
        return Err("mXSS combination file has no `[[mxss]]` entries".into());
    }
    for (i, c) in table.mxss.iter().enumerate() {
        if c.root.trim().is_empty() || c.child.trim().is_empty() {
            return Err(format!("mXSS entry {i} has an empty `root` or `child`"));
        }
    }
    Ok(table.mxss)
}

/// Every mXSS trigger combination whose root AND child are both reachable under
/// `model`'s allow/deny rules. Empty when the config is tight enough to foreclose
/// all listed combinations.
#[must_use]
pub fn mxss_candidates(model: &SanitizerModel) -> Vec<MxssCandidate> {
    mxss_candidates_with(model, &mxss_combinations())
}

/// [`mxss_candidates`] against a caller-supplied combination table (Tier-B
/// override / tests).
#[must_use]
pub fn mxss_candidates_with(
    model: &SanitizerModel,
    combos: &[MxssCombination],
) -> Vec<MxssCandidate> {
    combos
        .iter()
        .filter(|c| model.tag_reachable(&c.root) && model.tag_reachable(&c.child))
        .map(|c| MxssCandidate {
            root: c.root.clone(),
            child: c.child.clone(),
            class: c.class.clone(),
            note: c.note.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::SanitizerKind;

    fn model(forbidden: &[&str], allowed: Option<&[&str]>) -> SanitizerModel {
        SanitizerModel {
            kind: SanitizerKind::DomPurify,
            allowed_tags: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
            forbidden_tags: forbidden.iter().map(|s| s.to_string()).collect(),
            forbidden_attrs: Vec::new(),
            strips_event_handlers: false,
            blocked_schemes: Vec::new(),
            strip_patterns: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn embedded_table_loads_and_is_nonempty() {
        let combos = mxss_combinations();
        assert!(
            combos.len() >= 5,
            "ship a real mXSS table, got {}",
            combos.len()
        );
        assert!(combos.iter().any(|c| c.root == "svg" && c.child == "style"));
        assert!(combos.iter().any(|c| c.root == "math"));
    }

    #[test]
    fn loader_fails_closed_on_empty() {
        assert!(load_mxss_combinations("# nothing\n").is_err());
        assert!(load_mxss_combinations("").is_err());
    }

    #[test]
    fn loader_rejects_an_entry_with_an_empty_tag() {
        let bad = "[[mxss]]\nroot=\"\"\nchild=\"style\"\nclass=\"x\"\nnote=\"y\"\n";
        assert!(load_mxss_combinations(bad).is_err());
    }

    #[test]
    fn a_forbid_only_config_leaving_svg_and_style_reachable_is_flagged() {
        // DOMPurify forbidding only <script> still allows <svg> and <style>.
        let m = model(&["script"], None);
        let cands = mxss_candidates(&m);
        assert!(
            cands.iter().any(|c| c.root == "svg" && c.child == "style"),
            "svg+style must be flagged when neither is forbidden: {cands:?}"
        );
    }

    #[test]
    fn forbidding_one_tag_of_a_pair_forecloses_that_combination() {
        // Forbid <style> → the svg+style combination is no longer reachable.
        let m = model(&["style"], None);
        let cands = mxss_candidates(&m);
        assert!(
            !cands.iter().any(|c| c.root == "svg" && c.child == "style"),
            "forbidding <style> must foreclose svg+style: {cands:?}"
        );
    }

    #[test]
    fn a_tight_inert_allowlist_has_no_mxss_candidates() {
        // Only inert formatting tags allowed → no foreign-content root reachable.
        let m = model(&[], Some(&["b", "i", "em", "p"]));
        assert!(
            mxss_candidates(&m).is_empty(),
            "a tight allowlist must be mXSS-clean"
        );
    }

    #[test]
    fn an_allowlist_permitting_a_foreign_root_and_child_is_flagged() {
        let m = model(&[], Some(&["math", "mtext", "p"]));
        let cands = mxss_candidates(&m);
        assert!(
            cands.iter().any(|c| c.root == "math" && c.child == "mtext"),
            "math+mtext on the allowlist must be flagged: {cands:?}"
        );
    }

    #[test]
    fn html_spec_integration_points_are_in_the_table() {
        // The foreign-content HTML integration points (the structural roots of the
        // well-known DOMPurify namespace-confusion bypasses) MUST be named — the
        // miner can never surface them, so the Tier-B table is their only source.
        let combos = mxss_combinations();
        // MathML text integration point — the Bentkowski annotation-xml element.
        assert!(
            combos
                .iter()
                .any(|c| c.root == "math" && c.child == "annotation-xml"),
            "math+annotation-xml (the canonical DOMPurify mXSS element) must be listed"
        );
        // All three SVG HTML-integration-point elements.
        for child in ["foreignObject", "desc", "title"] {
            assert!(
                combos.iter().any(|c| c.root == "svg" && c.child == child),
                "svg+{child} HTML-integration-point must be listed"
            );
        }
    }

    #[test]
    fn a_math_allowing_config_flags_the_annotation_xml_integration_point() {
        // A config that forbids <script> but allows MathML (a real DOMPurify
        // profile for math-rendering apps) leaves the annotation-xml integration
        // point reachable — the exact namespace-confusion door.
        let m = model(&["script"], None);
        let cands = mxss_candidates(&m);
        let hit = cands
            .iter()
            .find(|c| c.root == "math" && c.child == "annotation-xml")
            .expect("annotation-xml must be flagged when math is reachable");
        assert_eq!(hit.class, "mathml-html-integration-point");
        assert!(
            hit.note.contains("integration point"),
            "note must explain the mechanism"
        );
    }

    #[test]
    fn forbidding_the_integration_point_child_forecloses_it() {
        // Allowing <svg> but forbidding <foreignObject> specifically must drop the
        // svg+foreignObject candidate while leaving other svg pairs reachable.
        let m = model(&["foreignObject"], None);
        let cands = mxss_candidates(&m);
        assert!(
            !cands.iter().any(|c| c.child == "foreignObject"),
            "forbidding <foreignObject> must foreclose its integration point: {cands:?}"
        );
    }

    #[test]
    fn candidates_carry_the_class_and_note_for_the_operator() {
        let m = model(&["script"], None);
        let cands = mxss_candidates(&m);
        let first = cands
            .first()
            .expect("forbid-script leaves combinations reachable");
        assert!(!first.class.is_empty() && !first.note.is_empty());
    }
}
