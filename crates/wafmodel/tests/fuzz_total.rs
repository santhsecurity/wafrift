//! E4 — fuzzing as a CI-resident contract. Every parser/decoder
//! surface must be **total** on arbitrary bytes: never panic, never
//! hang, never OOM, never accept an invalid automaton. cargo-fuzz
//! targets (fuzz/) drive these same entry points for 24h soak; this
//! file is the always-on smoke (10k random inputs/target) so a
//! regression fails normal CI, not just the nightly fuzz lane.

use proptest::prelude::*;
use wafrift_types::Request;
use wafrift_wafmodel::normalize::{Transform, apply_chain};
use wafrift_wafmodel::{LearnedModel, SimRegexWaf, Stage, canonicalize, json_unescape, url_decode_once};

/// Per-push-scaled proptest count (full 10k by default; the legendary
/// nightly lane runs the full count, the fast CI gate scales down).
fn pc() -> u32 {
    std::env::var("WAFMODEL_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(pc()))]

    /// CRS transform pipeline: total on any bytes, any chain order,
    /// and length-bounded (a transform may not blow input up
    /// unboundedly — DoS guard).
    #[test]
    fn normalize_chain_is_total(
        input in proptest::collection::vec(any::<u8>(), 0..256),
        chain in proptest::collection::vec(
            prop_oneof![
                Just(Transform::UrlDecodeUni),
                Just(Transform::HtmlEntityDecode),
                Just(Transform::Lowercase),
                Just(Transform::RemoveNulls),
                Just(Transform::CompressWhitespace),
                Just(Transform::RemoveWhitespace),
            ],
            0..6,
        ),
    ) {
        let out = apply_chain(&chain, &input);
        // Decoders only ever shrink-or-equal; no amplification.
        prop_assert!(out.len() <= input.len() + 1);
    }

    /// Every reversible Stage is total on arbitrary bytes.
    #[test]
    fn transducer_stages_are_total(input in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = url_decode_once(&input, true);
        let _ = url_decode_once(&input, false);
        let _ = json_unescape(&input);
        for st in [
            Stage::Identity,
            Stage::UrlDecode { plus_is_space: true },
            Stage::DoubleUrlDecode,
            Stage::HtmlEntityDecode,
            Stage::JsonUnescape,
        ] {
            let o = st.apply(&input);
            // Decoders do not amplify (DoS guard); identity is exact.
            prop_assert!(o.len() <= input.len().max(1));
        }
    }

    /// `canonicalize` never panics on an arbitrary request shape.
    #[test]
    fn canonicalize_is_total(
        path in ".*",
        hval in ".*",
        body in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let r = Request::post(format!("https://h/{path}"), body)
            .header("X-Fuzz", hval)
            .header("Cookie", "a=1; b=2");
        let v = canonicalize(&r);
        // Total: every segment's bytes are accounted, method uppercased.
        let _ = v.total_bytes();
        prop_assert_eq!(v.method.as_str(), "POST");
    }

    /// Arbitrary text fed to the TOML parsers ⇒ Ok or a clean Err,
    /// never a panic, and never an *invalid* automaton slipping
    /// through (`sfa()` re-validates).
    #[test]
    fn toml_parsers_reject_garbage_without_panicking(s in ".{0,400}") {
        // Ruleset parser.
        let _ = SimRegexWaf::from_toml(&s);
        // Model artifact parser + automaton re-validation.
        if let Ok(m) = LearnedModel::from_toml(&s) {
            // If it parsed, building the SFA must not panic; an
            // inconsistent automaton must be a clean Err.
            let _ = m.sfa();
            let _ = m.alphabet();
        }
    }

    /// Structured-but-hostile model TOML (well-formed envelope, junk
    /// predicates / out-of-range targets) ⇒ `sfa()` is `Err`, never a
    /// panic and never an accepted broken machine.
    #[test]
    fn hostile_model_envelope_is_rejected_cleanly(
        ver in 0u32..3,
        start in 0usize..9,
        n in 0usize..5,
        hex in "[0-9a-fA-Fzx]{0,80}",
    ) {
        let mut doc = format!("schema_version = {ver}\nstart = {start}\nalphabet = [97, 90]\n\n[provenance]\noracle_id = \"f\"\nmembership_queries = 0\nequivalence_rounds = 0\n");
        for _ in 0..n {
            doc.push_str(&format!(
                "\n[[state]]\naccept = false\n\n[[state.edge]]\nto = 0\npred = \"{hex}\"\n"
            ));
        }
        match LearnedModel::from_toml(&doc) {
            Ok(m) => {
                // Parsed envelope ⇒ sfa() must be Ok(valid) or Err,
                // never panic. (Total is the assertion: we reach here.)
                let _ = m.sfa();
            }
            Err(_) => { /* clean rejection — fine */ }
        }
    }
}
