//! Property tests for the client-sanitizer decompiler — public-API surface.
//!
//! Three fronts, thousands of cases each:
//! 1. **Parser robustness** — the source-map / VLQ / extractor parsers consume a
//!    target's untrusted JS and must never panic on any input, only return
//!    `Ok`/`Err`.
//! 2. **Codec faithfulness** — `encode_vlq` round-trips through the public
//!    mappings decoder.
//! 3. **Mining soundness** — every bypass `decompile_and_mine` reports genuinely
//!    survives the model (the CEGIS gate), the run is bounded (no hang), and it
//!    is deterministic.

use proptest::prelude::*;
use wafrift_sanitizer::extract::{SanitizerModel, extract_sanitizer};
use wafrift_sanitizer::mine::{canonical_vectors, decompile_and_mine};
use wafrift_sanitizer::sourcemap::{SourceMap, encode_vlq};

// ── 1. Parser robustness: never panic on hostile input ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// `SourceMap::parse` returns Ok or Err for ANY input — never panics.
    #[test]
    fn prop_parse_never_panics(s in ".{0,400}") {
        let _ = SourceMap::parse(&s);
    }

    /// A v3 map with an arbitrary `mappings` string decodes or errors — never
    /// panics (fuzzes the Base64-VLQ decoder, including overflow/truncation).
    #[test]
    fn prop_decode_mappings_never_panics(mappings in "[A-Za-z0-9+/,;]{0,200}") {
        let json = format!(
            r#"{{"version":3,"sources":["a.js"],"names":[],"mappings":"{mappings}"}}"#
        );
        if let Ok(map) = SourceMap::parse(&json) {
            let _ = map.decode_mappings();
        }
    }

    /// Arbitrary bytes-as-mappings (including non-Base64) never panic the decoder.
    #[test]
    fn prop_decode_arbitrary_mappings_never_panics(mappings in ".{0,120}") {
        // Escape quotes/backslashes so the JSON stays well-formed.
        let escaped = mappings.replace('\\', "\\\\").replace('"', "\\\"");
        let json = format!(
            r#"{{"version":3,"sources":["a.js"],"names":[],"mappings":"{escaped}"}}"#
        );
        if let Ok(map) = SourceMap::parse(&json) {
            let _ = map.decode_mappings();
        }
    }

    /// `extract_sanitizer` is total over arbitrary JS source — never panics.
    #[test]
    fn prop_extract_never_panics(src in ".{0,400}") {
        let _ = extract_sanitizer(&src);
    }
}

// ── 2. Codec faithfulness: encode → decode round-trip via the public API ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// A single-field segment encodes a generated-column delta; decoding the
    /// one-line mapping recovers exactly that column. Differential check of the
    /// VLQ encoder against the decoder through the real parser.
    #[test]
    fn prop_vlq_single_field_roundtrips(col in 0i64..(1 << 26)) {
        let mappings = encode_vlq(col);
        let json = format!(
            r#"{{"version":3,"sources":["a.js"],"names":[],"mappings":"{mappings}"}}"#
        );
        let map = SourceMap::parse(&json).expect("well-formed map parses");
        let lines = map.decode_mappings().expect("a single 1-field segment decodes");
        prop_assert_eq!(lines.len(), 1);
        prop_assert_eq!(lines[0].len(), 1);
        prop_assert_eq!(lines[0][0].generated_column, col);
    }
}

// ── 3. Mining soundness, boundedness, determinism over random models ────────

/// A vocabulary of tags the random models draw their forbid/allow lists from.
const TAGS: &[&str] = &["script", "svg", "img", "iframe", "math", "a", "b", "i", "em", "p"];
const SCHEMES: &[&str] = &["javascript", "data", "vbscript"];

prop_compose! {
    /// A random but structurally-valid sanitizer model.
    fn arb_model()(
        forbidden in proptest::collection::vec(0usize..TAGS.len(), 0..TAGS.len()),
        allow_some in any::<bool>(),
        allowed in proptest::collection::vec(0usize..TAGS.len(), 0..TAGS.len()),
        strips_handlers in any::<bool>(),
        schemes in proptest::collection::vec(0usize..SCHEMES.len(), 0..SCHEMES.len()),
        with_strip in any::<bool>(),
    ) -> SanitizerModel {
        let mut m = SanitizerModel::default();
        m.forbidden_tags = forbidden.into_iter().map(|i| TAGS[i].to_string()).collect();
        m.allowed_tags = allow_some.then(|| allowed.into_iter().map(|i| TAGS[i].to_string()).collect());
        m.strips_event_handlers = strips_handlers;
        m.blocked_schemes = schemes.into_iter().map(|i| SCHEMES[i].to_string()).collect();
        if with_strip {
            // The canonical on-handler strip regex — exercises the precompiled
            // hot path that once caused the per-query-recompile hang.
            m.strip_patterns = vec![r#"\son\w+=("[^"]*"|'[^']*'|[^\s>]*)"#.to_string()];
        }
        m
    }
}

proptest! {
    // Mining runs the L* learner (the expensive path). The MAX_EQ_ROUNDS round
    // cap bounds each mine() to ~1.2M membership queries, so even pathological
    // models finish fast — but to keep the SUITE quick the case count is modest
    // and the depth small. The cheap codec / parser properties above carry the
    // high-volume load; these assert the expensive invariants over ~100 models.
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// SOUNDNESS + BOUNDEDNESS in one mine() call per case: every reported bypass
    /// genuinely survives the model (the CEGIS gate never emits a sanitized
    /// payload) AND the membership-query count is bounded by the round cap — no
    /// model can drive the unbounded sweep that once pegged the decompiler.
    #[test]
    fn prop_mining_is_sound_and_bounded(model in arb_model()) {
        let result = decompile_and_mine(model.clone(), 40, 12, 3);
        for b in &result.bypasses {
            prop_assert!(b.survives_executable);
            prop_assert!(
                model.survives_executable(&b.payload),
                "reported bypass does not survive the model: {:?}", b.payload
            );
        }
        // Bounded by MAX_EQ_ROUNDS × EQ_QUERY_BUDGET + table-filling slack; the
        // absolute ceiling proves boundedness independent of the exact budget.
        prop_assert!(
            result.membership_queries <= 1_000_000,
            "membership queries exceeded the round-cap bound: {}", result.membership_queries
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// DETERMINISM: same model in, same bypasses out (two mine() calls per case).
    #[test]
    fn prop_mining_is_deterministic(model in arb_model()) {
        let a = decompile_and_mine(model.clone(), 40, 12, 3);
        let b = decompile_and_mine(model, 40, 12, 3);
        prop_assert_eq!(a.bypasses, b.bypasses);
    }

    /// A model that forbids every dangerous tag, strips handlers, blocks the
    /// dangerous schemes AND allowlists only inert tags admits NO bypass — the
    /// strict-model anti-rig at the CLI defaults (the exact hang-regression shape).
    #[test]
    fn prop_maximally_strict_model_admits_no_bypass(
        inert in proptest::collection::vec(prop::sample::select(vec!["b", "i", "em", "p"]), 1..4),
    ) {
        let mut m = SanitizerModel::default();
        m.forbidden_tags = ["script", "svg", "img", "iframe", "math", "a", "object", "embed"]
            .iter().map(|s| s.to_string()).collect();
        m.allowed_tags = Some(inert.into_iter().map(String::from).collect());
        m.strips_event_handlers = true;
        m.blocked_schemes = vec!["javascript".into(), "data".into()];
        m.strip_patterns = vec![r#"\son\w+=("[^"]*"|'[^']*'|[^\s>]*)"#.to_string()];
        let result = decompile_and_mine(m, 64, 20, 5);
        prop_assert!(result.bypasses.is_empty(), "strict model leaked: {:?}", result.bypasses);
    }
}

/// Anti-rig: every seeded canonical vector must itself be executable, or seeding
/// it would pollute the candidate pool with inert payloads.
#[test]
fn canonical_vectors_are_all_executable() {
    let vs = canonical_vectors();
    assert!(vs.len() >= 10, "ship a real vector corpus, got {}", vs.len());
    for v in &vs {
        assert!(
            wafrift_sanitizer::model::is_executable_html(v),
            "seed vector is not executable: {v:?}"
        );
    }
}
