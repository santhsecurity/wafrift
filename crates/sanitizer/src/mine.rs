//! Decompile a client sanitizer and mine the inputs that survive it.
//!
//! This is the payoff of the crate: it drives the **same** L*/SFA decompiler
//! that learns a server WAF over a [`SanitizerOracle`],
//! then intersects the learned "survives-executable" language with an XSS attack
//! grammar to mine concrete bypass candidates — inputs that stay executable
//! after this exact sanitizer config runs.
//!
//! Because the oracle is a pure in-process function (no network), learning is
//! free: unbounded membership L* with a bounded equivalence search always
//! terminates. Every mined candidate is then **re-verified against the model**
//! (a CEGIS-style soundness gate): a string that does not genuinely survive is
//! dropped, never reported. Surviving candidates are flagged for live scald DOM
//! confirmation — the model proposes, the browser disposes.

use wafrift_types::Request;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, EquivalenceOracle, Result as WafResult, Sfa, WafOracle,
    attack_grammar, l_star, mine_bypasses,
};

use crate::extract::SanitizerModel;
use crate::model::SanitizerOracle;

/// One mined sanitizer bypass: a payload that survives the modelled sanitizer
/// with an executable vector intact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SanitizerBypass {
    /// The surviving payload (re-verified against the model).
    pub payload: String,
    /// Always `true` here — the soundness gate drops non-survivors. Emitted
    /// explicitly so a consumer never has to assume.
    pub survives_executable: bool,
    /// Which executable vector class survived (`script` / `event_handler`).
    pub vector: &'static str,
}

/// The result of decompiling and mining a sanitizer.
#[derive(Debug, Clone)]
pub struct MineResult {
    /// The extracted model that was decompiled.
    pub model: SanitizerModel,
    /// Re-verified bypass candidates, deduplicated.
    pub bypasses: Vec<SanitizerBypass>,
    /// Membership queries the learner spent against the (free) model oracle.
    pub membership_queries: u64,
    /// Equivalence rounds.
    pub equivalence_rounds: u64,
    /// Candidates mined before the soundness re-verification dropped non-survivors.
    pub mined_before_verify: usize,
}

/// The XSS learning alphabet — every byte that appears in a needle MUST be
/// distinguished, or the KMP abstraction silently makes that needle unmatchable
/// (the exact invariant `model-evade` documents). `b'A'` is the catch-all.
fn xss_alphabet() -> Alphabet {
    Alphabet::new(
        vec![
            b'<', b'>', b'/', b'"', b'\'', b' ', b'=', b'(', b')', b's', b'c', b'r', b'i', b'p',
            b't', b'o', b'n', b'l', b'a', b'e', b'v', b'g', b'm', b'd',
        ],
        b'A',
    )
}

/// The executable XSS needles the grammar mines for.
fn xss_needles() -> Vec<&'static [u8]> {
    vec![
        b"<script" as &[u8],
        b"onerror=",
        b"onload=",
        b"<svg",
        b"<img",
        b"alert(",
    ]
}

/// Embedded Tier-B canonical executable XSS vectors.
const XSS_VECTORS_TOML: &str = include_str!("../rules/xss_vectors.toml");

/// Parse the Tier-B canonical-vector seed list, failing closed on malformed data
/// or an empty set.
pub fn vectors_from_toml(src: &str) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        vector: Vec<String>,
    }
    let parsed: File = toml::from_str(src).map_err(|e| format!("parsing xss vectors: {e}"))?;
    if parsed.vector.is_empty() {
        return Err("xss vector seed list is empty".to_string());
    }
    Ok(parsed.vector)
}

/// The embedded canonical executable XSS vectors used to seed mining.
#[must_use]
pub fn canonical_vectors() -> Vec<String> {
    vectors_from_toml(XSS_VECTORS_TOML)
        .expect("embedded xss vectors must be valid (asserted in tests)")
}

/// Classify which executable vector a surviving payload carries (for the report).
fn vector_class(payload: &str) -> &'static str {
    if payload.to_ascii_lowercase().contains("<script") {
        "script"
    } else {
        "event_handler"
    }
}

/// Per-equivalence-round membership-query budget. The membership predicate is a
/// pure in-process function (cost is CPU, not HTTP round-trips), but the BFS
/// frontier over the 24-symbol XSS alphabet reaches ~1M words at `eq_max_len=6`,
/// and a *strict* (no-bypass) model must reject every one of them every round —
/// an unbounded sweep that, combined with per-query regex compilation, hung the
/// decompiler for minutes. Capping per-round queries bounds the sweep to a fixed
/// budget; the obvious bypasses are guaranteed by the Tier-B canonical-vector
/// seed regardless, so the SFA search staying bounded never costs a real
/// survivor — it only trims deep, speculative variants.
const EQ_QUERY_BUDGET: u64 = 40_000;

/// Maximum number of L* equivalence ROUNDS. [`EQ_QUERY_BUDGET`] bounds work
/// *within* a round, but L* requests one round per refinement and a language with
/// a large minimal automaton (a complex extracted strip regex can produce one)
/// can demand many — so without this cap total work is `rounds × budget`, i.e.
/// unbounded. That let a single `decompile_and_mine` peg several cores for
/// minutes on certain configs. After the cap the learner stops refining and
/// proceeds with its current hypothesis; the Tier-B canonical-vector seed still
/// guarantees the obvious bypasses, so a capped (less-refined) SFA only trims
/// deep speculative variants — soundness is untouched (every survivor is still
/// re-verified). Total membership work is therefore bounded by
/// `MAX_EQ_ROUNDS × EQ_QUERY_BUDGET` plus table-filling.
const MAX_EQ_ROUNDS: usize = 12;

/// Bounds the number of L* equivalence rounds by declaring convergence once the
/// round budget is spent (see [`MAX_EQ_ROUNDS`]). Delegates each live round to
/// the inner [`BoundedExhaustiveEq`].
struct RoundCappedEq {
    inner: BoundedExhaustiveEq,
    rounds_left: usize,
}

impl EquivalenceOracle for RoundCappedEq {
    fn find_counterexample(
        &mut self,
        hyp: &Sfa,
        alpha: &Alphabet,
        mq: &mut dyn FnMut(&[usize]) -> WafResult<bool>,
    ) -> WafResult<Option<Vec<usize>>> {
        if self.rounds_left == 0 {
            return Ok(None); // budget spent → declare convergence, stop refining
        }
        self.rounds_left -= 1;
        self.inner.find_counterexample(hyp, alpha, mq)
    }
}

/// Decompile `model` and mine up to `max_mine` bypass candidates of length up to
/// `max_len`. `eq_max_len` bounds the equivalence-oracle counterexample search
/// (deeper = more faithful model, more queries).
///
/// Pure and deterministic: same model in, same bypasses out.
#[must_use]
pub fn decompile_and_mine(
    model: SanitizerModel,
    max_mine: usize,
    max_len: usize,
    eq_max_len: usize,
) -> MineResult {
    let alpha = xss_alphabet();
    let needles = xss_needles();

    let mut oracle = SanitizerOracle::new(model.clone());
    let build = |bytes: &[u8]| Request::post("https://sanitizer.local/", bytes.to_vec());
    let mut eq = RoundCappedEq {
        inner: BoundedExhaustiveEq {
            max_len: eq_max_len,
            max_queries: Some(EQ_QUERY_BUDGET),
        },
        rounds_left: MAX_EQ_ROUNDS,
    };

    // The model oracle is a pure function, so unbounded-membership L* with a
    // bounded equivalence search always terminates. A learning error is treated
    // as "no model" — we still fall through to zero bypasses, never panic.
    let report = l_star(&mut oracle, &build, &alpha, &mut eq);
    let (sfa, membership_queries, equivalence_rounds) = match report {
        Ok(r) => (r.sfa, r.membership_queries, r.equivalence_rounds),
        Err(_) => {
            return MineResult {
                model,
                bypasses: Vec::new(),
                membership_queries: oracle.queries(),
                equivalence_rounds: 0,
                mined_before_verify: 0,
            };
        }
    };

    let grammar = attack_grammar(&alpha, &needles);
    let mined = mine_bypasses(&sfa, &grammar, max_mine, max_len);
    let mined_before_verify = mined.len();

    // Candidate pool = the Tier-B canonical executable vectors (guaranteeing the
    // obvious bypasses are always tested) PLUS the L*/SFA-deduced variants the
    // learned boundary revealed. Every candidate then passes the soundness gate:
    // re-verified against the concrete model, only genuine survivors kept, deduped.
    let mut seen = std::collections::HashSet::new();
    let mut bypasses = Vec::new();
    let candidates = canonical_vectors().into_iter().chain(
        mined
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned()),
    );
    for payload in candidates {
        if model.survives_executable(&payload) && seen.insert(payload.clone()) {
            let vector = vector_class(&payload);
            bypasses.push(SanitizerBypass {
                payload,
                survives_executable: true,
                vector,
            });
        }
    }

    MineResult {
        model,
        bypasses,
        membership_queries,
        equivalence_rounds,
        mined_before_verify,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{SanitizerKind, SanitizerModel};

    fn model(forbidden: &[&str], allowed: Option<&[&str]>, strip_handlers: bool) -> SanitizerModel {
        SanitizerModel {
            kind: SanitizerKind::DomPurify,
            allowed_tags: allowed.map(|a| a.iter().map(|s| s.to_string()).collect()),
            forbidden_tags: forbidden.iter().map(|s| s.to_string()).collect(),
            forbidden_attrs: Vec::new(),
            strips_event_handlers: strip_handlers,
            blocked_schemes: Vec::new(),
            strip_patterns: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn every_reported_bypass_genuinely_survives_the_model() {
        // The core soundness contract: whatever decompile_and_mine reports must
        // actually survive the model — the re-verification gate guarantees it.
        let m = model(&["script"], None, false);
        let result = decompile_and_mine(m.clone(), 64, 16, 5);
        for b in &result.bypasses {
            assert!(b.survives_executable);
            assert!(
                m.survives_executable(&b.payload),
                "reported bypass does not survive: {:?}",
                b.payload
            );
        }
    }

    #[test]
    fn a_handler_leaking_config_yields_at_least_one_bypass() {
        // forbid <script> but do NOT strip handlers → svg/img+on* must be mined.
        let m = model(&["script"], None, false);
        let result = decompile_and_mine(m, 128, 20, 6);
        assert!(
            !result.bypasses.is_empty(),
            "a handler-leaking sanitizer must yield a bypass; mined={}",
            result.mined_before_verify
        );
        assert!(
            result.membership_queries > 0,
            "the learner must have queried the oracle"
        );
    }

    #[test]
    fn a_strict_config_yields_no_bypass() {
        // Forbid every dangerous tag AND strip handlers → the soundness gate must
        // leave zero reported bypasses (anti-rig: no fabricated survivors).
        let m = model(
            &[
                "script", "svg", "img", "iframe", "math", "a", "object", "embed",
            ],
            Some(&["b", "i", "em", "p"]),
            true,
        );
        let result = decompile_and_mine(m, 128, 20, 6);
        assert!(
            result.bypasses.is_empty(),
            "strict config must admit no bypass, got {:?}",
            result.bypasses
        );
    }

    #[test]
    fn strict_model_with_a_strip_pattern_terminates_fast_and_yields_no_bypass() {
        // Regression for the multi-minute hang: a strict (no-bypass) model that
        // ALSO carries an extracted regex `strip_pattern` once recompiled that
        // regex on every one of ~1M membership queries per EQ round, across
        // multiple rounds. The fix is two-fold — the oracle compiles strip
        // patterns once, and the EQ round is query-bounded (`EQ_QUERY_BUDGET`).
        // This is the exact CLI default-parameter case that hung the e2e.
        let mut m = model(
            &[
                "script", "svg", "img", "iframe", "math", "a", "object", "embed",
            ],
            Some(&["b", "i", "em", "p"]),
            true,
        );
        // The on-handler strip regex recovered from the strict fixture.
        m.strip_patterns = vec![r#"\son\w+=("[^"]*"|'[^']*'|[^\s>]*)"#.to_string()];

        let start = std::time::Instant::now();
        let result = decompile_and_mine(m, 128, 24, 6); // the CLI defaults
        let elapsed = start.elapsed();

        assert!(
            result.bypasses.is_empty(),
            "strict model must admit no bypass, got {:?}",
            result.bypasses
        );
        // Anti-hang guard: generous enough never to flake on a loaded box, tight
        // enough to catch the 15-minute regression that motivated this test.
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "strict decompile must be bounded; took {elapsed:?}"
        );
        // The per-round cap must actually bound the membership sweep.
        assert!(
            result.membership_queries <= 20 * EQ_QUERY_BUDGET,
            "membership queries must be bounded by the EQ budget; got {}",
            result.membership_queries
        );
    }

    #[test]
    fn mining_is_deterministic() {
        let m = model(&["script"], None, false);
        let a = decompile_and_mine(m.clone(), 64, 16, 5);
        let b = decompile_and_mine(m, 64, 16, 5);
        assert_eq!(a.bypasses, b.bypasses);
    }

    #[test]
    fn reported_bypasses_are_deduplicated() {
        let m = model(&["script"], None, false);
        let result = decompile_and_mine(m, 256, 24, 6);
        let mut payloads: Vec<&str> = result.bypasses.iter().map(|b| b.payload.as_str()).collect();
        let n = payloads.len();
        payloads.sort_unstable();
        payloads.dedup();
        assert_eq!(payloads.len(), n, "duplicate bypasses reported");
    }

    #[test]
    fn canonical_vectors_load_and_are_executable() {
        let vs = canonical_vectors();
        assert!(vs.len() >= 10, "ship a real vector corpus");
        // Anti-rig: every seeded vector must itself be executable, or seeding it
        // would pollute the candidate pool with inert payloads.
        for v in &vs {
            assert!(
                crate::model::is_executable_html(v),
                "seed vector is not executable: {v:?}"
            );
        }
    }

    #[test]
    fn vectors_loader_fails_closed_on_empty() {
        assert!(vectors_from_toml("").is_err());
        assert!(vectors_from_toml("# just a comment\n").is_err());
    }

    #[test]
    fn vector_class_is_labelled() {
        let m = model(&["script"], None, false);
        let result = decompile_and_mine(m, 128, 20, 6);
        for b in &result.bypasses {
            assert!(
                b.vector == "script" || b.vector == "event_handler",
                "unexpected vector label {:?}",
                b.vector
            );
        }
    }
}
