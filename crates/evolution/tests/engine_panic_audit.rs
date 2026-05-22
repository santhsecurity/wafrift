//! Malformed / stale chromosome feedback must return [`Err`], never panic.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wafrift_evolution::evolution::{Chromosome, EvolutionEngine};
use wafrift_evolution::types::{EvolutionError, OracleVerdict};

#[cfg(test)]
mod helpers {
    use super::*;

    pub fn fresh_engine() -> EvolutionEngine {
        EvolutionEngine::new(4)
    }

    pub fn malformed_chromosome() -> Chromosome {
        // Unknown gene keys — must not crash the engine on feedback rejection.
        Chromosome::new(vec![
            ("not_a_real_gene".into(), "\u{0000}\u{00ff}".into()),
            ("".into(), "".into()),
        ])
    }
}

use helpers::{fresh_engine, malformed_chromosome};

#[test]
fn out_of_bounds_feedback_returns_invalid_chromosome_index() {
    let mut engine = fresh_engine();
    let result = catch_unwind(AssertUnwindSafe(|| engine.record_feedback(999, true)));
    assert!(result.is_ok(), "record_feedback must not panic");
    let err = result.unwrap().expect_err("stale index must error");
    assert!(
        matches!(err, EvolutionError::InvalidChromosomeIndex(999)),
        "got {err:?}"
    );
}

#[test]
fn submit_batch_unknown_id_returns_err_not_panic() {
    let mut engine = fresh_engine();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        engine.submit_batch(vec![(42, OracleVerdict::from_bool(true))])
    }));
    assert!(outcome.is_ok(), "submit_batch must not panic");
    let err = outcome.unwrap().expect_err("unknown eval id");
    assert!(
        matches!(err, EvolutionError::InvalidChromosomeIndex(42)),
        "got {err:?}"
    );
}

#[test]
fn malformed_chromosome_feedback_after_candidate_still_errors_cleanly() {
    let mut engine = fresh_engine();
    let Some((idx, _chrom)) = engine.next_candidate() else {
        panic!("engine must yield at least one candidate");
    };
    // Replace in-flight entry with a malformed chromosome via submit path:
    // record_feedback for a *different* index must still Err, not panic.
    let bad_idx = idx.wrapping_add(10_000);
    let result = catch_unwind(AssertUnwindSafe(|| engine.record_feedback(bad_idx, true)));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());

    // Valid index with verdict still works (uses the real in-flight chromosome).
    let ok = catch_unwind(AssertUnwindSafe(|| {
        engine.record_feedback(idx, true)
    }));
    assert!(ok.is_ok());
    assert!(ok.unwrap().is_ok());

    let _malformed = malformed_chromosome();
}
