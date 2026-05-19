//! Documented injection-structure snippets — each oracle must classify them as semantically valid.

mod common;

use common::{CANON_CMDI, CANON_PATH, CANON_SSRF, split_corpus};
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

#[test]
fn tp_cmdi_corpus_detected() {
    let oracle = CmdiOracle;
    let samples = split_corpus(include_str!("data/tp_cmdi.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus tp_cmdi.txt must contain at least one <<<SAMPLE>>> block"
    );
    for inj in &samples {
        assert!(
            oracle.is_semantically_valid(CANON_CMDI, inj),
            "CMDI missed true injection structure\n---\n{inj}\n---"
        );
    }
}

#[test]
fn tp_path_corpus_detected() {
    let oracle = PathOracle;
    let samples = split_corpus(include_str!("data/tp_path.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus tp_path.txt must contain at least one <<<SAMPLE>>> block"
    );
    for inj in &samples {
        assert!(
            oracle.is_semantically_valid(CANON_PATH, inj),
            "Path oracle missed true traversal structure\n---\n{inj}\n---"
        );
    }
}

#[test]
fn tp_ssrf_corpus_detected() {
    let oracle = SsrfOracle;
    let samples = split_corpus(include_str!("data/tp_ssrf.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus tp_ssrf.txt must contain at least one <<<SAMPLE>>> block"
    );
    for inj in &samples {
        assert!(
            oracle.is_semantically_valid(CANON_SSRF, inj),
            "SSRF oracle missed URL structure\n---\n{inj}\n---"
        );
    }
}
