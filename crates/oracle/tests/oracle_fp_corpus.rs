//! Benign (non-injection) canned bodies — oracles must not accept these as semantically valid exploits.

mod common;

use common::{split_corpus, CANON_CMDI, CANON_PATH, CANON_SSRF};
use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

#[test]
fn fp_cmdi_corpus_has_no_false_positives() {
    let oracle = CmdiOracle;
    let samples = split_corpus(include_str!("data/fp_cmdi.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus fp_cmdi.txt must contain at least one <<<SAMPLE>>> block"
    );
    for body in &samples {
        assert!(
            !oracle.is_semantically_valid(CANON_CMDI, body),
            "CMDI false positive on benign body (expected injection semantics lost)\n---\n{body}\n---"
        );
    }
}

#[test]
fn fp_path_corpus_has_no_false_positives() {
    let oracle = PathOracle;
    let samples = split_corpus(include_str!("data/fp_path.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus fp_path.txt must contain at least one <<<SAMPLE>>> block"
    );
    for body in &samples {
        assert!(
            !oracle.is_semantically_valid(CANON_PATH, body),
            "Path traversal false positive on benign body\n---\n{body}\n---"
        );
    }
}

#[test]
fn fp_ssrf_corpus_has_no_false_positives() {
    let oracle = SsrfOracle;
    let samples = split_corpus(include_str!("data/fp_ssrf.txt"));
    assert!(
        !samples.is_empty(),
        "Fix: vendored corpus fp_ssrf.txt must contain at least one <<<SAMPLE>>> block"
    );
    for body in &samples {
        assert!(
            !oracle.is_semantically_valid(CANON_SSRF, body),
            "SSRF false positive on benign body\n---\n{body}\n---"
        );
    }
}
