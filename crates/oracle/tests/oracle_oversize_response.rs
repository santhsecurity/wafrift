//! Very large UTF-8 bodies must finish within a fixed wall-clock budget without blowing heap limits.

use std::time::{Duration, Instant};

use wafrift_oracle::cmdi::CmdiOracle;
use wafrift_oracle::path::PathOracle;
use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

/// One hundred megabytes of benign filler (ASCII — valid UTF-8, no injection structure).
const HUNDRED_MB: usize = 100 * 1024 * 1024;

#[test]
fn hundred_mb_body_finishes_within_budget() {
    let filler = "z".repeat(HUNDRED_MB);
    let budget = Duration::from_secs(180);

    let cmdi = CmdiOracle;
    let path = PathOracle;
    let ssrf = SsrfOracle;

    let canon_cmdi = "; cat /etc/passwd";
    let canon_path = "../../../etc/passwd";
    let canon_ssrf = "http://127.0.0.1/internal";

    let start = Instant::now();

    let r_cmdi = cmdi.is_semantically_valid(canon_cmdi, &filler);
    let r_cmdi_2 = cmdi.is_semantically_valid(canon_cmdi, &filler);
    assert_eq!(
        r_cmdi, r_cmdi_2,
        "Fix: CMDI oracle must be deterministic on identical oversize input"
    );

    let r_path = path.is_semantically_valid(canon_path, &filler);
    let r_path_2 = path.is_semantically_valid(canon_path, &filler);
    assert_eq!(
        r_path, r_path_2,
        "Fix: Path oracle must be deterministic on identical oversize input"
    );

    let r_ssrf = ssrf.is_semantically_valid(canon_ssrf, &filler);
    let r_ssrf_2 = ssrf.is_semantically_valid(canon_ssrf, &filler);
    assert_eq!(
        r_ssrf, r_ssrf_2,
        "Fix: SSRF oracle must be deterministic on identical oversize input"
    );

    let elapsed = start.elapsed();
    assert!(
        elapsed < budget,
        "Fix: oversize oracle scan took {elapsed:?} (budget {budget:?}). Reduce allocations or tighten scans."
    );

    assert!(
        !r_cmdi && !r_path && !r_ssrf,
        "Benign filler must not validate as injection (got cmdi={r_cmdi} path={r_path} ssrf={r_ssrf})"
    );
}
