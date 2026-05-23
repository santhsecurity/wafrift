//! Regression test: the auth-bypass probe count is documented in
//! THREE places — README, `wafrift bypass-probe --help`, and the
//! `bypass_probe.rs` module docstring. All three say "230 auth-bypass
//! header probes". If a contributor adds or removes a probe and
//! forgets to update the docs, the README + help-text claim becomes
//! a lie. This test is the single source of truth — it asserts the
//! actual count and fails with a "you also need to update the docs"
//! message so drift is caught at PR time.

use wafrift_encoding::auth_bypass::auth_bypass_probes;

const DOCUMENTED_COUNT: usize = 230;

#[test]
fn auth_bypass_probe_count_matches_documented_value() {
    let actual = auth_bypass_probes("/admin").len();
    assert_eq!(
        actual, DOCUMENTED_COUNT,
        "auth_bypass_probes returned {actual} probes; docs say {DOCUMENTED_COUNT}.\n\
         If the probe set changed intentionally, also update:\n  \
         - README.md (search for `230 auth-bypass`)\n  \
         - crates/cli/src/main.rs subcommand description for bypass-probe\n  \
         - crates/cli/src/bypass_probe.rs module docstring"
    );
}

#[test]
fn auth_bypass_probe_count_is_stable_across_paths() {
    // The probe count must not depend on the path argument — every
    // call returns the same fixed set, parameterised only on the
    // path being injected. A regression where path-content changed
    // the count would mean the documented number became per-call
    // instead of fixed.
    let counts = ["/admin", "/api/v1/users", "/", "/.env"]
        .iter()
        .map(|p| auth_bypass_probes(p).len())
        .collect::<Vec<_>>();
    assert!(
        counts.iter().all(|&c| c == DOCUMENTED_COUNT),
        "probe count varies by path: {counts:?} (each must be {DOCUMENTED_COUNT})"
    );
}
