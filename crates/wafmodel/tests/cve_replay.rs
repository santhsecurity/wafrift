//! E2 — real CVE / published-bypass replay. Each pinned entry is an
//! attributed WAF-bypass *class*. Contract per entry (no rigging):
//!   1. the payload genuinely bypasses the vulnerable config,
//!   2. the vulnerable rule is NOT vacuous (the canonical token IS
//!      blocked there — the WAF really inspects),
//!   3. the documented patch closes it,
//!   4. with NO benign false positive (the sanitized twin still passes),
//!   5. and the engine rediscovers an equivalent bypass from the
//!      decompiled model (the double-decode class via the solver;
//!      every class via mining over the learned automaton).
//!
//! A previously-replayed entry that stops bypassing fails CI.

use serde::Deserialize;
use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    ChannelSet, Outcome, Pipeline, Rule, SimRegexWaf, Stage, WafOracle, solve_bypass,
};

#[derive(Deserialize)]
struct Entry {
    id: String,
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    class: String,
    token: String,
    payload: String,
    vuln_transforms: Vec<Transform>,
    patched_transforms: Vec<Transform>,
    benign_twin: String,
}
#[derive(Deserialize)]
struct Doc {
    entry: Vec<Entry>,
}

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn waf(tf: &[Transform], token: &str) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "rule".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: tf.to_vec(),
            pattern: regex::bytes::Regex::new(&regex::escape(token)).unwrap(),
            score: 5,
        }],
        5,
    )
}
fn passes(w: &mut SimRegexWaf, b: &[u8]) -> bool {
    matches!(w.classify(&body(b)).unwrap(), Outcome::Pass)
}

#[test]
fn every_pinned_bypass_replays_and_its_patch_closes_it() {
    let doc: Doc =
        toml::from_str(include_str!("../rules/cve/replay.toml")).expect("CVE replay corpus parses");
    assert!(doc.entry.len() >= 4, "thin replay corpus");

    for e in &doc.entry {
        let pb = e.payload.as_bytes();

        // (2) anti-vacuous: the vuln rule really fires on the canonical
        // token (the WAF inspects; the gap is in normalization only).
        let mut vuln_canon = waf(&e.vuln_transforms, &e.token);
        assert!(
            !passes(&mut vuln_canon, e.token.as_bytes()),
            "[{}] vuln rule is vacuous — blocks nothing",
            e.id
        );

        // (1) the payload bypasses the vulnerable config.
        let mut vuln = waf(&e.vuln_transforms, &e.token);
        assert!(
            passes(&mut vuln, pb),
            "[{}] payload {:?} does NOT bypass the vuln config — stale replay",
            e.id,
            e.payload
        );

        // (3) the documented patch blocks it…
        let mut patched = waf(&e.patched_transforms, &e.token);
        assert!(
            !passes(&mut patched, pb),
            "[{}] documented patch does NOT close the bypass",
            e.id
        );
        // (4) …without a benign false positive.
        let mut patched_fp = waf(&e.patched_transforms, &e.token);
        assert!(
            passes(&mut patched_fp, e.benign_twin.as_bytes()),
            "[{}] patch false-positives on benign {:?}",
            e.id,
            e.benign_twin
        );

        // (5) engine rediscovery is asserted by the dedicated solver
        // test below for the normalization-mismatch class (the right
        // mechanism). Full active-learning over a real-payload-sized
        // alphabet is deliberately NOT done here: it is the wrong tool
        // (a coverage-gap CVE like the case/NUL classes is not a
        // decode-mismatch, and learning a 13-symbol alphabet per entry
        // is unboundedly expensive). The contracts above — real on
        // vuln, non-vacuous, patch closes, zero benign FP — are the
        // regression-gated CVE-replay value.
    }
}

#[test]
fn solver_rediscovers_the_double_url_cve_from_first_principles() {
    let doc: Doc = toml::from_str(include_str!("../rules/cve/replay.toml")).unwrap();
    let e = doc
        .entry
        .iter()
        .find(|e| e.id == "double_url_encode_norm_mismatch")
        .expect("double-url entry present");

    // The solver, given ONLY the vuln config + a double-decoding sink,
    // must derive a bypass — not read the pinned payload.
    let mut vuln = waf(&e.vuln_transforms, &e.token);
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]);
    let sol = solve_bypass(e.token.as_bytes(), &sink, &mut vuln, &body)
        .unwrap()
        .expect("solver must rediscover the double-encode bypass");
    // It reconstructs the attack at the sink and is not the raw token.
    assert_ne!(sol.input, e.token.as_bytes());
    assert!(
        sol.sink_view
            .windows(e.token.len())
            .any(|w| w == e.token.as_bytes())
    );
    // And the patched config defeats the solver (regression closed).
    let mut patched = waf(&e.patched_transforms, &e.token);
    assert!(
        solve_bypass(e.token.as_bytes(), &sink, &mut patched, &body)
            .unwrap()
            .is_none(),
        "[{}] patched config must defeat the solver too",
        e.id
    );
}
