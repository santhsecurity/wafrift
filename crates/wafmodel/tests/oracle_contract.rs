//! Truth contract for the WAF oracles.
//!
//! Ground-truth WAFs whose language we control, asserted to exact
//! Pass/Block outcomes with sanitized negative twins, plus proofs that
//! the *faithful CRS transforms actually fire* (a model that did not
//! decode would silently invent/hide bypasses).

use wafrift_types::Request;
use wafrift_wafmodel::{
    Channel, ChannelSet, Outcome, Rule, SimRegexWaf, Transform, WafOracle, oracle::FnOracle,
};

fn rule(id: &str, chans: ChannelSet, tf: &[Transform], pat: &str, score: u32) -> Rule {
    Rule {
        id: id.into(),
        channels: chans,
        transforms: tf.to_vec(),
        pattern: regex::bytes::Regex::new(pat).unwrap(),
        score,
    }
}

#[test]
fn channel_scoping_is_real_not_global() {
    // Rule inspects ONLY ArgValue.
    let waf = || {
        SimRegexWaf::new(
            vec![rule(
                "x",
                ChannelSet::none().with(Channel::ArgValue),
                &[Transform::Lowercase],
                "<script",
                5,
            )],
            5,
        )
    };

    let mut w = waf();
    assert_eq!(
        w.classify(&Request::get("https://t/p?q=<script>")).unwrap(),
        Outcome::Block,
        "payload in the inspected channel must block"
    );

    // Negative twin: identical bytes in a header (NOT in the rule's
    // channel mask) must PASS — channel scoping is the whole reason
    // delivery-shape evasion works and the model must honour it.
    let mut w = waf();
    let r = Request::get("https://t/p").header("X-Probe", "<script>");
    assert_eq!(w.classify(&r).unwrap(), Outcome::Pass);

    // Negative twin: benign value in the inspected channel passes.
    let mut w = waf();
    assert_eq!(
        w.classify(&Request::get("https://t/p?q=hello")).unwrap(),
        Outcome::Pass
    );
}

#[test]
fn faithful_transforms_actually_fire() {
    // UrlDecodeUni MUST run before matching: a %-encoded script tag is
    // caught exactly because the modelled WAF decodes like CRS.
    let mut decoding = SimRegexWaf::new(
        vec![rule(
            "x",
            ChannelSet::all(),
            &[Transform::UrlDecodeUni, Transform::Lowercase],
            "<script",
            5,
        )],
        5,
    );
    assert_eq!(
        decoding
            .classify(&Request::get("https://t/p?q=%3Cscript%3E"))
            .unwrap(),
        Outcome::Block,
        "UrlDecodeUni must decode %3Cscript before matching"
    );

    // Negative twin: the SAME rule WITHOUT the decode transform must
    // NOT fire on the encoded form (proves the block above came from
    // the transform, not an over-broad pattern).
    let mut nondecoding = SimRegexWaf::new(
        vec![rule(
            "x",
            ChannelSet::all(),
            &[Transform::Lowercase],
            "<script",
            5,
        )],
        5,
    );
    assert_eq!(
        nondecoding
            .classify(&Request::get("https://t/p?q=%3Cscript%3E"))
            .unwrap(),
        Outcome::Pass
    );

    // Case-sensitivity twin: `<SCRIPT>` blocks only with Lowercase.
    let mut cased = SimRegexWaf::new(vec![rule("x", ChannelSet::all(), &[], "<script", 5)], 5);
    assert_eq!(
        cased
            .classify(&Request::get("https://t/p?q=<SCRIPT>"))
            .unwrap(),
        Outcome::Pass,
        "no Lowercase ⇒ uppercase tag slips the lowercase pattern"
    );
}

#[test]
fn anomaly_scoring_sums_to_threshold() {
    // Two score-3 rules; threshold 5 ⇒ one alone passes, both block.
    let r1 = rule("a", ChannelSet::all(), &[], "aaa", 3);
    let r2 = rule("b", ChannelSet::all(), &[], "bbb", 3);
    let mut w = SimRegexWaf::new(vec![r1.clone(), r2.clone()], 5);
    assert_eq!(
        w.classify(&Request::get("https://t/p?q=aaa")).unwrap(),
        Outcome::Pass,
        "score 3 < threshold 5"
    );
    let mut w = SimRegexWaf::new(vec![r1, r2], 5);
    assert_eq!(
        w.classify(&Request::get("https://t/p?q=aaa-bbb")).unwrap(),
        Outcome::Block,
        "3+3 ≥ 5"
    );
}

#[test]
fn fn_oracle_counts_every_query_exactly() {
    let mut calls = 0u64;
    let mut o = FnOracle::new(|r: &Request| {
        calls += 1;
        Ok(if r.url().contains("evil") {
            Outcome::Block
        } else {
            Outcome::Pass
        })
    });
    assert_eq!(
        o.classify(&Request::get("https://t/ok")).unwrap(),
        Outcome::Pass
    );
    assert_eq!(
        o.classify(&Request::get("https://t/evil")).unwrap(),
        Outcome::Block
    );
    assert_eq!(o.queries(), 2, "every classify is one counted query");
}

#[test]
fn shipped_crs_ruleset_loads_and_classifies_real_attacks() {
    let src = include_str!("../rules/crs/core.toml");
    let mut waf = SimRegexWaf::from_toml(src).expect("Tier-B CRS ruleset must parse");
    assert!(waf.rule_count() >= 7, "all core rules loaded");
    assert_eq!(waf.threshold(), 5);

    // Real attacks block.
    for atk in [
        "https://t/p?q=<script>alert(1)</script>",
        "https://t/p?q=<svg onload=alert(1)>",
        "https://t/p?u=javascript:alert(1)",
        "https://t/p?id=1 UNION SELECT password FROM users",
        "https://t/p?id=1' or 1=1--",
        "https://t/p?id=1; SELECT sleep(5)",
    ] {
        assert_eq!(
            waf.classify(&Request::get(atk)).unwrap(),
            Outcome::Block,
            "CRS must block: {atk}"
        );
    }

    // Sanitized negative twins — benign, must pass (no FP).
    for ok in [
        "https://t/p?q=hello world",
        "https://t/p?name=O'Brien",
        "https://t/p?desc=I love javascript programming",
        "https://t/search?q=union square farmers market",
    ] {
        assert_eq!(
            waf.classify(&Request::get(ok)).unwrap(),
            Outcome::Pass,
            "benign must pass: {ok}"
        );
    }
}
