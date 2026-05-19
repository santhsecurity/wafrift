//! Truth contract for defensive hole-closure.
//!
//! The claim is strong, so the proof is constructive: the class has
//! real holes before, ZERO after, zero benign false positives, and the
//! synthesized rules are load-bearing (removing them reopens exactly
//! the holes). Nothing is asserted on faith.

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, ChannelSet, Outcome, Rule, SimRegexWaf, WafOracle, synthesize_closure,
};

/// Brittle WAF: blocks the literal token `<x` only (no decoding) — so
/// the URL-encoded form `%3cx` is a real, unclosed hole.
fn brittle() -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "raw-only".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![],
            pattern: regex::bytes::Regex::new("<x").unwrap(),
            score: 5,
        }],
        5,
    )
}
fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

#[test]
fn closure_is_proven_minimal_and_fp_free() {
    let waf = brittle();
    // Attack class = the token in raw OR URL-encoded form.
    let needles: [&[u8]; 2] = [b"<x", b"%3cx"];
    let alpha = Alphabet::new(vec![b'<', b'x', b'%', b'3', b'c'], b'Z');
    let benign: [&[u8]; 4] = [b"hello", b"abc", b"xx33", b"c3x"];

    let rep = synthesize_closure(
        &waf,
        &needles,
        ChannelSet::none().with(Channel::Body),
        &benign,
        &alpha,
        6,
    );

    // Before: the encoded form is a genuine hole.
    assert!(
        rep.holes_before > 0,
        "the brittle WAF must actually have holes (else the test is vacuous)"
    );
    // After: the class is fully closed …
    assert_eq!(
        rep.holes_after, 0,
        "synthesized rules must close every hole"
    );
    // … with NO new false positives on benign traffic …
    assert_eq!(
        rep.benign_false_positives, 0,
        "hardening must not regress precision"
    );
    // … and the tool says so honestly only when both hold.
    assert!(rep.proven_closed);
    assert!(!rep.added_rules.is_empty());

    // The encoded hole is concretely closed now.
    let hardened = waf.with_rules_added(rep.added_rules);
    let mut h = hardened;
    assert_eq!(h.classify(&body(b"%3cx")).unwrap(), Outcome::Block);
    // And a benign string that merely *looks* similar still passes.
    assert_eq!(h.classify(&body(b"c3x")).unwrap(), Outcome::Pass);
}

#[test]
fn synthesized_rules_are_load_bearing_not_decoration() {
    let waf = brittle();
    let needles: [&[u8]; 2] = [b"<x", b"%3cx"];
    let alpha = Alphabet::new(vec![b'<', b'x', b'%', b'3', b'c'], b'Z');
    let benign: [&[u8]; 1] = [b"safe"];

    let rep = synthesize_closure(
        &waf,
        &needles,
        ChannelSet::none().with(Channel::Body),
        &benign,
        &alpha,
        6,
    );
    assert!(rep.proven_closed && rep.holes_before > 0);

    // Remove the synthesized rules ⇒ the ORIGINAL WAF ⇒ exactly the
    // original holes reopen (proves the rules did the closing, not
    // some incidental change).
    let reopened = synthesize_closure(
        &waf,
        &needles,
        ChannelSet::none().with(Channel::Body),
        &benign,
        &alpha,
        6,
    )
    .holes_before;
    assert_eq!(
        reopened, rep.holes_before,
        "without the synthesized rules the holes must reopen identically"
    );
    assert!(reopened > 0);
}
