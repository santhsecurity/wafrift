//! Truth contract for the composition/preimage solver.
//!
//! The headline claim: the double-URL-encode bypass — and the JSON
//! bypass — are **discovered, not hard-coded**. The same `solve_bypass`
//! call, given different sink pipelines, emits different structurally-
//! derived encodings; and when the sink cannot reconstruct an evaded
//! payload it returns `None` (never a fabricated bypass).

use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::normalize::Transform;
use wafrift_wafmodel::{
    ChannelSet, Outcome, Pipeline, Rule, SimRegexWaf, Stage, WafOracle, solve_bypass,
};

/// WAF blocks `<script` after a SINGLE urlDecodeUni + lowercase
/// (faithful CRS) on the body — exactly the real normalization the
/// double-decode mismatch exploits.
fn crs_waf() -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "941".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        }],
        5,
    )
}
fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}

#[test]
fn double_url_encode_bypass_is_discovered_not_hardcoded() {
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]); // origin decodes twice
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a normalization-mismatch bypass exists for a double-decoding origin");

    // It is NOT the raw attack.
    assert_ne!(sol.input, attack.to_vec());
    // The solver derived the double-percent-encoding from the PIPELINE.
    assert_eq!(sol.input, b"%253Cscript%253E".to_vec());
    // Replays as PASS against the very same WAF (no model gap).
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    // And the sink genuinely reconstructs the live attack.
    assert!(sol.sink_view.windows(8).any(|w| w == attack));
    assert!(
        sol.raw_attack_blocked,
        "the raw attack must be blocked (control)"
    );
}

#[test]
fn same_solver_emits_a_json_escape_bypass_for_a_json_sink() {
    // Different sink, identical call. If the double-encode were
    // hard-coded this would fail; instead the structural preimage of a
    // JSON-unescaping sink is a JSON-escaped payload.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::JsonUnescape]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a JSON-unescape sink is bypassable by a JSON-escaped preimage");

    assert_eq!(sol.input, b"\\u003cscript\\u003e".to_vec());
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(8).any(|w| w == attack));
}

#[test]
fn identity_sink_has_no_bypass_solver_does_not_fabricate_one() {
    // If the origin does NOT decode, any payload that evades the WAF
    // arrives at the sink still-evaded (not the attack), and the raw
    // attack is blocked. There is no solution — and the solver must
    // say so rather than invent one.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::Identity]);
    let mut waf = crs_waf();
    let sol = solve_bypass(attack, &sink, &mut waf, &body).unwrap();
    assert!(
        sol.is_none(),
        "identity sink is unbypassable for this WAF — must return None, got {sol:?}"
    );
}

#[test]
fn solver_reports_none_when_waf_blocks_even_the_encoded_form() {
    // A WAF that ALSO double-decodes (sees the same as the origin)
    // cannot be beaten by the double-encode preimage — the candidate
    // decodes to `<script>` in the WAF's view too. Honest None.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]);
    let mut strong = SimRegexWaf::new(
        vec![Rule {
            id: "941-strong".into(),
            channels: ChannelSet::none().with(Channel::Body),
            // Two URL-decode passes in the WAF view ⇒ matches origin.
            transforms: vec![
                Transform::UrlDecodeUni,
                Transform::UrlDecodeUni,
                Transform::Lowercase,
            ],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        }],
        5,
    );
    let sol = solve_bypass(attack, &sink, &mut strong, &body).unwrap();
    assert!(
        sol.is_none(),
        "a WAF that normalizes like the origin has no mismatch to exploit"
    );
}
