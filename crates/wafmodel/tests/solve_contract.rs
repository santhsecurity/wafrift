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
use wafrift_wafmodel::solve::preimage_for;
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
fn never_policed_attack_yields_no_bypass_even_when_the_sink_reconstructs() {
    // The #7 false-positive trap: a WAF that blocks NOTHING (empty ruleset).
    // The raw attack already passes, so there is nothing to bypass — yet the
    // sink (DoubleUrlDecode) *can* reconstruct the attack from a double-encoded
    // preimage, and that preimage trivially "passes" the do-nothing WAF. A
    // naive solver returns that as a "bypass"; the sound solver must see the
    // raw attack was never blocked and return None.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]);
    // Empty ruleset, threshold 5 → score is always 0 < 5 → every request Passes.
    let mut open_waf = SimRegexWaf::new(vec![], 5);

    // Sanity: this WAF genuinely passes the raw attack (the precondition that
    // makes any reported bypass vacuous).
    assert_eq!(
        open_waf.classify(&body(attack)).unwrap(),
        Outcome::Pass,
        "control: the open WAF must pass the raw attack"
    );

    let sol = solve_bypass(attack, &sink, &mut open_waf, &body).unwrap();
    assert!(
        sol.is_none(),
        "a never-policed attack has no bypass — returning a Solution here is the \
         vacuous false-positive class #7 forbids; got {sol:?}"
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

/// A WAF that blocks a literal byte-string after the given transforms but does
/// NOT Unicode-normalize — the exact blind spot the homoglyph stages exploit.
fn lit_waf(pattern: &str, transforms: Vec<Transform>) -> SimRegexWaf {
    SimRegexWaf::new(
        vec![Rule {
            id: "lit".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms,
            pattern: regex::bytes::Regex::new(pattern).unwrap(),
            score: 5,
        }],
        5,
    )
}

#[test]
fn nfkc_homoglyph_bypass_is_deduced_for_an_nfkc_normalizing_origin() {
    // The SAME solver, given an NFKC-normalizing sink, derives a homoglyph
    // preimage — no homoglyph rule is hard-coded here. The WAF blocks the
    // literal `<script` and does not NFKC-normalize; the origin does.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::NfkcNormalize]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("an NFKC-normalizing origin is bypassable by a homoglyph preimage");

    // Derived, not raw — and carries NONE of the literal ASCII angle brackets
    // the WAF rule keys on.
    assert_ne!(sol.input, attack.to_vec());
    assert!(
        !sol.input.contains(&b'<') && !sol.input.contains(&b'>'),
        "the homoglyph preimage must hide the literal angle brackets: {:?}",
        String::from_utf8_lossy(&sol.input)
    );
    // The substituted bytes are non-ASCII homoglyphs (NFKC folds them to the
    // ASCII brackets); we assert the property, not a specific codepoint.
    assert!(
        sol.input.iter().any(|b| !b.is_ascii()),
        "preimage must carry non-ASCII homoglyph bytes: {:?}",
        String::from_utf8_lossy(&sol.input)
    );
    // Independent re-verification: a fresh real WAF passes it…
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    // …and the NFKC origin reconstructs the live attack.
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn bestfit_curly_quote_sqli_bypass_is_deduced_for_a_bestfit_origin() {
    // The canonical best-fit SQLi: a WAF blocks the literal single quote, an
    // origin best-fit-coerces a curly quote back to it. The solver derives the
    // curly-quote preimage from the sink pipeline alone.
    let attack = b"' or 1=1";
    let sink = Pipeline(vec![Stage::BestFitDownconvert]);
    let mut waf = lit_waf("'", vec![Transform::Lowercase]);

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a best-fit origin is bypassable by a curly-quote preimage");

    assert!(
        !sol.input.contains(&b'\''),
        "the preimage must carry no literal single quote: {:?}",
        String::from_utf8_lossy(&sol.input)
    );
    assert!(String::from_utf8_lossy(&sol.input).contains('\u{2018}'));
    let mut replay = lit_waf("'", vec![Transform::Lowercase]);
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn solver_composes_url_decode_and_nfkc_for_a_two_stage_origin() {
    // A sink that url-decodes THEN NFKC-normalizes (a fullwidth-aware framework
    // behind a decoding proxy). The solver inverts BOTH stages in reverse — no
    // single rule covers this composite; it falls out of the pipeline-as-data.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::UrlDecode { plus_is_space: false }, Stage::NfkcNormalize]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a url-decode∘NFKC origin must be solvable by the composed preimage");

    assert!(
        !sol.input.contains(&b'<') && !sol.input.contains(&b'>'),
        "composed preimage still hides the literal angle brackets: {:?}",
        String::from_utf8_lossy(&sol.input)
    );
    // The two-stage sink reconstructs the attack exactly.
    assert_eq!(sink.apply(&sol.input), sol.sink_view);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
}

#[test]
fn every_invertible_stage_inverse_actually_round_trips_anti_drift() {
    // Anti-drift coherence guard. The COMPILE-TIME half is structural:
    // `Stage::apply` and the solver's `stage_inverse` are both exhaustive
    // matches, so no Stage variant can exist without BOTH a forward and an
    // inverse arm. This test adds the RUNTIME half — the inverse must genuinely
    // round-trip, never a silent identity stub. A rich attack (every delimiter
    // class) exercises each stage's fold; the preimage must differ from the
    // attack AND reconstruct it under `apply`. A new invertible stage added
    // here keeps the set honest; Identity/CrsView are intentionally
    // non-inverting and excluded.
    let attack = b"\"'<>";
    for st in [
        Stage::UrlDecode { plus_is_space: false },
        Stage::DoubleUrlDecode,
        Stage::JsonUnescape,
        Stage::HtmlEntityDecode,
        Stage::NfkcNormalize,
        Stage::BestFitDownconvert,
        Stage::StripNulls,
        Stage::OverlongUtf8Decode,
        Stage::Base64Decode,
        Stage::HexDecode,
    ] {
        let sink = Pipeline(vec![st.clone()]);
        let pre = preimage_for(attack, &sink, false);
        assert_ne!(
            pre,
            attack.to_vec(),
            "stage {st:?}: inverse produced no evasion (silent no-op inverse)"
        );
        let back = sink.apply(&pre);
        assert!(
            back.windows(attack.len()).any(|w| w == attack),
            "stage {st:?}: inverse does not round-trip: {pre:?} -> {back:?}"
        );
    }
}

#[test]
fn null_strip_bypass_is_deduced_for_a_nul_stripping_origin() {
    // A WAF blocks the literal `<script`; an origin that strips NUL bytes lets
    // `<\0script>` through and reconstructs the attack. The solver derives the
    // NUL-injected preimage from the sink alone.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::StripNulls]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a NUL-stripping origin is bypassable by a NUL-injected preimage");

    assert!(sol.input.contains(&0), "preimage must carry an embedded NUL: {:?}", sol.input);
    assert_ne!(sol.input, attack.to_vec());
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn overlong_utf8_bypass_is_deduced_for_a_lenient_decoding_origin() {
    // A WAF blocks the literal `<script`; a lenient origin that accepts the
    // overlong 2-byte encoding of `<` folds `0xC0 0xBC` back to `<`. The solver
    // derives the overlong preimage — no literal `<` byte survives on the wire.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::OverlongUtf8Decode]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a lenient overlong-decoding origin is bypassable by the overlong preimage");

    assert!(!sol.input.contains(&b'<'), "no literal `<` byte may survive: {:?}", sol.input);
    assert!(sol.input.contains(&0xC0), "preimage must carry an overlong lead byte");
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn base64_bypass_is_deduced_for_a_base64_decoding_origin() {
    // The API-endpoint classic: a WAF blocks `<script`; a JSON/API origin
    // base64-decodes the field, so `PHNjcmlwdD4=` carries the attack past it.
    // The solver derives the base64 preimage from the sink pipeline alone.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::Base64Decode]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a base64-decoding origin is bypassable by a base64-encoded preimage");

    assert!(!sol.input.contains(&b'<'), "no literal `<` may survive: {:?}", sol.input);
    assert_ne!(sol.input, attack.to_vec());
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn hex_bypass_is_deduced_for_a_hex_decoding_origin() {
    // A WAF blocks `<script`; an origin that hex-decodes the field accepts
    // `3c7363726970743e` and reconstructs the attack. Derived from the sink.
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::HexDecode]);
    let mut waf = crs_waf();

    let sol = solve_bypass(attack, &sink, &mut waf, &body)
        .unwrap()
        .expect("a hex-decoding origin is bypassable by a hex-encoded preimage");

    assert!(!sol.input.contains(&b'<'), "no literal `<` may survive: {:?}", sol.input);
    assert_ne!(sol.input, attack.to_vec());
    let mut replay = crs_waf();
    assert_eq!(replay.classify(&body(&sol.input)).unwrap(), Outcome::Pass);
    assert!(sol.sink_view.windows(attack.len()).any(|w| w == attack));
    assert!(sol.raw_attack_blocked, "control: the raw attack must be blocked");
}

#[test]
fn nfkc_preimage_under_an_identity_sink_is_honest_none() {
    // Anti-fabrication: the homoglyph trick only works when the ORIGIN folds.
    // With an Identity sink (origin does not normalize), the WAF sees the same
    // bytes the sink delivers, so a blocked attack stays blocked — the solver
    // must return None rather than emit a homoglyph form the origin would never
    // collapse. (The positive NFKC case above is what makes this a real twin.)
    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::Identity]);
    let mut waf = crs_waf();
    let sol = solve_bypass(attack, &sink, &mut waf, &body).unwrap();
    assert!(sol.is_none(), "identity origin cannot fold a homoglyph — must be None");
}
