//! Truth contract for ruleset fingerprinting: every catalog config is
//! uniquely round-trip identified, the selected probe set is strictly
//! smaller than the battery (real information-gain economy), and an
//! out-of-catalog WAF is *abstained on*, never mis-identified.

use wafrift_wafmodel::{
    Candidate, ChannelSet, Fingerprinter, Rule, SimRegexWaf, Transform, default_battery,
};

fn rule(id: &str, tf: &[Transform], pat: &str) -> Rule {
    Rule {
        id: id.into(),
        channels: ChannelSet::all(),
        transforms: tf.to_vec(),
        pattern: regex::bytes::Regex::new(pat).unwrap(),
        score: 5,
    }
}

fn catalog() -> Vec<Candidate> {
    vec![
        // PL1 XSS: raw `<script` only (case-sensitive, no decode).
        Candidate {
            id: "xss-pl1".into(),
            waf: SimRegexWaf::new(vec![rule("941-pl1", &[], "<script")], 5),
        },
        // PL2 XSS: decodes + lowercases ⇒ also catches case/encoded.
        Candidate {
            id: "xss-pl2".into(),
            waf: SimRegexWaf::new(
                vec![rule(
                    "941-pl2",
                    &[
                        Transform::UrlDecodeUni,
                        Transform::HtmlEntityDecode,
                        Transform::Lowercase,
                    ],
                    "<script",
                )],
                5,
            ),
        },
        // SQLi-only family.
        Candidate {
            id: "sqli-only".into(),
            waf: SimRegexWaf::new(
                vec![rule(
                    "942",
                    &[Transform::Lowercase, Transform::CompressWhitespace],
                    "(?:union select|' or ')",
                )],
                5,
            ),
        },
        // Combined PL2 XSS + SQLi.
        Candidate {
            id: "combo".into(),
            waf: SimRegexWaf::new(
                vec![
                    rule(
                        "941-pl2",
                        &[
                            Transform::UrlDecodeUni,
                            Transform::HtmlEntityDecode,
                            Transform::Lowercase,
                        ],
                        "<script",
                    ),
                    rule(
                        "942",
                        &[Transform::Lowercase, Transform::CompressWhitespace],
                        "(?:union select|' or ')",
                    ),
                ],
                5,
            ),
        },
    ]
}

#[test]
fn every_catalog_config_is_uniquely_round_trip_identified() {
    let battery = default_battery();
    let battery_len = battery.len();
    let fp = Fingerprinter::build(catalog(), battery);

    // Information-gain economy: strictly fewer probes than the battery.
    let selected = fp.probes().len();
    assert!(
        selected < battery_len,
        "selected {selected} probes must be < battery {battery_len}"
    );
    assert!(selected >= 2, "≥4 configs need ≥2 bits to separate");

    // Round-trip: identifying each catalog member returns its own id,
    // using only the selected probes.
    for cand in catalog() {
        let want = cand.id.clone();
        let mut oracle = cand.waf;
        let id = fp.identify(&mut oracle).unwrap();
        assert_eq!(
            id.matched.as_deref(),
            Some(want.as_str()),
            "config {want} must self-identify; got {:?} sig {:?}",
            id.matched,
            id.signature
        );
        assert_eq!(id.probe_count, selected);
    }
}

#[test]
fn distinct_configs_have_distinct_signatures() {
    let fp = Fingerprinter::build(catalog(), default_battery());
    let mut sigs = Vec::new();
    for cand in catalog() {
        let mut o = cand.waf;
        sigs.push(fp.identify(&mut o).unwrap().signature);
    }
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            assert_ne!(
                sigs[i], sigs[j],
                "configs {i} and {j} collide — fingerprinting could not be unique"
            );
        }
    }
}

#[test]
fn out_of_catalog_waf_is_abstained_not_misidentified() {
    let fp = Fingerprinter::build(catalog(), default_battery());
    // A WAF unlike any catalog member: blocks only a token that no
    // battery probe contains ⇒ all selected probes Pass ⇒ a signature
    // no catalog member has ⇒ MUST abstain (matched = None).
    let mut alien = SimRegexWaf::new(vec![rule("x", &[], "nevermatchzzz")], 5);
    let id = fp.identify(&mut alien).unwrap();
    assert_eq!(
        id.matched, None,
        "unknown config must abstain, never false-identify; sig {:?}",
        id.signature
    );
}
