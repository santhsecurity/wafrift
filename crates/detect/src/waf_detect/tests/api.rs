use crate::waf_detect::{DetectedWaf, detect, suggest_evasion, supported_wafs};

#[test]
fn supported_wafs_list() {
    let wafs = supported_wafs();
    assert!(wafs.len() >= 13);
    assert!(wafs.contains(&"Cloudflare".to_string()));
    assert!(wafs.contains(&"Barracuda".to_string()));
    assert!(wafs.contains(&"Wordfence".to_string()));
}

#[test]
fn detected_waf_display() {
    let waf = DetectedWaf {
        name: "TestWAF".into(),
        confidence: 0.85,
        indicators: vec!["header match".into()],
    };
    let rendered = waf.to_string();
    assert!(rendered.contains("TestWAF"));
    assert!(rendered.contains("85%"));
}

#[test]
fn empty_body_doesnt_panic() {
    let result = detect(200, &[], b"");
    assert!(result.is_empty());
}

#[test]
fn suggest_evasion_cloudflare() {
    let suggestions = suggest_evasion("Cloudflare");
    assert!(!suggestions.is_empty());
    assert!(
        suggestions
            .iter()
            .any(|strategy| strategy.contains("ContentType"))
    );
}

#[test]
fn suggest_evasion_unknown() {
    let suggestions = suggest_evasion("UnknownWAF");
    assert!(!suggestions.is_empty());
}

#[test]
fn suggest_evasion_modsecurity() {
    let suggestions = suggest_evasion("ModSecurity");
    assert!(
        suggestions
            .iter()
            .any(|strategy| strategy.contains("SqlComment"))
    );
}
