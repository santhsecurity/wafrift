//! DNS-fingerprint test suite — engine matching, rule loading,
//! and embedded-catalog invariants for CNAME / PTR / ASN layers.

use super::rules::CnameRuleEngine;
use super::types::{AsnInfo, CnameHop, DnsProbe};

const TEST_TOML: &str = r#"
[[cname]]
name = "TestFastly"
vendor = "Fastly"
confidence_threshold = 0.5
evasions = ["DoubleUrlEncode"]
source = "test"
[[cname.signature]]
  host_regex = "\\.fastly\\.net$"
  weight = 0.7
[[cname.signature]]
  host_regex = "\\.map\\.fastly\\.net$"
  weight = 0.3

[[cname]]
name = "TestAkamai"
vendor = "Akamai"
confidence_threshold = 0.5
evasions = ["CaseAlternation"]
[[cname.signature]]
  host_regex = "\\.akamaiedge\\.net$"
  weight = 0.8
"#;

fn engine() -> CnameRuleEngine {
    CnameRuleEngine::from_toml(TEST_TOML).expect("parse test rules")
}

fn probe_from_hosts(query: &str, chain: &[&str]) -> DnsProbe {
    let mut hops = Vec::new();
    let mut current = query.to_string();
    for next in chain {
        hops.push(CnameHop {
            query: current.clone(),
            target: (*next).to_string(),
        });
        current = (*next).to_string();
    }
    DnsProbe {
        chain: hops,
        first_a: None,
        final_ptr: None,
        asn: None,
    }
}

#[test]
fn detect_fastly_via_map_fastly_net_cname() {
    let probe = probe_from_hosts("www.example.com", &["example.map.fastly.net"]);
    let r = engine().detect(&probe);
    assert!(
        r.iter().any(|d| d.name == "TestFastly"),
        "expected TestFastly to fire on map.fastly.net CNAME: {r:?}"
    );
}

#[test]
fn detect_akamai_via_akamaiedge_cname() {
    let probe = probe_from_hosts("www.example.com", &["e123.a.akamaiedge.net"]);
    let r = engine().detect(&probe);
    assert!(r.iter().any(|d| d.name == "TestAkamai"));
}

#[test]
fn no_detection_on_unrelated_chain() {
    let probe = probe_from_hosts("www.example.com", &["origin.example-internal.org"]);
    let r = engine().detect(&probe);
    assert!(r.is_empty(), "should not false-positive: {r:?}");
}

#[test]
fn matches_intermediate_hop_not_just_final() {
    // Fastly's POP chain often goes through `.map.fastly.net`
    // (the alias-cluster name) THEN to a regional pop — the
    // final hop may be a fastly-internal name we don't pattern
    // for.  Matching intermediate hops covers that.
    let probe = probe_from_hosts(
        "www.example.com",
        &["example.map.fastly.net", "anycast.fastly.fastly.net"],
    );
    let r = engine().detect(&probe);
    assert!(!r.is_empty());
}

#[test]
fn case_insensitive_host_matching() {
    // DNS is case-insensitive — a hostile resolver returning
    // CamelCase host names must not break detection.
    let probe = probe_from_hosts("www.example.com", &["Example.Map.Fastly.NET"]);
    let r = engine().detect(&probe);
    assert!(r.iter().any(|d| d.name == "TestFastly"));
}

#[test]
fn confidence_threshold_filters_weak_matches() {
    // A rule needing 0.5 confidence with one matching 0.3
    // signature shouldn't fire — partial chains are common
    // false positives on parked-domain registrars.
    let toml = r#"
[[cname]]
name = "WeakRule"
vendor = "test"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "\\.example\\.net$"
  weight = 0.3
"#;
    let eng = CnameRuleEngine::from_toml(toml).expect("parse");
    let probe = probe_from_hosts("a.com", &["b.example.net"]);
    assert!(eng.detect(&probe).is_empty());
}

#[test]
fn multi_vendor_chain_returns_all_layers() {
    // Cloudflare-on-top-of-Akamai (uncommon but seen in
    // hybrid setups).  Both rules must fire.
    let toml = r#"
[[cname]]
name = "Akamai"
vendor = "Akamai"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "\\.akamaiedge\\.net$"
  weight = 0.8

[[cname]]
name = "Fastly"
vendor = "Fastly"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "\\.fastly\\.net$"
  weight = 0.7
"#;
    let eng = CnameRuleEngine::from_toml(toml).expect("parse");
    let probe = probe_from_hosts("a.com", &["edge.fastly.net", "origin.a.akamaiedge.net"]);
    let r = eng.detect(&probe);
    let names: Vec<&str> = r.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"Akamai") && names.contains(&"Fastly"));
}

#[test]
fn empty_chain_does_not_panic() {
    let probe = DnsProbe::default();
    assert!(engine().detect(&probe).is_empty());
}

#[test]
fn rule_with_no_signatures_is_inert() {
    let toml = r#"
[[cname]]
name = "NoSig"
vendor = "test"
confidence_threshold = 0.3
signature = []
"#;
    let eng = CnameRuleEngine::from_toml(toml).expect("parse");
    let probe = probe_from_hosts("a.com", &["b.com"]);
    assert!(eng.detect(&probe).is_empty());
}

#[test]
fn malformed_toml_surfaces_as_err() {
    let r = CnameRuleEngine::from_toml("this is not valid toml [[[");
    assert!(r.is_err());
}

#[test]
fn bad_regex_surfaces_as_err() {
    let r = CnameRuleEngine::from_toml(
        r#"
[[cname]]
name = "Bad"
vendor = "test"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "([unclosed"
  weight = 0.5
"#,
    );
    assert!(r.is_err());
}

#[test]
fn embedded_ruleset_loads_and_has_rules() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded rules compile");
    assert!(
        eng.len() >= 5,
        "embedded CNAME ruleset has only {} rules — catalog shrank",
        eng.len()
    );
}

#[test]
fn embedded_ruleset_fires_on_canonical_fastly_chain() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = probe_from_hosts("www.example.com", &["example.map.fastly.net"]);
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("Fastly")),
        "embedded ruleset must catch canonical Fastly CNAME: {r:?}"
    );
}

#[test]
fn embedded_ruleset_fires_on_canonical_akamai_chain() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = probe_from_hosts("www.example.com", &["e88167.a.akamaiedge.net"]);
    let r = eng.detect(&probe);
    assert!(
        r.iter()
            .any(|d| d.name.contains("Akamai") || d.name.contains("Kona")),
        "embedded ruleset must catch canonical Akamai CNAME: {r:?}"
    );
}

#[test]
fn ptr_record_participates_in_signature_matching() {
    let toml = r#"
[[cname]]
name = "PtrOnly"
vendor = "test"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "\\.example-ptr\\.com$"
  weight = 0.7
"#;
    let eng = CnameRuleEngine::from_toml(toml).expect("parse");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("192.0.2.1".parse().unwrap()),
        final_ptr: Some("host42.example-ptr.com".to_string()),
        asn: None,
    };
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name == "PtrOnly"),
        "PTR-only signature must fire when forward chain is empty: {r:?}"
    );
}

#[test]
fn embedded_ruleset_fires_on_stripe_ptr_signature() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("198.137.150.111".parse().unwrap()),
        final_ptr: Some("198-137-150-111.s.stripe.com".to_string()),
        asn: None,
    };
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("Stripe")),
        "Embedded Stripe PTR rule must fire: {r:?}"
    );
}

#[test]
fn embedded_ruleset_fires_on_aws_compute_ptr() {
    // Slack's PTR (live capture, 2026-05-21):
    // `ec2-35-81-85-251.us-west-2.compute.amazonaws.com`.
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("35.81.85.251".parse().unwrap()),
        final_ptr: Some("ec2-35-81-85-251.us-west-2.compute.amazonaws.com".to_string()),
        asn: None,
    };
    let r = eng.detect(&probe);
    let names: Vec<&str> = r.iter().map(|d| d.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.contains("AWS") || n.contains("Amazon")),
        "AWS EC2 PTR must fire on canonical compute.amazonaws.com PTR: {r:?}"
    );
}

#[test]
fn embedded_ruleset_fires_on_github_lb_ptr() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("140.82.114.3".parse().unwrap()),
        final_ptr: Some("lb-140-82-114-3-iad.github.com".to_string()),
        asn: None,
    };
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("GitHub")),
        "GitHub edge LB PTR must fire: {r:?}"
    );
}

#[test]
fn embedded_ruleset_fires_on_akamai_ptr() {
    // Real-world PTR from ebay.com leaf IP, 2026-05-21.
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("23.209.84.185".parse().unwrap()),
        final_ptr: Some("a23-209-84-185.deploy.static.akamaitechnologies.com".to_string()),
        asn: None,
    };
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("Akamai")),
        "Embedded Akamai PTR rule must fire on a real-world PTR: {r:?}"
    );
}

#[test]
fn asn_name_participates_in_signature_matching() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![],
        first_a: Some("198.137.150.111".parse().unwrap()),
        final_ptr: None,
        asn: Some(AsnInfo {
            number: 395812,
            name: "STRIPE-AS, US".to_string(),
        }),
    };
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("Stripe")),
        "Stripe ASN org name must fire Stripe rule: {r:?}"
    );
}

#[test]
fn asn_matches_top_vendor_catch_alls() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    for (asn_name, expected_vendor) in [
        ("CLOUDFLARENET, US", "Cloudflare"),
        ("FASTLY, US", "Fastly"),
        ("AKAMAI-LINODE-AP, JP", "Akamai"),
        ("AMAZON-AES, US", "Amazon"),
        ("GOOGLE, US", "Google"),
        ("MICROSOFT-CORP-MSN-AS-BLOCK, US", "Microsoft"),
        ("DROPBOX, US", "Dropbox"),
        ("INCAPSULA, US", "Imperva"),
        ("GITHUB, US", "GitHub"),
    ] {
        let probe = DnsProbe {
            chain: vec![],
            first_a: Some("203.0.113.1".parse().unwrap()),
            final_ptr: None,
            asn: Some(AsnInfo {
                number: 0,
                name: asn_name.to_string(),
            }),
        };
        let r = eng.detect(&probe);
        assert!(
            r.iter().any(|d| d.name.contains(expected_vendor)),
            "ASN `{asn_name}` must fire {expected_vendor} rule. Got: {r:?}"
        );
    }
}

#[test]
fn ptr_missing_does_not_break_chain_only_detection() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = DnsProbe {
        chain: vec![CnameHop {
            query: "www.example.com".to_string(),
            target: "example.map.fastly.net".to_string(),
        }],
        first_a: None,
        final_ptr: None,
        asn: None,
    };
    let r = eng.detect(&probe);
    assert!(r.iter().any(|d| d.name.contains("Fastly")));
}

#[test]
fn embedded_ruleset_fires_on_canonical_cloudfront_chain() {
    let eng = CnameRuleEngine::load_embedded().expect("embedded");
    let probe = probe_from_hosts("aws.example.com", &["dr49lng3n1n2s.cloudfront.net"]);
    let r = eng.detect(&probe);
    assert!(
        r.iter().any(|d| d.name.contains("Cloudfront")),
        "embedded ruleset must catch canonical Cloudfront CNAME: {r:?}"
    );
}

// ── New tests added for the modularized layout ───────────

#[test]
fn vendor_for_returns_the_registered_vendor_name() {
    let eng = engine();
    assert_eq!(eng.vendor_for("TestFastly"), Some("Fastly"));
    assert_eq!(eng.vendor_for("TestAkamai"), Some("Akamai"));
    assert_eq!(eng.vendor_for("UnknownRule"), None);
}

#[test]
fn evasions_for_returns_rule_specific_techniques() {
    let eng = engine();
    let fastly = eng.evasions_for("TestFastly");
    assert!(fastly.contains(&"DoubleUrlEncode"));
    let akamai = eng.evasions_for("TestAkamai");
    assert!(akamai.contains(&"CaseAlternation"));
    assert!(eng.evasions_for("UnknownRule").is_empty());
}

#[test]
fn default_dnsprobe_is_empty_in_every_field() {
    let probe = DnsProbe::default();
    assert!(probe.chain.is_empty());
    assert!(probe.first_a.is_none());
    assert!(probe.final_ptr.is_none());
    assert!(probe.asn.is_none());
}

#[test]
fn tagged_hosts_ordering_matches_layered_priority() {
    // CNAME hops come first (each contributes one entry, plus the
    // final target gets pushed once more), then PTR, then ASN.
    // This is the order signature matching iterates and should
    // remain stable so indicator strings are deterministic.
    let probe = DnsProbe {
        chain: vec![
            CnameHop {
                query: "a.com".to_string(),
                target: "b.com".to_string(),
            },
            CnameHop {
                query: "b.com".to_string(),
                target: "c.com".to_string(),
            },
        ],
        first_a: Some("192.0.2.5".parse().unwrap()),
        final_ptr: Some("ptr.example".to_string()),
        asn: Some(AsnInfo {
            number: 12345,
            name: "EXAMPLE-AS".to_string(),
        }),
    };
    let tagged = probe.tagged_hosts();
    let labels: Vec<&str> = tagged.iter().map(|(l, _)| *l).collect();
    // Two chain queries + one final target + ptr + asn = 5.
    assert_eq!(labels, vec!["cname", "cname", "cname", "ptr", "asn"]);
}

#[test]
fn dnsprobe_error_display_is_human_readable() {
    use super::types::DnsProbeError;
    let cases = [
        (DnsProbeError::ResolverInitFailed, "resolver"),
        (DnsProbeError::Timeout, "timed out"),
        (DnsProbeError::NoRecords, "no DNS"),
        (DnsProbeError::DepthExceeded, "CNAME"),
        (DnsProbeError::Io, "I/O"),
    ];
    for (err, needle) in cases {
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains(&needle.to_lowercase()),
            "Display for {err:?} must mention `{needle}`: got `{msg}`"
        );
    }
}

#[test]
fn ruleset_detect_is_deterministic_across_runs() {
    // Property: the same probe must yield the same detection
    // vector every time.  Sort stability matters for downstream
    // consumers that fingerprint our output.
    let eng = engine();
    let probe = probe_from_hosts("a.com", &["edge.fastly.net", "origin.a.akamaiedge.net"]);
    let a = eng.detect(&probe);
    let b = eng.detect(&probe);
    let c = eng.detect(&probe);
    assert_eq!(a.len(), b.len());
    assert_eq!(b.len(), c.len());
    for ((r1, r2), r3) in a.iter().zip(b.iter()).zip(c.iter()) {
        assert_eq!(r1.name, r2.name);
        assert_eq!(r2.name, r3.name);
        assert_eq!(r1.confidence, r2.confidence);
    }
}

#[test]
fn rule_compilation_idempotent_for_same_toml() {
    // Loading the same TOML twice must produce equivalent engines
    // (no global state, no order-dependent compilation).
    let a = CnameRuleEngine::from_toml(TEST_TOML).expect("parse a");
    let b = CnameRuleEngine::from_toml(TEST_TOML).expect("parse b");
    assert_eq!(a.len(), b.len());
}

#[test]
fn signature_matching_is_anchored_at_end_for_dollar_patterns() {
    // The catalog uses `\.fastly\.net$` — must not match
    // `foo.fastly.net.evil.attacker.com`.  The `$` anchor is
    // crucial for preventing supply-chain false positives.
    let toml = r#"
[[cname]]
name = "Test"
vendor = "test"
confidence_threshold = 0.5
[[cname.signature]]
  host_regex = "\\.fastly\\.net$"
  weight = 0.7
"#;
    let eng = CnameRuleEngine::from_toml(toml).expect("parse");
    // Legit Fastly hop fires.
    let legit = probe_from_hosts("a.com", &["edge.fastly.net"]);
    assert!(!eng.detect(&legit).is_empty());
    // Attacker-controlled suffix does NOT fire.
    let attacker = probe_from_hosts("a.com", &["edge.fastly.net.attacker.example.com"]);
    assert!(
        eng.detect(&attacker).is_empty(),
        "anchored regex must not match a suffix-extension attack"
    );
}

#[test]
fn empty_rule_list_compiles_and_returns_empty_detect() {
    let eng = CnameRuleEngine::from_toml("").expect("empty TOML is valid");
    assert!(eng.is_empty());
    assert_eq!(eng.len(), 0);
    let probe = probe_from_hosts("a.com", &["b.fastly.net"]);
    assert!(eng.detect(&probe).is_empty());
}

#[test]
fn asn_info_equality_is_value_based() {
    let a = AsnInfo {
        number: 16509,
        name: "AMAZON-02".to_string(),
    };
    let b = AsnInfo {
        number: 16509,
        name: "AMAZON-02".to_string(),
    };
    let c = AsnInfo {
        number: 16509,
        name: "AMAZON-OTHER".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn cname_hop_equality_is_value_based() {
    let a = CnameHop {
        query: "a.com".to_string(),
        target: "b.com".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
    let c = CnameHop {
        query: "a.com".to_string(),
        target: "different.com".to_string(),
    };
    assert_ne!(a, c);
}
