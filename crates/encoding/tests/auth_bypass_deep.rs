//! Deep coverage for `auth_bypass::auth_bypass_probes` — the 230-probe
//! Tsai-class header bypass set. Catches duplicate header, missing
//! family, broken label, malformed value, mixing across the 5 families
//! (URL-rewrite, IP-trust, gateway-injected-identity, method-override,
//! header-smuggle-LWS).

use std::collections::HashSet;
use wafrift_encoding::auth_bypass::{AuthBypassProbe, auth_bypass_probes};

fn probes() -> Vec<AuthBypassProbe> {
    auth_bypass_probes("/admin")
}

// ────────────────────────────────────────────────────────────────
// Count + path independence
// ────────────────────────────────────────────────────────────────

#[test]
fn probe_count_is_230() {
    assert_eq!(probes().len(), 230);
}

#[test]
fn probe_count_independent_of_target_path() {
    let paths = ["/admin", "/", "/.env", "/api/v1/x/y/z", "//", "/?q=1#frag"];
    for p in &paths {
        assert_eq!(
            auth_bypass_probes(p).len(),
            230,
            "path {p} produced wrong count"
        );
    }
}

#[test]
fn probe_count_consistent_across_empty_and_whitespace_paths() {
    assert_eq!(auth_bypass_probes("").len(), 230);
    assert_eq!(auth_bypass_probes(" ").len(), 230);
}

// ────────────────────────────────────────────────────────────────
// No duplicate header+value pairs (each probe must be unique)
// ────────────────────────────────────────────────────────────────

#[test]
fn no_duplicate_header_value_pairs() {
    let ps = probes();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut dupes = vec![];
    for p in &ps {
        // Normalize header name (HTTP headers are case-insensitive).
        let key = (p.header.to_lowercase(), p.value.clone());
        if !seen.insert(key.clone()) {
            dupes.push(key);
        }
    }
    assert!(
        dupes.is_empty(),
        "duplicate (header, value) pairs found: {dupes:?}"
    );
}

#[test]
fn no_duplicate_labels_per_header_value() {
    // A given (header, value) pair always gets the same label.
    let ps = probes();
    let mut label_for: std::collections::HashMap<(String, String), &str> =
        std::collections::HashMap::new();
    for p in &ps {
        let key = (p.header.to_lowercase(), p.value.clone());
        if let Some(existing) = label_for.get(&key) {
            assert_eq!(
                *existing, p.label,
                "label drift for {key:?}: {existing} vs {}",
                p.label
            );
        }
        label_for.insert(key, p.label);
    }
}

// ────────────────────────────────────────────────────────────────
// Every probe is well-formed
// ────────────────────────────────────────────────────────────────

#[test]
fn every_probe_has_non_empty_header_name() {
    for p in &probes() {
        assert!(!p.header.is_empty(), "probe with empty header: {:?}", p);
    }
}

#[test]
fn every_probe_has_non_empty_value() {
    for p in &probes() {
        assert!(!p.value.is_empty(), "probe with empty value: {:?}", p);
    }
}

#[test]
fn every_probe_has_non_empty_label() {
    for p in &probes() {
        assert!(!p.label.is_empty(), "probe with empty label: {:?}", p);
    }
}

#[test]
fn every_probe_has_non_empty_description() {
    for p in &probes() {
        assert!(
            !p.description.is_empty(),
            "probe with empty description: {:?}",
            p
        );
        assert!(
            p.description.len() >= 10,
            "probe description too short: {:?}",
            p
        );
    }
}

#[test]
fn header_names_are_valid_ascii_except_for_lws_smuggle_family() {
    // header-smuggle-lws DELIBERATELY ships malformed header names
    // (soft-hyphen U+00AD, leading/trailing whitespace, underscore
    // swap) — that's the whole bypass mechanism: WAF parsers that
    // strip these chars disagree with origin parsers that don't.
    // For every OTHER family, headers must be valid ASCII tchars.
    for p in &probes() {
        if p.label == "header-smuggle-lws" {
            continue;
        }
        assert!(
            p.header.is_ascii(),
            "non-ASCII header in non-LWS family `{}`: {:?}",
            p.label,
            p.header
        );
    }
}

#[test]
fn header_names_contain_no_forbidden_chars_except_for_lws_smuggle() {
    // RFC 7230 token: alpha / digit / !#$%&'*+-.^_`|~
    // Same exception: LWS family is intentionally malformed.
    for p in &probes() {
        if p.label == "header-smuggle-lws" {
            continue;
        }
        for c in p.header.chars() {
            let ok = c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
            assert!(
                ok,
                "header `{}` (family `{}`) contains forbidden char `{c}`",
                p.header, p.label
            );
        }
    }
}

#[test]
fn lws_smuggle_family_actually_contains_malformed_headers() {
    // Anti-rig: the LWS family must contain AT LEAST ONE probe with
    // a non-tchar in the header name — otherwise the family is dead.
    let any_malformed = probes()
        .iter()
        .filter(|p| p.label == "header-smuggle-lws")
        .any(|p| {
            p.header.chars().any(|c| {
                !(c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
            })
        });
    assert!(
        any_malformed,
        "header-smuggle-lws family has zero malformed-header probes — \
         it's supposed to test parser disagreement on non-tchar bytes"
    );
}

#[test]
fn header_values_contain_no_cr_or_lf() {
    // CR/LF in a header value = HTTP request splitting vulnerability.
    for p in &probes() {
        assert!(
            !p.value.contains('\r') && !p.value.contains('\n'),
            "probe value contains CR/LF (request splitting): {:?}",
            p
        );
    }
}

#[test]
fn header_values_are_valid_utf8() {
    for p in &probes() {
        let _ = std::str::from_utf8(p.value.as_bytes()).unwrap();
    }
}

// ────────────────────────────────────────────────────────────────
// Family coverage — each documented family must appear
// ────────────────────────────────────────────────────────────────

fn labels() -> Vec<&'static str> {
    probes().into_iter().map(|p| p.label).collect()
}

#[test]
fn family_url_rewrite_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("url-rewrite")),
        "url-rewrite family label missing"
    );
}

#[test]
fn family_ip_trust_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("ip-trust")),
        "ip-trust family label missing"
    );
}

#[test]
fn family_host_trust_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("host-trust")),
        "host-trust family label missing"
    );
}

#[test]
fn family_method_override_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("method-override")),
        "method-override family label missing"
    );
}

#[test]
fn family_scheme_trust_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("scheme-trust")),
        "scheme-trust family label missing"
    );
}

#[test]
fn family_gateway_identity_present() {
    let ls = labels();
    // Family added 2026-05-23: Cloudflare Access, GCP IAP, AWS ALB OIDC,
    // Azure Easy Auth, Authentik, oauth2-proxy, Traefik, Grafana.
    assert!(
        ls.iter().any(|l| l.contains("gateway-identity")),
        "gateway-identity-spoof family label missing"
    );
}

#[test]
fn family_lws_smuggle_present() {
    let ls = labels();
    assert!(
        ls.iter().any(|l| l.contains("header-smuggle-lws")),
        "header-smuggle-lws family label missing"
    );
}

#[test]
fn all_seven_family_labels_present() {
    // Pin the exact set so adding/removing a family is an explicit
    // decision (not a silent regression).
    let expected: std::collections::HashSet<&str> = [
        "url-rewrite-header",
        "ip-trust-spoof",
        "host-trust-override",
        "method-override",
        "scheme-trust",
        "gateway-identity-spoof",
        "header-smuggle-lws",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::HashSet<&str> = labels().into_iter().collect();
    assert_eq!(
        actual, expected,
        "auth_bypass family label set drifted from documented 7"
    );
}

// ────────────────────────────────────────────────────────────────
// Path interpolation correctness
// ────────────────────────────────────────────────────────────────

#[test]
fn url_rewrite_probes_include_target_path() {
    let target = "/secret-admin-area-12345";
    let ps = auth_bypass_probes(target);
    let any_url_probe_has_path = ps
        .iter()
        .any(|p| p.label == "url-rewrite-header" && p.value.contains(target));
    assert!(
        any_url_probe_has_path,
        "no URL-rewrite probe interpolated the target path"
    );
}

#[test]
fn ip_trust_probes_dont_include_target_path() {
    let target = "/zzz-unique-marker-zzz";
    let ps = auth_bypass_probes(target);
    let ip_with_path = ps
        .iter()
        .any(|p| p.label == "ip-trust-spoof" && p.value.contains(target));
    assert!(
        !ip_with_path,
        "IP-trust probe leaked target path into value (semantic confusion)"
    );
}

#[test]
fn path_with_special_chars_does_not_break_probe_gen() {
    let weird = [
        "/admin?q=1&r=2",
        "/admin#fragment",
        "/admin/with spaces",
        "/admin/with\ttab",
        "/admin/日本",
        "/admin/🔥",
    ];
    for p in &weird {
        let ps = auth_bypass_probes(p);
        assert_eq!(ps.len(), 230, "weird path {p} produced wrong count");
    }
}

// ────────────────────────────────────────────────────────────────
// Specific known probes survive (regression pins)
// ────────────────────────────────────────────────────────────────

#[test]
fn x_forwarded_for_localhost_present() {
    let ps = probes();
    assert!(
        ps.iter().any(|p| p.header.eq_ignore_ascii_case("X-Forwarded-For")
            && p.value.contains("127.0.0.1")),
        "X-Forwarded-For 127.0.0.1 probe missing"
    );
}

#[test]
fn x_real_ip_present() {
    let ps = probes();
    assert!(
        ps.iter().any(|p| p.header.eq_ignore_ascii_case("X-Real-IP")),
        "X-Real-IP probe missing"
    );
}

#[test]
fn x_original_url_present() {
    let ps = probes();
    assert!(
        ps.iter().any(|p| p.header.eq_ignore_ascii_case("X-Original-URL")),
        "X-Original-URL probe missing"
    );
}

#[test]
fn x_http_method_override_present() {
    let ps = probes();
    assert!(
        ps.iter().any(|p| {
            let h = p.header.to_lowercase();
            h.contains("method-override") || h == "x-http-method-override"
        }),
        "X-HTTP-Method-Override family missing"
    );
}

// ────────────────────────────────────────────────────────────────
// Distribution invariants
// ────────────────────────────────────────────────────────────────

#[test]
fn at_least_30_distinct_header_names_present() {
    let names: HashSet<String> = probes()
        .iter()
        .map(|p| p.header.to_lowercase())
        .collect();
    assert!(
        names.len() >= 30,
        "only {} distinct headers (expected >= 30)",
        names.len()
    );
}

#[test]
fn exactly_7_distinct_labels_present() {
    // Pinned: one label per family (url-rewrite, ip-trust, host-trust,
    // method-override, scheme-trust, gateway-identity, header-smuggle-lws).
    let ls: HashSet<&str> = probes().iter().map(|p| p.label).collect();
    assert_eq!(
        ls.len(),
        7,
        "label set drifted from documented 7 families: {:?}",
        ls
    );
}

#[test]
fn no_header_dominates_more_than_50_pct() {
    let mut counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for p in &probes() {
        *counts.entry(p.header.to_lowercase()).or_default() += 1;
    }
    let total = probes().len();
    for (h, c) in &counts {
        assert!(
            (*c as f64) / (total as f64) < 0.5,
            "header `{h}` dominates: {c}/{total}",
        );
    }
}

// ────────────────────────────────────────────────────────────────
// Stability — multiple calls return identical sets
// ────────────────────────────────────────────────────────────────

#[test]
fn two_calls_return_identical_probes() {
    let a = auth_bypass_probes("/admin");
    let b = auth_bypass_probes("/admin");
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.header, y.header);
        assert_eq!(x.value, y.value);
        assert_eq!(x.label, y.label);
    }
}

#[test]
fn concurrent_calls_return_consistent_probes() {
    use std::thread;
    let expected = auth_bypass_probes("/admin");
    let mut handles = vec![];
    for _ in 0..16 {
        handles.push(thread::spawn(|| auth_bypass_probes("/admin")));
    }
    for h in handles {
        let got = h.join().unwrap();
        assert_eq!(got.len(), expected.len());
    }
}

// ────────────────────────────────────────────────────────────────
// AuthBypassProbe Debug/Clone trait sanity
// ────────────────────────────────────────────────────────────────

#[test]
fn probe_implements_clone_with_equality() {
    let ps = probes();
    let p = &ps[0];
    let copy = p.clone();
    assert_eq!(p.header, copy.header);
    assert_eq!(p.value, copy.value);
    assert_eq!(p.label, copy.label);
    assert_eq!(p.description, copy.description);
}

#[test]
fn probe_debug_output_non_empty() {
    let p = &probes()[0];
    assert!(!format!("{p:?}").is_empty());
}
