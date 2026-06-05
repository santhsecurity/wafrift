//! Cross-module `SmuggleProbe` trait integration.
//!
//! Verifies that the three encoding-crate probe families
//! (cookie_smuggle, auth_header_smuggle, range_header_smuggle) all
//! implement `wafrift_types::probe::SmuggleProbe` cleanly and can be
//! iterated through one `Vec<Box<dyn SmuggleProbe>>` operator path
//! — the whole point of the trait was to make this loop work.
//!
//! The trait now also covers `wafrift-content-type::ContentTypeVariant`
//! (body-shaping multipart smuggle probes), making it possible to
//! compose header-injection + body-shaping into one request through
//! one uniform API. See [`compose_header_plus_real_multipart_body`].

use wafrift_content_type::ContentTypeVariant;
use wafrift_content_type::json_smuggle::{JsonSmuggleProbe, JsonSmuggleTechnique};
use wafrift_content_type::multipart_smuggle::generate_smuggle_variants;
use wafrift_encoding::auth_header_smuggle::AuthSmuggleProbe;
use wafrift_encoding::cookie_smuggle::CookieSmuggleProbe;
use wafrift_encoding::host_header_smuggle::{HostSmuggleProbe, HostSmuggleTechnique};
use wafrift_encoding::jwt_smuggle::{JwtSmuggleProbe, JwtSmuggleTechnique};
use wafrift_encoding::path_normalize_smuggle::{PathNormalizeTechnique, PathSmuggleProbe};
use wafrift_encoding::range_header_smuggle::RangeSmuggleProbe;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe, compose_artifacts};

fn collect_probes() -> Vec<Box<dyn SmuggleProbe>> {
    vec![
        Box::new(CookieSmuggleProbe::empty_name_pair("v")),
        Box::new(CookieSmuggleProbe::duplicate_name_last_wins("a", "x", "y")),
        Box::new(AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "T")),
        Box::new(AuthSmuggleProbe::duplicate_header_first_wins_benign(
            "Authorization",
            "Bearer",
            "b",
            "s",
        )),
        Box::new(RangeSmuggleProbe::empty_range_set()),
        Box::new(RangeSmuggleProbe::overlapping_ranges()),
    ]
}

#[test]
fn trait_is_object_safe_across_all_three_families() {
    // The very act of constructing `Vec<Box<dyn SmuggleProbe>>` proves
    // the trait is object-safe. The compiler will reject a non-safe
    // signature, so this test is the canary.
    let probes = collect_probes();
    assert_eq!(probes.len(), 6, "expected six probes in the cross-family bundle");
}

#[test]
fn every_probe_returns_a_distinct_canary() {
    let probes = collect_probes();
    let canaries: std::collections::HashSet<String> = probes
        .iter()
        .map(|p| p.canary().token.clone())
        .collect();
    // The very point of the per-probe canary is unique correlation;
    // six independent constructions must produce six distinct tokens.
    assert_eq!(canaries.len(), probes.len(), "canaries must be unique per probe");
}

#[test]
fn every_probe_returns_non_empty_technique_identifier() {
    let probes = collect_probes();
    for p in &probes {
        let t = p.technique();
        assert!(!t.is_empty(), "technique() must be non-empty");
        // Every technique must follow the documented `family.variant`
        // convention so downstream telemetry can group by `family`.
        assert!(
            t.contains('.'),
            "technique {t:?} missing family.variant separator"
        );
    }
}

#[test]
fn family_identifiers_partition_into_three_distinct_namespaces() {
    let probes = collect_probes();
    let families: std::collections::HashSet<String> = probes
        .iter()
        .map(|p| {
            p.technique()
                .split('.')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .collect();
    // Three distinct families across the six probes.
    assert!(families.contains("cookie"));
    assert!(families.contains("auth"));
    assert!(families.contains("range"));
    assert_eq!(families.len(), 3, "expected three family namespaces");
}

#[test]
fn every_header_artifact_has_at_least_one_pair() {
    // All three encoding-crate probe families produce
    // `SmuggleArtifact::Headers`. A regression where the artifact
    // shape switched to BodyWithContentType or Frames would surface
    // here.
    let probes = collect_probes();
    for p in &probes {
        match p.artifact() {
            SmuggleArtifact::Headers(hs) => {
                assert!(
                    !hs.is_empty(),
                    "headers artifact must carry at least one pair for {}",
                    p.technique()
                );
            }
            other => panic!(
                "expected Headers artifact for {}, got {other:?}",
                p.technique()
            ),
        }
    }
}

#[test]
fn wire_byte_count_is_positive_for_every_probe() {
    let probes = collect_probes();
    for p in &probes {
        let n = p.artifact().wire_byte_count();
        assert!(
            n > 0,
            "wire_byte_count must be > 0 for {} (got {n})",
            p.technique()
        );
    }
}

#[test]
fn duplicate_header_variant_emits_two_pairs_with_same_name() {
    let p = AuthSmuggleProbe::duplicate_header_first_wins_benign(
        "Authorization",
        "Bearer",
        "benign",
        "smuggle",
    );
    let artifact = p.artifact();
    let SmuggleArtifact::Headers(hs) = artifact else {
        panic!("expected Headers artifact for duplicate-header variant");
    };
    assert_eq!(hs.len(), 2);
    assert_eq!(hs[0].0, "Authorization");
    assert_eq!(hs[1].0, "Authorization");
}

#[test]
fn compose_real_cookie_plus_auth_plus_range_into_one_request() {
    // The headline operator workflow: chain three independent
    // header-injection probes into one outbound request that
    // exercises three parser-differential surfaces simultaneously.
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let auth = AuthSmuggleProbe::lowercase_scheme("Authorization", "Bearer", "stolen-token");
    let range = RangeSmuggleProbe::over_large_last_position();

    let probes: Vec<&dyn SmuggleProbe> = vec![&cookie, &auth, &range];
    let composed = compose_artifacts(&probes);

    // Three independent header lines, each contributed by one probe.
    assert_eq!(composed.headers.len(), 3, "headers: {:?}", composed.headers);
    let header_names: std::collections::HashSet<&str> =
        composed.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(header_names.contains("Cookie"));
    assert!(header_names.contains("Authorization"));
    assert!(header_names.contains("Range"));

    // No body or frames — all three probes are header-shaped.
    assert!(composed.body.is_none());
    assert!(composed.frames.is_empty());

    // Three techniques tagged in input order so the operator can
    // reconstruct attribution.
    assert_eq!(composed.techniques.len(), 3);
    assert!(composed.techniques[0].starts_with("cookie."));
    assert!(composed.techniques[1].starts_with("auth."));
    assert!(composed.techniques[2].starts_with("range."));
}

#[test]
fn compose_header_plus_real_multipart_body() {
    // The headline depth-deepening test: chain a real CookieSmuggleProbe
    // (header artifact) with a real multipart smuggle ContentTypeVariant
    // (body artifact). One request, header AND body probes, both
    // attributable via per-probe canaries.
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let params = vec![
        ("user".to_string(), "admin".to_string()),
        ("token".to_string(), "smuggled".to_string()),
    ];
    let multipart_variants = generate_smuggle_variants(&params);
    let multipart: &ContentTypeVariant =
        multipart_variants.first().expect("multipart sweep emits >=1");

    let probes: Vec<&dyn SmuggleProbe> = vec![&cookie, multipart];
    let composed = compose_artifacts(&probes);

    // One Cookie header, one body. Both per-probe canaries are
    // still recoverable from the original probe instances.
    assert_eq!(composed.headers.len(), 1, "exactly one Cookie header line");
    let (ct, body) = composed.body.as_ref().expect("multipart body present");
    assert!(ct.starts_with("multipart/"), "body CT must be multipart, got: {ct}");
    assert!(!body.is_empty(), "multipart body must be non-empty");

    // Techniques tagged in input order, families come from the right
    // crates.
    assert_eq!(composed.techniques.len(), 2);
    assert!(composed.techniques[0].starts_with("cookie."));
    assert!(composed.techniques[1].starts_with("content-type."));

    // Per-probe canaries are still attributable post-compose.
    assert_eq!(cookie.canary().token.len(), 16);
    assert_eq!(multipart.canary().token.len(), 16);
    assert_ne!(
        cookie.canary().token,
        multipart.canary().token,
        "the two probes' canaries must remain independent after composition"
    );
}

#[test]
fn content_type_variant_artifact_is_body_with_content_type() {
    // Anti-rig: the multipart ContentTypeVariant MUST emit a
    // BodyWithContentType artifact (not Headers, not Frames) so
    // composition routes it correctly. A regression that flipped
    // the artifact variant would silently misroute the body bytes.
    let params = vec![("k".into(), "v".into())];
    let variants = generate_smuggle_variants(&params);
    for v in &variants {
        match v.artifact() {
            SmuggleArtifact::BodyWithContentType { content_type, body } => {
                assert!(content_type.starts_with("multipart/"));
                assert!(!body.is_empty());
            }
            other => panic!(
                "ContentTypeVariant {} produced wrong artifact shape: {:?}",
                v.technique(),
                other
            ),
        }
    }
}

#[test]
fn compose_duplicate_header_probes_preserves_all_header_lines() {
    // The duplicate-header variants (cookie + auth + range each have
    // one) emit MULTIPLE Cookie / Authorization / Range lines per
    // probe. Composition must preserve every line — collapsing
    // duplicates would defeat the whole point of those variants.
    let auth_dup = AuthSmuggleProbe::duplicate_header_first_wins_benign(
        "Authorization",
        "Bearer",
        "benign-token",
        "smuggle-token",
    );
    let range_dup = RangeSmuggleProbe::duplicate_header_first_wins_benign("bytes=100-199");

    let probes: Vec<&dyn SmuggleProbe> = vec![&auth_dup, &range_dup];
    let composed = compose_artifacts(&probes);

    // auth_dup contributes 2 Authorization lines + range_dup
    // contributes 2 Range lines = 4 total.
    assert_eq!(composed.headers.len(), 4);
    let auth_count = composed
        .headers
        .iter()
        .filter(|(n, _)| n == "Authorization")
        .count();
    let range_count = composed
        .headers
        .iter()
        .filter(|(n, _)| n == "Range")
        .count();
    assert_eq!(auth_count, 2, "duplicate Authorization preserved");
    assert_eq!(range_count, 2, "duplicate Range preserved");
}

#[test]
fn path_family_implements_trait_object_safely() {
    // Same canary test as `trait_is_object_safe_across_all_three_families`
    // but for the path-normalization family. If PathSmuggleProbe stops
    // being object-safe (e.g. someone adds a generic method to the
    // trait without making it Self: Sized) the compiler rejects this
    // expression and the test fails at build time, not test time.
    let probes: Vec<Box<dyn SmuggleProbe>> = vec![
        Box::new(PathSmuggleProbe::new(
            PathNormalizeTechnique::DotSegmentEncoded,
            "/admin",
        )),
        Box::new(PathSmuggleProbe::new(
            PathNormalizeTechnique::DoubleEncodedDotSegment,
            "/admin",
        )),
        Box::new(PathSmuggleProbe::new(
            PathNormalizeTechnique::OverlongUtf8Slash,
            "/admin",
        )),
    ];
    assert_eq!(probes.len(), 3);
    for p in &probes {
        assert!(p.technique().starts_with("path."));
        assert!(!p.description().is_empty());
        assert_eq!(p.canary().token.len(), 16);
    }
}

#[test]
fn compose_cookie_plus_path_chains_into_one_request() {
    // Real operator chain: forge a session cookie + request the
    // protected path through a normalization-bypass encoding. One
    // request, two parser-differential surfaces — the headline value
    // proposition of the path family.
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let path = PathSmuggleProbe::new(
        PathNormalizeTechnique::DotSegmentEncoded,
        "/admin",
    );
    let probes: Vec<&dyn SmuggleProbe> = vec![&cookie, &path];
    let composed = compose_artifacts(&probes);

    // Two header lines: one Cookie, one :path.
    assert_eq!(composed.headers.len(), 2);
    let header_names: std::collections::HashSet<&str> =
        composed.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(header_names.contains("Cookie"));
    assert!(header_names.contains(":path"));

    // No body or frames.
    assert!(composed.body.is_none());
    assert!(composed.frames.is_empty());

    // Techniques tagged in input order.
    assert_eq!(composed.techniques.len(), 2);
    assert!(composed.techniques[0].starts_with("cookie."));
    assert!(composed.techniques[1].starts_with("path."));
}

#[test]
fn path_artifact_value_carries_encoded_dot_dot() {
    // Anti-rig: the path-family artifact must actually contain the
    // encoded traversal payload — a regression that defaulted the
    // path string to the protected_path verbatim would silently
    // defeat the whole bypass.
    let p = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/admin");
    if let SmuggleArtifact::Headers(hs) = p.artifact() {
        let (name, value) = &hs[0];
        assert_eq!(name, ":path");
        assert!(
            value.contains("%2e%2e"),
            "path artifact must encode the traversal: {value}"
        );
    } else {
        panic!("path probe must emit Headers artifact");
    }
}

#[test]
fn path_family_canaries_are_unique_per_variant() {
    use std::collections::HashSet;
    let variants = wafrift_encoding::path_normalize_smuggle::all_variants("/admin");
    let tokens: HashSet<String> = variants.iter().map(|p| p.canary().token.clone()).collect();
    assert_eq!(
        tokens.len(),
        variants.len(),
        "every path variant must carry a distinct canary"
    );
}

#[test]
fn json_family_implements_trait_object_safely() {
    let probes: Vec<Box<dyn SmuggleProbe>> = vec![
        Box::new(JsonSmuggleProbe::new(
            JsonSmuggleTechnique::DuplicateKeyLastWins,
            &[("role".to_string(), "admin".to_string())],
        )),
        Box::new(JsonSmuggleProbe::new(
            JsonSmuggleTechnique::BomPrefix,
            &[("role".to_string(), "admin".to_string())],
        )),
        Box::new(JsonSmuggleProbe::new(
            JsonSmuggleTechnique::JsonInString,
            &[("role".to_string(), "admin".to_string())],
        )),
    ];
    assert_eq!(probes.len(), 3);
    for p in &probes {
        assert!(p.technique().starts_with("json."));
        assert!(!p.description().is_empty());
        assert_eq!(p.canary().token.len(), 16);
    }
}

#[test]
fn json_family_artifact_is_body_with_application_json_content_type() {
    // Anti-rig: a regression that switched JSON probes to Headers
    // or Frames artifacts would silently misroute the body bytes.
    let p = JsonSmuggleProbe::new(
        JsonSmuggleTechnique::DuplicateKeyLastWins,
        &[("role".to_string(), "admin".to_string())],
    );
    match p.artifact() {
        SmuggleArtifact::BodyWithContentType { content_type, body } => {
            assert_eq!(content_type, "application/json");
            assert!(!body.is_empty());
        }
        other => panic!("json probe must emit BodyWithContentType, got {other:?}"),
    }
}

#[test]
fn compose_cookie_plus_path_plus_json_into_one_request() {
    // Three-way composition spanning header (cookie), header
    // (:path), and body (JSON) — the full operator chain. One
    // request, three parser-differential surfaces, three
    // independent canaries preserved.
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let path = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/admin");
    let json = JsonSmuggleProbe::new(
        JsonSmuggleTechnique::DuplicateKeyLastWins,
        &[("role".to_string(), "admin".to_string())],
    );
    let probes: Vec<&dyn SmuggleProbe> = vec![&cookie, &path, &json];
    let composed = compose_artifacts(&probes);

    // Two headers (Cookie + :path).
    assert_eq!(composed.headers.len(), 2);
    // One body (JSON).
    let (ct, body) = composed.body.as_ref().expect("json body present");
    assert_eq!(ct, "application/json");
    assert!(!body.is_empty());

    // Three techniques + three canaries, all distinct and
    // attributable.
    assert_eq!(composed.techniques.len(), 3);
    assert_eq!(composed.canaries.len(), 3);
    assert!(composed.techniques[0].starts_with("cookie."));
    assert!(composed.techniques[1].starts_with("path."));
    assert!(composed.techniques[2].starts_with("json."));
    let token_set: std::collections::HashSet<&String> = composed.canaries.iter().collect();
    assert_eq!(
        token_set.len(),
        3,
        "all three component canaries must remain distinct"
    );
}

#[test]
fn json_duplicate_key_body_contains_both_role_pairs() {
    // Anti-rig: the duplicate-key variant must actually emit two
    // key occurrences. A regression that collapsed to one would
    // defeat the parser-differential.
    let p = JsonSmuggleProbe::new(
        JsonSmuggleTechnique::DuplicateKeyLastWins,
        &[("role".to_string(), "admin".to_string())],
    );
    if let SmuggleArtifact::BodyWithContentType { body, .. } = p.artifact() {
        let body_str = String::from_utf8(body).expect("utf8");
        assert_eq!(
            body_str.matches("\"role\":").count(),
            2,
            "duplicate-key variant must emit two role pairs: {body_str}"
        );
    } else {
        panic!("json probe must emit BodyWithContentType");
    }
}

#[test]
fn host_family_implements_trait_object_safely() {
    let probes: Vec<Box<dyn SmuggleProbe>> = vec![
        Box::new(HostSmuggleProbe::new(
            HostSmuggleTechnique::DuplicateHostHeaderLastWins,
            "admin.example.com",
        )),
        Box::new(HostSmuggleProbe::new(
            HostSmuggleTechnique::HostWithFullwidthDot,
            "admin.example.com",
        )),
        Box::new(HostSmuggleProbe::new(
            HostSmuggleTechnique::HostWithEmbeddedTab,
            "admin.example.com",
        )),
    ];
    assert_eq!(probes.len(), 3);
    for p in &probes {
        assert!(p.technique().starts_with("host."));
        assert!(!p.description().is_empty());
        assert_eq!(p.canary().token.len(), 16);
    }
}

#[test]
fn host_family_artifact_is_headers_with_host_name() {
    let p = HostSmuggleProbe::new(
        HostSmuggleTechnique::HostWithTrailingDot,
        "admin.example.com",
    );
    match p.artifact() {
        SmuggleArtifact::Headers(hs) => {
            assert!(!hs.is_empty());
            assert_eq!(hs[0].0, "Host");
        }
        other => panic!("host probe must emit Headers, got {other:?}"),
    }
}

#[test]
fn compose_host_plus_path_plus_cookie_chains_into_one_request() {
    // Four-way virtual host bypass chain: forge a vhost via Host
    // header, request a path-normalization-bypassed URL, forge a
    // session cookie. One request, three independent
    // parser-differential surfaces.
    let host = HostSmuggleProbe::new(
        HostSmuggleTechnique::DuplicateHostHeaderLastWins,
        "admin.example.com",
    );
    let path = PathSmuggleProbe::new(PathNormalizeTechnique::DotSegmentEncoded, "/admin");
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let probes: Vec<&dyn SmuggleProbe> = vec![&host, &path, &cookie];
    let composed = compose_artifacts(&probes);

    // host emits 2 Host pairs + path emits 1 :path pair + cookie
    // emits 1 Cookie pair = 4 headers total.
    assert_eq!(composed.headers.len(), 4);
    let names: std::collections::HashSet<&str> =
        composed.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains("Host"));
    assert!(names.contains(":path"));
    assert!(names.contains("Cookie"));

    // Three techniques, three canaries.
    assert_eq!(composed.techniques.len(), 3);
    assert_eq!(composed.canaries.len(), 3);
    assert!(composed.techniques[0].starts_with("host."));
    assert!(composed.techniques[1].starts_with("path."));
    assert!(composed.techniques[2].starts_with("cookie."));
}

#[test]
fn host_duplicate_header_emits_two_host_pairs() {
    // Anti-rig: the duplicate-header variant MUST emit two Host
    // entries. A regression that collapses to one defeats the
    // first-vs-last differential entirely.
    let p = HostSmuggleProbe::new(
        HostSmuggleTechnique::DuplicateHostHeaderLastWins,
        "admin.example.com",
    );
    if let SmuggleArtifact::Headers(hs) = p.artifact() {
        let host_count = hs.iter().filter(|(n, _)| n == "Host").count();
        assert_eq!(host_count, 2, "expected two Host headers");
    } else {
        panic!("host probe must emit Headers");
    }
}

#[test]
fn jwt_family_implements_trait_object_safely() {
    let probes: Vec<Box<dyn SmuggleProbe>> = vec![
        Box::new(JwtSmuggleProbe::new(
            JwtSmuggleTechnique::AlgNone,
            "wafrift-test-token",
        )),
        Box::new(JwtSmuggleProbe::new(
            JwtSmuggleTechnique::KidSqlInjection,
            "wafrift-test-token",
        )),
        Box::new(JwtSmuggleProbe::new(
            JwtSmuggleTechnique::PayloadDuplicateKey,
            "wafrift-test-token",
        )),
    ];
    assert_eq!(probes.len(), 3);
    for p in &probes {
        assert!(p.technique().starts_with("jwt."));
        assert!(!p.description().is_empty());
        assert_eq!(p.canary().token.len(), 16);
    }
}

#[test]
fn jwt_family_emits_bearer_authorization_header() {
    let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNone, "wafrift-test-token");
    match p.artifact() {
        SmuggleArtifact::Headers(hs) => {
            assert_eq!(hs.len(), 1);
            assert_eq!(hs[0].0, "Authorization");
            assert!(hs[0].1.starts_with("Bearer "));
        }
        other => panic!("expected Headers, got {other:?}"),
    }
}

#[test]
fn compose_cookie_plus_host_plus_jwt_chains_into_one_request() {
    // Full impersonation chain: forge a Cookie, request a vhost
    // via Host header, smuggle a JWT for auth bypass. Three
    // independent attack surfaces in one request.
    let cookie = CookieSmuggleProbe::duplicate_name_last_wins("session", "guest", "admin");
    let host = HostSmuggleProbe::new(
        HostSmuggleTechnique::DuplicateHostHeaderLastWins,
        "admin.example.com",
    );
    let jwt = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNone, "wafrift-test-token");
    let probes: Vec<&dyn SmuggleProbe> = vec![&cookie, &host, &jwt];
    let composed = compose_artifacts(&probes);

    // cookie emits 1 Cookie + host emits 2 Host + jwt emits 1
    // Authorization = 4 headers.
    assert_eq!(composed.headers.len(), 4);
    let names: std::collections::HashSet<&str> =
        composed.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains("Cookie"));
    assert!(names.contains("Host"));
    assert!(names.contains("Authorization"));

    assert_eq!(composed.techniques.len(), 3);
    assert_eq!(composed.canaries.len(), 3);
    assert!(composed.techniques[0].starts_with("cookie."));
    assert!(composed.techniques[1].starts_with("host."));
    assert!(composed.techniques[2].starts_with("jwt."));
}

#[test]
fn descriptions_are_non_trivial_human_readable_strings() {
    // Anti-rig: a regression that wired `description()` to an empty
    // string or to the technique-id would break operator logs but
    // still pass compile-time checks. Force a length floor.
    let probes = collect_probes();
    for p in &probes {
        let d = p.description();
        assert!(
            d.len() >= 16,
            "description for {} is suspiciously short: {d:?}",
            p.technique()
        );
        // Description must NOT be the same as the technique
        // identifier (those are different surfaces for different
        // audiences — operator log vs telemetry tag).
        assert_ne!(
            d,
            p.technique(),
            "description must differ from technique() for {}",
            p.technique()
        );
    }
}
