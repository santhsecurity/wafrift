//! Integration tests for wafrift-types — new modules added in features 1-6.

use wafrift_types::discovery::{
    DiscoveredEndpoint, DiscoverySource, InjectionPoint, ParameterLocation,
};
use wafrift_types::explanation::{DiffHunk, Explanation, ExplanationMode, RuleAttribution};
use wafrift_types::format::BodyFormat;
use wafrift_types::injection_context::{ContextualEncodeError, InjectionContext};
use wafrift_types::oob::{OobCanary, OobConfirmation, OobInteraction, OobProvider};
use wafrift_types::session::{CsrfInjectionLocation, JwtManipulation, SessionConfig};
use wafrift_types::{Method, Technique};

// ── InjectionContext ───────────────────────────────────────────────────────

#[test]
fn injection_context_default_is_plain_body() {
    assert_eq!(InjectionContext::default(), InjectionContext::PlainBody);
}

#[test]
fn injection_context_roundtrip_serde() {
    let ctx = InjectionContext::JsonString;
    let json = serde_json::to_string(&ctx).unwrap();
    let back: InjectionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn all_injection_contexts_serializable() {
    use InjectionContext::*;
    for ctx in [
        JsonString,
        JsonNumber,
        XmlAttribute,
        XmlCdata,
        XmlText,
        HtmlAttribute,
        HtmlText,
        UrlQuery,
        UrlPath,
        UrlFragment,
        HeaderValue,
        CookieValue,
        MultipartField,
        MultipartFileName,
        PlainBody,
    ] {
        let json = serde_json::to_string(&ctx).unwrap();
        let back: InjectionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }
}

// ── ContextualEncodeError ──────────────────────────────────────────────────

#[test]
fn contextual_encode_error_display() {
    let err = ContextualEncodeError::ContextIncompatible {
        strategy: "UnicodeEscape".into(),
        context: InjectionContext::JsonNumber,
        reason: "not a valid number".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("UnicodeEscape"));
    assert!(msg.contains("JsonNumber"));
    assert!(msg.contains("not a valid number"));
}

#[test]
fn contextual_encode_error_serde_roundtrip() {
    let err = ContextualEncodeError::PayloadTooLarge {
        context: InjectionContext::JsonString,
        size: 9999,
        max: 100,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ContextualEncodeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ── SessionConfig ──────────────────────────────────────────────────────────

#[test]
fn session_config_default_csrf_location() {
    let config = SessionConfig {
        cookie_jar_path: None,
        csrf_extract_regex: None,
        csrf_injection: CsrfInjectionLocation::default(),
        auth_header: None,
        jwt_manipulation: None,
        jwt_signing_key: None,
    };
    assert_eq!(config.csrf_injection, CsrfInjectionLocation::Header);
}

#[test]
fn session_config_serde_roundtrip() {
    let config = SessionConfig {
        cookie_jar_path: Some("/tmp/jar.txt".into()),
        csrf_extract_regex: Some(r#"<meta content="([^"]+)""#.into()),
        csrf_injection: CsrfInjectionLocation::Query,
        auth_header: Some("Authorization: Bearer tok".into()),
        jwt_manipulation: Some(JwtManipulation::StripAlg),
        jwt_signing_key: Some("c2VjcmV0".into()),
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: SessionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.cookie_jar_path, back.cookie_jar_path);
    assert_eq!(config.csrf_injection, back.csrf_injection);
    assert_eq!(config.jwt_manipulation, back.jwt_manipulation);
}

#[test]
fn jwt_manipulation_variants_serde() {
    for manipulation in [
        JwtManipulation::StripAlg,
        JwtManipulation::Hs256WithKey,
        JwtManipulation::JwkEmbed {
            jwk: r#"{"kty":"RSA"}"#.into(),
        },
    ] {
        let json = serde_json::to_string(&manipulation).unwrap();
        let back: JwtManipulation = serde_json::from_str(&json).unwrap();
        assert_eq!(manipulation, back);
    }
}

// ── Oob types ──────────────────────────────────────────────────────────────

#[test]
fn oob_provider_serde_roundtrip() {
    let providers = [
        OobProvider::Interactsh {
            server: "oast.pro".into(),
        },
        OobProvider::BurpCollaborator {
            url: "https://collab".into(),
        },
        OobProvider::CustomDns {
            pattern: "$(uuid).cb.example.com".into(),
        },
    ];
    for provider in providers {
        let json = serde_json::to_string(&provider).unwrap();
        let back: OobProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, back);
    }
}

#[test]
fn oob_confirmation_variants() {
    assert_ne!(OobConfirmation::Confirmed, OobConfirmation::Timeout);
    assert_ne!(OobConfirmation::Timeout, OobConfirmation::Error);
}

#[test]
fn oob_canary_serde_without_created_at() {
    let canary = OobCanary {
        id: uuid::Uuid::new_v4(),
        expected_dns: "test.oast.pro".into(),
        expected_http_path: "/oob/123".into(),
        created_at: None,
    };
    let json = serde_json::to_string(&canary).unwrap();
    let back: OobCanary = serde_json::from_str(&json).unwrap();
    assert_eq!(canary.id, back.id);
    assert_eq!(canary.expected_dns, back.expected_dns);
    // created_at is skipped in serialization
    assert!(back.created_at.is_none());
}

#[test]
fn oob_interaction_serde() {
    let interactions = [
        OobInteraction::DnsQuery {
            query: "test.oast.pro".into(),
            source_ip: "1.2.3.4".into(),
        },
        OobInteraction::HttpRequest {
            path: "/oob/123".into(),
            headers: vec![("User-Agent".into(), "curl".into())],
            body: Some("body".into()),
        },
    ];
    for interaction in interactions {
        let json = serde_json::to_string(&interaction).unwrap();
        let back: OobInteraction = serde_json::from_str(&json).unwrap();
        assert_eq!(interaction, back);
    }
}

// ── Discovery types ────────────────────────────────────────────────────────

#[test]
fn discovered_endpoint_serde() {
    let endpoint = DiscoveredEndpoint {
        url: "https://api.example.com/users".into(),
        method: Method::Post,
        injection_points: vec![InjectionPoint {
            name: "username".into(),
            location: ParameterLocation::Body,
            context: InjectionContext::JsonString,
            content_type_hint: Some("application/json".into()),
            required: true,
        }],
        source: DiscoverySource::OpenApi,
    };
    let json = serde_json::to_string(&endpoint).unwrap();
    let back: DiscoveredEndpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(endpoint.url, back.url);
    assert_eq!(endpoint.injection_points.len(), back.injection_points.len());
}

#[test]
fn parameter_location_all_variants() {
    use ParameterLocation::*;
    for loc in [Query, Header, Path, Body, Cookie] {
        let json = serde_json::to_string(&loc).unwrap();
        let back: ParameterLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }
}

// ── Explanation types ──────────────────────────────────────────────────────

#[test]
fn explanation_mode_default_is_standard() {
    assert_eq!(ExplanationMode::default(), ExplanationMode::Standard);
}

#[test]
fn diff_hunk_serde() {
    let hunks = [
        DiffHunk::Equal("same".into()),
        DiffHunk::Delete("removed".into()),
        DiffHunk::Insert("added".into()),
    ];
    for hunk in hunks {
        let json = serde_json::to_string(&hunk).unwrap();
        let back: DiffHunk = serde_json::from_str(&json).unwrap();
        assert_eq!(hunk, back);
    }
}

#[test]
fn rule_attribution_partial_eq() {
    let a = RuleAttribution {
        rule_id: "SQLI-001".into(),
        rule_name: "SQL Union".into(),
        matched_substring: "UNION".into(),
        matched_pattern: r#"(?i)union"#.into(),
        confidence: 0.95,
    };
    let b = RuleAttribution {
        rule_id: "SQLI-001".into(),
        rule_name: "SQL Union".into(),
        matched_substring: "UNION".into(),
        matched_pattern: r#"(?i)union"#.into(),
        confidence: 0.95,
    };
    assert_eq!(a, b);
}

#[test]
fn explanation_full_serde_roundtrip() {
    let explanation = Explanation {
        original_payload: "' OR 1=1--".into(),
        bypass_payload: "' OR 1=1/**/--".into(),
        technique_chain: vec![Technique::GrammarMutation("sql".into())],
        triggered_rules: vec![RuleAttribution {
            rule_id: "SQLI-001".into(),
            rule_name: "SQL Union".into(),
            matched_substring: "OR".into(),
            matched_pattern: r#"(?i)or"#.into(),
            confidence: 0.95,
        }],
        diff: vec![
            DiffHunk::Equal("' ".into()),
            DiffHunk::Delete("OR".into()),
            DiffHunk::Insert("OR 1=1/**/".into()),
        ],
        human_summary: "Bypass explanation".into(),
        mode: ExplanationMode::Standard,
    };
    let json = serde_json::to_string(&explanation).unwrap();
    let back: Explanation = serde_json::from_str(&json).unwrap();
    assert_eq!(explanation.original_payload, back.original_payload);
    assert_eq!(
        explanation.technique_chain.len(),
        back.technique_chain.len()
    );
}

// ── BodyFormat ─────────────────────────────────────────────────────────────

#[test]
fn body_format_all_variants_serde() {
    use BodyFormat::*;
    for format in [Json, Xml, Multipart, Protobuf, MessagePack, GrpcWeb, Raw] {
        let json = serde_json::to_string(&format).unwrap();
        let back: BodyFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(format, back);
    }
}
