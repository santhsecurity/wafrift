//! GraphQL introspection — POST `__schema { queryType / mutationType /
//! subscriptionType { fields { name args { name type { ... } } } } }`
//! and convert each top-level operation field into a discovered endpoint
//! with its arguments as injection points.
//!
//! GraphQL's transport is a single URL with all operations multiplexed
//! over it, so every emitted endpoint shares the same `url` and uses
//! `POST` (the canonical transport).

use crate::discovery::openapi::DiscoveryError;
use serde_json::{Value, json};
use wafrift_types::Method;
use wafrift_types::discovery::{
    DiscoveredEndpoint, DiscoverySource, InjectionPoint, ParameterLocation,
};
use wafrift_types::injection_context::InjectionContext;

const INTROSPECTION_QUERY: &str = r"{
  __schema {
    queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
    mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
    subscriptionType { name fields { name args { name type { name kind ofType { name kind } } } } }
  }
}";

/// Probe a GraphQL endpoint via introspection and emit one
/// [`DiscoveredEndpoint`] per top-level field on Query / Mutation /
/// Subscription, with each field's args as `Body` injection points.
///
/// # Errors
///
/// - [`DiscoveryError::IntrospectionDisabled`] if the server returned
///   an error response or no `__schema` data (introspection-disabled
///   GraphQL servers commonly return `{"errors": [...]}`).
/// - [`DiscoveryError::GraphQlEndpointNotFound`] on transport error
///   or non-2xx HTTP response.
pub async fn from_graphql(
    endpoint: &str,
    client: &reqwest::Client,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    let body = json!({ "query": INTROSPECTION_QUERY });
    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|_| DiscoveryError::GraphQlEndpointNotFound {
            url: endpoint.to_string(),
        })?;
    // F128: Many GraphQL servers reject introspection with a 4xx (often
    // 400 or 403) AND `{"errors":[{"message":"introspection is not
    // allowed"}]}` in the body. Pre-fix any non-2xx mapped to
    // GraphQlEndpointNotFound — operator saw "wrong URL" when the URL
    // was correct and only introspection was off. Peek at the body for
    // an `errors` array before deciding which classification to return.
    let status_ok = resp.status().is_success();
    // §15 decompression-bomb defence: reqwest auto-decompresses gzip/br with
    // NO size cap, so a hostile endpoint can answer a tiny introspection
    // query with a ~1 KB bomb that expands to gigabytes and OOMs the
    // scanner. Read chunk-by-chunk and stop at a generous cap — even a huge
    // real introspection schema is single-digit MB, so 16 MiB sits far above
    // any legitimate response while staying laptop-safe. Mirrors the sibling
    // bounded reads (lib.rs `CT_RESPONSE_MAX_BYTES`, active/http.rs
    // `DRAIN_CAP`, param_miner `read_bounded_len`).
    const INTROSPECTION_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;
    let mut resp = resp;
    let mut bytes: Vec<u8> = Vec::with_capacity(64 * 1024);
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > INTROSPECTION_RESPONSE_MAX_BYTES {
                    // An oversized response to a tiny introspection query is
                    // not a usable GraphQL endpoint — refuse rather than
                    // buffer the bomb (same `GraphQlEndpointNotFound` bucket
                    // the transport/parse failures below already use).
                    return Err(DiscoveryError::GraphQlEndpointNotFound {
                        url: endpoint.to_string(),
                    });
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(DiscoveryError::GraphQlEndpointNotFound {
                    url: endpoint.to_string(),
                });
            }
        }
    }
    if !status_ok {
        return Err(classify_non_success_response(&bytes, endpoint));
    }
    let json_resp: Value =
        serde_json::from_slice(&bytes).map_err(|_| DiscoveryError::GraphQlEndpointNotFound {
            url: endpoint.to_string(),
        })?;
    parse_introspection_response(&json_resp, endpoint)
}

/// Classify a non-2xx GraphQL response. Body is the response bytes
/// (may or may not be valid JSON). Returns the appropriate
/// `DiscoveryError` — `IntrospectionDisabled` when the body parses as
/// JSON containing the standard `errors` array (the introspection-off
/// pattern), `GraphQlEndpointNotFound` otherwise. Pure / testable.
pub fn classify_non_success_response(
    body: &[u8],
    endpoint: &str,
) -> DiscoveryError {
    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        return DiscoveryError::GraphQlEndpointNotFound {
            url: endpoint.to_string(),
        };
    };
    if json.get("errors").and_then(Value::as_array).is_some() {
        DiscoveryError::IntrospectionDisabled {
            url: endpoint.to_string(),
        }
    } else {
        DiscoveryError::GraphQlEndpointNotFound {
            url: endpoint.to_string(),
        }
    }
}

/// Pure parsing helper — split out so unit tests don't need a live server.
pub fn parse_introspection_response(
    response: &Value,
    endpoint: &str,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    let Some(schema) = response.pointer("/data/__schema") else {
        return Err(DiscoveryError::IntrospectionDisabled {
            url: endpoint.to_string(),
        });
    };
    let mut endpoints = Vec::new();
    for op_kind in &["queryType", "mutationType", "subscriptionType"] {
        let Some(fields) = schema
            .get(op_kind)
            .and_then(|t| t.get("fields"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for field in fields {
            let Some(field_name) = field.get("name").and_then(Value::as_str) else {
                continue;
            };
            let mut points = Vec::new();
            if let Some(args) = field.get("args").and_then(Value::as_array) {
                // Cap defends against an adversarial introspection
                // response that lists a million args per operation —
                // each would allocate an InjectionPoint (~120 bytes)
                // and OOM the process well before any real probe.
                if args.len() > super::openapi::MAX_GRAPHQL_ARGS_PER_FIELD {
                    return Err(super::openapi::DiscoveryError::InputCapExceeded {
                        what: "graphql.field.args",
                        got: args.len(),
                        cap: super::openapi::MAX_GRAPHQL_ARGS_PER_FIELD,
                    });
                }
                for arg in args {
                    let Some(arg_name) = arg.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    // GraphQL arg type: `kind: NON_NULL` => required.
                    let required = arg
                        .get("type")
                        .and_then(|t| t.get("kind"))
                        .and_then(Value::as_str)
                        == Some("NON_NULL");
                    points.push(InjectionPoint {
                        name: arg_name.to_string(),
                        location: ParameterLocation::Body,
                        context: InjectionContext::JsonString,
                        content_type_hint: Some("application/json".to_string()),
                        required,
                    });
                }
            }
            endpoints.push(DiscoveredEndpoint {
                url: format!("{endpoint}#{op_kind}.{field_name}"),
                method: Method::Post,
                injection_points: points,
                source: DiscoverySource::GraphQlIntrospection,
            });
        }
    }
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_fields() {
        let resp = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": {
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "args": [
                                    {"name": "id", "type": {"kind": "NON_NULL"}}
                                ]
                            },
                            {
                                "name": "search",
                                "args": [
                                    {"name": "q", "type": {"kind": "SCALAR"}},
                                    {"name": "limit", "type": {"kind": "SCALAR"}}
                                ]
                            }
                        ]
                    }
                }
            }
        });
        let eps = parse_introspection_response(&resp, "https://api.example.com/graphql").unwrap();
        assert_eq!(eps.len(), 2);
        let user = eps.iter().find(|e| e.url.ends_with("user")).unwrap();
        assert_eq!(user.injection_points.len(), 1);
        assert!(user.injection_points[0].required);
        assert_eq!(
            user.injection_points[0].context,
            InjectionContext::JsonString
        );
        let search = eps.iter().find(|e| e.url.ends_with("search")).unwrap();
        assert_eq!(search.injection_points.len(), 2);
        assert!(!search.injection_points[0].required); // SCALAR (not NON_NULL)
    }

    #[test]
    fn detects_introspection_disabled() {
        let resp = serde_json::json!({
            "errors": [{"message": "GraphQL introspection is not allowed"}]
        });
        let err =
            parse_introspection_response(&resp, "https://api.example.com/graphql").unwrap_err();
        assert!(matches!(err, DiscoveryError::IntrospectionDisabled { .. }));
    }

    #[test]
    fn handles_mutations_and_subscriptions() {
        let resp = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query", "fields": []},
                    "mutationType": {
                        "name": "Mutation",
                        "fields": [
                            {"name": "createUser", "args": [
                                {"name": "input", "type": {"kind": "NON_NULL"}}
                            ]}
                        ]
                    },
                    "subscriptionType": {
                        "name": "Subscription",
                        "fields": [
                            {"name": "userUpdated", "args": []}
                        ]
                    }
                }
            }
        });
        let eps = parse_introspection_response(&resp, "https://x").unwrap();
        assert_eq!(eps.len(), 2);
        assert!(
            eps.iter()
                .any(|e| e.url.contains("mutationType.createUser"))
        );
        assert!(
            eps.iter()
                .any(|e| e.url.contains("subscriptionType.userUpdated"))
        );
        assert!(eps.iter().all(|e| e.method == Method::Post));
        assert!(
            eps.iter()
                .all(|e| e.source == DiscoverySource::GraphQlIntrospection)
        );
    }

    #[test]
    fn missing_field_skips_silently() {
        let resp = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": {
                        "name": "Query",
                        "fields": [
                            {"args": []}, // no name → skip
                            {"name": "valid", "args": []}
                        ]
                    }
                }
            }
        });
        let eps = parse_introspection_response(&resp, "https://x").unwrap();
        assert_eq!(eps.len(), 1);
        assert!(eps[0].url.ends_with("valid"));
    }

    /// §15 anti-rig: the introspection body read must stay byte-bounded
    /// (a `.chunk()` loop enforcing a cap), never reqwest's unbounded
    /// auto-decompressing whole-body read — a hostile endpoint can answer a
    /// tiny introspection query with a gzip bomb. A future "simplification"
    /// back to the raw form is a decompression-bomb regression and must fail
    /// here. (Mirrors the sibling `recon_http_body_drain_is_bounded`.)
    #[test]
    fn graphql_introspection_read_is_bounded() {
        let src = include_str!("graphql.rs");
        assert!(
            src.contains("resp.chunk().await"),
            "introspection body must drain via a bounded .chunk() loop"
        );
        assert!(
            src.contains("INTROSPECTION_RESPONSE_MAX_BYTES"),
            "introspection read must reference the byte cap constant"
        );
        // Old unbounded pattern must be absent (assembled via concat! so the
        // banned literal doesn't appear in source and self-trip the check).
        let banned = concat!("resp.", "bytes().", "await");
        assert!(
            !src.contains(banned),
            "introspection read must not use unbounded .bytes().await — \
             decompression-bomb regression"
        );
    }

    // F128 regression: a 4xx response with `{"errors":[...]}` is the
    // introspection-disabled pattern (most GraphQL servers reject the
    // request with 400 or 403 + the standard errors body). Pre-fix
    // mapped every non-2xx to GraphQlEndpointNotFound — operator
    // chasing a "wrong URL" they actually had correct.
    #[test]
    fn classify_400_with_errors_body_is_introspection_disabled() {
        let body =
            br#"{"errors":[{"message":"GraphQL introspection is not allowed"}]}"#;
        let err = classify_non_success_response(body, "https://api.example.com/graphql");
        assert!(matches!(err, DiscoveryError::IntrospectionDisabled { .. }));
    }

    #[test]
    fn classify_403_with_errors_body_is_introspection_disabled() {
        let body = br#"{"errors":[{"message":"forbidden"}]}"#;
        let err = classify_non_success_response(body, "https://x/graphql");
        assert!(matches!(err, DiscoveryError::IntrospectionDisabled { .. }));
    }

    #[test]
    fn classify_html_404_body_is_endpoint_not_found() {
        // A 404 with an HTML body (not JSON) means the URL is wrong.
        let body = b"<html><body>404 Not Found</body></html>";
        let err = classify_non_success_response(body, "https://x/wrong");
        assert!(matches!(err, DiscoveryError::GraphQlEndpointNotFound { .. }));
    }

    #[test]
    fn classify_json_without_errors_field_is_endpoint_not_found() {
        // 500 with a JSON body that doesn't carry the standard
        // GraphQL `errors` shape — could be anything; treat as
        // wrong-URL rather than incorrectly claiming introspection
        // was the issue.
        let body = br#"{"message":"server error"}"#;
        let err = classify_non_success_response(body, "https://x/graphql");
        assert!(matches!(err, DiscoveryError::GraphQlEndpointNotFound { .. }));
    }

    #[test]
    fn classify_errors_present_but_not_array_is_endpoint_not_found() {
        // GraphQL spec requires `errors` to be an array. A scalar at
        // that key is malformed and not the introspection-off signal.
        let body = br#"{"errors":"oops"}"#;
        let err = classify_non_success_response(body, "https://x/graphql");
        assert!(matches!(err, DiscoveryError::GraphQlEndpointNotFound { .. }));
    }

    #[test]
    fn classify_empty_body_is_endpoint_not_found() {
        let err = classify_non_success_response(b"", "https://x/graphql");
        assert!(matches!(err, DiscoveryError::GraphQlEndpointNotFound { .. }));
    }

    #[test]
    fn classify_url_is_echoed_in_either_error_variant() {
        let intro =
            classify_non_success_response(br#"{"errors":[]}"#, "https://t/intro-off");
        match intro {
            DiscoveryError::IntrospectionDisabled { url } => {
                assert_eq!(url, "https://t/intro-off");
            }
            _ => panic!("wrong variant"),
        }
        let notfound = classify_non_success_response(b"<html/>", "https://t/wrong-url");
        match notfound {
            DiscoveryError::GraphQlEndpointNotFound { url } => {
                assert_eq!(url, "https://t/wrong-url");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn empty_schema_returns_empty_vec() {
        let resp = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": null,
                    "mutationType": null,
                    "subscriptionType": null
                }
            }
        });
        let eps = parse_introspection_response(&resp, "https://x").unwrap();
        assert!(eps.is_empty());
    }
}
