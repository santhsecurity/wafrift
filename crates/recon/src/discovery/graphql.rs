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

const INTROSPECTION_QUERY: &str = r#"{
  __schema {
    queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
    mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
    subscriptionType { name fields { name args { name type { name kind ofType { name kind } } } } }
  }
}"#;

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
    if !resp.status().is_success() {
        return Err(DiscoveryError::GraphQlEndpointNotFound {
            url: endpoint.to_string(),
        });
    }
    let json_resp: Value =
        resp.json()
            .await
            .map_err(|_| DiscoveryError::GraphQlEndpointNotFound {
                url: endpoint.to_string(),
            })?;
    parse_introspection_response(&json_resp, endpoint)
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
                url: format!("{}#{}.{}", endpoint, op_kind, field_name),
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
