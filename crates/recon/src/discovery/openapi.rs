//! Parse an `OpenAPI` 2.0 (Swagger) or 3.x JSON spec into wafrift's
//! injection-point graph.
//!
//! For each `paths.<path>.<method>` entry, emit one [`DiscoveredEndpoint`]
//! whose `injection_points` lists every parameter the operation accepts.
//! Body parameters are unpacked from `requestBody.content.<mediaType>`
//! (3.x) or the `body`-typed parameter (2.0). Path templating
//! (`/users/{id}`) maps each `{id}` to a `ParameterLocation::Path` point.

use serde_json::Value;
use thiserror::Error;
use wafrift_types::Method;
use wafrift_types::discovery::{
    DiscoveredEndpoint, DiscoverySource, InjectionPoint, ParameterLocation,
};
use wafrift_types::injection_context::InjectionContext;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Spec parse error at line {line}: {reason}")]
    SpecParseError { line: usize, reason: String },
    #[error("Unsupported OpenAPI version: {version}")]
    UnsupportedVersion { version: String },
    #[error("GraphQL endpoint not found: {url}")]
    GraphQlEndpointNotFound { url: String },
    #[error("Introspection disabled at: {url}")]
    IntrospectionDisabled { url: String },
    #[error("Rate limited, retry after {retry_after}s")]
    RateLimited { retry_after: u64 },
    #[error("Wordlist empty")]
    WordlistEmpty,
    #[error(
        "Discovery input cap exceeded ({what}: {got} > {cap}) — refusing to process hostile-looking spec/response"
    )]
    InputCapExceeded {
        what: &'static str,
        got: usize,
        cap: usize,
    },
}

/// Hard cap on the number of `paths` entries we'll iterate from a
/// single OpenAPI spec. An adversarial / unbounded spec with
/// 100k+ paths × 100 vars each would allocate hundreds of MB of
/// InjectionPoints before producing usable output.
pub const MAX_OPENAPI_PATHS: usize = 10_000;

/// Hard cap on the wordlist length param_miner will spawn tasks for.
/// One task per entry is allocated up-front; a typo'd
/// `--wordlist /dev/urandom` previously caused tens-of-millions of
/// queued futures and OOM'd the process before the Semaphore-limited
/// concurrency could land any actual probes.
pub const MAX_PARAM_WORDLIST: usize = 100_000;

/// Hard cap on the number of GraphQL `args` per field we'll parse.
/// An adversarial introspection response with a million args per
/// operation would otherwise allocate ~120 MB per operation in
/// InjectionPoint structs.
pub const MAX_GRAPHQL_ARGS_PER_FIELD: usize = 1_000;

/// Parse an `OpenAPI` spec (2.0 or 3.x JSON) into discovered endpoints.
///
/// # Errors
///
/// - [`DiscoveryError::SpecParseError`] on malformed JSON.
/// - [`DiscoveryError::UnsupportedVersion`] for `OpenAPI` < 2.0 or
///   anything that lacks both `swagger` and `openapi` version keys.
pub fn from_openapi(spec: &str) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    let root: Value = serde_json::from_str(spec).map_err(|e| DiscoveryError::SpecParseError {
        line: e.line(),
        reason: e.to_string(),
    })?;

    let version_kind = if let Some(v) = root.get("openapi").and_then(Value::as_str) {
        if v.starts_with("3.") {
            VersionKind::V3
        } else {
            return Err(DiscoveryError::UnsupportedVersion {
                version: v.to_string(),
            });
        }
    } else if let Some(v) = root.get("swagger").and_then(Value::as_str) {
        if v.starts_with("2.") {
            VersionKind::V2
        } else {
            return Err(DiscoveryError::UnsupportedVersion {
                version: v.to_string(),
            });
        }
    } else {
        return Err(DiscoveryError::UnsupportedVersion {
            version: "<no openapi/swagger key>".into(),
        });
    };

    // OpenAPI 3.x: prefer `servers[0].url` (absolute URL with scheme
    // and host). Swagger 2.0: synthesize from `schemes[0]` + `host` +
    // `basePath`. Falling back to `basePath` alone is the legacy
    // behaviour and the source of the discover→scan workflow bug:
    // path-only URLs flowed into `scan --from-discovery` which then
    // fired at `https:///login` (empty host). Emit absolute when we
    // can; downstream `scan --from-discovery` also re-joins against
    // `--target` for any remaining relative entries.
    let servers_base = root
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("url"))
        .and_then(Value::as_str)
        .map(|s| s.trim_end_matches('/').to_string());
    let swagger2_base = if servers_base.is_some() {
        None
    } else {
        let host = root.get("host").and_then(Value::as_str);
        let scheme = root
            .get("schemes")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_str)
            .unwrap_or("https");
        let base_path_only = root
            .get("basePath")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_end_matches('/');
        host.map(|h| format!("{scheme}://{h}{base_path_only}"))
    };
    let absolute_base = servers_base.or(swagger2_base);
    let base_path = root
        .get("basePath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_end_matches('/');

    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    if paths.len() > MAX_OPENAPI_PATHS {
        return Err(DiscoveryError::InputCapExceeded {
            what: "openapi.paths",
            got: paths.len(),
            cap: MAX_OPENAPI_PATHS,
        });
    }

    let mut endpoints = Vec::new();
    for (path, ops) in paths {
        let Some(ops) = ops.as_object() else {
            continue;
        };
        let path_level_params = ops.get("parameters").and_then(Value::as_array);
        for (method_str, op) in ops {
            let Some(method) = parse_method(method_str) else {
                continue;
            };
            let url = match &absolute_base {
                Some(base) => format!("{base}{path}"),
                None => format!("{base_path}{path}"),
            };
            let mut points = Vec::new();
            // path-level parameters apply to every operation
            if let Some(arr) = path_level_params {
                for p in arr {
                    if let Some(point) = parameter_to_point(p, version_kind) {
                        points.push(point);
                    }
                }
            }
            // operation-level parameters
            if let Some(arr) = op.get("parameters").and_then(Value::as_array) {
                for p in arr {
                    if let Some(point) = parameter_to_point(p, version_kind) {
                        points.push(point);
                    }
                }
            }
            // 3.x requestBody → unpack content[mediaType].schema.properties
            if version_kind == VersionKind::V3
                && let Some(rb) = op.get("requestBody")
            {
                points.extend(request_body_to_points(rb));
            }
            // path templating: /users/{id} → InjectionPoint id (Path)
            for tpl in extract_path_template_vars(path) {
                if !points.iter().any(|p| p.name == tpl) {
                    points.push(InjectionPoint {
                        name: tpl,
                        location: ParameterLocation::Path,
                        context: InjectionContext::UrlPath,
                        content_type_hint: None,
                        required: true,
                    });
                }
            }
            endpoints.push(DiscoveredEndpoint {
                url,
                method,
                injection_points: points,
                source: DiscoverySource::OpenApi,
            });
        }
    }
    Ok(endpoints)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum VersionKind {
    V2,
    V3,
}

fn parse_method(s: &str) -> Option<Method> {
    match s.to_ascii_uppercase().as_str() {
        "GET" => Some(Method::Get),
        "POST" => Some(Method::Post),
        "PUT" => Some(Method::Put),
        "DELETE" => Some(Method::Delete),
        "PATCH" => Some(Method::Patch),
        "HEAD" => Some(Method::Head),
        "OPTIONS" => Some(Method::Options),
        _ => None, // skip parameters/summary/description/x-* etc.
    }
}

fn parameter_to_point(p: &Value, version: VersionKind) -> Option<InjectionPoint> {
    let name = p.get("name").and_then(Value::as_str)?.to_string();
    let in_str = p.get("in").and_then(Value::as_str)?;
    let required = p.get("required").and_then(Value::as_bool).unwrap_or(false);
    let location = match in_str {
        "query" => ParameterLocation::Query,
        "path" => ParameterLocation::Path,
        "header" => ParameterLocation::Header,
        "cookie" => ParameterLocation::Cookie,
        // 2.0 has `body` as a parameter location; 3.x uses requestBody instead.
        "body" if version == VersionKind::V2 => ParameterLocation::Body,
        "formData" if version == VersionKind::V2 => ParameterLocation::Body,
        _ => return None,
    };
    let context = location_to_default_context(location);
    Some(InjectionPoint {
        name,
        location,
        context,
        content_type_hint: None,
        required,
    })
}

/// F107: per-schema property cap. An adversarial OpenAPI spec with
/// `MAX_OPENAPI_PATHS` paths × an unbounded properties map per body
/// schema would allocate N × 10_000 `InjectionPoint` structs before
/// any caller could react. The sibling GraphQL parser caps args per
/// field at 1_000; mirror that here.
pub const MAX_OPENAPI_PROPS_PER_SCHEMA: usize = 1_000;

fn request_body_to_points(rb: &Value) -> Vec<InjectionPoint> {
    let mut out = Vec::new();
    let Some(content) = rb.get("content").and_then(Value::as_object) else {
        return out;
    };
    for (media_type, mt_obj) in content {
        let context = media_type_to_context(media_type);
        let Some(schema) = mt_obj.get("schema") else {
            continue;
        };
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            // Whole-body injection point — schema with no properties
            // (e.g. a string body or an array body). Emit one point named
            // after the media type.
            out.push(InjectionPoint {
                name: media_type.clone(),
                location: ParameterLocation::Body,
                context,
                content_type_hint: Some(media_type.clone()),
                required: rb.get("required").and_then(Value::as_bool).unwrap_or(false),
            });
            continue;
        };
        let required_set: std::collections::HashSet<String> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // F107: silently truncate at the per-schema cap rather than
        // erroring — request_body_to_points returns a Vec (no Result),
        // and a partial enumeration is still useful for discovery.
        // The cap is high enough that no realistic spec hits it.
        for (prop_name, _) in properties.iter().take(MAX_OPENAPI_PROPS_PER_SCHEMA) {
            out.push(InjectionPoint {
                name: prop_name.clone(),
                location: ParameterLocation::Body,
                context,
                content_type_hint: Some(media_type.clone()),
                required: required_set.contains(prop_name),
            });
        }
        if properties.len() > MAX_OPENAPI_PROPS_PER_SCHEMA {
            tracing::warn!(
                got = properties.len(),
                cap = MAX_OPENAPI_PROPS_PER_SCHEMA,
                media_type = %media_type,
                "OpenAPI body schema exceeded per-schema property cap; truncated"
            );
        }
    }
    out
}

fn media_type_to_context(media_type: &str) -> InjectionContext {
    if media_type.contains("json") {
        InjectionContext::JsonString
    } else if media_type.contains("xml") {
        InjectionContext::XmlText
    } else if media_type.contains("html") {
        InjectionContext::HtmlText
    } else if media_type.contains("multipart/form-data") {
        InjectionContext::MultipartField
    } else if media_type.contains("x-www-form-urlencoded") {
        InjectionContext::UrlQuery
    } else {
        InjectionContext::PlainBody
    }
}

fn location_to_default_context(loc: ParameterLocation) -> InjectionContext {
    match loc {
        ParameterLocation::Query => InjectionContext::UrlQuery,
        ParameterLocation::Path => InjectionContext::UrlPath,
        ParameterLocation::Header => InjectionContext::HeaderValue,
        ParameterLocation::Cookie => InjectionContext::CookieValue,
        ParameterLocation::Body => InjectionContext::PlainBody,
    }
}

fn extract_path_template_vars(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    if !name.is_empty() {
                        out.push(name);
                    }
                    break;
                }
                name.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_json() {
        let err = from_openapi("not json at all").unwrap_err();
        assert!(matches!(err, DiscoveryError::SpecParseError { .. }));
    }

    #[test]
    fn rejects_unknown_version() {
        let err = from_openapi(r#"{"info": {"title": "x"}}"#).unwrap_err();
        assert!(matches!(err, DiscoveryError::UnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_swagger_1_x() {
        let err = from_openapi(r#"{"swagger": "1.2"}"#).unwrap_err();
        assert!(matches!(err, DiscoveryError::UnsupportedVersion { .. }));
    }

    #[test]
    fn parses_openapi_3_query_param() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "required": true},
                            {"name": "limit", "in": "query"}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        assert_eq!(endpoints.len(), 1);
        let ep = &endpoints[0];
        assert_eq!(ep.url, "/search");
        assert_eq!(ep.method, Method::Get);
        assert_eq!(ep.source, DiscoverySource::OpenApi);
        assert_eq!(ep.injection_points.len(), 2);
        let q = ep.injection_points.iter().find(|p| p.name == "q").unwrap();
        assert!(q.required);
        assert_eq!(q.location, ParameterLocation::Query);
    }

    #[test]
    fn parses_openapi_3_request_body_json() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        },
                                        "required": ["name"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        let ep = &endpoints[0];
        assert_eq!(ep.injection_points.len(), 2);
        let name_point = ep
            .injection_points
            .iter()
            .find(|p| p.name == "name")
            .unwrap();
        assert!(name_point.required);
        assert_eq!(name_point.location, ParameterLocation::Body);
        assert_eq!(name_point.context, InjectionContext::JsonString);
        assert_eq!(
            name_point.content_type_hint.as_deref(),
            Some("application/json")
        );
        let email_point = ep
            .injection_points
            .iter()
            .find(|p| p.name == "email")
            .unwrap();
        assert!(!email_point.required);
    }

    #[test]
    fn extracts_path_template_vars_as_injection_points() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}/posts/{postId}": {
                    "get": {}
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        let ep = &endpoints[0];
        assert_eq!(ep.injection_points.len(), 2);
        let id = ep.injection_points.iter().find(|p| p.name == "id").unwrap();
        assert_eq!(id.location, ParameterLocation::Path);
        assert!(id.required);
        assert!(ep.injection_points.iter().any(|p| p.name == "postId"));
    }

    #[test]
    fn parses_swagger_2_with_basepath_and_body() {
        let spec = r#"{
            "swagger": "2.0",
            "basePath": "/api/v1",
            "paths": {
                "/users": {
                    "post": {
                        "parameters": [
                            {"name": "user", "in": "body", "required": true}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        let ep = &endpoints[0];
        assert_eq!(ep.url, "/api/v1/users");
        let body = ep
            .injection_points
            .iter()
            .find(|p| p.name == "user")
            .unwrap();
        assert_eq!(body.location, ParameterLocation::Body);
        assert!(body.required);
    }

    #[test]
    fn skips_unknown_in_locations() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/foo": {
                    "get": {
                        "parameters": [
                            {"name": "x", "in": "query"},
                            {"name": "y", "in": "weirdspot"}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        // Only `x` should make it through; `y` had unknown in location.
        let ep = &endpoints[0];
        assert_eq!(ep.injection_points.len(), 1);
        assert_eq!(ep.injection_points[0].name, "x");
    }

    #[test]
    fn xml_request_body_gets_xml_context() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/raw": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/xml": {
                                    "schema": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        let ep = &endpoints[0];
        assert_eq!(ep.injection_points.len(), 1);
        assert_eq!(ep.injection_points[0].context, InjectionContext::XmlText);
    }

    #[test]
    fn path_level_params_propagate_to_all_methods() {
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/items": {
                    "parameters": [
                        {"name": "tenant", "in": "header"}
                    ],
                    "get": {},
                    "post": {}
                }
            }
        }"#;
        let endpoints = from_openapi(spec).unwrap();
        assert_eq!(endpoints.len(), 2);
        for ep in &endpoints {
            assert!(ep.injection_points.iter().any(|p| p.name == "tenant"));
        }
    }

    #[test]
    fn from_openapi_rejects_over_max_paths_count() {
        // Build a spec with MAX_OPENAPI_PATHS + 1 unique paths.
        let mut paths = String::new();
        for i in 0..=MAX_OPENAPI_PATHS {
            if i > 0 {
                paths.push(',');
            }
            paths.push_str(&format!("\"/p{i}\":{{\"get\":{{}}}}"));
        }
        let spec = format!("{{\"openapi\":\"3.0.0\",\"paths\":{{{paths}}}}}");
        let err = from_openapi(&spec).expect_err("over-cap must reject");
        match err {
            DiscoveryError::InputCapExceeded { what, got, cap } => {
                assert_eq!(what, "openapi.paths");
                assert!(got > cap, "got={got} cap={cap}");
                assert_eq!(cap, MAX_OPENAPI_PATHS);
            }
            other => panic!("expected InputCapExceeded, got {other:?}"),
        }
    }
}
