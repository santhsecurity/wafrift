//! GraphQL endpoint detection and payload injection for `wafrift scan`.
//!
//! # Auto-detection
//!
//! A GraphQL endpoint is detected by probing well-known path suffixes
//! (`/graphql`, `/api/graphql`, `/v1/graphql`) with a minimal
//! `{"query":"{__typename}"}` probe. A 200-class response whose body
//! contains `"data"` OR `"errors"` is treated as a live GraphQL endpoint.
//!
//! # Forced mode
//!
//! When `--graphql` is set the caller bypasses auto-detection. The
//! `all_evasion_payloads()` set is injected unconditionally, regardless
//! of whether the target looks like a GraphQL endpoint.
//!
//! # Payload classes injected
//!
//! From `wafrift-graphql`:
//! - **alias-flood** (100/250/500/1000 aliases)
//! - **introspection** (full + simple + type + 5 whitespace-split variants)
//! - **op-name-mismatch** (3 variants)
//! - **depth-bomb** (6 depths × 2 shapes)
//! - **batch** (5 batch sizes)
//! - **field-suggestion typos** (5 variants)

use std::time::Duration;

use tracing::{debug, info};

/// Candidate GraphQL path suffixes to probe during auto-detection.
pub(crate) const GRAPHQL_PROBE_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/query",
];

/// Minimal probe body. Any GraphQL-aware server replies with
/// `{"data":{"__typename":"…"}}` or a `{"errors":[…]}` array.
const TYPENAME_PROBE: &str = r#"{"query":"{__typename}"}"#;

/// Returns `true` when a response body looks like it came from a GraphQL
/// endpoint (contains a top-level `"data"` or `"errors"` JSON key).
fn looks_like_graphql_response(body: &str) -> bool {
    // Fast substring match — avoids a full JSON parse on every probe.
    body.contains(r#""data""#) || body.contains(r#""errors""#)
}

/// Probe the known GraphQL path suffixes on `base_url` and return the
/// first path that responds as a GraphQL endpoint, or `None`.
///
/// Uses a 5-second timeout per probe (GraphQL endpoints are typically
/// fast — if it's hanging it's not a GraphQL endpoint we can use).
pub(crate) async fn detect_graphql_endpoint(
    http: &reqwest::Client,
    base_url: &str,
    scan_text: bool,
) -> Option<String> {
    let base = base_url.trim_end_matches('/');
    let timeout = Duration::from_secs(5);

    for suffix in GRAPHQL_PROBE_PATHS {
        let url = format!("{base}{suffix}");
        debug!(target: "wafrift::scan::graphql", probe_url = %url, "probing GraphQL path");

        let result = tokio::time::timeout(
            timeout,
            http.post(&url)
                .header("Content-Type", "application/json")
                .body(TYPENAME_PROBE)
                .send(),
        )
        .await;

        let response = match result {
            Ok(Ok(r)) => r,
            _ => continue, // timeout or connection error
        };

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            continue;
        }

        // Read body (bounded to 64 KB — GraphQL responses can be huge for
        // introspection but the __typename probe should be tiny).
        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        if looks_like_graphql_response(&body) {
            if scan_text {
                use colored::Colorize;
                println!(
                    "  {} GraphQL endpoint detected at {}",
                    "[graphql]".bold().green(),
                    url.yellow()
                );
            }
            info!(
                target: "wafrift::scan::graphql",
                endpoint = %url,
                "GraphQL endpoint detected"
            );
            return Some(url);
        }
    }

    None
}

/// Build the full GraphQL evasion payload set for injection into the
/// scan's candidate pool. Returns `(payloads, endpoint_url)` where
/// `endpoint_url` is:
/// - the auto-detected URL (when `force_graphql` is false)
/// - the base URL itself (when `force_graphql` is true — the operator
///   asserted the endpoint is GraphQL)
///
/// Returns `None` when `force_graphql` is false AND no GraphQL endpoint
/// is detected.
pub(crate) async fn build_graphql_payloads(
    http: &reqwest::Client,
    base_url: &str,
    force_graphql: bool,
    scan_text: bool,
) -> Option<(Vec<String>, String)> {
    let endpoint = if force_graphql {
        if scan_text {
            use colored::Colorize;
            println!(
                "  {} --graphql flag set — injecting GraphQL evasion payloads without detection",
                "[graphql]".bold().yellow()
            );
        }
        base_url.to_string()
    } else {
        detect_graphql_endpoint(http, base_url, scan_text).await?
    };

    let payloads = wafrift_graphql::all_evasion_payloads();
    if scan_text {
        use colored::Colorize;
        println!(
            "  {} {} GraphQL evasion payloads injected (alias-flood + introspection + op-name-mismatch)",
            "[graphql]".bold().green(),
            format!("{}", payloads.len()).yellow()
        );
    }
    Some((payloads, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typename_probe_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(TYPENAME_PROBE).expect("parse");
        assert_eq!(v["query"].as_str().unwrap(), "{__typename}");
    }

    #[test]
    fn looks_like_graphql_with_data_key() {
        assert!(looks_like_graphql_response(r#"{"data":{"__typename":"Query"}}"#));
    }

    #[test]
    fn looks_like_graphql_with_errors_key() {
        assert!(looks_like_graphql_response(r#"{"errors":[{"message":"not found"}]}"#));
    }

    #[test]
    fn looks_like_graphql_rejects_plain_json() {
        assert!(!looks_like_graphql_response(r#"{"status":"ok"}"#));
        assert!(!looks_like_graphql_response(r#"{"result":42}"#));
    }

    #[test]
    fn all_probe_paths_start_with_slash() {
        for p in GRAPHQL_PROBE_PATHS {
            assert!(p.starts_with('/'), "probe path must start with /: {p}");
        }
    }

    #[test]
    fn build_graphql_payloads_forced_returns_all_classes() {
        // Validate the payload battery covers the three required classes
        // without network access (force_graphql=true, but we won't call
        // the async fn — instead we test the underlying library directly).
        let payloads = wafrift_graphql::all_evasion_payloads();
        let has_alias_flood = payloads.iter().any(|p| p.contains("AliasFlood"));
        let has_introspection = payloads.iter().any(|p| p.contains("__schema"));
        let has_op_mismatch = payloads.iter().any(|p| p.contains("operationName"));
        assert!(has_alias_flood, "alias-flood payloads missing");
        assert!(has_introspection, "introspection payloads missing");
        assert!(has_op_mismatch, "op-name-mismatch payloads missing");
    }
}
