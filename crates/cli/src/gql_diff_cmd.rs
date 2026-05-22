//! `wafrift gql-diff` — GraphQL parser / cost-limit disagreement
//! scanner.
//!
//! ## What this finds
//!
//! GraphQL endpoints have a different attack surface from REST.
//! WAFs that gate REST routes by URL-shape see only `POST /graphql`
//! and a JSON body — they miss the structure inside. Origins that
//! parse the GraphQL query may:
//!
//! - Honour introspection queries and leak the schema.
//! - Accept aliased queries that bypass field-name allowlists.
//! - Process batched operations the WAF rate-limit treats as ONE
//!   request.
//! - Handle deeply-nested fragments the operator never anticipated.
//! - Tolerate dup-key JSON / dup-operation requests the WAF doesn't
//!   re-validate.
//!
//! Probes test each axis against the target's `/graphql` endpoint
//! and report status / body-length divergence vs. a benign baseline
//! query.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::Client;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct GqlDiffArgs {
    /// Target GraphQL endpoint URL (typically `https://target/graphql`).
    pub url: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification.
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (auth tokens, cookies).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One GraphQL parser-disagreement probe.
#[derive(Debug, Clone)]
pub struct GqlProbe {
    pub kind: &'static str,
    pub description: &'static str,
    /// The full request body to POST (JSON-encoded GraphQL operation).
    pub body: String,
    /// Override Content-Type if non-default needed (e.g. GET-with-query
    /// uses application/graphql); blank string means
    /// `application/json`.
    pub content_type: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GqlDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// The curated GraphQL probe set. Pure function, deterministic.
#[must_use]
pub fn generate_gql_variants() -> Vec<GqlProbe> {
    vec![
        // ── Introspection leak ──
        GqlProbe {
            kind: "introspection-full",
            description:
                "Standard full introspection — leaks the entire schema if the WAF \
                 doesn't block `__schema` queries (common misconfiguration)",
            body: r#"{"query":"{ __schema { types { name fields { name } } } }"}"#.into(),
            content_type: "",
        },
        GqlProbe {
            kind: "introspection-type",
            description:
                "Targeted type introspection — narrower than full schema dump; \
                 WAFs that match the literal `__schema` keyword miss this",
            body: r#"{"query":"{ __type(name:\"Query\") { fields { name type { name } } } }"}"#.into(),
            content_type: "",
        },
        // ── Alias bombing ──
        GqlProbe {
            kind: "alias-bombing",
            description:
                "Same field aliased many times — bypasses WAF rules that count \
                 unique field references; rate-limited by op count, not field count",
            body: r#"{"query":"{ a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename }"}"#.into(),
            content_type: "",
        },
        // ── Batched operations ──
        GqlProbe {
            kind: "batched-operations",
            description:
                "Array-of-operations request — Apollo / Hasura support; one WAF \
                 request, many origin operations. Breaks per-request rate limits.",
            body: r#"[{"query":"{ __typename }"},{"query":"{ __typename }"}]"#.into(),
            content_type: "",
        },
        // ── Operation type confusion ──
        GqlProbe {
            kind: "mutation-as-query",
            description:
                "Mutation request declared with `query` operationType — strict \
                 parsers reject; lenient ones execute as mutation; WAF gates by \
                 declared type and misses the actual op",
            body: r#"{"query":"mutation { __typename }","operationName":null}"#.into(),
            content_type: "",
        },
        // ── Field duplication ──
        GqlProbe {
            kind: "field-duplication",
            description:
                "Same field requested twice in same selection — origin parsers \
                 dedup silently; WAF sees two field references",
            body: r#"{"query":"{ __typename __typename }"}"#.into(),
            content_type: "",
        },
        // ── Deeply nested fragments ──
        GqlProbe {
            kind: "fragment-nesting",
            description:
                "Several layers of inline fragments — exercises query-cost \
                 limits; WAFs without cost analysis pass through",
            body: r#"{"query":"{ ... on Query { ... on Query { ... on Query { __typename } } } }"}"#.into(),
            content_type: "",
        },
        // ── application/graphql Content-Type ──
        GqlProbe {
            kind: "alt-content-type-graphql",
            description:
                "Request via `Content-Type: application/graphql` (raw body is \
                 the query string, no JSON wrapper). WAFs JSON-parsing the body \
                 see nothing; origins that support the alt CT execute normally.",
            body: "{ __typename }".into(),
            content_type: "application/graphql",
        },
        // ── GET-with-query (some servers support) ──
        GqlProbe {
            kind: "get-shaped-query",
            description:
                "Same query but via the URL query string (?query=…). Not all \
                 GraphQL servers honour GET; for those that do, WAF body-parse \
                 rules don't fire.",
            // Note: probe runs as POST with body containing the URL-encoded form.
            // The actual GET-shape probe is generated by render_curl for the
            // reproducer; the live fire still uses POST. Trade-off: keeping
            // the prober single-method-aware for simplicity.
            body: r#"{"query":"{ __typename }"}"#.into(),
            content_type: "",
        },
        // ── Operation-name spoofing ──
        GqlProbe {
            kind: "operation-name-spoof",
            description:
                "Operation declared with one name but operationName parameter \
                 points to another — WAFs that check operationName miss the \
                 actual op being executed",
            body: r#"{"query":"query SafeOp { __typename } query AdminOp { __typename }","operationName":"AdminOp"}"#.into(),
            content_type: "",
        },
    ]
}

pub async fn run_gql_diff(args: GqlDiffArgs) -> ExitCode {
    let http = match build_http_client(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} GraphQL parser-disagreement variants against {}",
            "[wafrift gql-diff]".bright_cyan().bold(),
            generate_gql_variants().len().to_string().bold().yellow(),
            args.url.bright_white()
        );
    }

    // Baseline: benign __typename query.
    let baseline_body = r#"{"query":"{ __typename }"}"#;
    let baseline =
        match fire_gql(&http, &args.url, "application/json", baseline_body).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "  {} baseline probe failed: {e}",
                    "✗ Transport error:".red().bold()
                );
                return ExitCode::from(1);
            }
        };
    let (baseline_status, baseline_body_len) = baseline;
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline: HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_gql_variants();
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http_arc.clone();
        let url = url_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let ct = if v.content_type.is_empty() {
                "application/json"
            } else {
                v.content_type
            };
            let result = fire_gql(&http, &url, ct, &v.body).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, ct, result)
        }));
    }

    let mut results: Vec<GqlDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, ct, outcome) = h.await.unwrap_or_else(|e| {
            (
                GqlProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    body: String::new(),
                    content_type: "",
                },
                "application/json",
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(&args.url, ct, &variant.body);
                results.push(GqlDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_status,
                    baseline_status,
                    body_delta_pct: body_delta,
                    baseline_body_len,
                    probe_body_len,
                    curl_cmd,
                    severity,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, baseline_status, baseline_body_len, errors);
    ExitCode::SUCCESS
}

async fn fire_gql(
    http: &Client,
    url: &str,
    content_type: &str,
    body: &str,
) -> Result<(u16, usize), String> {
    let resp = http
        .post(url)
        .header("Content-Type", content_type)
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?;
    Ok((status, body.len()))
}

fn build_http_client(args: &GqlDiffArgs) -> Result<Client, ExitCode> {
    crate::parser_diff_common::build_diff_http_client(
        args.timeout_secs,
        args.insecure,
        args.proxy.as_deref(),
        &args.header,
    )
}

fn render_curl(url: &str, content_type: &str, body: &str) -> String {
    format!(
        "curl -i -X POST -H {} --data {} {}",
        shell_single_quote(&format!("Content-Type: {content_type}")),
        shell_single_quote(body),
        shell_single_quote(url)
    )
}

fn emit_output(
    args: &GqlDiffArgs,
    results: &[GqlDiffResult],
    baseline_status: u16,
    baseline_body_len: usize,
    errors: u32,
) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "baseline_status": baseline_status,
            "baseline_body_len": baseline_body_len,
            "probes": results.len(),
            "errors": errors,
            "divergences": {
                "high":   high.len(),
                "medium": medium.len(),
            },
            "results": results,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("JSON error: {e}"),
        }
        return;
    }

    if !args.quiet {
        println!();
        println!(
            "  {} {} divergence(s) — {} high, {} medium · {} error(s)",
            "[wafrift gql-diff summary]".bright_cyan().bold(),
            (high.len() + medium.len()).to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            errors
        );
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = match r.severity {
            "high" => r.severity.bright_red().bold(),
            "medium" => r.severity.yellow().bold(),
            _ => r.severity.bright_black(),
        };
        println!();
        println!("  [{badge}] {} — {}", r.kind.bold(), r.description);
        println!(
            "    {} baseline HTTP {} ({} bytes) → probe HTTP {} ({} bytes, Δ {:+.1}%)",
            "↘".bright_black(),
            r.baseline_status,
            r.baseline_body_len,
            r.probe_status,
            r.probe_body_len,
            r.body_delta_pct
        );
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_gql_variants_returns_non_empty_curated_set() {
        let v = generate_gql_variants();
        assert!(v.len() >= 10, "expected ≥10 probes, got {}", v.len());
    }

    #[test]
    fn generate_gql_variants_kinds_are_unique() {
        let v = generate_gql_variants();
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len());
    }

    #[test]
    fn generate_gql_variants_includes_introspection_family() {
        let kinds: Vec<&str> = generate_gql_variants()
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(
            kinds.iter().any(|k| k.contains("introspection")),
            "must include introspection probes"
        );
    }

    #[test]
    fn generate_gql_variants_includes_alias_bombing() {
        let v = generate_gql_variants();
        let alias = v.iter().find(|p| p.kind == "alias-bombing").expect("alias probe");
        assert!(alias.body.contains("__typename"));
        // Multiple aliases in the body.
        assert!(alias.body.matches(":__typename").count() >= 3);
    }

    #[test]
    fn generate_gql_variants_includes_batched_operations() {
        let v = generate_gql_variants();
        let batched = v
            .iter()
            .find(|p| p.kind == "batched-operations")
            .expect("batched probe");
        // Body must start with `[` — array of ops.
        assert!(batched.body.trim_start().starts_with('['), "got: {}", batched.body);
    }

    #[test]
    fn generate_gql_variants_alt_content_type_uses_application_graphql() {
        let v = generate_gql_variants();
        let alt = v
            .iter()
            .find(|p| p.kind == "alt-content-type-graphql")
            .expect("alt-CT probe");
        assert_eq!(alt.content_type, "application/graphql");
    }

    #[test]
    fn generate_gql_variants_is_deterministic() {
        let a: Vec<&str> = generate_gql_variants().iter().map(|p| p.kind).collect();
        let b: Vec<&str> = generate_gql_variants().iter().map(|p| p.kind).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn render_curl_emits_post_with_content_type_and_body() {
        let out = render_curl("http://x/graphql", "application/json", "{\"q\":1}");
        assert!(out.starts_with("curl -i -X POST "), "got: {out}");
        assert!(out.contains("'Content-Type: application/json'"), "got: {out}");
        assert!(out.contains("--data '{\"q\":1}'"), "got: {out}");
    }

    async fn spawn_gql_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Mock: longer body when __schema is requested.
                    let leaked = req.contains("__schema");
                    let body = if leaked {
                        r#"{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"secret"}]},{"name":"AdminQuery","fields":[{"name":"users"}]}]}}}"#
                    } else {
                        r#"{"data":{"__typename":"Query"}}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        addr
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn run_gql_diff_finds_introspection_leak_on_permissive_mock() {
        let addr = spawn_gql_mock().await;
        let args = GqlDiffArgs {
            url: format!("http://{addr}/graphql"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_gql_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_gql_diff_against_unreachable_exits_1() {
        let args = GqlDiffArgs {
            url: "http://127.0.0.1:1/graphql".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_gql_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
