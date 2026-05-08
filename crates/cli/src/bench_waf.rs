//! Reproducible WAF benchmark: fixed seed requests, latency, block classification.

use colored::Colorize;
use reqwest::Client;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use wafrift_transport::is_waf_block;

const DEFAULT_PAYLOADS: &str = include_str!("../bench_payloads/default.json");

#[derive(Debug, clap::Args)]
pub struct BenchWafArgs {
    /// Base URL of the WAF front door (no trailing path), e.g. http://127.0.0.1:18080.
    /// If omitted, uses `WAFRIFT_MODSEC_URL` or `http://127.0.0.1:18080`.
    #[arg(long)]
    pub base_url: Option<String>,

    /// JSON file with benchmark cases (defaults to built-in seed list).
    #[arg(long)]
    pub payloads: Option<PathBuf>,

    /// Delay between requests in milliseconds.
    #[arg(long, default_value_t = 50)]
    pub delay_ms: u64,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Disable TLS certificate verification.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
struct BenchFile {
    #[allow(dead_code)]
    version: Option<u32>,
    cases: Vec<BenchCase>,
}

#[derive(Debug, Deserialize)]
struct BenchCase {
    id: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    query: Option<String>,
    /// `allowed`, `blocked`, or `any` (no expectation).
    #[serde(default = "default_expect")]
    expect: String,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_expect() -> String {
    "any".to_string()
}

fn build_url(base: &str, path: &str, query: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    match query {
        None | Some("") => format!("{base}{path}"),
        Some(q) => format!("{base}{path}?{q}"),
    }
}

fn parse_bench_json(raw: &str) -> Result<BenchFile, String> {
    serde_json::from_str(raw).map_err(|e| format!("invalid benchmark JSON: {e}"))
}

fn load_cases(args: &BenchWafArgs) -> Result<BenchFile, String> {
    if let Some(path) = &args.payloads {
        let s = fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        parse_bench_json(&s)
    } else {
        parse_bench_json(DEFAULT_PAYLOADS)
    }
}

/// Run benchmark and print results; returns non-zero if any `expect` mismatch.
pub fn run_bench_waf(args: BenchWafArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match rt.block_on(run_bench_waf_async(args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            ExitCode::from(1)
        }
    }
}

fn resolve_base_url(args: &BenchWafArgs) -> String {
    if let Some(ref u) = args.base_url {
        return u.clone();
    }
    std::env::var("WAFRIFT_MODSEC_URL").unwrap_or_else(|_| "http://127.0.0.1:18080".to_string())
}

async fn run_bench_waf_async(args: BenchWafArgs) -> Result<ExitCode, String> {
    let base_url = resolve_base_url(&args);
    let file = load_cases(&args)?;
    let mut client_builder = Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout_secs))
        .user_agent("wafrift-bench/0.1");
    if args.insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let mut rows = Vec::new();
    let mut mismatches = 0u32;

    for (idx, case) in file.cases.iter().enumerate() {
        if idx > 0 && args.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(args.delay_ms)).await;
        }
        let url = build_url(&base_url, &case.path, case.query.as_deref());
        let start = Instant::now();
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("{}: {e}", case.id))?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(|e| format!("{} body: {e}", case.id))?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let blocked = is_waf_block(status, &body);

        let expect_ok = match case.expect.to_ascii_lowercase().as_str() {
            "any" => true,
            "allowed" | "allow" => !blocked,
            "blocked" | "block" => blocked,
            other => return Err(format!("case {}: bad expect {:?}", case.id, other)),
        };
        if !expect_ok {
            mismatches += 1;
        }

        rows.push(BenchRow {
            id: case.id.clone(),
            url,
            status,
            blocked,
            latency_ms: elapsed_ms,
            expect: case.expect.clone(),
            expect_ok,
        });
    }

    if args.format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "base_url": base_url,
                "mismatches": mismatches,
                "results": rows.iter().map(|r| serde_json::json!({
                    "id": &r.id,
                    "url": &r.url,
                    "status": r.status,
                    "blocked": r.blocked,
                    "latency_ms": (r.latency_ms * 1000.0).round() / 1000.0,
                    "expect": &r.expect,
                    "expect_ok": r.expect_ok,
                })).collect::<Vec<_>>(),
            }))
            .map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{}",
            format!(
                "WAF bench — {} ({} cases)\n",
                base_url,
                rows.len()
            )
            .bold()
        );
        println!(
            "{:<22} {:>5} {:>8} {:>8} {:>10} ok",
            "id", "http", "ms", "blocked", "expect"
        );
        println!("{}", "—".repeat(76));
        for r in &rows {
            let ok_str = if r.expect.eq_ignore_ascii_case("any") {
                "—".to_string()
            } else if r.expect_ok {
                "yes".green().to_string()
            } else {
                "NO".red().to_string()
            };
            println!(
                "{:<22} {:>5} {:>8.2} {:>8} {:>10} {}",
                r.id,
                r.status,
                r.latency_ms,
                r.blocked,
                r.expect,
                ok_str
            );
        }
        if mismatches > 0 {
            println!(
                "\n{}",
                format!("expectation mismatches: {mismatches} (CRS tuning / WAF may differ)")
                    .yellow()
            );
        } else {
            println!(
                "\n{}",
                "all expectations satisfied (for cases that define expect)."
                    .green()
            );
        }
    }

    Ok(if mismatches > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

struct BenchRow {
    id: String,
    url: String,
    status: u16,
    blocked: bool,
    latency_ms: f64,
    expect: String,
    expect_ok: bool,
}
