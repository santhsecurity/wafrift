use clap::Args;
use serde::Serialize;
use std::process::ExitCode;
use wafrift_recon::{discover_subdomains_ct, resolve_origins};

#[derive(Args, Debug)]
pub struct ReconArgs {
    /// Target domain to discover origin IPs for (e.g., example.com).
    #[arg(long)]
    pub domain: String,

    /// Output format. `text` (default) is human-friendly with hints;
    /// `json` is a stable, machine-parseable surface for piping into
    /// jq, ansible, or downstream automation. JSON output suppresses
    /// the human stdout decoration.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

#[derive(Serialize)]
struct ReconReport<'a> {
    schema_version: u32,
    domain: &'a str,
    subdomains: Vec<String>,
    origin_ips: Vec<String>,
}

const RECON_SCHEMA_VERSION: u32 = 1;

pub fn run_recon(args: ReconArgs) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("✗ Failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(async {
        let json_mode = args.format == "json";
        if !json_mode {
            println!("🔍 Starting discovery for domain: {}", args.domain);
        }

        let subdomains = match discover_subdomains_ct(&args.domain).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("✗ CT log discovery failed: {e}");
                return ExitCode::from(1);
            }
        };

        if !json_mode {
            println!("✓ Found {} potential subdomains.", subdomains.len());
            for sub in &subdomains {
                println!("  - {sub}");
            }
        }

        let ips = if subdomains.is_empty() {
            Vec::new()
        } else {
            if !json_mode {
                println!("\n🔍 Resolving subdomains to identify potential origin IPs...");
            }
            match resolve_origins(&subdomains).await {
                Ok(ips) => {
                    if !json_mode {
                        if ips.is_empty() {
                            println!("⚠ No IPs resolved.");
                        } else {
                            println!("✓ Found {} origin IPs:", ips.len());
                            for ip in &ips {
                                println!("  - {ip}");
                            }
                        }
                    }
                    ips
                }
                Err(e) => {
                    eprintln!("✗ Resolution failed: {e}");
                    return ExitCode::from(1);
                }
            }
        };

        if json_mode {
            let report = ReconReport {
                schema_version: RECON_SCHEMA_VERSION,
                domain: &args.domain,
                subdomains,
                origin_ips: ips,
            };
            match serde_json::to_string_pretty(&report) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("✗ Failed to serialize JSON: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        ExitCode::SUCCESS
    })
}
