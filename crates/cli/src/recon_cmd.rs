use clap::Args;
use serde_json::json;
use std::process::ExitCode;
use wafrift_recon::{discover_subdomains_ct, resolve_origins};

#[derive(Args, Debug)]
pub struct ReconArgs {
    /// Target domain to discover origin IPs for (e.g., example.com)
    #[arg(long)]
    pub domain: String,
}

pub fn run_recon(args: ReconArgs, quiet: bool) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if !quiet {
            println!("Starting discovery for domain: {}", args.domain);
        }

        match discover_subdomains_ct(&args.domain).await {
            Ok(subdomains) => {
                if !quiet {
                    println!("Found {} potential subdomains.", subdomains.len());
                    for sub in &subdomains {
                        println!("  - {}", sub);
                    }
                }

                let ips = if !subdomains.is_empty() {
                    if !quiet {
                        println!("\nResolving subdomains to identify potential origin IPs...");
                    }
                    match resolve_origins(&subdomains).await {
                        Ok(ips) => ips,
                        Err(e) => {
                            eprintln!("Resolution failed: {e}. Fix: verify network connectivity and DNS resolution.");
                            return ExitCode::from(1);
                        }
                    }
                } else {
                    Vec::new()
                };

                if quiet {
                    println!("{}", json!({
                        "schema_version": 1,
                        "domain": args.domain,
                        "subdomains": subdomains,
                        "ips": ips,
                    }));
                } else {
                    if ips.is_empty() {
                        println!("No IPs resolved.");
                    } else {
                        println!("Found {} origin IPs:", ips.len());
                        for ip in ips {
                            println!("  - {}", ip);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("CT log discovery failed: {e}. Fix: verify the domain is public and has CT records.");
                return ExitCode::from(1);
            }
        }
        ExitCode::SUCCESS
    })
}
