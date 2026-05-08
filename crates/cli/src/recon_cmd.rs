use clap::Args;
use std::process::ExitCode;
use wafrift_recon::{discover_subdomains_ct, resolve_origins};

#[derive(Args, Debug)]
pub struct ReconArgs {
    /// Target domain to discover origin IPs for (e.g., example.com)
    #[arg(long)]
    pub domain: String,
}

pub fn run_recon(args: ReconArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        println!("🔍 Starting discovery for domain: {}", args.domain);

        match discover_subdomains_ct(&args.domain).await {
            Ok(subdomains) => {
                println!("✓ Found {} potential subdomains.", subdomains.len());
                for sub in &subdomains {
                    println!("  - {}", sub);
                }

                if !subdomains.is_empty() {
                    println!("\n🔍 Resolving subdomains to identify potential origin IPs...");
                    match resolve_origins(&subdomains).await {
                        Ok(ips) => {
                            if ips.is_empty() {
                                println!("⚠ No IPs resolved.");
                            } else {
                                println!("✓ Found {} origin IPs:", ips.len());
                                for ip in ips {
                                    println!("  - {}", ip);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Resolution failed: {}", e);
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("✗ CT log discovery failed: {}", e);
                return ExitCode::from(1);
            }
        }
        ExitCode::SUCCESS
    })
}
