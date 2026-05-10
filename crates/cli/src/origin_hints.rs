//! DNS-based origin IP hints for `EvasionConfig::origin_bypass` (authorized testing only).

use colored::Colorize;
use serde_json::json;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::ExitCode;

#[derive(Debug, clap::Args)]
pub struct OriginHintsArgs {
    /// Hostname only (e.g. `api.example.com`), not a full URL.
    #[arg(long)]
    pub host: String,

    /// `text` or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Strip `http(s)://`, path, and port from user input; returns hostname for DNS.
fn normalize_host(input: &str) -> Result<String, String> {
    let s = input.trim();
    let without_scheme = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let hostport = without_scheme.split('/').next().unwrap_or("").trim();
    if hostport.is_empty() {
        return Err("empty host".into());
    }
    let hostname = hostport
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(hostport)
        .trim();

    let hostname = if hostname.starts_with('[') {
        let Some(end) = hostname.find(']') else {
            return Err(format!("invalid IPv6 host: {input:?}"));
        };
        hostname[1..end].to_ascii_lowercase()
    } else {
        hostname
            .split(':')
            .next()
            .unwrap_or(hostname)
            .trim()
            .to_ascii_lowercase()
    };
    if hostname.is_empty() || hostname.contains(' ') {
        return Err(format!("invalid host: {input:?}"));
    }
    Ok(hostname)
}

async fn resolve_ips(hostname: &str) -> Result<Vec<IpAddr>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for port in [443u16, 80] {
        let sock = format!("{hostname}:{port}");
        let iter = tokio::net::lookup_host(&sock)
            .await
            .map_err(|e| format!("lookup_host({sock}): {e}"))?;
        for addr in iter {
            let ip = addr.ip();
            if seen.insert(ip) {
                out.push(ip);
            }
        }
    }
    if out.is_empty() {
        return Err(format!("no addresses for {hostname:?}"));
    }
    Ok(out)
}

pub fn run_origin_hints(args: OriginHintsArgs) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} failed to start tokio runtime: {e}",
                "error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run_async(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            ExitCode::from(1)
        }
    }
}

async fn run_async(args: &OriginHintsArgs) -> Result<(), String> {
    let host = normalize_host(&args.host)?;
    let ips = resolve_ips(&host).await?;

    if ips.is_empty() {
        return Err(format!("no IP addresses resolved for {host}"));
    }

    let first_ip = ips[0];
    let origin_bypass_example = json!({ &host: first_ip.to_string() });

    if args.format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "host": host,
                "ips": ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                "origin_bypass_example": origin_bypass_example,
                "note": "Use the host key that matches your request Host header; verify TLS/SNI and certificate before bypassing the edge.",
            }))
            .map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("{}", format!("Origin hints for `{host}`").bold());
    println!("\nResolved IPs:");
    for ip in &ips {
        println!("  - {ip}");
    }
    println!(
        "\n{}",
        "Use only on targets you are authorized to test. Prefer the IP that answers HTTPS with the correct certificate for this host."
            .yellow()
    );
    println!(
        "\n{}",
        "Copy into EvasionConfig JSON (pick one host key and one IP):".bright_black()
    );
    let example = json!({ "origin_bypass": { &host: first_ip.to_string() } });
    println!(
        "{}",
        serde_json::to_string_pretty(&example).map_err(|e| e.to_string())?
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_host;

    #[test]
    fn normalize_strips_scheme_and_path() {
        assert_eq!(
            normalize_host("https://API.EXAMPLE.com/v1/x").unwrap(),
            "api.example.com"
        );
        assert_eq!(normalize_host("http://10.0.0.1:8080/").unwrap(), "10.0.0.1");
    }

    #[test]
    fn normalize_ipv6_bracket_host() {
        assert_eq!(
            normalize_host("https://[2001:db8::1]:8443/path").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(normalize_host("").is_err());
    }
}
