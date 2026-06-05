//! DNS-based origin IP hints for `EvasionConfig::origin_bypass` (authorized testing only).

use colored::Colorize;
use serde_json::json;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::ExitCode;

#[derive(Debug, clap::Args)]
pub(crate) struct OriginHintsArgs {
    /// Hostname only (e.g. `api.example.com`), not a full URL. Accepted
    /// as the first positional argument (`wafrift origin-hints
    /// api.example.com`); on equal footing with `--host` (kept for
    /// backwards compatibility).
    #[arg(value_name = "HOST")]
    pub host_positional: Option<String>,

    /// Long-form alias for the positional hostname — kept so every
    /// pre-existing `wafrift origin-hints --host <HOST>` invocation
    /// continues to parse. Mutually exclusive with the positional form.
    #[arg(
        long = "host",
        value_name = "HOST",
        conflicts_with = "host_positional",
        required_unless_present = "host_positional"
    )]
    pub host: Option<String>,

    /// `text` or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

impl OriginHintsArgs {
    /// Resolved hostname — positional form first, then the
    /// long-form `--host` flag. clap's `required_unless_present`
    /// guarantees at least one is set.
    #[must_use]
    pub fn resolved_host(&self) -> &str {
        self.host_positional
            .as_deref()
            .or(self.host.as_deref())
            .unwrap_or("")
    }
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
        .map_or(hostport, |(_, h)| h)
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

pub(crate) fn run_origin_hints(args: OriginHintsArgs) -> ExitCode {
    crate::helpers::block_on_with_runtime(async move {
        match run_async(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{} {e}", "error:".red().bold());
                ExitCode::from(1)
            }
        }
    })
}

async fn run_async(args: &OriginHintsArgs) -> Result<(), String> {
    let host = normalize_host(args.resolved_host())?;
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
                "ips": ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
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
