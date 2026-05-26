use clap::Args;
use serde_json::json;
use std::process::ExitCode;
use wafrift_recon::active::{
    ActiveProbeConfig, HttpHeaderProbeSnapshot, probe_http_headers,
};
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

    /// Run `wafrift_recon::active::probe_http_headers` against each
    /// discovered subdomain (https://<sub>/) after CT-log enumeration.
    /// Captures the response status + normalized headers and classifies
    /// them via the embedded `HeaderRules` TOML to attach WAF / CDN /
    /// framework tags to each subdomain. Off by default — adds one
    /// HTTPS GET per subdomain to the recon footprint.
    #[arg(long, default_value_t = false)]
    pub active_probe: bool,

    /// HTTP timeout (seconds) for each `--active-probe` request.
    /// Default 10 s — short enough to drop dead hosts quickly across a
    /// large CT-log subdomain set, long enough that a healthy edge
    /// finishes the round-trip + TLS handshake in time.
    #[arg(long, default_value_t = 10)]
    pub active_probe_timeout_secs: u64,
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

/// Run `probe_http_headers` against each subdomain (https://<sub>/)
/// and return per-host rows.  Sequential rather than parallel because
/// recon targets often share an edge; firing 100 concurrent HEAD-style
/// GETs would burn the operator's per-source rate budget on the very
/// first scan. Operators wanting parallel probing can run multiple
/// recon invocations.
async fn run_active_probes(
    subdomains: &[String],
    timeout_secs: u64,
    json_mode: bool,
) -> Vec<ActiveProbeRow> {
    let mut config = ActiveProbeConfig::default();
    config.http_timeout = std::time::Duration::from_secs(timeout_secs);
    let mut rows = Vec::with_capacity(subdomains.len());
    for sub in subdomains {
        let url = format!("https://{sub}/");
        match probe_http_headers(&url, &config).await {
            Ok(snap) => {
                if !json_mode {
                    let tags: Vec<String> = snap
                        .tags
                        .iter()
                        .map(|t| format!("{:?}:{}", t.family, t.id))
                        .collect();
                    println!(
                        "  ✓ {sub:<40}  status={}  tags=[{}]",
                        snap.status,
                        tags.join(", ")
                    );
                }
                rows.push(ActiveProbeRow {
                    subdomain: sub.clone(),
                    reachable: true,
                    snapshot: Some(snap),
                    error: None,
                });
            }
            Err(e) => {
                if !json_mode {
                    println!("  ✗ {sub:<40}  unreachable: {e}");
                }
                rows.push(ActiveProbeRow {
                    subdomain: sub.clone(),
                    reachable: false,
                    snapshot: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_omits_active_probes_when_empty() {
        // The JSON schema must not emit `active_probes: []` when off.
        // Operators piping recon JSON through jq filters on key
        // presence; leaking an empty array would force a separate
        // emptiness check in every downstream consumer.
        let report = ReconReport {
            schema_version: RECON_SCHEMA_VERSION,
            wafrift_version: "test",
            domain: "example.com",
            subdomains: vec!["www.example.com".into()],
            origin_ips: vec![],
            active_probes: vec![],
        };
        let s = serde_json::to_string(&report).unwrap();
        assert!(
            !s.contains("active_probes"),
            "empty active_probes must be skipped: {s}"
        );
    }

    #[test]
    fn report_emits_active_probes_when_present() {
        let report = ReconReport {
            schema_version: RECON_SCHEMA_VERSION,
            wafrift_version: "test",
            domain: "example.com",
            subdomains: vec!["www.example.com".into()],
            origin_ips: vec![],
            active_probes: vec![ActiveProbeRow {
                subdomain: "www.example.com".into(),
                reachable: false,
                snapshot: None,
                error: Some("connection refused".into()),
            }],
        };
        let s = serde_json::to_string(&report).unwrap();
        assert!(s.contains("active_probes"));
        assert!(s.contains("www.example.com"));
        assert!(s.contains("connection refused"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_active_probes_empty_input_returns_empty() {
        let rows = run_active_probes(&[], 1, true).await;
        assert!(rows.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_active_probes_unreachable_host_returns_err_row() {
        // 127.0.0.1 is a TLD that won't resolve; record an unreachable row
        // without panicking and surface the error.
        let subs = vec!["this-domain-does-not-exist-12345.invalid".to_string()];
        let rows = run_active_probes(&subs, 2, true).await;
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].reachable);
        assert!(rows[0].snapshot.is_none());
        assert!(rows[0].error.is_some(), "must surface the transport error");
    }
}
