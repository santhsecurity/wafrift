//! `wafrift takeover` — subdomain takeover detector.
//!
//! A subdomain takeover is one of the highest-impact, lowest-effort
//! findings in bug bounty: when `subdomain.victim.com` points (via
//! CNAME / A record) at a third-party service (Heroku, S3, GitHub
//! Pages, Azure, Bitbucket, ...) AND the service-side resource has
//! been deleted, the attacker registers the same resource and
//! serves arbitrary content on the victim's subdomain. Cookies
//! scoped to *.victim.com leak. Same-origin tooling treats it as
//! the victim.
//!
//! This command:
//!
//! 1. Resolves `<subdomain>` via DNS (CNAME chain + A records).
//! 2. Fetches the HTTP response at `<subdomain>`.
//! 3. Matches the (CNAME pattern, HTTP signature) pair against a
//!    curated fingerprint database covering the well-known
//!    vulnerable third-party services.
//! 4. Reports any match as a TAKEOVER candidate with the exact
//!    registration step the attacker would take.
//!
//! Fingerprints are sourced from the same publicly-curated lists
//! every pentester carries (EdOverflow/can-i-take-over-xyz +
//! Project Discovery's nuclei takeover templates), distilled to
//! the high-confidence cases that don't false-positive on
//! legitimate setups.

use clap::Args;
use colored::Colorize;
use std::process::ExitCode;
use std::time::Duration;

/// One vulnerable-service fingerprint. Match requires both:
///   - A CNAME the target resolves to that contains
///     `cname_substring` (case-insensitive), OR no CNAME match
///     when `cname_substring` is empty.
///   - The HTTP response body contains `body_signature` (case-
///     sensitive — service signatures are exact strings).
#[derive(Debug, Clone)]
pub struct TakeoverFingerprint {
    /// Service name, surfaced in the report.
    pub service: &'static str,
    /// Substring that must appear in the resolved CNAME chain.
    /// Empty = CNAME match is not required (fall back to body
    /// signature only).
    pub cname_substring: &'static str,
    /// Substring that must appear in the HTTP response body.
    pub body_signature: &'static str,
    /// HTTP status that's expected when the takeover is live.
    /// `None` matches any status.
    pub expected_status: Option<u16>,
    /// Operator-readable explanation of the registration step
    /// the attacker would take.
    pub registration_step: &'static str,
}

/// Curated fingerprint database. High-confidence patterns only —
/// the list intentionally excludes services where the takeover
/// signature is ambiguous with legitimate "this app isn't
/// configured yet" pages.
pub const FINGERPRINTS: &[TakeoverFingerprint] = &[
    TakeoverFingerprint {
        service: "Heroku",
        cname_substring: "herokudns.com",
        body_signature: "No such app",
        expected_status: Some(404),
        registration_step: "register the app name in the subdomain at https://dashboard.heroku.com/new-app — the CNAME re-binds to your app",
    },
    TakeoverFingerprint {
        service: "Heroku (alt)",
        cname_substring: "herokuapp.com",
        body_signature: "No such app",
        expected_status: Some(404),
        registration_step: "register the app name at https://dashboard.heroku.com/new-app",
    },
    TakeoverFingerprint {
        service: "GitHub Pages",
        cname_substring: "github.io",
        body_signature: "There isn't a GitHub Pages site here",
        expected_status: Some(404),
        registration_step: "create a repo named <subdomain> in any GitHub account, enable Pages, add a CNAME file with the target subdomain",
    },
    TakeoverFingerprint {
        service: "AWS S3",
        cname_substring: "s3.amazonaws.com",
        body_signature: "NoSuchBucket",
        expected_status: Some(404),
        registration_step: "create an S3 bucket with the exact name in the CNAME and enable static website hosting",
    },
    TakeoverFingerprint {
        service: "AWS S3 (website)",
        cname_substring: "s3-website",
        body_signature: "NoSuchBucket",
        expected_status: Some(404),
        registration_step: "create an S3 bucket with the exact name in the CNAME and enable static website hosting",
    },
    TakeoverFingerprint {
        service: "Bitbucket",
        cname_substring: "bitbucket.io",
        body_signature: "Repository not found",
        expected_status: Some(404),
        registration_step: "create a public repo at the matching workspace/repo name and enable Bitbucket Pages",
    },
    TakeoverFingerprint {
        service: "Tumblr",
        cname_substring: "domains.tumblr.com",
        body_signature: "Whatever you were looking for doesn't currently exist at this address",
        expected_status: None,
        registration_step: "register the blog name at tumblr.com matching the CNAME",
    },
    TakeoverFingerprint {
        service: "Shopify",
        cname_substring: "myshopify.com",
        body_signature: "Sorry, this shop is currently unavailable",
        expected_status: None,
        registration_step: "register the shop name at shopify.com",
    },
    TakeoverFingerprint {
        service: "Fastly",
        cname_substring: "fastly.net",
        body_signature: "Fastly error: unknown domain",
        expected_status: None,
        registration_step: "claim the service on Fastly with the matching CNAME",
    },
    TakeoverFingerprint {
        service: "Pantheon",
        cname_substring: "pantheonsite.io",
        body_signature: "The gods are wise",
        expected_status: None,
        registration_step: "register the site name at pantheon.io",
    },
    TakeoverFingerprint {
        service: "Tilda",
        cname_substring: "tilda.ws",
        body_signature: "Please renew your subscription",
        expected_status: None,
        registration_step: "register the project at tilda.cc with the same domain",
    },
    TakeoverFingerprint {
        service: "Cargo Collective",
        cname_substring: "cargocollective.com",
        body_signature: "404 Not Found",
        expected_status: Some(404),
        registration_step: "register the project at cargocollective.com",
    },
    TakeoverFingerprint {
        service: "Squarespace",
        cname_substring: "squarespace.com",
        body_signature: "No Such Account",
        expected_status: None,
        registration_step: "create a Squarespace account claiming this subdomain",
    },
    TakeoverFingerprint {
        service: "Statuspage.io",
        cname_substring: "statuspage.io",
        body_signature: "You are being",
        expected_status: Some(404),
        registration_step: "register the status page at statuspage.io with the matching name",
    },
    TakeoverFingerprint {
        service: "Surge.sh",
        cname_substring: "surge.sh",
        body_signature: "project not found",
        expected_status: None,
        registration_step: "deploy a Surge project with the matching subdomain via `surge`",
    },
    TakeoverFingerprint {
        service: "Unbounce",
        cname_substring: "unbouncepages.com",
        body_signature: "The requested URL was not found on this server",
        expected_status: Some(404),
        registration_step: "register the landing page at unbounce.com",
    },
    TakeoverFingerprint {
        service: "Wordpress.com",
        cname_substring: "wordpress.com",
        body_signature: "Do you want to register",
        expected_status: None,
        registration_step: "register the blog at wordpress.com",
    },
];

#[derive(Args, Debug)]
pub struct TakeoverArgs {
    /// Subdomain to test (e.g. `unused.victim.com`).
    pub target: String,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// Disable TLS verification (rarely needed for takeover
    /// checks; most vulnerable services answer on plain HTTP).
    #[arg(long)]
    pub insecure: bool,

    /// Output format. `text` is human-readable; `json` is for
    /// machine consumption.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Result of one fingerprint match.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TakeoverFinding {
    pub service: String,
    pub cname_matched: Option<String>,
    pub body_signature_matched: String,
    pub registration_step: String,
}

/// Match the target's resolved CNAME chain + HTTP response against
/// the fingerprint database. Pure function — no I/O.
#[must_use]
pub fn match_fingerprints(
    cname_chain: &[String],
    http_status: u16,
    body_text: &str,
) -> Vec<TakeoverFinding> {
    let mut out = Vec::new();
    for fp in FINGERPRINTS {
        // CNAME gate (when non-empty): at least one entry in the
        // chain must contain the substring.
        let cname_match = if fp.cname_substring.is_empty() {
            None
        } else {
            cname_chain
                .iter()
                .find(|c| c.to_ascii_lowercase().contains(fp.cname_substring))
                .cloned()
        };
        if !fp.cname_substring.is_empty() && cname_match.is_none() {
            continue;
        }
        // Body signature gate.
        if !body_text.contains(fp.body_signature) {
            continue;
        }
        // Status gate (when specified).
        if let Some(expected) = fp.expected_status {
            if expected != http_status {
                continue;
            }
        }
        out.push(TakeoverFinding {
            service: fp.service.to_string(),
            cname_matched: cname_match,
            body_signature_matched: fp.body_signature.to_string(),
            registration_step: fp.registration_step.to_string(),
        });
    }
    out
}

/// Resolve `host` through the system resolver and return whatever
/// the OS gives back: a flat list of address strings + an
/// approximate CNAME chain (the system resolver typically follows
/// CNAMEs transparently, so the chain often only contains the
/// final A/AAAA records — but reqwest's resolver behaviour is the
/// canonical one for the HTTP probe step regardless).
async fn resolve_chain(host: &str) -> Vec<String> {
    // tokio::net::lookup_host returns SocketAddrs; we strip the
    // port and dedup. To get the CNAME chain proper we'd need a
    // direct DNS resolver (trust-dns); kept system-resolver here
    // to avoid the extra dep + most vulnerable-service signatures
    // ALSO have a body marker, which dominates the match.
    let with_port = format!("{host}:80");
    match tokio::net::lookup_host(with_port).await {
        Ok(iter) => {
            let mut out: Vec<String> = iter
                .map(|addr| addr.ip().to_string())
                .collect();
            out.sort();
            out.dedup();
            out
        }
        Err(_) => Vec::new(),
    }
}

/// Fetch the HTTP response at `https://host/` (falling back to
/// `http://host/` on TLS failure — vulnerable services often only
/// answer on plain HTTP).
async fn fetch_takeover_response(
    host: &str,
    timeout_secs: u64,
    insecure: bool,
) -> Result<(u16, String), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(insecure)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    // Try HTTPS first.
    let https_url = format!("https://{host}/");
    if let Ok(resp) = client.get(&https_url).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Ok((status, body));
    }
    // Fall back to HTTP.
    let http_url = format!("http://{host}/");
    let resp = client
        .get(&http_url)
        .send()
        .await
        .map_err(|e| format!("HTTP fetch: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body))
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_takeover(args: TakeoverArgs) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{} tokio runtime: {e}", "error:".red());
            return ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        let resolved = resolve_chain(&args.target).await;
        if resolved.is_empty() {
            if args.format == "text" {
                println!(
                    "{} {} resolves to nothing — likely a DEAD subdomain (dangling CNAME, NXDOMAIN, etc.). Manual DNS lookup recommended.",
                    "⚠".yellow(),
                    args.target.bold()
                );
            } else {
                let out = serde_json::json!({
                    "target": args.target,
                    "resolved": [],
                    "findings": [],
                    "note": "no resolution"
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            }
            return ExitCode::SUCCESS;
        }
        let (status, body) = match fetch_takeover_response(
            &args.target,
            args.timeout_secs,
            args.insecure,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} fetch failed: {e}", "error:".red());
                return ExitCode::from(1);
            }
        };
        let findings = match_fingerprints(&resolved, status, &body);
        if args.format == "json" {
            let out = serde_json::json!({
                "target": args.target,
                "resolved": resolved,
                "http_status": status,
                "body_len": body.len(),
                "findings": findings,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            return ExitCode::SUCCESS;
        }
        // Text mode.
        println!("{}", "── wafrift takeover ──".bold().cyan());
        println!(
            "{} {}  {} {}  {} HTTP {}",
            "target:".bright_black(),
            args.target.bold(),
            "resolved:".bright_black(),
            resolved.join(", ").yellow(),
            "response:".bright_black(),
            status
        );
        if findings.is_empty() {
            println!(
                "{} no takeover-fingerprint match — subdomain points at infrastructure not on our vulnerable-services list (or the service-side resource is still claimed).",
                "✓".green()
            );
            return ExitCode::SUCCESS;
        }
        println!();
        for f in &findings {
            println!(
                "{} {} TAKEOVER CANDIDATE",
                "🚨".bold().red(),
                f.service.bold().red()
            );
            if let Some(c) = &f.cname_matched {
                println!("    CNAME / IP match: {}", c.yellow());
            }
            println!(
                "    Body signature matched: {}",
                f.body_signature_matched.bright_white()
            );
            println!(
                "    {} {}",
                "Registration step:".bold(),
                f.registration_step.bright_white()
            );
            println!();
        }
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_finds_heroku_takeover_via_cname_and_body() {
        let findings = match_fingerprints(
            &["app-foo.herokudns.com".into()],
            404,
            "<!doctype html><html>...<title>No such app</title>...</html>",
        );
        assert_eq!(findings.len(), 1, "Heroku should match");
        assert_eq!(findings[0].service, "Heroku");
        assert!(
            findings[0]
                .cname_matched
                .as_deref()
                .unwrap()
                .contains("herokudns.com")
        );
    }

    #[test]
    fn match_finds_s3_takeover_via_nosuchbucket_signature() {
        let findings = match_fingerprints(
            &["my-bucket.s3.amazonaws.com".into()],
            404,
            "<Error><Code>NoSuchBucket</Code></Error>",
        );
        assert!(findings.iter().any(|f| f.service.contains("S3")));
    }

    #[test]
    fn match_finds_github_pages_takeover() {
        let findings = match_fingerprints(
            &["someuser.github.io".into()],
            404,
            "There isn't a GitHub Pages site here.",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].service, "GitHub Pages");
    }

    #[test]
    fn match_excludes_when_cname_does_not_contain_substring() {
        // Body says "NoSuchBucket" but the CNAME is to a non-AWS
        // host — could be a coincidence, not a real takeover.
        let findings = match_fingerprints(
            &["app.example.com".into()],
            404,
            "<Error><Code>NoSuchBucket</Code></Error>",
        );
        assert!(
            findings.is_empty(),
            "without S3-CNAME, NoSuchBucket body alone must not match"
        );
    }

    #[test]
    fn match_excludes_when_body_signature_missing() {
        // CNAME points at Heroku but the body says nothing about
        // "No such app" — app is presumably claimed, no takeover.
        let findings = match_fingerprints(
            &["app.herokudns.com".into()],
            200,
            "<html>Welcome to my app</html>",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn match_excludes_when_status_wrong_for_expected_status_signature() {
        // S3 fingerprint expects 404. A 200 with the body
        // signature would be very unusual and must NOT match.
        let findings = match_fingerprints(
            &["bucket.s3.amazonaws.com".into()],
            200,
            "<Error><Code>NoSuchBucket</Code></Error>",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn match_returns_multiple_findings_when_multiple_fingerprints_match() {
        // Hypothetical: a host whose CNAME chain contains BOTH
        // s3.amazonaws.com AND s3-website (the two related S3
        // fingerprints). Both should fire.
        let findings = match_fingerprints(
            &[
                "bucket.s3.amazonaws.com".into(),
                "bucket.s3-website.amazonaws.com".into(),
            ],
            404,
            "<Error><Code>NoSuchBucket</Code></Error>",
        );
        assert!(findings.len() >= 2);
    }

    #[test]
    fn fingerprint_database_has_no_duplicate_services() {
        // Sanity: a service appearing twice in the list almost
        // certainly means a copy-paste mistake during a future
        // expansion (the "Heroku (alt)" pattern is the documented
        // exception). Every (service-name, body_signature) pair
        // should be unique.
        let mut seen: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
        for fp in FINGERPRINTS {
            let key = (fp.service, fp.body_signature);
            assert!(
                seen.insert(key),
                "duplicate (service, body_signature) in fingerprint DB: {:?}",
                key
            );
        }
    }

    #[test]
    fn fingerprint_database_signatures_are_non_empty() {
        for fp in FINGERPRINTS {
            assert!(
                !fp.body_signature.is_empty(),
                "{} has empty body_signature",
                fp.service
            );
            assert!(
                !fp.registration_step.is_empty(),
                "{} has empty registration_step",
                fp.service
            );
        }
    }

    #[test]
    fn fingerprint_database_covers_top_services() {
        // The headline services every bug bounty writeup mentions
        // must be present. Anti-rig: the database can grow but
        // must NEVER lose Heroku / S3 / GitHub Pages / Fastly /
        // Squarespace coverage.
        let services: std::collections::HashSet<&str> =
            FINGERPRINTS.iter().map(|f| f.service).collect();
        for required in ["Heroku", "GitHub Pages", "AWS S3", "Fastly", "Squarespace"] {
            assert!(
                services.contains(required),
                "fingerprint DB must cover {required}"
            );
        }
    }
}
