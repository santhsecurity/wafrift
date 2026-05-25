//! `wafrift cache-diff` — cache-key confusion / cache-poisoning
//! surface scanner.
//!
//! ## The innovation
//!
//! In front of most origins sits a CACHING LAYER (CDN, Varnish,
//! nginx proxy_cache, Apache mod_cache). The cache stores responses
//! keyed by some subset of the request — typically `(method, host,
//! path, query)`, but the EXACT key construction varies. WAFs sit
//! between the client and the cache; they make decisions on the
//! REQUEST they see; the cache makes decisions on the KEY it
//! computes.
//!
//! Disagreement on what's "the same request" between the WAF, the
//! cache, and the origin opens a SECOND attack surface beyond
//! payload bypass: **cache poisoning.** An attacker sends a
//! variant request the WAF doesn't recognise but the origin
//! processes (using the parser-diff family); the cache stores the
//! resulting attack response under a key that ALSO matches benign
//! user requests — and every subsequent visitor gets the poisoned
//! payload until the cache entry expires.
//!
//! ## What this scanner finds
//!
//! Sends variant requests that should be SEMANTICALLY IDENTICAL to
//! a baseline (different surface form, same meaning) and reports:
//!
//! 1. Variants that return the SAME response (Age / ETag / body
//!    hash) — strong cache key collision. Attacker can poison
//!    via the variant, victims fetched via the baseline get poisoned.
//! 2. Variants that return DIFFERENT responses — separate cache
//!    keys; weaker but still meaningful (the variant is a fresh
//!    cache slot the attacker can poison, even if benign users
//!    don't fetch via the variant directly).
//!
//! ## Probes
//!
//! Each probe sends a single GET. Baseline = `?q=baseline`.
//! Variants exercise key-construction edge cases: Host header
//! case, query parameter ORDER, trailing slash, query param case,
//! fragment leak, X-Forwarded-Host injection, Cookie variation.
//!
//! Cache hit detection: presence of cache-relevant headers (`Age`,
//! `X-Cache`, `CF-Cache-Status`, `Via`, `X-Served-By`) + body hash
//! comparison.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::{Client, Url};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;

#[derive(Args, Debug)]
pub struct CacheDiffArgs {
    /// Target URL — fixed authority + path. The scanner varies
    /// only key-affecting surface (host header case, query order,
    /// fragment, etc.).
    pub url: String,

    /// Parameter name to use as the baseline query (`?<param>=baseline`).
    #[arg(long, default_value = "q")]
    pub param: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Accept self-signed TLS certificates.
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (`-H 'Name: Value'`, repeatable).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode — suppress per-probe progress.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One cache-key-confusion probe.
#[derive(Debug, Clone)]
pub struct CacheKeyProbe {
    /// Stable short identifier.
    pub kind: &'static str,
    /// Human description.
    pub description: &'static str,
    /// URL to probe (may differ from baseline in path / query).
    pub probe_url: String,
    /// Extra headers to apply to the probe (on top of operator's `-H`).
    /// Variants like "Host case" inject the variant Host here.
    pub extra_headers: Vec<(String, String)>,
}

/// Result of one cache-diff probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_url: String,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_hash_match: bool,
    pub cache_signals_match: bool,
    pub probe_cache_signal: Option<String>,
    pub baseline_cache_signal: Option<String>,
    pub probe_body_len: usize,
    pub baseline_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the cache-key-confusion variant set. Pure function.
/// `baseline_url` is the URL to vary; `param` is the canonical
/// query-parameter name.
#[must_use]
pub fn generate_cache_variants(baseline_url: &str, param: &str) -> Vec<CacheKeyProbe> {
    let mut out = Vec::new();

    // Parse the URL once so probes can mutate the parts they care about.
    let parsed = Url::parse(baseline_url);

    // ── 1. Host header case variation ────────────────────────
    if let Ok(u) = &parsed
        && let Some(host) = u.host_str()
    {
        out.push(CacheKeyProbe {
            kind: "host-case-upper",
            description: "Host header in UPPERCASE — RFC says case-insensitive, but \
                     some caches key on the literal byte string and treat the \
                     variant as a separate cache slot",
            probe_url: baseline_url.to_string(),
            extra_headers: vec![("Host".into(), host.to_ascii_uppercase())],
        });
        out.push(CacheKeyProbe {
            kind: "host-case-mixed",
            description: "Host header mixed-case (CamelCase) — same idea, harder to \
                     spot in logs",
            probe_url: baseline_url.to_string(),
            extra_headers: vec![("Host".into(), camel_case(host))],
        });
    }

    // ── 2. X-Forwarded-Host injection ────────────────────────
    out.push(CacheKeyProbe {
        kind: "x-forwarded-host-attacker",
        description: "X-Forwarded-Host claims attacker.example. Caches that include this \
             in the key give the attacker their own cache slot; origins that \
             reflect XFH into the response Host poison links",
        probe_url: baseline_url.to_string(),
        extra_headers: vec![("X-Forwarded-Host".into(), "attacker.example.com".into())],
    });

    // ── 3. Trailing slash ────────────────────────────────────
    if let Ok(u) = &parsed {
        let mut alt = u.clone();
        let new_path = if alt.path().ends_with('/') {
            alt.path().trim_end_matches('/').to_string()
        } else {
            format!("{}/", alt.path())
        };
        alt.set_path(&new_path);
        out.push(CacheKeyProbe {
            kind: "trailing-slash",
            description: "Path with toggled trailing slash — many caches treat /foo and \
                 /foo/ as distinct keys; origins typically don't",
            probe_url: alt.to_string(),
            extra_headers: vec![],
        });
    }

    // ── 4. Query parameter ORDER ─────────────────────────────
    out.push(CacheKeyProbe {
        kind: "query-param-order",
        description: "Same param set, reordered — RFC says equivalent, but most caches \
             key on the literal query bytestring",
        probe_url: with_query(baseline_url, &format!("z=1&{param}=baseline&a=2")),
        extra_headers: vec![],
    });
    out.push(CacheKeyProbe {
        kind: "query-baseline",
        description: "Canonical query (also serves as the in-set baseline) — confirms \
             our probe shape matches the reference",
        probe_url: with_query(baseline_url, &format!("{param}=baseline")),
        extra_headers: vec![],
    });

    // ── 5. Param name case ───────────────────────────────────
    out.push(CacheKeyProbe {
        kind: "param-name-case",
        description: "Param name in alternate case — RFC says case-sensitive but some \
             caches normalise; if they do, this is a key collision",
        probe_url: with_query(baseline_url, &format!("{}=baseline", upper_first(param))),
        extra_headers: vec![],
    });

    // ── 6. Trailing extra junk param ─────────────────────────
    out.push(CacheKeyProbe {
        kind: "tracking-param-junk",
        description: "Added UTM-style tracking param — caches that strip known trackers \
             (Cloudflare, Akamai) collapse to the baseline key, exposing the \
             collision via Age",
        probe_url: with_query(
            baseline_url,
            &format!("{param}=baseline&utm_source=pentest&utm_medium=cache"),
        ),
        extra_headers: vec![],
    });

    // ── 7. Fragment leak ─────────────────────────────────────
    out.push(CacheKeyProbe {
        kind: "fragment-leak",
        description: "URL with a #fragment — fragments are client-side and shouldn't \
             reach the server, but some library configs propagate; harmless \
             if cleanly stripped, key collision if not",
        probe_url: with_query(baseline_url, &format!("{param}=baseline#frag")),
        extra_headers: vec![],
    });

    // ── 8. Cookie variation ──────────────────────────────────
    out.push(CacheKeyProbe {
        kind: "cookie-key-leak",
        description: "Random Cookie value — caches that include Cookie in the key \
             give each cookie value its own slot; caches that DON'T let \
             cookied responses leak to anonymous users",
        probe_url: baseline_url.to_string(),
        extra_headers: vec![("Cookie".into(), "wafrift_test=random_value".into())],
    });

    out
}

/// Run the cache-diff scanner.
pub async fn run_cache_diff(mut args: CacheDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let baseline_url = with_query(&args.url, &format!("{}=baseline", args.param));
    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing cache-key surface against {}",
            "[wafrift cache-diff]".bright_cyan().bold(),
            args.url.bright_white()
        );
    }

    let baseline = match fire_get(&http, &baseline_url, &[]).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "  {} baseline probe failed: {e}",
                "✗ Transport error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline: HTTP {} ({} bytes, cache={})",
            "↘".bright_black(),
            baseline.status,
            baseline.body_len,
            baseline.cache_signal.as_deref().unwrap_or("none observed")
        );
    }

    let variants = generate_cache_variants(&args.url, &args.param);
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let counter = Arc::new(AtomicUsize::new(0));
    let baseline_arc = Arc::new(baseline);

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        let baseline = baseline_arc.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let outcome = fire_get(&http, &v.probe_url, &v.extra_headers).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, outcome, baseline)
        }));
    }

    let mut results: Vec<CacheDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome, baseline) = h.await.unwrap_or_else(|e| {
            (
                CacheKeyProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    probe_url: String::new(),
                    extra_headers: Vec::new(),
                },
                Err(format!("{e}")),
                Arc::new(FireOutcome {
                    status: 0,
                    body_len: 0,
                    body_hash: 0,
                    cache_signal: None,
                }),
            )
        });
        match outcome {
            Ok(probe) => {
                let curl = render_curl(&variant.probe_url, &variant.extra_headers);
                let body_hash_match = probe.body_hash == baseline.body_hash && probe.body_len > 0;
                let cache_signals_match =
                    probe.cache_signal == baseline.cache_signal && baseline.cache_signal.is_some();
                let severity = severity_of(
                    body_hash_match,
                    cache_signals_match,
                    probe.status,
                    baseline.status,
                );
                results.push(CacheDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_url: variant.probe_url.clone(),
                    probe_status: probe.status,
                    baseline_status: baseline.status,
                    body_hash_match,
                    cache_signals_match,
                    probe_cache_signal: probe.cache_signal.clone(),
                    baseline_cache_signal: baseline.cache_signal.clone(),
                    probe_body_len: probe.body_len,
                    baseline_body_len: baseline.body_len,
                    curl_cmd: curl,
                    severity,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, &baseline_arc, errors);
    ExitCode::SUCCESS
}

#[derive(Debug, Clone)]
struct FireOutcome {
    status: u16,
    body_len: usize,
    /// Cheap rolling hash of the body bytes — used to compare
    /// "is this the same response" without keeping the full body.
    body_hash: u64,
    /// Concatenated cache-relevant response headers (Age, X-Cache,
    /// CF-Cache-Status, X-Served-By, Via). `None` if none present.
    cache_signal: Option<String>,
}

async fn fire_get(
    http: &Client,
    url: &str,
    extra_headers: &[(String, String)],
) -> Result<FireOutcome, String> {
    let mut req = http.get(url);
    for (n, v) in extra_headers {
        req = req.header(n.as_str(), v);
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let cache_signal = extract_cache_signal(resp.headers());
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?;
    let body_hash = fnv1a(&body);
    Ok(FireOutcome {
        status,
        body_len: body.len(),
        body_hash,
        cache_signal,
    })
}

/// Pull cache-relevant headers into a single comparable string.
/// Empty/None when no signal is present.
fn extract_cache_signal(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for name in [
        "age",
        "x-cache",
        "cf-cache-status",
        "x-served-by",
        "via",
        "x-cache-hits",
    ] {
        if let Some(v) = headers.get(name).and_then(|h| h.to_str().ok()) {
            parts.push(format!("{name}={v}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// FNV-1a 64-bit hash. Pure, deterministic, fast.
fn fnv1a(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// `"high"` — body hash matches baseline (strong cache hit /
/// collision evidence); `"medium"` — cache-signal headers match
/// (weaker — cache layer is in front but content differs); `"none"`
/// otherwise.
fn severity_of(
    body_hash_match: bool,
    cache_signals_match: bool,
    probe_status: u16,
    baseline_status: u16,
) -> &'static str {
    if body_hash_match && probe_status == baseline_status {
        "high"
    } else if cache_signals_match {
        "medium"
    } else {
        "none"
    }
}

/// Replace (or append) the query string on a URL. Pure.
fn with_query(base: &str, new_query: &str) -> String {
    match Url::parse(base) {
        Ok(mut u) => {
            u.set_query(Some(new_query));
            u.to_string()
        }
        Err(_) => {
            // Fallback for non-parseable inputs: strip any existing
            // ? and append.
            let trimmed = base.split_once('?').map(|(b, _)| b).unwrap_or(base);
            format!("{trimmed}?{new_query}")
        }
    }
}

fn camel_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for ch in s.chars() {
        if upper && ch.is_ascii_alphabetic() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
        upper = !ch.is_ascii_alphabetic();
    }
    out
}

fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => format!("{}{}", c.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

fn render_curl(url: &str, extra_headers: &[(String, String)]) -> String {
    let mut out = String::from("curl -i");
    for (n, v) in extra_headers {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("{n}: {v}")));
    }
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

crate::impl_parser_diff_http_args!(CacheDiffArgs);

fn emit_output(
    args: &CacheDiffArgs,
    results: &[CacheDiffResult],
    baseline: &FireOutcome,
    errors: u32,
) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "param": args.param,
            "baseline_status": baseline.status,
            "baseline_body_len": baseline.body_len,
            "baseline_cache_signal": baseline.cache_signal,
            "probes": results.len(),
            "errors": errors,
            "divergences": {
                "high": high.len(),
                "medium": medium.len(),
            },
            "results": results,
        });
        crate::parser_diff_common::print_pretty_json(&out);
        return;
    }

    if !args.quiet {
        println!();
        println!(
            "  {} {} cache-key collision(s) — {} strong, {} weak · {} error(s)",
            "[wafrift cache-diff summary]".bright_cyan().bold(),
            (high.len() + medium.len()).to_string().bold().yellow(),
            high.len().to_string().bright_red().bold(),
            medium.len().to_string().yellow(),
            errors
        );
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {} — {}", r.kind.bold(), r.description);
        println!(
            "    {} body_hash_match={} · cache_signals_match={}",
            "↘".bright_black(),
            r.body_hash_match,
            r.cache_signals_match,
        );
        if let Some(s) = &r.probe_cache_signal {
            println!("    probe cache header: {s}");
        }
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate_cache_variants ───────────────────────────────

    #[test]
    fn generate_cache_variants_returns_non_empty_curated_set() {
        let v = generate_cache_variants("http://example.com/path", "q");
        assert!(v.len() >= 8, "expected at least 8 probes, got {}", v.len());
    }

    #[test]
    fn generate_cache_variants_kinds_are_unique() {
        let v = generate_cache_variants("http://example.com/path", "q");
        let mut kinds: Vec<&str> = v.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), v.len());
    }

    #[test]
    fn generate_cache_variants_covers_host_case_family() {
        let kinds: Vec<&str> = generate_cache_variants("http://example.com/p", "q")
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(kinds.iter().any(|k| k.contains("host-case")));
    }

    #[test]
    fn generate_cache_variants_covers_query_order_family() {
        let kinds: Vec<&str> = generate_cache_variants("http://example.com/p", "q")
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(kinds.iter().any(|k| k.contains("query-param-order")));
    }

    #[test]
    fn generate_cache_variants_x_forwarded_host_carries_attacker_value() {
        let v = generate_cache_variants("http://example.com/p", "q");
        let xfh = v
            .iter()
            .find(|p| p.kind == "x-forwarded-host-attacker")
            .expect("x-forwarded-host-attacker probe");
        let has_xfh = xfh
            .extra_headers
            .iter()
            .any(|(n, val)| n.eq_ignore_ascii_case("x-forwarded-host") && val.contains("attacker"));
        assert!(has_xfh);
    }

    #[test]
    fn generate_cache_variants_trailing_slash_toggles_path() {
        let v_no_slash = generate_cache_variants("http://x/foo", "q");
        let v_slash = generate_cache_variants("http://x/foo/", "q");
        let ts_no = v_no_slash
            .iter()
            .find(|p| p.kind == "trailing-slash")
            .expect("trailing-slash probe");
        let ts_yes = v_slash
            .iter()
            .find(|p| p.kind == "trailing-slash")
            .expect("trailing-slash probe");
        // Without slash → variant should HAVE the slash.
        assert!(ts_no.probe_url.ends_with("/"), "got: {}", ts_no.probe_url);
        // With slash → variant should NOT have the trailing slash.
        assert!(
            !ts_yes.probe_url.trim_end_matches('?').ends_with("/foo/"),
            "got: {}",
            ts_yes.probe_url
        );
    }

    // ── extract_cache_signal ──────────────────────────────────

    #[test]
    fn extract_cache_signal_returns_none_when_no_cache_headers_present() {
        let map = reqwest::header::HeaderMap::new();
        assert!(extract_cache_signal(&map).is_none());
    }

    #[test]
    fn extract_cache_signal_picks_up_age_header() {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert("age", "12".parse().unwrap());
        let sig = extract_cache_signal(&map).expect("signal");
        assert!(sig.contains("age=12"));
    }

    #[test]
    fn extract_cache_signal_combines_multiple_known_headers() {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert("age", "0".parse().unwrap());
        map.insert("x-cache", "HIT".parse().unwrap());
        map.insert("cf-cache-status", "REVALIDATED".parse().unwrap());
        let sig = extract_cache_signal(&map).expect("signal");
        assert!(sig.contains("age=0"));
        assert!(sig.contains("x-cache=HIT"));
        assert!(sig.contains("cf-cache-status=REVALIDATED"));
    }

    #[test]
    fn extract_cache_signal_ignores_unknown_headers() {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert("server", "nginx/1.25".parse().unwrap());
        map.insert("content-type", "text/html".parse().unwrap());
        assert!(extract_cache_signal(&map).is_none());
    }

    // ── fnv1a hash ────────────────────────────────────────────

    #[test]
    fn fnv1a_returns_known_offset_for_empty_input() {
        assert_eq!(fnv1a(b""), 0xcbf29ce484222325);
    }

    #[test]
    fn fnv1a_is_deterministic() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
    }

    #[test]
    fn fnv1a_distinguishes_different_inputs() {
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }

    #[test]
    fn fnv1a_distinguishes_single_byte_diff() {
        assert_ne!(fnv1a(b"hello"), fnv1a(b"hellp"));
    }

    // ── severity_of ───────────────────────────────────────────

    #[test]
    fn severity_of_high_when_body_hash_matches_and_status_matches() {
        assert_eq!(severity_of(true, false, 200, 200), "high");
    }

    #[test]
    fn severity_of_not_high_when_status_differs_even_if_body_matches() {
        // Identical bodies under different statuses is unusual but
        // possible — treat as "medium" only if cache headers match,
        // else "none".
        assert_eq!(severity_of(true, false, 200, 403), "none");
        assert_eq!(severity_of(true, true, 200, 403), "medium");
    }

    #[test]
    fn severity_of_medium_when_only_cache_signals_match() {
        assert_eq!(severity_of(false, true, 200, 200), "medium");
    }

    #[test]
    fn severity_of_none_when_nothing_matches() {
        assert_eq!(severity_of(false, false, 200, 200), "none");
    }

    // ── with_query ────────────────────────────────────────────

    #[test]
    fn with_query_replaces_existing_query() {
        let out = with_query("http://x/p?old=1", "new=2");
        // url crate may reorder, but the new query must be present
        // and the old must be gone.
        assert!(out.contains("new=2"), "got: {out}");
        assert!(!out.contains("old=1"), "got: {out}");
    }

    #[test]
    fn with_query_appends_when_no_existing_query() {
        let out = with_query("http://x/p", "new=2");
        assert!(out.contains("?new=2"), "got: {out}");
    }

    #[test]
    fn with_query_falls_back_for_unparseable_url() {
        let out = with_query("not a url", "q=1");
        assert!(out.contains("?q=1"), "got: {out}");
    }

    // ── camel_case + upper_first ──────────────────────────────

    #[test]
    fn camel_case_alternates_after_non_alpha() {
        assert_eq!(camel_case("example.com"), "Example.Com");
        assert_eq!(camel_case("a.b.c"), "A.B.C");
    }

    #[test]
    fn upper_first_uppercases_only_first_char() {
        assert_eq!(upper_first("query"), "Query");
        assert_eq!(upper_first("q"), "Q");
        assert_eq!(upper_first(""), "");
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_curl_dash_i_with_quoted_url_and_headers() {
        let out = render_curl("http://x/?q=1", &[("Host".into(), "X".into())]);
        assert!(out.starts_with("curl -i "));
        assert!(out.contains("-H 'Host: X'"), "got: {out}");
        assert!(out.contains("'http://x/?q=1'"), "got: {out}");
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_cache_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a Cloudflare-style cache: emit X-Cache
                    // header on every response. Body is the SAME for
                    // every request (simulates an aggressively-cached
                    // static asset).
                    let body = "<html>cached static asset</html>";
                    let _ = req;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\
                         CF-Cache-Status: HIT\r\nAge: 42\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn run_cache_diff_against_mock_succeeds() {
        let addr = spawn_cache_mock().await;
        let args = CacheDiffArgs {
            url: format!("http://{addr}/path"),
            param: "q".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cache_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_cache_diff_against_unreachable_target_exits_1() {
        let args = CacheDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            param: "q".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cache_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
