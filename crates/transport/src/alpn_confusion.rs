//! TLS ALPN scheme confusion — negotiate one protocol, speak another.
//!
//! Some WAF inspection pipelines route traffic to protocol-specific parsers
//! based on the ALPN token negotiated during the TLS handshake.  When the
//! client negotiates `h2` but subsequently writes HTTP/1.1 bytes, the WAF
//! applies its HTTP/2 parser to HTTP/1.1 bytes and may fail to recognise an
//! injection payload that would otherwise be caught.
//!
//! # What this module provides
//!
//! [`AlpnConfusionPayload`] is a pure description of the confusion probe:
//! - Which ALPN tokens to advertise in the ClientHello
//! - Which bytes to write on the wire after the handshake
//! - A human-readable description of the targeted flaw
//!
//! The module intentionally does **not** open live TCP connections; the
//! caller drives the TLS handshake with tokio-rustls and then writes
//! [`AlpnConfusionPayload::wire_bytes`] through the established stream.
//! This makes the generators deterministic, fast, and testable without
//! a network.
//!
//! # Feasibility of raw writes after a rustls handshake
//!
//! tokio-rustls wraps a `rustls::ClientConnection` inside a
//! `tokio::io::AsyncReadExt` / `AsyncWriteExt` facade.  The
//! `tokio_rustls::TlsStream` produced by `TlsConnector::connect` is a
//! `tokio::io::AsyncWrite` implementation whose `poll_write` pushes
//! plaintext into `rustls`'s plaintext buffer and seals it with the
//! negotiated cipher suite.  The on-wire bytes are the **TLS record**-
//! wrapped form of whatever the caller writes — which is exactly what we
//! need: write HTTP/1.1 bytes on a stream the WAF believes carries h2, or
//! write the HTTP/2 preface on a stream the WAF believes carries HTTP/1.1.
//! No internal rustls hook is needed; `AsyncWrite` is the raw-write path.
//!
//! The `TlsConnector::connect(server_name, tcp_stream)` call uses the
//! `alpn_protocols` configured on the `ClientConfig` to negotiate ALPN.
//! After the handshake completes the caller can write arbitrary bytes —
//! the TLS record layer is already established.

use thiserror::Error;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from ALPN confusion payload construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AlpnConfusionError {
    /// An ALPN token exceeded the 255-byte RFC 7301 limit.
    #[error("ALPN token too long ({len} bytes, max 255): {token:?}")]
    TokenTooLong { token: String, len: usize },

    /// The wire payload was empty.
    #[error("wire payload must be non-empty")]
    EmptyWirePayload,
}

// ── Core types ───────────────────────────────────────────────────────────────

/// Which dimension of confusion this probe targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnConfusionVariant {
    /// Negotiate `h2`; write HTTP/1.1 bytes on the wire.
    H2NegotiatedH1Spoken,
    /// Negotiate `http/1.1`; write the HTTP/2 client preface bytes.
    H1NegotiatedH2Spoken,
    /// Send a ClientHello with no ALPN extension at all; write HTTP/2
    /// preface bytes (WAF defaults to H1 inspector, origin defaults to H2).
    AlpnAbsentH2Spoken,
    /// Advertise both `h2` and `http/1.1`; let origin preference disagree
    /// with WAF's assumed preference.  Wire bytes are HTTP/2 preface
    /// (WAF assumes h1 when multiple are offered; origin picks h2).
    MultiAlpnH2Preface,
}

/// A self-contained description of an ALPN confusion probe.
///
/// Contains:
/// - The ALPN tokens to place into the ClientHello (empty = no extension).
/// - The raw plaintext bytes to write after handshake.
/// - Metadata for reporting.
#[derive(Debug, Clone)]
pub struct AlpnConfusionPayload {
    /// Human-readable name.
    pub name: &'static str,
    /// Longer description of the targeted WAF flaw.
    pub description: &'static str,
    /// Which confusion variant.
    pub variant: AlpnConfusionVariant,
    /// ALPN protocol tokens to negotiate.  An empty list means "no ALPN
    /// extension in the ClientHello".
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Raw plaintext to write on the wire after the handshake.  The TLS
    /// record layer wraps these bytes; the WAF sees them inside a stream
    /// whose ALPN it believes is determined by `alpn_protocols`.
    pub wire_bytes: Vec<u8>,
}

impl AlpnConfusionPayload {
    /// Build the payload, validating invariants.
    pub fn build(
        name: &'static str,
        description: &'static str,
        variant: AlpnConfusionVariant,
        alpn_protocols: Vec<Vec<u8>>,
        wire_bytes: Vec<u8>,
    ) -> Result<Self, AlpnConfusionError> {
        for tok in &alpn_protocols {
            if tok.len() > 255 {
                return Err(AlpnConfusionError::TokenTooLong {
                    token: String::from_utf8_lossy(tok).into_owned(),
                    len: tok.len(),
                });
            }
        }
        if wire_bytes.is_empty() {
            return Err(AlpnConfusionError::EmptyWirePayload);
        }
        Ok(Self {
            name,
            description,
            variant,
            alpn_protocols,
            wire_bytes,
        })
    }
}

// ── HTTP/2 client preface ─────────────────────────────────────────────────

/// The HTTP/2 client connection preface mandated by RFC 9113 §3.4.
///
/// 24-byte magic followed by an empty SETTINGS frame (9 bytes):
/// ```text
/// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
/// 0x00 0x00 0x00  // length = 0
/// 0x04            // type   = SETTINGS
/// 0x00            // flags  = 0
/// 0x00 0x00 0x00 0x00  // stream id = 0
/// ```
pub const HTTP2_CLIENT_PREFACE: &[u8] =
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Minimal HTTP/1.1 GET request bytes that a WAF's H1 parser would inspect.
pub const MINIMAL_H1_GET: &[u8] =
    b"GET / HTTP/1.1\r\nHost: target.invalid\r\nConnection: close\r\n\r\n";

// ── Generators ────────────────────────────────────────────────────────────

/// Build all four ALPN confusion probes.
///
/// Returns `Err` if an invariant is violated (should not happen with
/// the hard-coded constants below, but the builder validates regardless).
pub fn all_probes() -> Result<Vec<AlpnConfusionPayload>, AlpnConfusionError> {
    Ok(vec![
        h2_negotiated_h1_spoken()?,
        h1_negotiated_h2_spoken()?,
        alpn_absent_h2_spoken()?,
        multi_alpn_h2_preface()?,
    ])
}

/// Negotiate `h2`; write HTTP/1.1 bytes after the handshake.
///
/// WAF routes the stream to its HTTP/2 frame parser which cannot
/// parse `GET / HTTP/1.1\r\n…` and may skip the request altogether,
/// yielding a bypass window.
pub fn h2_negotiated_h1_spoken() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    AlpnConfusionPayload::build(
        "h2-negotiated-h1-spoken",
        "Negotiate h2 ALPN; write HTTP/1.1 request bytes. \
         WAF applies H2 frame parser to H1 bytes — unrecognised frame \
         type triggers fallthrough or parse error, bypassing inspection.",
        AlpnConfusionVariant::H2NegotiatedH1Spoken,
        vec![b"h2".to_vec()],
        MINIMAL_H1_GET.to_vec(),
    )
}

/// Negotiate `http/1.1`; write the HTTP/2 client preface bytes.
///
/// WAF routes the stream to its HTTP/1.1 parser which sees
/// `PRI * HTTP/2.0` as a malformed request line and either rejects or
/// passes without inspection.
pub fn h1_negotiated_h2_spoken() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    AlpnConfusionPayload::build(
        "http1-negotiated-h2-spoken",
        "Negotiate http/1.1 ALPN; write HTTP/2 preface bytes. \
         WAF applies H1 parser to H2 bytes — the preface magic is not \
         a valid request-line so the WAF either errors-open or drops \
         inspection.",
        AlpnConfusionVariant::H1NegotiatedH2Spoken,
        vec![b"http/1.1".to_vec()],
        HTTP2_CLIENT_PREFACE.to_vec(),
    )
}

/// Send no ALPN extension; write HTTP/2 preface bytes.
///
/// When no ALPN extension is present some WAFs default to H1 inspection
/// while origins default to H2 (opportunistic upgrade).  The WAF's H1
/// parser cannot parse the H2 preface, creating a bypass gap.
pub fn alpn_absent_h2_spoken() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    AlpnConfusionPayload::build(
        "alpn-absent-h2-spoken",
        "No ALPN extension in ClientHello; write HTTP/2 preface bytes. \
         WAF defaults to H1 inspection; origin uses opportunistic H2 — \
         parser mismatch at both ends.",
        AlpnConfusionVariant::AlpnAbsentH2Spoken,
        vec![], // no ALPN extension
        HTTP2_CLIENT_PREFACE.to_vec(),
    )
}

/// Advertise `[h2, http/1.1]`; write HTTP/2 preface bytes.
///
/// Some WAFs, when given multiple ALPN tokens, assume the lower-priority
/// protocol (http/1.1) will be selected and apply H1 inspection.  Many
/// origins prefer h2 when offered alongside http/1.1, so the session
/// actually carries h2 frames that the WAF's H1 parser cannot follow.
pub fn multi_alpn_h2_preface() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    AlpnConfusionPayload::build(
        "multi-alpn-h2-preface",
        "Offer [h2, http/1.1] ALPN; write HTTP/2 preface. \
         WAF assumes http/1.1 wins (conservative); origin picks h2 — \
         WAF's H1 inspector processes H2 frames.",
        AlpnConfusionVariant::MultiAlpnH2Preface,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        HTTP2_CLIENT_PREFACE.to_vec(),
    )
}

// ── Additional specialised probes ─────────────────────────────────────────

/// A probe that sends the HTTP/2 preface then immediately follows it with
/// a crafted HTTP/1.1 request, creating a dual-protocol stream.
///
/// This targets WAFs that inspect only the first protocol boundary and stop.
pub fn h2_preface_then_h1_request() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    let mut wire = HTTP2_CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(MINIMAL_H1_GET);
    AlpnConfusionPayload::build(
        "h2-preface-then-h1-request",
        "Negotiate h2; write H2 preface then H1 request bytes back-to-back. \
         WAF parser may stop after the preface and miss the H1 payload.",
        AlpnConfusionVariant::H2NegotiatedH1Spoken,
        vec![b"h2".to_vec()],
        wire,
    )
}

/// A probe that sends a partial HTTP/2 preface (truncated after the magic
/// line, before `SM`) then continues with an HTTP/1.1 request.
///
/// Targets WAFs that detect the HTTP/2 magic and switch parsers without
/// waiting for the complete preface, leaving the H1 request uninspected.
pub fn partial_h2_preface_then_h1() -> Result<AlpnConfusionPayload, AlpnConfusionError> {
    // Partial preface: magic line + \r\n\r\n only, no SM\r\n\r\n
    let partial_preface = b"PRI * HTTP/2.0\r\n\r\n";
    let mut wire = partial_preface.to_vec();
    wire.extend_from_slice(MINIMAL_H1_GET);
    AlpnConfusionPayload::build(
        "partial-h2-preface-then-h1",
        "Negotiate h2; write partial H2 magic then H1 bytes. \
         WAF that parser-switches on magic string alone sees H1 bytes \
         through its H2 parser — parse confusion.",
        AlpnConfusionVariant::H2NegotiatedH1Spoken,
        vec![b"h2".to_vec()],
        wire,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Structural invariants ──────────────────────────────────────────────

    #[test]
    fn all_probes_builds_without_error() {
        let probes = all_probes().expect("all_probes must succeed");
        assert_eq!(probes.len(), 4, "expected exactly 4 probes");
    }

    #[test]
    fn all_probes_have_non_empty_wire_bytes() {
        for p in all_probes().unwrap() {
            assert!(
                !p.wire_bytes.is_empty(),
                "probe {:?} has empty wire_bytes",
                p.name
            );
        }
    }

    #[test]
    fn all_probes_have_non_empty_names_and_descriptions() {
        for p in all_probes().unwrap() {
            assert!(!p.name.is_empty(), "probe has empty name");
            assert!(
                !p.description.is_empty(),
                "probe {:?} has empty description",
                p.name
            );
        }
    }

    #[test]
    fn alpn_tokens_within_rfc7301_limit() {
        for p in all_probes().unwrap() {
            for tok in &p.alpn_protocols {
                assert!(
                    tok.len() <= 255,
                    "probe {:?}: token exceeds 255 bytes",
                    p.name
                );
            }
        }
    }

    // ── h2-negotiated-h1-spoken ───────────────────────────────────────────

    #[test]
    fn h2_negotiated_h1_spoken_alpn_is_h2_only() {
        let p = h2_negotiated_h1_spoken().unwrap();
        assert_eq!(p.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn h2_negotiated_h1_spoken_wire_is_valid_http1() {
        let p = h2_negotiated_h1_spoken().unwrap();
        let s = std::str::from_utf8(&p.wire_bytes).expect("wire bytes must be valid UTF-8");
        assert!(s.contains("HTTP/1.1"), "wire must contain HTTP/1.1 version");
        assert!(s.contains("GET"), "wire must contain a method");
    }

    #[test]
    fn h2_negotiated_h1_spoken_variant() {
        let p = h2_negotiated_h1_spoken().unwrap();
        assert_eq!(p.variant, AlpnConfusionVariant::H2NegotiatedH1Spoken);
    }

    // ── h1-negotiated-h2-spoken ───────────────────────────────────────────

    #[test]
    fn h1_negotiated_h2_spoken_alpn_is_http11() {
        let p = h1_negotiated_h2_spoken().unwrap();
        assert_eq!(p.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn h1_negotiated_h2_spoken_wire_starts_with_h2_preface() {
        let p = h1_negotiated_h2_spoken().unwrap();
        assert!(
            p.wire_bytes
                .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            "wire must begin with the HTTP/2 client connection preface"
        );
    }

    #[test]
    fn h1_negotiated_h2_spoken_variant() {
        let p = h1_negotiated_h2_spoken().unwrap();
        assert_eq!(p.variant, AlpnConfusionVariant::H1NegotiatedH2Spoken);
    }

    // ── alpn-absent-h2-spoken ─────────────────────────────────────────────

    #[test]
    fn alpn_absent_probe_has_no_alpn_tokens() {
        let p = alpn_absent_h2_spoken().unwrap();
        assert!(
            p.alpn_protocols.is_empty(),
            "ALPN-absent probe must carry zero ALPN tokens"
        );
    }

    #[test]
    fn alpn_absent_probe_wire_is_h2_preface() {
        let p = alpn_absent_h2_spoken().unwrap();
        assert!(
            p.wire_bytes
                .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        );
    }

    #[test]
    fn alpn_absent_probe_variant() {
        let p = alpn_absent_h2_spoken().unwrap();
        assert_eq!(p.variant, AlpnConfusionVariant::AlpnAbsentH2Spoken);
    }

    // ── multi-alpn-h2-preface ─────────────────────────────────────────────

    #[test]
    fn multi_alpn_probe_advertises_both_protocols() {
        let p = multi_alpn_h2_preface().unwrap();
        assert!(p.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(p.alpn_protocols.contains(&b"http/1.1".to_vec()));
        assert_eq!(p.alpn_protocols.len(), 2);
    }

    #[test]
    fn multi_alpn_probe_wire_is_h2_preface() {
        let p = multi_alpn_h2_preface().unwrap();
        assert!(
            p.wire_bytes
                .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        );
    }

    #[test]
    fn multi_alpn_probe_variant() {
        let p = multi_alpn_h2_preface().unwrap();
        assert_eq!(p.variant, AlpnConfusionVariant::MultiAlpnH2Preface);
    }

    // ── specialised probes ────────────────────────────────────────────────

    #[test]
    fn h2_preface_then_h1_contains_both_protocols() {
        let p = h2_preface_then_h1_request().unwrap();
        let wire = &p.wire_bytes;
        // Starts with H2 preface
        assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        // Followed by H1 GET
        let s = std::str::from_utf8(wire).expect("wire must be ASCII");
        assert!(s.contains("GET / HTTP/1.1"));
    }

    #[test]
    fn partial_h2_preface_then_h1_wire_structure() {
        let p = partial_h2_preface_then_h1().unwrap();
        let wire = &p.wire_bytes;
        assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\n"));
        // Must NOT contain the SM continuation (partial preface)
        let preface_end = b"PRI * HTTP/2.0\r\n\r\n".len();
        let remainder = std::str::from_utf8(&wire[preface_end..]).unwrap();
        assert!(
            remainder.starts_with("GET"),
            "H1 request must follow the partial preface"
        );
    }

    // ── error paths ───────────────────────────────────────────────────────

    #[test]
    fn builder_rejects_oversized_alpn_token() {
        let big_token = vec![b'x'; 256];
        let err = AlpnConfusionPayload::build(
            "test",
            "desc",
            AlpnConfusionVariant::H2NegotiatedH1Spoken,
            vec![big_token],
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AlpnConfusionError::TokenTooLong { len: 256, .. }),
            "unexpected error variant: {err}"
        );
    }

    #[test]
    fn builder_rejects_empty_wire_payload() {
        let err = AlpnConfusionPayload::build(
            "test",
            "desc",
            AlpnConfusionVariant::H2NegotiatedH1Spoken,
            vec![b"h2".to_vec()],
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, AlpnConfusionError::EmptyWirePayload);
    }

    // ── HTTP/2 preface correctness ────────────────────────────────────────

    #[test]
    fn http2_preface_constant_matches_rfc9113() {
        // RFC 9113 §3.4: 24-byte magic string
        let magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(&HTTP2_CLIENT_PREFACE[..24], magic);
        // Followed by a valid empty SETTINGS frame (9 bytes, length=0, type=0x4)
        let settings = &HTTP2_CLIENT_PREFACE[24..];
        assert_eq!(settings.len(), 9);
        assert_eq!(settings[3], 0x04, "frame type must be SETTINGS (4)");
        assert_eq!(
            u32::from_be_bytes([settings[0], settings[1], settings[2], 0]) >> 8,
            0,
            "payload length must be 0"
        );
    }

    #[test]
    fn http2_preface_total_length() {
        // 24 bytes magic + 9 bytes SETTINGS = 33 bytes
        assert_eq!(HTTP2_CLIENT_PREFACE.len(), 33);
    }
}
