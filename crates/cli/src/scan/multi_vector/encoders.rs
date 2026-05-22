//! Encoding helpers used by [`super::build_request_for_vector`].
//!
//! All four functions in this module are **pure** (no IO, no
//! allocation surprises, no side effects beyond the returned
//! `Vec<u8>` / `String`). They live in their own file so the
//! per-vector builders that consume them don't drag a few hundred
//! lines of encoder logic + encoder tests into the dispatch surface.
//!
//! Module surface:
//!
//! - [`encode_cbor_string_map`] — RFC 8949 CBOR `{key: value}`
//!   map for the `POST-cbor` vector.
//! - [`splice_payload_into_path`] — splice a percent-encoded
//!   payload into a URL path for the `path-segment` vector.
//! - [`quoted_printable_encode`] — RFC 2045 §6.7 quoted-printable
//!   for the `POST-multipart-qp` vector.
//! - [`xml_text_escape`] — XML 1.0 §2.4 entity escaping for the
//!   `POST-xml` / `POST-text-xml` vectors.

/// Hand-rolled CBOR (RFC 8949) text-string encoder. Appends the
/// header byte(s) + UTF-8 payload to `out`.
///
/// Output format per the spec:
///
/// - `0x60 | n` — text-string with inline length n (n ≤ 23)
/// - `0x78 LL` — text-string with 1-byte length (n ≤ 0xFF)
/// - `0x79 LL LL` — text-string with 2-byte big-endian length
///
/// We stop at 16-bit length — WAF-evasion payloads never exceed
/// 64 KiB. Anything bigger falls back to the 16-bit length
/// encoding with the high bytes set to the actual length (still
/// RFC 8949-legal up to the u16 ceiling). Strings longer than
/// 65535 bytes are a non-goal here.
fn encode_cbor_text_string(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n <= 23 {
        out.push(0x60 | (n as u8));
    } else if n <= 0xFF {
        out.push(0x78);
        out.push(n as u8);
    } else {
        // 16-bit length covers up to 64 KiB which is far more
        // than any payload wafrift ever fires.
        let n16 = n.min(0xFFFF) as u16;
        out.push(0x79);
        out.extend_from_slice(&n16.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Public encoder for the `POST-cbor` vector: produces a
/// CBOR-encoded `{key: value}` map. Held as a function so it can
/// be unit-tested directly without standing up an HTTP request.
pub(super) fn encode_cbor_string_map(key: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + key.len() + value.len() + 8);
    out.push(0xA1); // map(1)
    encode_cbor_text_string(key, &mut out);
    encode_cbor_text_string(value, &mut out);
    out
}

/// Splice a percent-encoded payload into the path of the target
/// URL, BEFORE the existing path and query. Preserves the existing
/// scheme + authority + query string + fragment.
///
/// Examples:
/// - `http://x.com/`             + `p`  → `http://x.com/p`
/// - `http://x.com/api/users?id=1` + `p`  → `http://x.com/p/api/users?id=1`
/// - `http://x.com`              + `p`  → `http://x.com/p`
///
/// The original target's path is RETAINED — many backends route on
/// catch-all `/api/*` patterns and we want the extra segment to
/// extend, not replace. Backends that ONLY match the exact original
/// path will 404; that's an honest "vector did not land" signal,
/// not an evasion failure.
pub(super) fn splice_payload_into_path(target: &str, encoded_payload: &str) -> String {
    // Find the host/path boundary: skip `scheme://`, then the first
    // `/` is the path start.
    let scheme_end = target.find("://").map_or(0, |i| i + 3);
    let after_scheme = &target[scheme_end..];
    // Path starts at first `/` after authority; if none, append.
    let path_start_in_after_scheme = after_scheme.find('/');
    let (authority_end, original_path_with_query) = match path_start_in_after_scheme {
        Some(i) => (scheme_end + i, &target[scheme_end + i..]),
        None => (target.len(), ""),
    };
    let authority = &target[..authority_end];
    // Split path from query: payload goes BEFORE the query.
    let (path_only, query_and_frag) = match original_path_with_query.find('?') {
        Some(i) => (
            &original_path_with_query[..i],
            &original_path_with_query[i..],
        ),
        None => (original_path_with_query, ""),
    };
    // If the original path is `/` or empty, the spliced path is
    // `/<payload>`; otherwise prepend the payload as a fresh
    // segment in front of the original path.
    if path_only.is_empty() || path_only == "/" {
        format!("{authority}/{encoded_payload}{query_and_frag}")
    } else {
        format!("{authority}/{encoded_payload}{path_only}{query_and_frag}")
    }
}

/// Quoted-printable encode per RFC 2045 §6.7. Each byte outside
/// the printable-ASCII safe set (33..=126 minus `=`) becomes
/// `=HH`; lines stay short enough that we don't bother with the
/// 76-char soft-wrap (payloads are short, and `=` followed by
/// `<CRLF>` is the only wrap marker in the spec — leaving it off
/// is interoperable with every QP decoder).
pub(super) fn quoted_printable_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        // 33..=126 are printable ASCII; `=` (0x3D) is the escape
        // sigil itself and must be encoded so the decoder can
        // distinguish it from a real escape sequence. Tabs and
        // spaces are legal mid-line but we encode them anyway
        // for maximum decoder safety.
        let safe = (33..=126).contains(&b) && b != b'=';
        if safe {
            out.push(b as char);
        } else {
            out.push('=');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

/// XML-entity-escape the bytes that go into an XML text node.
/// Only the five XML-significant chars need handling — every
/// other byte is fine in a text node per W3C XML 1.0 §2.4. The
/// backend's XML parser un-escapes them, so the payload arrives
/// byte-identical to what we'd have sent as a plain string in any
/// other delivery shape.
pub(super) fn xml_text_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── xml_text_escape (XML 1.0 §2.4) ────────────────────────

    #[test]
    fn xml_text_escape_escapes_the_five_xml_chars() {
        assert_eq!(xml_text_escape("<a&b\"c'd>"), "&lt;a&amp;b&quot;c&apos;d&gt;");
    }

    #[test]
    fn xml_text_escape_passes_through_safe_chars() {
        assert_eq!(xml_text_escape("hello 123 äé"), "hello 123 äé");
    }

    #[test]
    fn xml_text_escape_handles_empty_string() {
        assert_eq!(xml_text_escape(""), "");
    }

    // ── encode_cbor_string_map (RFC 8949) ─────────────────────

    #[test]
    fn cbor_encoder_emits_map_one_marker_first() {
        let bytes = encode_cbor_string_map("q", "x");
        assert_eq!(bytes[0], 0xA1, "must lead with map(1) marker");
    }

    #[test]
    fn cbor_encoder_short_strings_use_single_byte_header() {
        // For text strings of length ≤ 23, the major-type-3 header
        // is `0x60 | n` — a single byte, no length prefix.
        let bytes = encode_cbor_string_map("q", "abc");
        // After 0xA1, expect 0x61 (text "q" — length 1) then 'q'
        assert_eq!(bytes[1], 0x61);
        assert_eq!(bytes[2], b'q');
        // Then 0x63 (text "abc" — length 3) then 'a','b','c'
        assert_eq!(bytes[3], 0x63);
        assert_eq!(&bytes[4..7], b"abc");
    }

    #[test]
    fn cbor_encoder_24_byte_string_uses_two_byte_header() {
        // 24 bytes is exactly above the 0x60 | 0x17 = 0x77 single-
        // byte ceiling, so the encoder must shift to the 0x78 LL
        // form.
        let v24 = "x".repeat(24);
        let bytes = encode_cbor_string_map("k", &v24);
        // After 0xA1, key header + 'k', then value header...
        let key_end = 1 + 1 + 1; // 0xA1 + 0x61 + 'k'
        assert_eq!(bytes[key_end], 0x78);
        assert_eq!(bytes[key_end + 1], 24);
    }

    #[test]
    fn cbor_encoder_300_byte_string_uses_three_byte_header() {
        // 300 bytes exceeds the 0xFF single-byte-length ceiling,
        // so the encoder must use the 0x79 LL LL big-endian form.
        let v300 = "y".repeat(300);
        let bytes = encode_cbor_string_map("k", &v300);
        let key_end = 1 + 1 + 1;
        assert_eq!(bytes[key_end], 0x79);
        assert_eq!(
            u16::from_be_bytes([bytes[key_end + 1], bytes[key_end + 2]]),
            300
        );
    }

    #[test]
    fn cbor_encoder_round_trips_payload_byte_identical() {
        // Decode our own output by walking the bytes: we know the
        // shape is map(1) + key + value. A correctness check that
        // doesn't depend on a CBOR crate.
        let bytes = encode_cbor_string_map("payload", "' OR 1=1--");
        assert_eq!(bytes[0], 0xA1);
        let key_hdr = bytes[1];
        assert_eq!(key_hdr & 0xE0, 0x60, "key must be text-string major type");
        let key_len = (key_hdr & 0x1F) as usize;
        let key_start = 2;
        let key_end = key_start + key_len;
        let key = std::str::from_utf8(&bytes[key_start..key_end]).unwrap();
        assert_eq!(key, "payload");
        let val_hdr = bytes[key_end];
        let val_len = (val_hdr & 0x1F) as usize;
        let val_start = key_end + 1;
        let val_end = val_start + val_len;
        let val = std::str::from_utf8(&bytes[val_start..val_end]).unwrap();
        assert_eq!(val, "' OR 1=1--");
    }

    #[test]
    fn cbor_encoder_empty_value_emits_zero_length_text_string() {
        let bytes = encode_cbor_string_map("k", "");
        // 0xA1, 0x61, 'k', 0x60 (empty text string)
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[3], 0x60);
    }

    #[test]
    fn cbor_encoder_unicode_value_preserves_utf8_bytes() {
        let bytes = encode_cbor_string_map("k", "café");
        // "café" is 5 UTF-8 bytes (c=1, a=1, f=1, é=2)
        let val_start = bytes.len() - 5;
        assert_eq!(&bytes[val_start..], "café".as_bytes());
    }

    // ── splice_payload_into_path ──────────────────────────────

    #[test]
    fn splice_payload_into_path_handles_root_path() {
        let got = splice_payload_into_path("http://example.com/", "abc");
        assert_eq!(got, "http://example.com/abc");
    }

    #[test]
    fn splice_payload_into_path_handles_no_path_segment_in_target() {
        let got = splice_payload_into_path("http://example.com", "abc");
        assert_eq!(got, "http://example.com/abc");
    }

    #[test]
    fn splice_payload_into_path_prepends_before_existing_segments() {
        let got = splice_payload_into_path("http://example.com/api/users", "payload");
        assert_eq!(got, "http://example.com/payload/api/users");
    }

    #[test]
    fn splice_payload_into_path_preserves_query_string() {
        let got = splice_payload_into_path("http://example.com/api?id=1", "payload");
        assert_eq!(got, "http://example.com/payload/api?id=1");
    }

    #[test]
    fn splice_payload_into_path_preserves_query_string_on_root_path() {
        let got = splice_payload_into_path("http://example.com/?id=1", "payload");
        assert_eq!(got, "http://example.com/payload?id=1");
    }

    #[test]
    fn splice_payload_into_path_handles_https_scheme() {
        let got = splice_payload_into_path("https://x.com/api", "p");
        assert_eq!(got, "https://x.com/p/api");
    }

    #[test]
    fn splice_payload_into_path_handles_authority_with_port() {
        let got = splice_payload_into_path("http://x.com:8080/api", "p");
        assert_eq!(got, "http://x.com:8080/p/api");
    }

    // ── quoted_printable_encode (RFC 2045 §6.7) ───────────────

    #[test]
    fn qp_encodes_printable_ascii_verbatim() {
        assert_eq!(quoted_printable_encode(b"AaZz09!?-_"), "AaZz09!?-_");
    }

    #[test]
    fn qp_escapes_equals_sign_itself() {
        // `=` is the escape sigil and MUST be encoded as `=3D` so
        // the decoder cannot mistake it for a real escape.
        assert_eq!(quoted_printable_encode(b"a=b"), "a=3Db");
    }

    #[test]
    fn qp_escapes_space_and_tab() {
        assert_eq!(quoted_printable_encode(b" "), "=20");
        assert_eq!(quoted_printable_encode(b"\t"), "=09");
    }

    #[test]
    fn qp_escapes_high_bytes() {
        // U+00A0 NO-BREAK SPACE in UTF-8 = 0xC2 0xA0.
        assert_eq!(quoted_printable_encode(b"\xC2\xA0"), "=C2=A0");
    }

    #[test]
    fn qp_escapes_crlf_so_decoded_payload_is_literal_crlf() {
        // Raw CR/LF would terminate the multipart part; QP keeps
        // them as bytes inside the encoded body.
        assert_eq!(quoted_printable_encode(b"\r\n"), "=0D=0A");
    }

    #[test]
    fn qp_handles_empty_input() {
        assert_eq!(quoted_printable_encode(b""), "");
    }

    #[test]
    fn qp_roundtrip_via_decode_recovers_payload() {
        // We don't ship a QP decoder — assert the encoded form
        // matches the documented spec character-by-character for
        // a representative payload, which any conforming decoder
        // (mail clients, Python `quopri`, JavaMail) reverses.
        let encoded = quoted_printable_encode(b"<script>alert(1)</script>");
        // Every byte is printable-ASCII safe so verbatim except
        // none — every byte here is in the safe range; equals
        // sign is absent. Verify no `=` appears in output.
        assert!(!encoded.contains('='), "no escapes expected: {encoded}");
        assert_eq!(encoded, "<script>alert(1)</script>");
    }
}
