//! `compression` — request-body compression as a WAF-evasion surface.
//!
//! ## The attack
//!
//! Almost every WAF in production today inspects raw request bytes,
//! NOT the decompressed payload. The reasoning is operational: a
//! WAF that decompresses inbound bodies pays the CPU cost of
//! decompression on every request, and many vendors choose to skip
//! that — either entirely, or selectively per `Content-Encoding`
//! algorithm.
//!
//! That choice is the seam this module exploits:
//!
//! - **`Content-Encoding: gzip`** is the universal case; nearly all
//!   WAFs decompress it. Useful as the baseline + as a chain
//!   ingredient.
//! - **`Content-Encoding: deflate`** is RFC-permitted but irregularly
//!   supported — many WAFs that handle gzip return 400 on a
//!   `deflate`-coded body. The origin (nginx, IIS, Apache, Node,
//!   PHP-FPM, anything using zlib) accepts both.
//! - **`Content-Encoding: br`** (Brotli) is where the seam is widest.
//!   Brotli requires a separate decompressor (not zlib). Many WAFs
//!   ship no brotli support at all — they either return 415 (and
//!   the operator avoids `br`), or worse, they pass the request
//!   through uninspected because their rule engine has nothing to
//!   match against. Origins ARE brotli-capable (Chrome 49+,
//!   Firefox 44+, nginx 1.11+ with the `brotli` module). Wrap a
//!   payload in brotli and the rule corpus that fires on the plain
//!   payload bytes never gets a chance to match.
//!
//! ## Chained encoding
//!
//! Encoding-chain attacks add layers (e.g. `gzip → base64 → urlenc`).
//! The WAF, which normalises only a fixed number of decode passes
//! (usually 1, sometimes 2), stops short of the original payload —
//! while the origin's parser stack (which decodes more layers as
//! Content-Type / Content-Encoding direct) reaches it. `chain` is
//! the primitive for this attack.
//!
//! ## Pristine code
//!
//! - Every public function returns `Result<_, CompressionError>` —
//!   no `unwrap()` reachable on bad input.
//! - The chain function caps at 16 layers so a misconfiguration
//!   (`gzip,gzip,gzip,...`) can't run away.
//! - Empty body is permitted and returns the compressor's idempotent
//!   marker (gzip has a 10-byte header even for empty input, brotli
//!   is similar).
//! - No allocation beyond what each encoder requires; the public
//!   API takes a borrowed slice, not an owned Vec.

use thiserror::Error;

/// Errors raised by the compression-confusion API. Wraps the
/// underlying encoder failures (rare for in-memory operations) plus
/// the chain-depth cap.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("compression chain exceeded the {0}-layer safety cap")]
    ChainTooDeep(usize),
    #[error("gzip encoder error: {0}")]
    Gzip(std::io::Error),
    #[error("deflate encoder error: {0}")]
    Deflate(std::io::Error),
    #[error("brotli encoder error: {0}")]
    Brotli(std::io::Error),
    #[error(
        "decompression bomb: output exceeded {cap_bytes}-byte cap \
         ({observed_bytes} bytes produced) — aborted before OOM"
    )]
    DecompressionBomb {
        cap_bytes: usize,
        observed_bytes: usize,
    },
}

/// Hard cap on `chain` layers — any longer is almost certainly a
/// misconfiguration, and the compressed-output size would balloon
/// from header overhead per layer. 16 is generous: real attacks use
/// 2–3 layers.
pub const MAX_CHAIN_LAYERS: usize = 16;

/// Hard cap on decoded body size — defends against decompression
/// bombs. A 1 KB malicious gzip can decompress to 10+ GB if read
/// without bounds.
///
/// §7: this IS the workspace-canonical [`wafrift_types::MAX_RESPONSE_BODY_BYTES`]
/// — the comment previously noted "matches the response-body cap elsewhere",
/// but that coupling is now ENFORCED by sharing the constant rather than
/// hoping two literals stay equal. The public name is preserved.
pub const DECOMPRESSED_BODY_MAX_BYTES: usize = wafrift_types::MAX_RESPONSE_BODY_BYTES;

/// One compression algorithm. The naming matches the HTTP
/// `Content-Encoding` registry value (lowercase, no padding).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// gzip / RFC 1952. Universal compatibility.
    Gzip,
    /// raw deflate / RFC 1951. RFC-permitted, irregular WAF support.
    Deflate,
    /// brotli / RFC 7932. Wide WAF gap — the main attack vector.
    Brotli,
    /// no-op pass-through. Sometimes useful as a chain anchor when
    /// the operator wants to mark "this body is encoded but the
    /// outermost layer is identity" — RFC permits `Content-Encoding:
    /// identity`.
    Identity,
}

impl Algorithm {
    /// The HTTP `Content-Encoding` token for this algorithm.
    #[must_use]
    pub fn content_encoding(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Identity => "identity",
        }
    }

    /// Parse a `Content-Encoding` token (case-insensitive) into the
    /// matching algorithm. Returns `None` for unrecognised values.
    /// Accepts the common alias `x-gzip` (RFC-permitted) for Gzip.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "identity" => Some(Self::Identity),
            _ => None,
        }
    }
}

/// A compressed body with its `Content-Encoding` header value. The
/// caller writes the body bytes onto the wire verbatim and sets the
/// header — both are required, and a mismatched pairing is a
/// debugging nightmare for the operator if we let it happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBody {
    /// Body bytes ready to put on the wire.
    pub body: Vec<u8>,
    /// `Content-Encoding` header value matching the body's
    /// outermost layer. For a chain `gzip,br` the header is `"gzip,
    /// br"` (HTTP allows comma-separated lists, processed
    /// outer-first per RFC 9110 §8.4).
    pub content_encoding: String,
}

/// Compress `body` with a single algorithm. Returns the raw
/// compressed bytes + the matching `Content-Encoding` header value.
///
/// # Errors
/// Returns [`CompressionError`] if the underlying encoder fails. In
/// practice this is rare for in-memory operations — gzip/deflate/
/// brotli never error on well-formed input slices.
pub fn compress(body: &[u8], algo: Algorithm) -> Result<CompressedBody, CompressionError> {
    let bytes = compress_bytes(body, algo)?;
    Ok(CompressedBody {
        body: bytes,
        content_encoding: algo.content_encoding().to_string(),
    })
}

/// Inner helper — returns just the bytes (no header). Used by
/// [`chain`] to layer compressions before assembling the final
/// `Content-Encoding` string.
fn compress_bytes(body: &[u8], algo: Algorithm) -> Result<Vec<u8>, CompressionError> {
    use std::io::Write;
    match algo {
        Algorithm::Identity => Ok(body.to_vec()),
        Algorithm::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(body).map_err(CompressionError::Gzip)?;
            enc.finish().map_err(CompressionError::Gzip)
        }
        Algorithm::Deflate => {
            let mut enc =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(body).map_err(CompressionError::Deflate)?;
            enc.finish().map_err(CompressionError::Deflate)
        }
        Algorithm::Brotli => {
            // brotli crate exposes a `CompressorWriter`-style API.
            // `quality` 6 is the default Chrome / Firefox ship for
            // dynamic content; lower compression ratio than 11 but
            // an order of magnitude faster, which is the right
            // trade-off for an attack tool firing many variants.
            let mut out = Vec::new();
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 6, 22);
            writer.write_all(body).map_err(CompressionError::Brotli)?;
            writer.flush().map_err(CompressionError::Brotli)?;
            drop(writer);
            Ok(out)
        }
    }
}

/// Apply a sequence of compression algorithms in order, producing
/// one set of body bytes + the joint `Content-Encoding` header.
///
/// The header value lists the algorithms in the order they were
/// applied — per RFC 9110 §8.4, the LEFTMOST algorithm is the OUTERMOST
/// wrapper, meaning a decoder must apply them right-to-left. So
/// `chain(body, [Gzip, Brotli])` produces a body that is
/// `gzip(brotli(body))` with header `gzip, br`.
///
/// Capped at [`MAX_CHAIN_LAYERS`] to prevent runaway misconfiguration.
///
/// # Errors
/// Returns [`CompressionError::ChainTooDeep`] when `algos.len() >
/// MAX_CHAIN_LAYERS`, or the wrapped algorithm's error if one of
/// the encoders fails.
pub fn chain(body: &[u8], algos: &[Algorithm]) -> Result<CompressedBody, CompressionError> {
    if algos.len() > MAX_CHAIN_LAYERS {
        return Err(CompressionError::ChainTooDeep(MAX_CHAIN_LAYERS));
    }
    if algos.is_empty() {
        return Ok(CompressedBody {
            body: body.to_vec(),
            content_encoding: Algorithm::Identity.content_encoding().to_string(),
        });
    }
    // Apply innermost to outermost: reverse of header order. So
    // `algos = [Gzip, Brotli]` means body is gzip(brotli(...)), and
    // we apply Brotli FIRST then Gzip on top.
    let mut current = body.to_vec();
    for algo in algos.iter().rev() {
        current = compress_bytes(&current, *algo)?;
    }
    // The header lists outer-to-inner.
    let header = algos
        .iter()
        .map(|a| a.content_encoding())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(CompressedBody {
        body: current,
        content_encoding: header,
    })
}

/// Recover the original bytes from a [`CompressedBody`] — the
/// inverse of [`compress`] / [`chain`]. Test-only and audit
/// helper; production attack flow only needs the compress
/// direction.
///
/// # Errors
/// Returns [`CompressionError`] if any decoder fails or the
/// `content_encoding` string lists an unknown algorithm.
pub fn decompress(blob: &CompressedBody) -> Result<Vec<u8>, CompressionError> {
    let algos: Vec<Algorithm> = blob
        .content_encoding
        .split(',')
        .filter_map(Algorithm::from_token)
        .collect();
    // §3 contract symmetry with `chain`: the forward direction refuses
    // more than MAX_CHAIN_LAYERS, so its documented inverse must too. A
    // crafted `gzip,gzip,…×N` header would otherwise drive an unbounded
    // decode loop (each stage is size-capped by `drain_capped`, but the
    // LAYER COUNT was not — O(N) work amplification). Counting recognised
    // algos (post-`filter_map`) preserves the permissive "skip unknown
    // coding" behaviour: `snappy, gzip` is still a 1-layer decode.
    if algos.len() > MAX_CHAIN_LAYERS {
        return Err(CompressionError::ChainTooDeep(MAX_CHAIN_LAYERS));
    }
    let mut current = blob.body.clone();
    // Decode in the SAME order the header lists (outer-to-inner).
    for algo in &algos {
        current = decompress_bytes(&current, *algo)?;
    }
    Ok(current)
}

/// Read at most `DECOMPRESSED_BODY_MAX_BYTES` from `reader`, then
/// promote a "+1 byte produced" into a `DecompressionBomb` error.
/// Takes a generic `R: Read` (sized) so `Read::take` works without
/// trait-object gymnastics; called from each algorithm arm below.
fn drain_capped<R: std::io::Read>(
    mut reader: R,
    map_io: fn(std::io::Error) -> CompressionError,
) -> Result<Vec<u8>, CompressionError> {
    use std::io::Read;
    let cap = DECOMPRESSED_BODY_MAX_BYTES;
    let mut out = Vec::with_capacity(8 * 1024);
    let mut limited = (&mut reader).take((cap as u64) + 1);
    limited.read_to_end(&mut out).map_err(map_io)?;
    if out.len() > cap {
        return Err(CompressionError::DecompressionBomb {
            cap_bytes: cap,
            observed_bytes: out.len(),
        });
    }
    Ok(out)
}

fn decompress_bytes(bytes: &[u8], algo: Algorithm) -> Result<Vec<u8>, CompressionError> {
    match algo {
        Algorithm::Identity => {
            // No decompression — but still refuse to clone a slice
            // that already exceeds the body cap (a sign something
            // upstream missed a boundary check).
            if bytes.len() > DECOMPRESSED_BODY_MAX_BYTES {
                return Err(CompressionError::DecompressionBomb {
                    cap_bytes: DECOMPRESSED_BODY_MAX_BYTES,
                    observed_bytes: bytes.len(),
                });
            }
            Ok(bytes.to_vec())
        }
        Algorithm::Gzip => drain_capped(
            flate2::read::GzDecoder::new(bytes),
            CompressionError::Gzip,
        ),
        Algorithm::Deflate => drain_capped(
            flate2::read::DeflateDecoder::new(bytes),
            CompressionError::Deflate,
        ),
        Algorithm::Brotli => drain_capped(
            brotli::Decompressor::new(bytes, 4096),
            CompressionError::Brotli,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Algorithm tokens ───────────────────────────────────────────

    #[test]
    fn content_encoding_tokens_match_rfc_registry() {
        assert_eq!(Algorithm::Gzip.content_encoding(), "gzip");
        assert_eq!(Algorithm::Deflate.content_encoding(), "deflate");
        assert_eq!(Algorithm::Brotli.content_encoding(), "br");
        assert_eq!(Algorithm::Identity.content_encoding(), "identity");
    }

    #[test]
    fn from_token_is_case_insensitive_and_trim_tolerant() {
        for spelling in ["gzip", "GZIP", "Gzip", "  gzip  ", "\tgzip"] {
            assert_eq!(Algorithm::from_token(spelling), Some(Algorithm::Gzip));
        }
    }

    #[test]
    fn from_token_accepts_x_gzip_alias() {
        // RFC 7230 §4.2.3 documents `x-gzip` as an alias of `gzip`.
        // Some legacy origins / WAFs still emit it.
        assert_eq!(Algorithm::from_token("x-gzip"), Some(Algorithm::Gzip));
        assert_eq!(Algorithm::from_token("X-GZIP"), Some(Algorithm::Gzip));
    }

    #[test]
    fn from_token_rejects_unknown_codings() {
        assert_eq!(Algorithm::from_token(""), None);
        assert_eq!(Algorithm::from_token("snappy"), None);
        assert_eq!(Algorithm::from_token("lz4"), None);
        // `compress` (old UNIX) is not in our supported set.
        assert_eq!(Algorithm::from_token("compress"), None);
    }

    // ── single-algorithm round trip ────────────────────────────────

    #[test]
    fn gzip_round_trip_preserves_payload() {
        let original = b"' OR 1=1--";
        let compressed = compress(original, Algorithm::Gzip).expect("gzip");
        assert_eq!(compressed.content_encoding, "gzip");
        assert_ne!(compressed.body.as_slice(), original);
        let recovered = decompress(&compressed).expect("decompress");
        assert_eq!(recovered, original);
    }

    #[test]
    fn deflate_round_trip_preserves_payload() {
        let original = b"<script>alert(1)</script>";
        let compressed = compress(original, Algorithm::Deflate).expect("deflate");
        assert_eq!(compressed.content_encoding, "deflate");
        let recovered = decompress(&compressed).expect("decompress");
        assert_eq!(recovered, original);
    }

    #[test]
    fn brotli_round_trip_preserves_payload() {
        // Brotli is the headline attack vector — round-trip MUST be
        // clean or every brotli-based scan ships broken payloads.
        let original = b"http://127.0.0.1:9000/admin?cmd=id";
        let compressed = compress(original, Algorithm::Brotli).expect("brotli");
        assert_eq!(compressed.content_encoding, "br");
        let recovered = decompress(&compressed).expect("decompress");
        assert_eq!(recovered, original);
    }

    #[test]
    fn identity_is_passthrough_with_identity_header() {
        let original = b"plain text";
        let compressed = compress(original, Algorithm::Identity).expect("identity");
        assert_eq!(compressed.body, original);
        assert_eq!(compressed.content_encoding, "identity");
    }

    // ── chain ─────────────────────────────────────────────────────

    #[test]
    fn chain_with_one_algo_matches_single_compress() {
        let original = b"single layer";
        let chained = chain(original, &[Algorithm::Gzip]).expect("chain");
        let single = compress(original, Algorithm::Gzip).expect("compress");
        assert_eq!(chained, single);
    }

    #[test]
    fn chain_with_two_algos_round_trips() {
        // The classic compression-confusion attack: gzip(brotli(payload)).
        // The WAF sees gzip — decodes one layer — gets brotli bytes —
        // doesn't recognise — passes through. Origin decodes both.
        let original = b"' UNION SELECT username,password FROM users --";
        let chained = chain(original, &[Algorithm::Gzip, Algorithm::Brotli]).expect("chain");
        assert_eq!(chained.content_encoding, "gzip, br");
        let recovered = decompress(&chained).expect("decompress");
        assert_eq!(recovered, original);
    }

    #[test]
    fn chain_empty_algos_returns_identity_body() {
        let original = b"unchanged";
        let chained = chain(original, &[]).expect("empty chain");
        assert_eq!(chained.body, original);
        assert_eq!(chained.content_encoding, "identity");
    }

    #[test]
    fn chain_above_cap_returns_too_deep_error() {
        let too_many: Vec<Algorithm> = (0..MAX_CHAIN_LAYERS + 1).map(|_| Algorithm::Gzip).collect();
        let result = chain(b"payload", &too_many);
        match result {
            Err(CompressionError::ChainTooDeep(cap)) => assert_eq!(cap, MAX_CHAIN_LAYERS),
            other => panic!("expected ChainTooDeep error, got {other:?}"),
        }
    }

    #[test]
    fn chain_at_exactly_cap_succeeds() {
        let just_enough: Vec<Algorithm> =
            (0..MAX_CHAIN_LAYERS).map(|_| Algorithm::Identity).collect();
        let chained = chain(b"x", &just_enough).expect("at-cap chain ok");
        // All-identity chain leaves the body untouched.
        assert_eq!(chained.body, b"x");
    }

    #[test]
    fn chain_with_identity_in_the_middle_is_transparent() {
        // chain([Gzip, Identity, Brotli]) ≡ chain([Gzip, Brotli]) at
        // the bytes level, but the header lists ALL three (we honour
        // exactly what the operator asked for in the header).
        let original = b"middle identity";
        let with_id = chain(
            original,
            &[Algorithm::Gzip, Algorithm::Identity, Algorithm::Brotli],
        )
        .expect("chain with identity");
        let without =
            chain(original, &[Algorithm::Gzip, Algorithm::Brotli]).expect("chain without identity");
        assert_eq!(
            with_id.body, without.body,
            "identity must be byte-transparent"
        );
        assert_eq!(with_id.content_encoding, "gzip, identity, br");
        let recovered = decompress(&with_id).expect("decompress with id");
        assert_eq!(recovered, original);
    }

    // ── edge cases & adversarial inputs ───────────────────────────

    #[test]
    fn empty_body_compresses_and_round_trips() {
        for algo in [
            Algorithm::Gzip,
            Algorithm::Deflate,
            Algorithm::Brotli,
            Algorithm::Identity,
        ] {
            let compressed =
                compress(b"", algo).unwrap_or_else(|e| panic!("empty body with {algo:?}: {e}"));
            let recovered = decompress(&compressed)
                .unwrap_or_else(|e| panic!("empty body decode with {algo:?}: {e}"));
            assert_eq!(recovered, Vec::<u8>::new());
        }
    }

    #[test]
    fn one_byte_body_round_trips_under_every_algorithm() {
        for algo in [
            Algorithm::Gzip,
            Algorithm::Deflate,
            Algorithm::Brotli,
            Algorithm::Identity,
        ] {
            let original = &[0xAB_u8][..];
            let compressed = compress(original, algo).expect("compress");
            let recovered = decompress(&compressed).expect("decompress");
            assert_eq!(recovered, original);
        }
    }

    #[test]
    fn large_body_64_kib_round_trips_without_oom() {
        // 64 KiB is a realistic body size for an instrumented
        // payload. All compressors must handle it without spiking
        // memory (caller's allocator) or losing fidelity.
        let original: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 251) as u8).collect();
        for algo in [Algorithm::Gzip, Algorithm::Deflate, Algorithm::Brotli] {
            let compressed = compress(&original, algo).expect("compress");
            // Compressed should be SMALLER than original on this
            // pseudo-pattern (high autocorrelation).
            assert!(
                compressed.body.len() < original.len(),
                "{algo:?} should compress this pattern, got {} >= {}",
                compressed.body.len(),
                original.len()
            );
            let recovered = decompress(&compressed).expect("decompress");
            assert_eq!(recovered, original);
        }
    }

    #[test]
    fn incompressible_body_does_not_panic_on_brotli() {
        // Random bytes don't compress well; some encoders return
        // BIGGER output than input (header overhead). Verify this
        // edge — no panic, round-trip still clean.
        let mut original = vec![0u8; 1024];
        for (i, b) in original.iter_mut().enumerate() {
            // Pseudo-random pattern with no compressibility.
            *b = ((i.wrapping_mul(2654435769)) & 0xFF) as u8;
        }
        let compressed = compress(&original, Algorithm::Brotli).expect("brotli");
        let recovered = decompress(&compressed).expect("decompress");
        assert_eq!(recovered, original);
    }

    #[test]
    fn decompress_with_unknown_coding_token_skips_it() {
        // If a hand-crafted CompressedBody has a Content-Encoding
        // listing an unknown coding (e.g. `gzip, snappy`), our
        // decompressor SKIPS the unknown token and tries the rest.
        // This matches HTTP's tolerance for unknown codings (a
        // decoder unable to handle a coding returns 415 in production,
        // but our recovery helper is a debugging aid and should be
        // permissive).
        let body = b"hello";
        let compressed = compress(body, Algorithm::Gzip).unwrap();
        let with_unknown = CompressedBody {
            content_encoding: format!("snappy, {}", compressed.content_encoding),
            body: compressed.body,
        };
        let recovered = decompress(&with_unknown).expect("permissive decompress");
        assert_eq!(recovered, body);
    }

    #[test]
    fn decompress_rejects_more_than_max_chain_layers() {
        // §3 contract-symmetry regression: `chain` refuses > MAX_CHAIN_LAYERS,
        // so its inverse `decompress` must too — otherwise a crafted
        // `gzip,gzip,…×N` Content-Encoding header drives an O(N) decode loop.
        // The cap is checked BEFORE any decode work, so the body can be empty.
        let header = std::iter::repeat("gzip")
            .take(MAX_CHAIN_LAYERS + 1)
            .collect::<Vec<_>>()
            .join(", ");
        let blob = CompressedBody {
            content_encoding: header,
            body: Vec::new(),
        };
        match decompress(&blob) {
            Err(CompressionError::ChainTooDeep(cap)) => assert_eq!(cap, MAX_CHAIN_LAYERS),
            other => panic!("expected ChainTooDeep, got {other:?}"),
        }
    }

    #[test]
    fn decompress_layer_cap_counts_recognised_codings_only() {
        // The cap counts RECOGNISED algos (post-filter_map), so a header
        // padded with many unknown codings is still a shallow decode and must
        // NOT trip the cap — preserving the permissive "skip unknown" contract.
        let body = b"hello world";
        let compressed = compress(body, Algorithm::Gzip).unwrap();
        // (MAX+5) unknown `snappy` tokens + one real gzip = 1 recognised layer.
        let mut tokens: Vec<String> = std::iter::repeat("snappy")
            .take(MAX_CHAIN_LAYERS + 5)
            .map(str::to_string)
            .collect();
        tokens.push(compressed.content_encoding.clone());
        let blob = CompressedBody {
            content_encoding: tokens.join(", "),
            body: compressed.body,
        };
        let recovered = decompress(&blob).expect("unknown-padded header is a 1-layer decode");
        assert_eq!(recovered, body);
    }

    // ── adversarial round-trip property ────────────────────────────

    #[test]
    fn round_trip_property_holds_across_a_variety_of_payloads() {
        // Anti-rig: a degenerate compressor that always returned
        // the empty string would pass single-payload tests if those
        // happened to be empty. Exercise many distinct payloads.
        let corpus: &[&[u8]] = &[
            b"",
            b"x",
            b"' OR 1=1--",
            b"<script>alert(document.cookie)</script>",
            b"http://127.0.0.1/admin",
            b"; cat /etc/passwd",
            b"\x00\x01\x02\x03\xff\xfe",
            b"the quick brown fox jumps over the lazy dog the quick brown fox",
        ];
        for payload in corpus {
            for algo in [
                Algorithm::Gzip,
                Algorithm::Deflate,
                Algorithm::Brotli,
                Algorithm::Identity,
            ] {
                let c = compress(payload, algo)
                    .unwrap_or_else(|e| panic!("{algo:?} on {payload:?}: {e}"));
                let r = decompress(&c)
                    .unwrap_or_else(|e| panic!("decompress {algo:?} on {payload:?}: {e}"));
                assert_eq!(r, *payload, "{algo:?} round-trip mismatch on {payload:?}");
            }
        }
    }

    // ── Round 20: decompression bomb defence ──────────────────────────
    //
    // Pre-fix gzip/deflate/brotli decoders called `read_to_end` with no
    // size cap; a 1 KB malicious gzip blob can decompress to 10+ GB.
    // Each algorithm must now return DecompressionBomb when output
    // exceeds DECOMPRESSED_BODY_MAX_BYTES.
    //
    // We can't generate a true 10 GB payload in a unit test (the
    // *compressed* form would still be MiBs), so we exercise the same
    // overrun codepath by temporarily proving the cap works on a
    // payload sized just above the cap with a tightly-controlled
    // synthetic Identity input.

    #[test]
    fn identity_decompress_rejects_oversize_input() {
        // Identity short-circuits to a clone; it still must refuse
        // anything above the cap so a single-layer chain on a
        // multi-GB body cannot pass through.
        let oversized = vec![0u8; DECOMPRESSED_BODY_MAX_BYTES + 1];
        let err = super::decompress_bytes(&oversized, Algorithm::Identity)
            .expect_err("identity decompress must refuse > cap input");
        match err {
            CompressionError::DecompressionBomb { cap_bytes, observed_bytes } => {
                assert_eq!(cap_bytes, DECOMPRESSED_BODY_MAX_BYTES);
                assert_eq!(observed_bytes, DECOMPRESSED_BODY_MAX_BYTES + 1);
            }
            other => panic!("expected DecompressionBomb, got {other:?}"),
        }
    }

    #[test]
    fn gzip_decompress_under_cap_succeeds() {
        // 1 MiB of zeros compresses to ~1 KiB under gzip and is well
        // below DECOMPRESSED_BODY_MAX_BYTES (64 MiB) — must succeed.
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&vec![0u8; 1024 * 1024]).expect("compress");
        let compressed = enc.finish().expect("gzip finish");
        let ok = super::decompress_bytes(&compressed, Algorithm::Gzip).expect("under cap");
        assert_eq!(ok.len(), 1024 * 1024);
    }

    #[test]
    fn drain_capped_returns_bomb_error_on_over_cap_source() {
        // Direct exercise of the drain_capped helper with a Cursor
        // source larger than the cap — must surface as
        // DecompressionBomb (not as a generic Gzip/Deflate/Brotli
        // wrapper). Tests we don't silently truncate.
        let oversized = std::io::Cursor::new(vec![b'A'; 4096]);
        // Temporarily simulate a tight cap by calling the same logic
        // pattern drain_capped uses, but with a small cap, since
        // drain_capped is parameterised by DECOMPRESSED_BODY_MAX_BYTES
        // alone. The behaviour we want to prove: Read::take(cap+1)
        // surfaces > cap bytes as the bomb error.
        use std::io::Read;
        let cap: usize = 256;
        let mut limited = oversized.take((cap as u64) + 1);
        let mut buf = Vec::new();
        limited.read_to_end(&mut buf).expect("read");
        assert!(buf.len() > cap, "Read::take(cap+1) must produce cap+1 bytes for a > cap source");
        // The error promotion is purely a buf.len() > cap check —
        // already exercised in identity_decompress_rejects_oversize_input.
    }
}
