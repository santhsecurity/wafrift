//! Pipeline-stage transducers.
//!
//! A real request crosses a chain of byte rewriters before its bytes
//! reach the vulnerable sink:
//!
//! ```text
//! wire ─▶ CDN normalize ─▶ WAF view ─▶ proxy ─▶ framework parse ─▶ sink
//! ```
//!
//! Every stage is a total `&[u8] -> Vec<u8>` transducer. A
//! normalization-mismatch bypass is precisely an input `x` where the
//! **WAF view** of `x` is inert (the WAF passes it) but the **sink
//! view** of `x` still reconstructs the live attack. The hand-coded
//! "double-URL-encode" trick is one instance; modelling every stage as
//! a composable transducer lets the P2 solver *rediscover that class
//! and others* instead of shipping them as rules.
//!
//! These reuse the CRS [`crate::normalize`] primitives for the WAF
//! view and add the *origin/framework* decoders (single URL-decode,
//! JSON string unescape) that the WAF does **not** apply — the gap
//! that the whole class of bypasses lives in.

use crate::normalize::{Transform, apply_chain};
use wafrift_grammar::grammar::{bestfit, nfkc_preimage};

/// One pipeline stage.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    /// Bytes pass through unchanged.
    Identity,
    /// Framework URL-decode, **single pass** `%XX` (and optionally
    /// `+`→space for form bodies). Note this is *not* CRS
    /// `urlDecodeUni`: no `%uXXXX`, and exactly one pass — the
    /// asymmetry double-encoding exploits.
    UrlDecode {
        /// Treat `+` as space (form-urlencoded bodies).
        plus_is_space: bool,
    },
    /// Two URL-decode passes (stacks that decode at proxy *and* app).
    DoubleUrlDecode,
    /// HTML entity decode (framework templating / browser).
    HtmlEntityDecode,
    /// JSON string unescape (`\"`, `\\`, `\n`, `\uXXXX`, surrogate
    /// pairs) — what a JSON body parser hands the application.
    JsonUnescape,
    /// Origin/runtime **NFKC normalization** — Node `String.prototype
    /// .normalize`, Python `unicodedata.normalize`, Java `Normalizer`, .NET,
    /// and many template/identifier pipelines apply it before the value
    /// reaches the sink. Its compatibility decomposition collapses the
    /// styled-letter and fullwidth homoglyph families back to ASCII
    /// (`＜script＞` → `<script>`). A WAF that does *not* NFKC-normalize sees
    /// inert homoglyph bytes; this sink reconstructs the attack. The exact
    /// gap [`wafrift_grammar::grammar::nfkc_preimage`] inverts — making the
    /// solver *derive* the homoglyph bypass instead of shipping it as a rule.
    NfkcNormalize,
    /// Origin **best-fit / charset down-conversion** — Windows
    /// `WideCharToMultiByte` (default, no `WC_NO_BEST_FIT_CHARS`), MySQL
    /// latin1, .NET `Encoding.GetEncoding(1252)`, iconv `//TRANSLIT`. Coerces
    /// curly quotes / dashes / slashes to their ASCII delimiters (`'` → `'`),
    /// the SQLi string-breakout gap [`wafrift_grammar::grammar::bestfit`]
    /// inverts. NFKC leaves these punctuation codepoints alone; best-fit does
    /// not — a distinct, composable origin stage.
    BestFitDownconvert,
    /// Origin **NUL-byte stripping** — PHP/C string handling, many frameworks,
    /// and some loggers drop embedded `\0` before the value reaches the sink.
    /// A WAF matching the literal `<script` misses `<scr\0ipt>`; the origin
    /// strips the NUL and reconstructs the attack. (CRS *can* `RemoveNulls`,
    /// so this stage is the gap when the WAF does not but the origin does.)
    StripNulls,
    /// Origin **overlong UTF-8 decode** — a lenient/legacy UTF-8 decoder that
    /// accepts the non-canonical 2-byte overlong encoding of an ASCII byte
    /// (`<` as `0xC0 0xBC`) and folds it back to ASCII. Conformant decoders
    /// reject overlong forms (a security MUST), so the origin set is narrow but
    /// historically real; a WAF reading the raw bytes sees no `<`. Only the
    /// invalid `0xC0`/`0xC1` lead-byte overlongs are decoded (the exact forms a
    /// faithful-but-lenient decoder accepts); all other bytes pass through.
    OverlongUtf8Decode,
    /// Origin **Base64 decode** — JSON/API endpoints, cookies, JWT segments,
    /// and `data:` handlers routinely base64-decode a field before it reaches
    /// the sink. A WAF matching `<script` never sees it in `PHNjcmlwdD4=`; the
    /// origin decodes and the attack lands. A whole-value transform (not
    /// per-byte): the inverse base64-encodes the entire preimage. Invalid
    /// base64 passes through unchanged (a real decoder rejects it, modelled as
    /// identity — never fabricates a fold).
    Base64Decode,
    /// Origin **hex decode** — APIs, binary-as-text fields, and some templating
    /// hex-decode a value (`3c736372697074` → `<script`). A whole-value
    /// transform like base64: the inverse hex-encodes the entire preimage.
    /// Odd-length or non-hex input passes through unchanged.
    HexDecode,
    /// The WAF's own view: a CRS `t:` transform chain.
    CrsView(Vec<Transform>),
}

impl Stage {
    /// Apply this stage.
    #[must_use]
    pub fn apply(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Stage::Identity => input.to_vec(),
            Stage::UrlDecode { plus_is_space } => url_decode_once(input, *plus_is_space),
            Stage::DoubleUrlDecode => url_decode_once(&url_decode_once(input, false), false),
            Stage::HtmlEntityDecode => Transform::HtmlEntityDecode.apply(input),
            Stage::JsonUnescape => json_unescape(input),
            Stage::NfkcNormalize => normalize_text_stage(input, nfkc_preimage::normalize),
            Stage::BestFitDownconvert => normalize_text_stage(input, bestfit::normalize),
            Stage::StripNulls => input.iter().copied().filter(|&b| b != 0).collect(),
            Stage::OverlongUtf8Decode => overlong_utf8_decode(input),
            Stage::Base64Decode => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(input)
                    .unwrap_or_else(|_| input.to_vec())
            }
            Stage::HexDecode => hex::decode(input).unwrap_or_else(|_| input.to_vec()),
            Stage::CrsView(chain) => apply_chain(chain, input),
        }
    }
}

/// Decode the non-canonical 2-byte overlong UTF-8 encoding of ASCII bytes: a
/// `0xC0`/`0xC1` lead followed by an `0x80..=0xBF` continuation folds to the
/// low 7 bits (`0xC0` covers `0x00..=0x3F`, `0xC1` covers `0x40..=0x7F`, so the
/// pair spans every ASCII byte). These leads are invalid in conformant UTF-8,
/// so the transform only ever fires on genuinely-overlong input and never
/// alters well-formed bytes. Total and non-amplifying (2 bytes → 1).
fn overlong_utf8_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if (b == 0xC0 || b == 0xC1) && i + 1 < input.len() {
            let c = input[i + 1];
            if (0x80..=0xBF).contains(&c) {
                out.push(((b & 0x1F) << 6) | (c & 0x3F));
                i += 2;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    out
}

/// Apply an origin text-normalizer (`&str -> String`) to raw request bytes:
/// decode UTF-8, normalize, re-encode. Invalid UTF-8 passes through unchanged
/// — a real text normalizer operates on decoded characters, and modelling
/// undecodable bytes as identity is the sound conservative choice (it never
/// fabricates a fold that the origin would not actually perform).
fn normalize_text_stage(input: &[u8], f: impl Fn(&str) -> String) -> Vec<u8> {
    match std::str::from_utf8(input) {
        Ok(s) => f(s).into_bytes(),
        Err(_) => input.to_vec(),
    }
}

/// An ordered chain of stages: wire bytes in, sink bytes out.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Pipeline(pub Vec<Stage>);

impl Pipeline {
    /// Fold every stage left-to-right.
    #[must_use]
    pub fn apply(&self, input: &[u8]) -> Vec<u8> {
        self.0.iter().fold(input.to_vec(), |acc, s| s.apply(&acc))
    }

    /// Stage count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No stages (identity pipeline).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn hexv(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Single-pass `%XX` decode. A `%` not followed by two hex digits is
/// emitted literally (and scanning continues at the next byte) — the
/// behaviour real servers exhibit, and the reason `%253C` survives one
/// pass as `%3C` and only a *second* pass yields `<`.
#[must_use]
pub fn url_decode_once(input: &[u8], plus_is_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                if let (Some(h), Some(l)) = (hexv(input[i + 1]), hexv(input[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    match cp {
        0..=0x7F => out.push(cp as u8),
        0x80..=0x7FF => {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        0x800..=0xFFFF => {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
        _ => {
            out.push(0xF0 | (cp >> 18) as u8);
            out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
    }
}

fn read_u4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut v = 0u32;
    for &c in &b[..4] {
        v = v * 16 + u32::from(hexv(c)?);
    }
    Some(v)
}

/// JSON string-content unescape: `\" \\ \/ \b \f \n \r \t` and
/// `\uXXXX` including UTF-16 surrogate pairs. An unknown/short escape
/// is left literal (lenient, like permissive parsers). Total.
#[must_use]
pub fn json_unescape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        match input[i + 1] {
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'/' => {
                out.push(b'/');
                i += 2;
            }
            b'b' => {
                out.push(0x08);
                i += 2;
            }
            b'f' => {
                out.push(0x0C);
                i += 2;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'u' => {
                if let Some(hi) = read_u4(&input[i + 2..]) {
                    // UTF-16 surrogate pair?
                    if (0xD800..=0xDBFF).contains(&hi)
                        && input.get(i + 6) == Some(&b'\\')
                        && input.get(i + 7) == Some(&b'u')
                        && let Some(lo) = read_u4(&input[i + 8..])
                        && (0xDC00..=0xDFFF).contains(&lo)
                    {
                        let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                        push_utf8(&mut out, cp);
                        i += 12;
                    } else if (0xD800..=0xDFFF).contains(&hi) {
                        // F84: lone UTF-16 surrogate. Encoding it as UTF-8
                        // would produce WTF-8 / CESU-8 — invalid UTF-8 that
                        // downstream `from_utf8` will reject or replace
                        // differently than the framework would. Emit
                        // U+FFFD to match `String::from_utf8_lossy`, which
                        // is what every sensible downstream framework does.
                        push_utf8(&mut out, 0xFFFD);
                        i += 6;
                    } else {
                        push_utf8(&mut out, hi);
                        i += 6;
                    }
                } else {
                    out.push(b'\\');
                    i += 1;
                }
            }
            _ => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    out
}
