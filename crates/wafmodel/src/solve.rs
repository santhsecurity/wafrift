//! Composition + preimage solver — the part that turns "encoding
//! tricks" from hand-written rules into *emergent solutions*.
//!
//! A working bypass of the whole pipeline is any input `x` with:
//!
//! ```text
//!   WAF passes  (the WAF's normalized view of x is inert)
//!     ∧  sink(x) reconstructs the live attack
//! ```
//!
//! The solver never hard-codes "double-URL-encode" or any other trick.
//! It takes the **sink pipeline as data**, computes the *structural
//! preimage* of the attack under that pipeline (compose each stage's
//! inverse encoder in reverse order), then runs a CEGIS loop: generate
//! a candidate preimage, test it against the real WAF oracle and the
//! sink, and on failure escalate to a deeper/likewise-structural
//! encoding. Point the same code at a JSON-unescaping sink and it
//! emits a JSON-escaped bypass; at a double-decoding sink, the
//! double-encoding falls out. The trick is *derived from the pipeline*,
//! not retrieved from a list.

use crate::error::Result;
use crate::oracle::WafOracle;
use crate::outcome::Outcome;
use crate::transduce::{Pipeline, Stage};
use wafrift_grammar::grammar::{bestfit, nfkc_preimage};
use wafrift_types::Request;

/// Which bytes a structural encoder rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Every byte (maximally evasive, longest).
    All,
    /// Only the "dangerous" bytes a WAF rule keys on (minimal, often
    /// enough and much shorter).
    Danger,
}

const DANGER: &[u8] = b"<>()'\"/;= \t\r\n&%{}[]:";

/// Lookup table: PCT_TABLE[b] = b"%XY" where XY is the uppercase hex of b.
/// Eliminates `format!("%{b:02X}")` allocation in the per-byte hot loop.
static PCT_TABLE: &[&[u8]; 256] = &[
    b"%00", b"%01", b"%02", b"%03", b"%04", b"%05", b"%06", b"%07", b"%08", b"%09", b"%0A", b"%0B",
    b"%0C", b"%0D", b"%0E", b"%0F", b"%10", b"%11", b"%12", b"%13", b"%14", b"%15", b"%16", b"%17",
    b"%18", b"%19", b"%1A", b"%1B", b"%1C", b"%1D", b"%1E", b"%1F", b"%20", b"%21", b"%22", b"%23",
    b"%24", b"%25", b"%26", b"%27", b"%28", b"%29", b"%2A", b"%2B", b"%2C", b"%2D", b"%2E", b"%2F",
    b"%30", b"%31", b"%32", b"%33", b"%34", b"%35", b"%36", b"%37", b"%38", b"%39", b"%3A", b"%3B",
    b"%3C", b"%3D", b"%3E", b"%3F", b"%40", b"%41", b"%42", b"%43", b"%44", b"%45", b"%46", b"%47",
    b"%48", b"%49", b"%4A", b"%4B", b"%4C", b"%4D", b"%4E", b"%4F", b"%50", b"%51", b"%52", b"%53",
    b"%54", b"%55", b"%56", b"%57", b"%58", b"%59", b"%5A", b"%5B", b"%5C", b"%5D", b"%5E", b"%5F",
    b"%60", b"%61", b"%62", b"%63", b"%64", b"%65", b"%66", b"%67", b"%68", b"%69", b"%6A", b"%6B",
    b"%6C", b"%6D", b"%6E", b"%6F", b"%70", b"%71", b"%72", b"%73", b"%74", b"%75", b"%76", b"%77",
    b"%78", b"%79", b"%7A", b"%7B", b"%7C", b"%7D", b"%7E", b"%7F", b"%80", b"%81", b"%82", b"%83",
    b"%84", b"%85", b"%86", b"%87", b"%88", b"%89", b"%8A", b"%8B", b"%8C", b"%8D", b"%8E", b"%8F",
    b"%90", b"%91", b"%92", b"%93", b"%94", b"%95", b"%96", b"%97", b"%98", b"%99", b"%9A", b"%9B",
    b"%9C", b"%9D", b"%9E", b"%9F", b"%A0", b"%A1", b"%A2", b"%A3", b"%A4", b"%A5", b"%A6", b"%A7",
    b"%A8", b"%A9", b"%AA", b"%AB", b"%AC", b"%AD", b"%AE", b"%AF", b"%B0", b"%B1", b"%B2", b"%B3",
    b"%B4", b"%B5", b"%B6", b"%B7", b"%B8", b"%B9", b"%BA", b"%BB", b"%BC", b"%BD", b"%BE", b"%BF",
    b"%C0", b"%C1", b"%C2", b"%C3", b"%C4", b"%C5", b"%C6", b"%C7", b"%C8", b"%C9", b"%CA", b"%CB",
    b"%CC", b"%CD", b"%CE", b"%CF", b"%D0", b"%D1", b"%D2", b"%D3", b"%D4", b"%D5", b"%D6", b"%D7",
    b"%D8", b"%D9", b"%DA", b"%DB", b"%DC", b"%DD", b"%DE", b"%DF", b"%E0", b"%E1", b"%E2", b"%E3",
    b"%E4", b"%E5", b"%E6", b"%E7", b"%E8", b"%E9", b"%EA", b"%EB", b"%EC", b"%ED", b"%EE", b"%EF",
    b"%F0", b"%F1", b"%F2", b"%F3", b"%F4", b"%F5", b"%F6", b"%F7", b"%F8", b"%F9", b"%FA", b"%FB",
    b"%FC", b"%FD", b"%FE", b"%FF",
];

/// Lookup table: JSON_TABLE[b] = b"\\uXXXX" for each byte value.
/// Eliminates `format!("\\u{b:04x}")` allocation in the per-byte hot loop.
static JSON_TABLE: &[&[u8]; 256] = &[
    b"\\u0000", b"\\u0001", b"\\u0002", b"\\u0003", b"\\u0004", b"\\u0005", b"\\u0006", b"\\u0007",
    b"\\u0008", b"\\u0009", b"\\u000a", b"\\u000b", b"\\u000c", b"\\u000d", b"\\u000e", b"\\u000f",
    b"\\u0010", b"\\u0011", b"\\u0012", b"\\u0013", b"\\u0014", b"\\u0015", b"\\u0016", b"\\u0017",
    b"\\u0018", b"\\u0019", b"\\u001a", b"\\u001b", b"\\u001c", b"\\u001d", b"\\u001e", b"\\u001f",
    b"\\u0020", b"\\u0021", b"\\u0022", b"\\u0023", b"\\u0024", b"\\u0025", b"\\u0026", b"\\u0027",
    b"\\u0028", b"\\u0029", b"\\u002a", b"\\u002b", b"\\u002c", b"\\u002d", b"\\u002e", b"\\u002f",
    b"\\u0030", b"\\u0031", b"\\u0032", b"\\u0033", b"\\u0034", b"\\u0035", b"\\u0036", b"\\u0037",
    b"\\u0038", b"\\u0039", b"\\u003a", b"\\u003b", b"\\u003c", b"\\u003d", b"\\u003e", b"\\u003f",
    b"\\u0040", b"\\u0041", b"\\u0042", b"\\u0043", b"\\u0044", b"\\u0045", b"\\u0046", b"\\u0047",
    b"\\u0048", b"\\u0049", b"\\u004a", b"\\u004b", b"\\u004c", b"\\u004d", b"\\u004e", b"\\u004f",
    b"\\u0050", b"\\u0051", b"\\u0052", b"\\u0053", b"\\u0054", b"\\u0055", b"\\u0056", b"\\u0057",
    b"\\u0058", b"\\u0059", b"\\u005a", b"\\u005b", b"\\u005c", b"\\u005d", b"\\u005e", b"\\u005f",
    b"\\u0060", b"\\u0061", b"\\u0062", b"\\u0063", b"\\u0064", b"\\u0065", b"\\u0066", b"\\u0067",
    b"\\u0068", b"\\u0069", b"\\u006a", b"\\u006b", b"\\u006c", b"\\u006d", b"\\u006e", b"\\u006f",
    b"\\u0070", b"\\u0071", b"\\u0072", b"\\u0073", b"\\u0074", b"\\u0075", b"\\u0076", b"\\u0077",
    b"\\u0078", b"\\u0079", b"\\u007a", b"\\u007b", b"\\u007c", b"\\u007d", b"\\u007e", b"\\u007f",
    b"\\u0080", b"\\u0081", b"\\u0082", b"\\u0083", b"\\u0084", b"\\u0085", b"\\u0086", b"\\u0087",
    b"\\u0088", b"\\u0089", b"\\u008a", b"\\u008b", b"\\u008c", b"\\u008d", b"\\u008e", b"\\u008f",
    b"\\u0090", b"\\u0091", b"\\u0092", b"\\u0093", b"\\u0094", b"\\u0095", b"\\u0096", b"\\u0097",
    b"\\u0098", b"\\u0099", b"\\u009a", b"\\u009b", b"\\u009c", b"\\u009d", b"\\u009e", b"\\u009f",
    b"\\u00a0", b"\\u00a1", b"\\u00a2", b"\\u00a3", b"\\u00a4", b"\\u00a5", b"\\u00a6", b"\\u00a7",
    b"\\u00a8", b"\\u00a9", b"\\u00aa", b"\\u00ab", b"\\u00ac", b"\\u00ad", b"\\u00ae", b"\\u00af",
    b"\\u00b0", b"\\u00b1", b"\\u00b2", b"\\u00b3", b"\\u00b4", b"\\u00b5", b"\\u00b6", b"\\u00b7",
    b"\\u00b8", b"\\u00b9", b"\\u00ba", b"\\u00bb", b"\\u00bc", b"\\u00bd", b"\\u00be", b"\\u00bf",
    b"\\u00c0", b"\\u00c1", b"\\u00c2", b"\\u00c3", b"\\u00c4", b"\\u00c5", b"\\u00c6", b"\\u00c7",
    b"\\u00c8", b"\\u00c9", b"\\u00ca", b"\\u00cb", b"\\u00cc", b"\\u00cd", b"\\u00ce", b"\\u00cf",
    b"\\u00d0", b"\\u00d1", b"\\u00d2", b"\\u00d3", b"\\u00d4", b"\\u00d5", b"\\u00d6", b"\\u00d7",
    b"\\u00d8", b"\\u00d9", b"\\u00da", b"\\u00db", b"\\u00dc", b"\\u00dd", b"\\u00de", b"\\u00df",
    b"\\u00e0", b"\\u00e1", b"\\u00e2", b"\\u00e3", b"\\u00e4", b"\\u00e5", b"\\u00e6", b"\\u00e7",
    b"\\u00e8", b"\\u00e9", b"\\u00ea", b"\\u00eb", b"\\u00ec", b"\\u00ed", b"\\u00ee", b"\\u00ef",
    b"\\u00f0", b"\\u00f1", b"\\u00f2", b"\\u00f3", b"\\u00f4", b"\\u00f5", b"\\u00f6", b"\\u00f7",
    b"\\u00f8", b"\\u00f9", b"\\u00fa", b"\\u00fb", b"\\u00fc", b"\\u00fd", b"\\u00fe", b"\\u00ff",
];

/// Lookup table: HTML_TABLE[b] = b"&#xN;" or b"&#xNN;" for each byte value.
/// Eliminates `format!("&#x{b:x};")` allocation in the per-byte hot loop.
/// Entries are stored as slices into static byte strings.
static HTML_TABLE: &[&[u8]; 256] = &[
    b"&#x0;", b"&#x1;", b"&#x2;", b"&#x3;", b"&#x4;", b"&#x5;", b"&#x6;", b"&#x7;", b"&#x8;",
    b"&#x9;", b"&#xa;", b"&#xb;", b"&#xc;", b"&#xd;", b"&#xe;", b"&#xf;", b"&#x10;", b"&#x11;",
    b"&#x12;", b"&#x13;", b"&#x14;", b"&#x15;", b"&#x16;", b"&#x17;", b"&#x18;", b"&#x19;",
    b"&#x1a;", b"&#x1b;", b"&#x1c;", b"&#x1d;", b"&#x1e;", b"&#x1f;", b"&#x20;", b"&#x21;",
    b"&#x22;", b"&#x23;", b"&#x24;", b"&#x25;", b"&#x26;", b"&#x27;", b"&#x28;", b"&#x29;",
    b"&#x2a;", b"&#x2b;", b"&#x2c;", b"&#x2d;", b"&#x2e;", b"&#x2f;", b"&#x30;", b"&#x31;",
    b"&#x32;", b"&#x33;", b"&#x34;", b"&#x35;", b"&#x36;", b"&#x37;", b"&#x38;", b"&#x39;",
    b"&#x3a;", b"&#x3b;", b"&#x3c;", b"&#x3d;", b"&#x3e;", b"&#x3f;", b"&#x40;", b"&#x41;",
    b"&#x42;", b"&#x43;", b"&#x44;", b"&#x45;", b"&#x46;", b"&#x47;", b"&#x48;", b"&#x49;",
    b"&#x4a;", b"&#x4b;", b"&#x4c;", b"&#x4d;", b"&#x4e;", b"&#x4f;", b"&#x50;", b"&#x51;",
    b"&#x52;", b"&#x53;", b"&#x54;", b"&#x55;", b"&#x56;", b"&#x57;", b"&#x58;", b"&#x59;",
    b"&#x5a;", b"&#x5b;", b"&#x5c;", b"&#x5d;", b"&#x5e;", b"&#x5f;", b"&#x60;", b"&#x61;",
    b"&#x62;", b"&#x63;", b"&#x64;", b"&#x65;", b"&#x66;", b"&#x67;", b"&#x68;", b"&#x69;",
    b"&#x6a;", b"&#x6b;", b"&#x6c;", b"&#x6d;", b"&#x6e;", b"&#x6f;", b"&#x70;", b"&#x71;",
    b"&#x72;", b"&#x73;", b"&#x74;", b"&#x75;", b"&#x76;", b"&#x77;", b"&#x78;", b"&#x79;",
    b"&#x7a;", b"&#x7b;", b"&#x7c;", b"&#x7d;", b"&#x7e;", b"&#x7f;", b"&#x80;", b"&#x81;",
    b"&#x82;", b"&#x83;", b"&#x84;", b"&#x85;", b"&#x86;", b"&#x87;", b"&#x88;", b"&#x89;",
    b"&#x8a;", b"&#x8b;", b"&#x8c;", b"&#x8d;", b"&#x8e;", b"&#x8f;", b"&#x90;", b"&#x91;",
    b"&#x92;", b"&#x93;", b"&#x94;", b"&#x95;", b"&#x96;", b"&#x97;", b"&#x98;", b"&#x99;",
    b"&#x9a;", b"&#x9b;", b"&#x9c;", b"&#x9d;", b"&#x9e;", b"&#x9f;", b"&#xa0;", b"&#xa1;",
    b"&#xa2;", b"&#xa3;", b"&#xa4;", b"&#xa5;", b"&#xa6;", b"&#xa7;", b"&#xa8;", b"&#xa9;",
    b"&#xaa;", b"&#xab;", b"&#xac;", b"&#xad;", b"&#xae;", b"&#xaf;", b"&#xb0;", b"&#xb1;",
    b"&#xb2;", b"&#xb3;", b"&#xb4;", b"&#xb5;", b"&#xb6;", b"&#xb7;", b"&#xb8;", b"&#xb9;",
    b"&#xba;", b"&#xbb;", b"&#xbc;", b"&#xbd;", b"&#xbe;", b"&#xbf;", b"&#xc0;", b"&#xc1;",
    b"&#xc2;", b"&#xc3;", b"&#xc4;", b"&#xc5;", b"&#xc6;", b"&#xc7;", b"&#xc8;", b"&#xc9;",
    b"&#xca;", b"&#xcb;", b"&#xcc;", b"&#xcd;", b"&#xce;", b"&#xcf;", b"&#xd0;", b"&#xd1;",
    b"&#xd2;", b"&#xd3;", b"&#xd4;", b"&#xd5;", b"&#xd6;", b"&#xd7;", b"&#xd8;", b"&#xd9;",
    b"&#xda;", b"&#xdb;", b"&#xdc;", b"&#xdd;", b"&#xde;", b"&#xdf;", b"&#xe0;", b"&#xe1;",
    b"&#xe2;", b"&#xe3;", b"&#xe4;", b"&#xe5;", b"&#xe6;", b"&#xe7;", b"&#xe8;", b"&#xe9;",
    b"&#xea;", b"&#xeb;", b"&#xec;", b"&#xed;", b"&#xee;", b"&#xef;", b"&#xf0;", b"&#xf1;",
    b"&#xf2;", b"&#xf3;", b"&#xf4;", b"&#xf5;", b"&#xf6;", b"&#xf7;", b"&#xf8;", b"&#xf9;",
    b"&#xfa;", b"&#xfb;", b"&#xfc;", b"&#xfd;", b"&#xfe;", b"&#xff;",
];

fn in_scope(b: u8, s: Scope) -> bool {
    match s {
        Scope::All => true,
        Scope::Danger => DANGER.contains(&b),
    }
}

/// Percent-encode `input`. Uses a precomputed lookup table — zero `format!`
/// calls, no per-byte heap allocation.
fn pct_encode(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(PCT_TABLE[b as usize]);
        } else {
            out.push(b);
        }
    }
    out
}

/// JSON-escape `input` as `\uXXXX`. Uses a precomputed lookup table —
/// zero `format!` calls, no per-byte heap allocation.
fn json_escape(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 6);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(JSON_TABLE[b as usize]);
        } else {
            out.push(b);
        }
    }
    out
}

/// HTML-entity-encode `input` as `&#xN;`. Uses a precomputed lookup table —
/// zero `format!` calls, no per-byte heap allocation.
fn html_entity_encode(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 6);
    for &b in input {
        if in_scope(b, scope) {
            out.extend_from_slice(HTML_TABLE[b as usize]);
        } else {
            out.push(b);
        }
    }
    out
}

/// Homoglyph-encode `input`: replace each in-scope ASCII character with a
/// single codepoint that the origin normalizer `first` folds back to it. This
/// is the structural inverse of a text-normalizing sink — the exact dual of
/// [`pct_encode`] for a URL-decoding sink. Characters that are non-ASCII,
/// out-of-scope, or have no preimage pass through, so
/// `origin_normalize(homoglyph_encode(x)) == x` by construction (and the
/// caller's reconstruction gate re-checks it, so an unsound fold can never
/// escape as a fabricated bypass). Invalid UTF-8 passes through unchanged.
fn homoglyph_encode(input: &[u8], scope: Scope, first: fn(char) -> Option<char>) -> Vec<u8> {
    match std::str::from_utf8(input) {
        Ok(s) => {
            let mut out = String::with_capacity(s.len() * 2);
            for c in s.chars() {
                if c.is_ascii()
                    && in_scope(c as u8, scope)
                    && let Some(h) = first(c)
                {
                    out.push(h);
                    continue;
                }
                out.push(c);
            }
            out.into_bytes()
        }
        Err(_) => input.to_vec(),
    }
}

/// Inject a NUL after each in-scope byte — the structural inverse of an origin
/// that strips NULs. `strip_nulls(null_inject(x)) == x` for any NUL-free `x`
/// (attacks are NUL-free), since stripping removes exactly the injected NULs.
fn null_inject(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        out.push(b);
        if in_scope(b, scope) {
            out.push(0);
        }
    }
    out
}

/// Overlong-UTF-8-encode each in-scope ASCII byte as its non-canonical 2-byte
/// form — the structural inverse of an origin that overlong-decodes.
/// `overlong_decode(overlong_encode(b)) == b` for `b <= 0x7F`. Non-ASCII bytes
/// have no 2-byte overlong form, so they pass through unchanged.
fn overlong_encode(input: &[u8], scope: Scope) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        if b <= 0x7F && in_scope(b, scope) {
            out.push(0xC0 | (b >> 6));
            out.push(0x80 | (b & 0x3F));
        } else {
            out.push(b);
        }
    }
    out
}

/// The structural inverse of one stage: bytes that this stage decodes
/// back to its input. `None` ⇒ the stage is not a decoder the solver
/// can invert (it is treated as identity in the preimage).
fn stage_inverse(stage: &Stage, input: &[u8], scope: Scope) -> Vec<u8> {
    match stage {
        Stage::UrlDecode { .. } => pct_encode(input, scope),
        Stage::DoubleUrlDecode => pct_encode(&pct_encode(input, scope), scope),
        Stage::JsonUnescape => json_escape(input, scope),
        Stage::HtmlEntityDecode => html_entity_encode(input, scope),
        // Origin Unicode-normalization stages: the preimage is a homoglyph
        // form the normalizer collapses back to the attack. The map lives in
        // wafrift-grammar (single source); the solver only composes it.
        Stage::NfkcNormalize => homoglyph_encode(input, scope, nfkc_preimage::first_preimage),
        Stage::BestFitDownconvert => homoglyph_encode(input, scope, bestfit::first_preimage),
        Stage::StripNulls => null_inject(input, scope),
        Stage::OverlongUtf8Decode => overlong_encode(input, scope),
        // Whole-value transform: base64 reshapes the entire field, so the
        // inverse encodes all of `input` regardless of `scope` (you cannot
        // base64 only the dangerous bytes of a token and have it decode back).
        Stage::Base64Decode => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes()
        }
        // Whole-value transform (like base64): hex-encode all of `input`.
        Stage::HexDecode => hex::encode(input).into_bytes(),
        Stage::Identity | Stage::CrsView(_) => input.to_vec(),
    }
}

/// The structural preimage of `attack` under `sink`: compose each
/// stage's inverse encoder in reverse pipeline order, so that
/// `sink.apply(preimage) == attack` by construction.
fn structural_preimage(attack: &[u8], sink: &Pipeline, scope: Scope) -> Vec<u8> {
    sink.0
        .iter()
        .rev()
        .fold(attack.to_vec(), |acc, st| stage_inverse(st, &acc, scope))
}

/// The structural preimage of `attack` under `sink` (encode every
/// dangerous byte, or every byte). `sink.apply(result)` reconstructs
/// `attack` by construction — public so the equiv bridge can mint
/// pipeline-conditioned members without re-deriving the inversion.
#[must_use]
pub fn preimage_for(attack: &[u8], sink: &Pipeline, encode_all: bool) -> Vec<u8> {
    structural_preimage(
        attack,
        sink,
        if encode_all {
            Scope::All
        } else {
            Scope::Danger
        },
    )
}

/// A solved end-to-end bypass.
#[derive(Debug, Clone)]
pub struct Solution {
    /// The input bytes to send (the solved preimage).
    pub input: Vec<u8>,
    /// Human label of the encoding the solver derived (not chosen from
    /// a list — describes the structural preimage it computed).
    pub encoding: String,
    /// Whether the *raw* attack is blocked by this WAF. Always `true` for a
    /// returned `Solution`: [`solve_bypass`] never yields one when the raw
    /// attack already passes (that would be the vacuous never-policed case).
    /// Retained as a proof-carrying field the control tests assert.
    pub raw_attack_blocked: bool,
    /// What the sink reconstructed (must contain the attack).
    pub sink_view: Vec<u8>,
}

/// Solve for an input that bypasses `oracle` yet still delivers
/// `attack` through `sink`. `build` turns candidate bytes into the
/// request shape under test (so the same solver works against a
/// learned model, a `SimRegexWaf`, or a live target).
///
/// CEGIS: candidates are ordered minimal-first (encode only dangerous
/// bytes) then escalated (encode everything); each is *verified*
/// against the real oracle and the real sink. `None` ⇒ no bypass —
/// either the raw attack is **not blocked** (nothing to bypass; the
/// never-policed case) or it is blocked but no structural preimage
/// passes this pipeline (e.g. an identity sink). Both are reported
/// honestly as `None`, never a fabricated bypass.
pub fn solve_bypass<B>(
    attack: &[u8],
    sink: &Pipeline,
    oracle: &mut dyn WafOracle,
    build: &B,
) -> Result<Option<Solution>>
where
    B: Fn(&[u8]) -> Request,
{
    // The raw attack is the control: confirm the WAF actually blocks it.
    // If it does NOT, the attack already reaches the sink unmodified — there
    // is nothing to bypass, and any candidate that "passes" merely reproduces
    // that fact. Returning a Solution here is the vacuous / never-policed
    // false-positive class (#7). Fail closed: report no bypass and let the
    // caller distinguish "not policed" from "blocked-but-unbypassable" with
    // this same control probe.
    let raw_blocked = matches!(oracle.classify(&build(attack))?, Outcome::Block);
    if !raw_blocked {
        return Ok(None);
    }

    for scope in [Scope::Danger, Scope::All] {
        let cand = structural_preimage(attack, sink, scope);
        // The sink must reconstruct the literal attack.
        let sink_view = sink.apply(&cand);
        let reconstructs = sink_view.windows(attack.len()).any(|w| w == attack);
        if !reconstructs {
            continue;
        }
        // The WAF must pass the candidate while the raw attack did not — a
        // genuine bypass (raw_blocked is true here by the guard above).
        let passes = matches!(oracle.classify(&build(&cand))?, Outcome::Pass);
        if passes {
            return Ok(Some(Solution {
                input: cand,
                encoding: format!(
                    "structural-preimage[raw-blocked]({} stages, scope={scope:?})",
                    sink.len(),
                ),
                raw_attack_blocked: true,
                sink_view,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod speed_tests {
    use super::*;

    /// Pins the lookup-table encoder throughput: encoding 10 KiB of
    /// "dangerous" bytes must complete in under 2 ms.  Pre-fix this
    /// was slower due to per-byte `format!()` calls; post-fix all 256
    /// byte encodings are pure table lookups with no heap allocation.
    #[test]
    fn pct_encode_table_throughput() {
        // 10 KiB of DANGER bytes (worst case: every byte needs encoding).
        let input: Vec<u8> = std::iter::repeat_n(b'<', 10 * 1024).collect();
        let start = std::time::Instant::now();
        let out = pct_encode(&input, Scope::All);
        let elapsed = start.elapsed();
        // Every '<' → "%3C" (3 bytes), so output is 30 KiB.
        assert_eq!(out.len(), input.len() * 3);
        assert!(
            elapsed < std::time::Duration::from_millis(2),
            "pct_encode 10 KiB took {elapsed:?}; expected < 2 ms"
        );
    }

    #[test]
    fn json_escape_table_throughput() {
        let input: Vec<u8> = std::iter::repeat_n(b'"', 10 * 1024).collect();
        let start = std::time::Instant::now();
        let out = json_escape(&input, Scope::All);
        let elapsed = start.elapsed();
        // Every '"' → "\\u0022" (6 bytes)
        assert_eq!(out.len(), input.len() * 6);
        assert!(
            elapsed < std::time::Duration::from_millis(3),
            "json_escape 10 KiB took {elapsed:?}; expected < 3 ms"
        );
    }

    #[test]
    fn html_encode_table_throughput() {
        let input: Vec<u8> = std::iter::repeat_n(b'<', 10 * 1024).collect();
        let start = std::time::Instant::now();
        let out = html_entity_encode(&input, Scope::All);
        let elapsed = start.elapsed();
        // Every '<' → "&#x3c;" (6 bytes)
        assert_eq!(out.len(), input.len() * 6);
        assert!(
            elapsed < std::time::Duration::from_millis(3),
            "html_entity_encode 10 KiB took {elapsed:?}; expected < 3 ms"
        );
    }

    /// Correctness: table output must match what `format!` would produce.
    #[test]
    fn pct_table_matches_format_output() {
        for b in 0u8..=255 {
            let table_out = PCT_TABLE[b as usize];
            let fmt_out = format!("%{b:02X}");
            assert_eq!(
                table_out,
                fmt_out.as_bytes(),
                "PCT_TABLE[{b}] mismatch: {:?} vs {:?}",
                table_out,
                fmt_out
            );
        }
    }

    #[test]
    fn json_table_matches_format_output() {
        for b in 0u8..=255 {
            let table_out = JSON_TABLE[b as usize];
            let fmt_out = format!("\\u{b:04x}");
            assert_eq!(
                table_out,
                fmt_out.as_bytes(),
                "JSON_TABLE[{b}] mismatch: {:?} vs {:?}",
                table_out,
                fmt_out
            );
        }
    }

    #[test]
    fn html_table_matches_format_output() {
        for b in 0u8..=255 {
            let table_out = HTML_TABLE[b as usize];
            let fmt_out = format!("&#x{b:x};");
            assert_eq!(
                table_out,
                fmt_out.as_bytes(),
                "HTML_TABLE[{b}] mismatch: {:?} vs {:?}",
                table_out,
                fmt_out
            );
        }
    }

    /// Pins `overlong_encode`'s exact bytes: every ASCII byte becomes its
    /// canonical non-shortest 2-byte UTF-8 form `[0xC0 | (b >> 6), 0x80 | (b &
    /// 0x3F)]`, and every non-ASCII byte passes through untouched. This is the
    /// structural inverse of `Stage::OverlongUtf8Decode`, so the precise bytes
    /// are the contract — asserting the length alone would be decoration.
    ///
    /// Anti-rig (E5): asserting the exact bytes kills the shift-direction
    /// mutant `b >> 6 -> b << 6` (which corrupts the lead byte whenever b has
    /// bit 0/1 set — e.g. 'A' would emit 0xC0 instead of 0xC1) and the
    /// scope-guard mutant `&& -> ||` (which would wrongly overlong-encode the
    /// pass-through non-ASCII bytes instead of leaving them intact).
    #[test]
    fn overlong_encode_emits_canonical_two_byte_form_for_ascii_only() {
        // Every ASCII byte under Scope::All maps to its 2-byte overlong form.
        for b in 0u8..=0x7F {
            assert_eq!(
                overlong_encode(&[b], Scope::All),
                vec![0xC0 | (b >> 6), 0x80 | (b & 0x3F)],
                "ASCII {b:#04x} must overlong-encode to the canonical 2-byte form"
            );
        }
        // Concrete lead-byte witness: 'A' (0x41) has bit 0 set, so b >> 6 == 1
        // gives 0xC1; the b << 6 mutant would truncate to 0xC0.
        assert_eq!(overlong_encode(b"A", Scope::All), vec![0xC1, 0x81]);

        // Non-ASCII bytes (> 0x7F) have no 2-byte overlong form and MUST pass
        // through unchanged even when in scope — this is exactly what the `&&`
        // scope guard protects and `||` would break.
        for b in 0x80u8..=0xFF {
            assert_eq!(
                overlong_encode(&[b], Scope::All),
                vec![b],
                "non-ASCII {b:#04x} must pass through unchanged"
            );
        }
    }
}
