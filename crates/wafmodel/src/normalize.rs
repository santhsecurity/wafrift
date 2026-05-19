//! CRS input transformations — the decoding a ModSecurity/Coraza-class
//! WAF applies to a variable *before* matching a rule against it
//! (`t:urlDecodeUni`, `t:htmlEntityDecode`, `t:lowercase`, …).
//!
//! These are faithful to ModSecurity semantics, not approximations:
//! the whole reason WAF evasion exists is that the WAF normalizes
//! differently than the origin, and a sloppy model here would invent
//! bypasses that do not exist or hide ones that do. Each transform is
//! a total `Vec<u8> -> Vec<u8>` function; a pipeline is their left
//! fold. They double as the atomic transducers the P2 composition
//! solver composes.

/// One ModSecurity-style transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Transform {
    /// `t:urlDecodeUni` — decode `%XX` and `%uXXXX`. Invalid escapes
    /// are left literally (ModSecurity behaviour: a lone `%` or a
    /// short/invalid sequence is not consumed).
    UrlDecodeUni,
    /// `t:htmlEntityDecode` — decode `&#DD;`, `&#xHH;`, and the named
    /// entities ModSecurity recognises (`lt gt amp quot nbsp`). The
    /// trailing `;` is optional for numeric forms, matching libmodsec.
    HtmlEntityDecode,
    /// `t:lowercase`.
    Lowercase,
    /// `t:removeNulls` — drop NUL bytes.
    RemoveNulls,
    /// `t:compressWhitespace` — collapse runs of ASCII whitespace to a
    /// single space.
    CompressWhitespace,
    /// `t:removeWhitespace` — drop all ASCII whitespace.
    RemoveWhitespace,
}

impl Transform {
    /// Apply this single transform.
    #[must_use]
    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            Transform::UrlDecodeUni => url_decode_uni(input),
            Transform::HtmlEntityDecode => html_entity_decode(input),
            Transform::Lowercase => input.to_ascii_lowercase(),
            Transform::RemoveNulls => input.iter().copied().filter(|&b| b != 0).collect(),
            Transform::CompressWhitespace => compress_ws(input),
            Transform::RemoveWhitespace => input
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect(),
        }
    }
}

/// Left-fold a transform pipeline over `input` (the CRS `t:` chain
/// order is significant and preserved).
#[must_use]
pub fn apply_chain(chain: &[Transform], input: &[u8]) -> Vec<u8> {
    chain.iter().fold(input.to_vec(), |acc, t| t.apply(&acc))
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `%XX` / `%uXXXX` decode. A `%` that does not introduce a valid
/// escape is emitted literally and scanning continues at the next byte
/// (ModSecurity `urlDecodeUni`).
fn url_decode_uni(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            // %uXXXX
            if i + 5 < input.len()
                && (input[i + 1] | 0x20) == b'u'
                && let (Some(a), Some(b), Some(c), Some(d)) = (
                    hexval(input[i + 2]),
                    hexval(input[i + 3]),
                    hexval(input[i + 4]),
                    hexval(input[i + 5]),
                )
            {
                let cp =
                    (u32::from(a) << 12) | (u32::from(b) << 8) | (u32::from(c) << 4) | u32::from(d);
                // ModSecurity narrows %uXXXX to a byte (low 8 bits)
                // for the single-byte variable view; full-width
                // chars never reach the byte matcher.
                out.push((cp & 0xff) as u8);
                i += 6;
                continue;
            }
            // %XX
            if i + 2 < input.len()
                && let (Some(h), Some(l)) = (hexval(input[i + 1]), hexval(input[i + 2]))
            {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            // Invalid — literal `%`.
            out.push(b'%');
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Named entities ModSecurity's `htmlEntityDecode` recognises.
const NAMED: &[(&[u8], u8)] = &[
    (b"lt", b'<'),
    (b"gt", b'>'),
    (b"amp", b'&'),
    (b"quot", b'"'),
    (b"apos", b'\''),
    (b"nbsp", b' '),
];

fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        // Numeric: &#DD; or &#xHH;  (trailing ; optional)
        if rest.first() == Some(&b'#') {
            let (is_hex, mut j) = if rest.get(1).map(|c| c | 0x20) == Some(b'x') {
                (true, 2)
            } else {
                (false, 1)
            };
            let start = j;
            let mut val: u32 = 0;
            while j < rest.len() {
                let d = if is_hex {
                    hexval(rest[j]).map(u32::from)
                } else if rest[j].is_ascii_digit() {
                    Some(u32::from(rest[j] - b'0'))
                } else {
                    None
                };
                match d {
                    Some(d) => {
                        val = val
                            .saturating_mul(if is_hex { 16 } else { 10 })
                            .saturating_add(d);
                        j += 1;
                    }
                    None => break,
                }
            }
            if j > start {
                out.push((val & 0xff) as u8);
                i += 1 + j + usize::from(rest.get(j) == Some(&b';'));
                continue;
            }
        } else {
            // Named.
            let mut matched = None;
            for (name, ch) in NAMED {
                if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name) {
                    matched = Some((name.len(), *ch));
                    break;
                }
            }
            if let Some((nlen, ch)) = matched {
                out.push(ch);
                i += 1 + nlen + usize::from(rest.get(nlen) == Some(&b';'));
                continue;
            }
        }
        // Not an entity — literal `&`.
        out.push(b'&');
        i += 1;
    }
    out
}

fn compress_ws(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_ws = false;
    for &b in input {
        if b.is_ascii_whitespace() {
            if !in_ws {
                out.push(b' ');
                in_ws = true;
            }
        } else {
            out.push(b);
            in_ws = false;
        }
    }
    out
}
