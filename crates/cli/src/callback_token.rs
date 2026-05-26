//! Shared OOB callback-token primitives. Both `wafrift listener` (the
//! receiver) and `wafrift scan` (the sender that embeds the token in
//! a payload and waits for the callback) consume this module — a
//! single source of truth for the token format means the receiver
//! and sender can never drift.
//!
//! Tokens are 128-bit, base32-encoded (RFC 4648 alphabet, no
//! padding) — URL-safe by construction so the operator can drop a
//! token into any URL path / query / header / body without further
//! encoding.

use rand::RngCore;

/// 128-bit randomness, encoded to base32 (26 ASCII chars).
/// Collision probability for N tokens is N² / 2^129 — same security
/// floor as UUIDv4.
#[must_use]
pub fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// RFC 4648 base32 (upper-case, no padding). 16-byte input -> 26
/// characters. Less code than a base32 crate dep would be, and
/// the alphabet + size is fixed for our use.
pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(char::from(ALPHABET[idx]));
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(char::from(ALPHABET[idx]));
    }
    out
}

/// Embed a fresh callback URL in `payload` everywhere it contains
/// the `{{CALLBACK}}` placeholder. The base URL is appended with
/// `/<token>` and the substitution is performed verbatim — no URL
/// encoding because the base32 alphabet (`A-Z2-7`) is already
/// URL-safe.
///
/// Returns `None` when no `{{CALLBACK}}` placeholder is present in
/// the payload (so the caller knows to skip the verification path
/// instead of generating a token nothing references).
///
/// All placeholder occurrences in a single payload share the SAME
/// token — that lets a payload include the callback in multiple
/// positions (e.g. SSRF in a Location-header + a body-side echo
/// channel) and still correlate to one observation.
#[must_use]
pub fn substitute(payload: &str, callback_base_url: &str) -> Option<Substitution> {
    if !payload.contains("{{CALLBACK}}") {
        return None;
    }
    let token = generate_token();
    let callback_url = format!("{}/{token}", callback_base_url.trim_end_matches('/'));
    let substituted = payload.replace("{{CALLBACK}}", &callback_url);
    Some(Substitution {
        payload: substituted,
        token,
        callback_url,
    })
}

/// Result of a callback substitution — the new payload, the token
/// that was inserted, and the full callback URL the operator can
/// search for in the listener log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    /// Payload bytes with `{{CALLBACK}}` replaced by `callback_url`.
    pub payload: String,
    /// The base32 token embedded in this variant. Unique per call.
    pub token: String,
    /// The full URL the target backend will fetch / reflect.
    pub callback_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_token_is_26_chars_base32() {
        let t = generate_token();
        assert_eq!(t.len(), 26);
        for c in t.chars() {
            assert!(
                c.is_ascii_uppercase() || ('2'..='7').contains(&c),
                "non-base32 char `{c}`"
            );
        }
    }

    #[test]
    fn one_thousand_tokens_do_not_collide() {
        let set: HashSet<String> = (0..1000).map(|_| generate_token()).collect();
        assert_eq!(set.len(), 1000, "collision in 1000-sample run");
    }

    #[test]
    fn base32_encode_known_vectors_match_rfc_4648() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn substitute_returns_none_when_placeholder_absent() {
        let s = substitute("plain payload no placeholder", "http://callback:9000");
        assert!(s.is_none());
    }

    #[test]
    fn substitute_replaces_placeholder_with_callback_url() {
        let s = substitute("<img src='{{CALLBACK}}/x.png'>", "http://callback:9000")
            .expect("placeholder present");
        assert!(s.payload.contains(&s.callback_url));
        assert!(!s.payload.contains("{{CALLBACK}}"));
        assert!(s.callback_url.starts_with("http://callback:9000/"));
        assert!(s.callback_url.ends_with(&s.token));
    }

    #[test]
    fn substitute_trims_trailing_slash_in_base_url() {
        // The base URL might be passed with or without a trailing
        // slash; output should not double the slash.
        let s = substitute("{{CALLBACK}}", "http://h:9000/").expect("substituted");
        assert!(s.callback_url.starts_with("http://h:9000/"));
        // No "//" before the token (anchored at the token's start).
        assert!(
            !s.callback_url[..s.callback_url.rfind('/').unwrap()].contains("//h:9000")
                || s.callback_url.matches("//").count() == 1,
            "trailing slash should not duplicate: {}",
            s.callback_url
        );
    }

    #[test]
    fn substitute_all_occurrences_share_one_token() {
        // A payload with multiple `{{CALLBACK}}` placeholders gets
        // ONE token, substituted everywhere — so a single recorded
        // callback correlates to the variant uniquely.
        let s = substitute(
            "<img src='{{CALLBACK}}/a'><script>fetch('{{CALLBACK}}/b')</script>",
            "http://x:9000",
        )
        .expect("multi-occurrence");
        let occurrences = s.payload.matches(&s.token).count();
        assert_eq!(
            occurrences, 2,
            "both placeholders should have substituted; payload = {}",
            s.payload
        );
    }

    #[test]
    fn substitute_generates_distinct_tokens_per_call() {
        // Each call must produce a fresh token, otherwise correlating
        // a callback back to a specific variant is impossible.
        let mut tokens: HashSet<String> = HashSet::new();
        for _ in 0..200 {
            let s = substitute("{{CALLBACK}}", "http://x:9000").expect("substituted");
            assert!(tokens.insert(s.token.clone()), "duplicate token");
        }
    }

    #[test]
    fn substitute_payload_with_special_chars_keeps_them_intact() {
        // Anti-rig: the substitution must NOT mangle other bytes in
        // the payload — only the `{{CALLBACK}}` literal is touched.
        let payload = "<svg/onload=fetch('{{CALLBACK}}')>// 'quote' && cat";
        let s = substitute(payload, "http://x:9000").expect("substituted");
        assert!(s.payload.contains("<svg/onload="));
        assert!(s.payload.contains("'quote'"));
        assert!(s.payload.contains("&& cat"));
        assert!(!s.payload.contains("{{CALLBACK}}"));
    }
}
