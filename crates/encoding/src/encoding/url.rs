//! URL-based encoding strategies.
use std::fmt::Write as _;

/// RFC 3986 unreserved characters that should NOT be percent-encoded.
const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

fn is_unreserved(b: u8) -> bool {
    UNRESERVED.contains(&b)
}

/// Standard URL encoding — only encodes reserved and non-unreserved bytes.
#[must_use]
pub fn url_encode(payload: impl AsRef<[u8]>) -> String {
    let payload = payload.as_ref();
    let mut out = String::with_capacity(payload.len() * 3);

    for b in payload {
        if is_unreserved(*b) {
            out.push(*b as char);
        } else {
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

/// Lowercase hex variant of URL encoding.
#[must_use]
pub fn url_encode_lower(payload: impl AsRef<[u8]>) -> String {
    let payload = payload.as_ref();
    let mut out = String::with_capacity(payload.len() * 3);

    for b in payload {
        if is_unreserved(*b) {
            out.push(*b as char);
        } else {
            let _ = write!(&mut out, "%{b:02x}");
        }
    }
    out
}

/// Double URL encoding — every byte becomes `%25XX`.
///
/// Bypasses WAFs that decode URL encoding once before matching.
/// Pre-encoded `%XX` sequences are detected and only the `%` is
/// double-encoded to avoid triple-encoding artifacts.
#[must_use]
pub fn double_url_encode(payload: impl AsRef<[u8]>) -> String {
    let bytes = payload.as_ref();
    let mut result = String::with_capacity(bytes.len() * 4);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // Already-encoded %XX → double-encode the percent only
            result.push_str("%25");
            result.push(bytes[i + 1] as char);
            result.push(bytes[i + 2] as char);
            i += 3;
        } else {
            let _ = write!(&mut result, "%25{:02X}", bytes[i]);
            i += 1;
        }
    }
    result
}

/// Triple URL encoding — every byte becomes `%2525XX`.
///
/// For WAFs that decode URL encoding twice before rule matching.
/// Detects existing `%2525XX` sequences to avoid quadruple-encoding.
/// Single-encoded (`%XX`) and double-encoded (`%25XX`) sequences are
/// both converted to `%2525XX` (triple-encoded form).
#[must_use]
pub fn triple_url_encode(payload: impl AsRef<[u8]>) -> String {
    let bytes = payload.as_ref();
    let mut out = String::with_capacity(bytes.len() * 7);
    let mut i = 0;

    while i < bytes.len() {
        // Check for existing triple-encoded sequence %2525XX
        if bytes[i] == b'%'
            && i + 6 < bytes.len()
            && bytes[i + 1..i + 5].eq_ignore_ascii_case(b"2525")
            && bytes[i + 5].is_ascii_hexdigit()
            && bytes[i + 6].is_ascii_hexdigit()
        {
            // Preserve as-is
            for j in 0..7 {
                out.push(bytes[i + j] as char);
            }
            i += 7;
        }
        // Check for double-encoded sequence %25XX
        else if bytes[i] == b'%'
            && i + 4 < bytes.len()
            && bytes[i + 1..i + 3].eq_ignore_ascii_case(b"25")
            && bytes[i + 3].is_ascii_hexdigit()
            && bytes[i + 4].is_ascii_hexdigit()
        {
            out.push_str("%2525");
            out.push(bytes[i + 3] as char);
            out.push(bytes[i + 4] as char);
            i += 5;
        }
        // Check for single encoded %XX
        else if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push_str("%2525");
            out.push(bytes[i + 1] as char);
            out.push(bytes[i + 2] as char);
            i += 3;
        } else {
            let _ = write!(&mut out, "%2525{:02X}", bytes[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("A"), "A");
        assert_eq!(url_encode("AB"), "AB");
        assert_eq!(url_encode("A B"), "A%20B");
    }

    #[test]
    fn url_encode_preserves_unreserved() {
        // RFC 3986 unreserved: A-Za-z0-9-_.~
        assert_eq!(url_encode("A-Za-z0-9-_.~"), "A-Za-z0-9-_.~");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode(" "), "%20");
        assert_eq!(url_encode("="), "%3D");
        assert_eq!(url_encode("'"), "%27");
        assert_eq!(url_encode("/"), "%2F");
    }

    #[test]
    fn url_encode_accepts_raw_bytes() {
        assert_eq!(url_encode([0x00_u8, 0xFF, b'A']), "%00%FFA");
    }

    #[test]
    fn url_encode_lower_case() {
        assert_eq!(url_encode_lower(" /"), "%20%2f");
    }

    #[test]
    fn double_url_encode_basic() {
        assert_eq!(double_url_encode("A"), "%2541");
    }

    #[test]
    fn double_url_encode_preserves_existing() {
        let result = double_url_encode("%20");
        assert_eq!(result, "%2520");
    }

    #[test]
    fn triple_url_encode_basic() {
        assert_eq!(triple_url_encode("A"), "%252541");
    }

    #[test]
    fn triple_url_encode_preserves_double_encoded() {
        // Single-encoded %20 should become triple-encoded space
        let result = triple_url_encode("%20");
        assert_eq!(result, "%252520");
    }

    #[test]
    fn triple_url_encode_preserves_triple_encoded() {
        // Already triple-encoded should be preserved
        let result = triple_url_encode("%252541");
        assert_eq!(result, "%252541");
    }

    #[test]
    fn url_encode_empty() {
        assert_eq!(url_encode(""), "");
        assert_eq!(url_encode_lower(""), "");
        assert_eq!(double_url_encode(""), "");
        assert_eq!(triple_url_encode(""), "");
    }

    #[test]
    fn url_encode_sql_injection() {
        let encoded = url_encode("' OR 1=1--");
        assert!(encoded.contains("%27")); // '
        assert!(encoded.contains("%20")); // space
        assert!(!encoded.contains("%4F")); // O is unreserved
    }

    #[test]
    fn double_url_encode_trailing_percent() {
        // Input ending in bare '%' must not produce an incomplete %2 fragment.
        assert_eq!(double_url_encode("%"), "%2525");
        assert_eq!(double_url_encode("foo%"), "foo%2525");
        assert_eq!(double_url_encode("%2"), "%2525%2532");
        assert_eq!(double_url_encode("%G"), "%2525%2547");
    }

    #[test]
    fn triple_url_encode_trailing_percent() {
        assert_eq!(triple_url_encode("%"), "%252525");
        assert_eq!(triple_url_encode("foo%"), "foo%252525");
        assert_eq!(triple_url_encode("%2"), "%252525%252532");
        assert_eq!(triple_url_encode("%G"), "%252525%252547");
    }

    #[test]
    fn triple_url_encode_handles_double_encoded() {
        // %2520 is double-encoded space; triple-encoding should yield %252520.
        assert_eq!(triple_url_encode("%2520"), "%252520");
        // %2525 is double-encoded '%'; triple-encoding should yield %252525.
        assert_eq!(triple_url_encode("%2525"), "%252525");
        // Mixed: raw space + double-encoded space.
        assert_eq!(triple_url_encode(" %2520"), "%252520%252520");
        // Already triple-encoded must be preserved.
        assert_eq!(triple_url_encode("%252520"), "%252520");
    }
}
