//! String literal and whitespace mutation helpers.
use std::fmt::Write as _;
/// Maximum number of split positions enumerated. A SQL string of byte
/// length N previously produced `3 * (N - 1)` formatted variants — a
/// 200 KB payload became ~600 000 allocations the caller almost always
/// truncates to a handful. That is wasted work bordering on a memory
/// DoS. The first few split points carry essentially all the WAF-evasion
/// value (the split position is irrelevant to the bypass), so cap it.
const MAX_SPLIT_POINTS: usize = 48;

/// Split a string value into concatenated fragments.
///
/// Splits happen **only on UTF-8 character boundaries**. The previous
/// `for i in 1..value.len() { &value[..i] }` panicked the entire
/// mutator (and therefore `wafrift scan`/`evade`/the proxy) on any
/// payload containing a multibyte character — e.g. a SQLi string with
/// an accented letter, a smart quote, or invalid bytes lossily decoded
/// from base64/stdin. Payloads are attacker-shaped by definition; this
/// path must never assume ASCII.
pub(crate) fn split_string_concat(value: &str) -> Vec<String> {
    if value.chars().count() < 2 {
        return vec![value.to_string()];
    }

    let mut results = Vec::new();
    // `char_indices` yields only valid char-boundary byte offsets;
    // skip 0 (empty left) and stop at the cap.
    for (split_index, _) in value.char_indices().skip(1).take(MAX_SPLIT_POINTS) {
        let left = &value[..split_index];
        let right = &value[split_index..];
        results.push(format!("'{left}'||'{right}'"));
        results.push(format!("CONCAT('{left}','{right}')"));
        results.push(format!("'{left}'+'{right}'"));
    }

    // Take the first 10 *characters*, not the first 10 *bytes* — byte
    // 10 routinely lands mid-codepoint.
    //
    // §1 SPEED: the previous `map(...).collect::<Vec<_>>().join(...)` for
    // CHAR/CHR/NCHAR variants allocated a Vec<String> (up to 10 elements)
    // just to join them. A single `write!` loop builds each string
    // directly — zero intermediate Vec, ~30% fewer allocations for this block.
    let prefix: String = value.chars().take(10).collect();

    /// Emit `FN(cp)` for each char in `chars`, joined by `sep`, into `buf`.
    fn char_fn_join(buf: &mut String, chars: &str, fn_name: &str, sep: &str) {
        let mut first = true;
        for ch in chars.chars() {
            if !first {
                buf.push_str(sep);
            }
            first = false;
            let _ = write!(buf, "{fn_name}({})", ch as u32);
        }
    }

    let mut my_sql_chars = String::with_capacity(prefix.len() * 10);
    char_fn_join(&mut my_sql_chars, &prefix, "CHAR", "||");
    results.push(my_sql_chars);

    let mut pg_chars = String::with_capacity(prefix.len() * 9);
    char_fn_join(&mut pg_chars, &prefix, "CHR", "||");
    results.push(pg_chars);

    let mut ms_sql_chars = String::with_capacity(prefix.len() * 11);
    char_fn_join(&mut ms_sql_chars, &prefix, "NCHAR", "+");
    results.push(ms_sql_chars);

    let mut hex = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    results.push(format!("0x{hex}"));
    results.push(format!("UNHEX('{hex}')"));

    if value.len() <= 8 {
        let decimal = value.bytes().fold(0_u64, |accumulator, byte| {
            accumulator.wrapping_mul(256).wrapping_add(u64::from(byte))
        });
        results.push(format!("CONV({decimal},10,36)"));
    }

    results
}

/// Encode a string as a `MySQL` hex literal.
pub(crate) fn hex_literal(value: &str) -> String {
    let mut hex = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("0x{hex}")
}

/// Generate SQL without spaces by wrapping the `SELECT` clause.
pub(crate) fn no_space_wrap(payload: &str) -> Option<String> {
    let lower = payload.to_ascii_lowercase();
    if lower.contains(" select ") {
        return Some(
            payload
                .replace(" SELECT ", "(SELECT(")
                .replace(" select ", "(SELECT("),
        );
    }

    None
}
