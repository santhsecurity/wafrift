//! String literal and whitespace mutation helpers.
use std::fmt::Write as _;
/// Split a string value into concatenated fragments.
pub(crate) fn split_string_concat(value: &str) -> Vec<String> {
    if value.len() < 2 {
        return vec![value.to_string()];
    }

    let mut results = Vec::new();
    for split_index in 1..value.len() {
        let left = &value[..split_index];
        let right = &value[split_index..];
        results.push(format!("'{left}'||'{right}'"));
        results.push(format!("CONCAT('{left}','{right}')"));
        results.push(format!("'{left}'+'{right}'"));
    }

    let limit = value.len().min(10);
    let my_sql_chars = value[..limit]
        .chars()
        .map(|character| format!("CHAR({})", character as u32))
        .collect::<Vec<_>>()
        .join("||");
    results.push(my_sql_chars);

    let pg_chars = value[..limit]
        .chars()
        .map(|character| format!("CHR({})", character as u32))
        .collect::<Vec<_>>()
        .join("||");
    results.push(pg_chars);

    let ms_sql_chars = value[..limit]
        .chars()
        .map(|character| format!("NCHAR({})", character as u32))
        .collect::<Vec<_>>()
        .join("+");
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
