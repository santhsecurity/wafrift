//! Built-in tamper strategy implementations.

use super::TamperStrategy;

/// URL encoding tamper strategy.
pub struct UrlEncodeTamper;

impl TamperStrategy for UrlEncodeTamper {
    fn name(&self) -> &'static str {
        "url_encode"
    }

    fn description(&self) -> &'static str {
        "Standard URL encoding (%XX for each byte)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.15
    }
}

/// Double URL encoding tamper strategy.
pub struct DoubleUrlEncodeTamper;

impl TamperStrategy for DoubleUrlEncodeTamper {
    fn name(&self) -> &'static str {
        "double_url_encode"
    }

    fn description(&self) -> &'static str {
        "Double URL encoding (%25XX) — bypasses WAFs that decode once"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::double_url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.4
    }
}

/// Unicode escape tamper strategy.
pub struct UnicodeEscapeTamper;

impl TamperStrategy for UnicodeEscapeTamper {
    fn name(&self) -> &'static str {
        "unicode_escape"
    }

    fn description(&self) -> &'static str {
        "Unicode escape sequences (\\uXXXX)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::unicode_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// HTML entity tamper strategy.
pub struct HtmlEntityTamper;

impl TamperStrategy for HtmlEntityTamper {
    fn name(&self) -> &'static str {
        "html_entity"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding (&#xXX;)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::html_entity_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.3
    }
}

/// Case alternation tamper strategy.
pub struct CaseAlternationTamper;

impl TamperStrategy for CaseAlternationTamper {
    fn name(&self) -> &'static str {
        "case_alternation"
    }

    fn description(&self) -> &'static str {
        "Alternating upper/lower case (SeLeCt)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.1
    }
}

/// Random case tamper strategy.
pub struct RandomCaseTamper;

impl TamperStrategy for RandomCaseTamper {
    fn name(&self) -> &'static str {
        "random_case"
    }

    fn description(&self) -> &'static str {
        "Random mixed case"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::random_case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.12
    }
}

/// Whitespace insertion tamper strategy.
pub struct WhitespaceInsertionTamper;

impl TamperStrategy for WhitespaceInsertionTamper {
    fn name(&self) -> &'static str {
        "whitespace_insertion"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with tabs"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::whitespace_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.2
    }
}

/// SQL comment tamper strategy.
pub struct SqlCommentTamper;

impl TamperStrategy for SqlCommentTamper {
    fn name(&self) -> &'static str {
        "sql_comment"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with SQL comments (/**/)"
    }

    fn tamper(&self, payload: &str, context: Option<&str>) -> String {
        let _ = context;
        crate::encoding::keyword::sql_comment_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.25
    }
}

/// Null byte tamper strategy.
pub struct NullByteTamper;

impl TamperStrategy for NullByteTamper {
    fn name(&self) -> &'static str {
        "null_byte"
    }

    fn description(&self) -> &'static str {
        "Null byte injection (%00 or %00.jpg)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::null_byte_inject(payload)
            .expect("payload is &str so always valid UTF-8")
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// Overlong UTF-8 tamper strategy.
pub struct OverlongUtf8Tamper;

impl TamperStrategy for OverlongUtf8Tamper {
    fn name(&self) -> &'static str {
        "overlong_utf8"
    }

    fn description(&self) -> &'static str {
        "Overlong UTF-8 encoding for ASCII non-alphanumeric"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::overlong_utf8(payload)
            .expect("payload is &str so always valid UTF-8")
    }

    fn aggressiveness(&self) -> f64 {
        0.8
    }
}

/// Base64 tamper strategy.
pub struct Base64Tamper;

impl TamperStrategy for Base64Tamper {
    fn name(&self) -> &'static str {
        "base64"
    }

    fn description(&self) -> &'static str {
        "Base64 encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::base64_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.75
    }
}

/// Hex encoding tamper strategy.
pub struct HexEncodeTamper;

impl TamperStrategy for HexEncodeTamper {
    fn name(&self) -> &'static str {
        "hex_encode"
    }

    fn description(&self) -> &'static str {
        "Hexadecimal encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::hex_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.85
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_tamper() {
        let strategy = UrlEncodeTamper;
        assert_eq!(strategy.tamper("A<", None), "A%3C");
        assert_eq!(strategy.aggressiveness(), 0.15);
    }

    #[test]
    fn double_url_encode_tamper() {
        let strategy = DoubleUrlEncodeTamper;
        assert_eq!(strategy.tamper("A", None), "%2541");
        assert!(strategy.tamper("%20", None).contains("%25"));
    }

    #[test]
    fn case_alternation_tamper() {
        let strategy = CaseAlternationTamper;
        assert_eq!(strategy.tamper("select", None), "SeLeCt");
    }

    #[test]
    fn random_case_tamper() {
        let strategy = RandomCaseTamper;
        let result = strategy.tamper("select", None);
        assert_eq!(result.to_ascii_lowercase(), "select");
    }

    #[test]
    fn null_byte_with_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("file.php", None), "file.php%00.jpg");
    }

    #[test]
    fn null_byte_without_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("payload", None), "payload%00");
    }

    #[test]
    fn sql_comment_insertion() {
        let strategy = SqlCommentTamper;
        let result = strategy.tamper("SELECT * FROM users", Some("sql"));
        assert!(result.contains("/**/"));
        assert_eq!(result, "SELECT/**/*/**/FROM/**/users");
    }

    #[test]
    fn whitespace_insertion() {
        let strategy = WhitespaceInsertionTamper;
        let result = strategy.tamper("SELECT * FROM users", None);
        assert!(result.contains('\t'));
        assert_eq!(result, "SELECT\t*\tFROM\tusers");
    }

    #[test]
    fn base64_tamper() {
        let strategy = Base64Tamper;
        assert_eq!(strategy.tamper("hello", None), "aGVsbG8=");
    }

    #[test]
    fn hex_encode_tamper() {
        let strategy = HexEncodeTamper;
        assert_eq!(strategy.tamper("ABC", None), "414243");
    }

    #[test]
    fn unicode_escape_tamper() {
        let strategy = UnicodeEscapeTamper;
        assert_eq!(strategy.tamper("AB", None), "\\u0041\\u0042");
    }

    #[test]
    fn html_entity_tamper() {
        let strategy = HtmlEntityTamper;
        assert_eq!(strategy.tamper("<>", None), "&#x3C;&#x3E;");
    }

    #[test]
    fn overlong_utf8_tamper() {
        let strategy = OverlongUtf8Tamper;
        let result = strategy.tamper("/", None);
        assert!(result.contains("%C0"));
    }
}
