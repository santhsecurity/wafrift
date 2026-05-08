#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::header::{
        HeaderTechnique, all_obfuscations, case_mix, comma_join, duplicate_header,
        lf_only_line_fold, lf_only_multi_line_fold, line_fold, multi_line_fold, null_byte_inject,
        tab_separator, trailing_space, underscore_substitute, whitespace_pad,
    };

    #[test]
    fn case_mix_alternates() {
        let result = case_mix("Content-Type");
        assert_ne!(result, "Content-Type");
        assert_eq!(result.to_ascii_lowercase(), "content-type");
    }

    #[test]
    fn case_mix_preserves_non_alpha() {
        let result = case_mix("X-Forwarded-For");
        assert!(result.contains('-'));
    }

    #[test]
    fn tab_separator_uses_tab() {
        let result = tab_separator("Content-Type", "application/json");
        assert!(result.contains(":\t"));
    }

    #[test]
    fn whitespace_padding_has_extra_spaces() {
        let result = whitespace_pad("Host", "example.com");
        assert!(result.starts_with("Host:"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn line_folding_splits_value() {
        let result = line_fold("Content-Type", "application/json");
        assert!(result.contains("\r\n\t"));
    }

    #[test]
    fn lf_only_line_folding_splits_value() {
        let result = lf_only_line_fold("Content-Type", "application/json");
        assert!(result.contains("\n\t"));
        assert!(!result.contains("\r\n"));
    }

    #[test]
    fn line_folding_short_value_no_split() {
        let result = line_fold("X", "ab");
        assert!(!result.contains("\r\n\t"));
    }

    #[test]
    fn multi_line_folding_three_parts() {
        let result = multi_line_fold("Content-Type", "application/json");
        assert!(
            result.matches("\r\n").count() >= 2,
            "should have at least 2 continuation lines: {result:?}"
        );
    }

    #[test]
    fn lf_only_multi_line_folding_three_parts() {
        let result = lf_only_multi_line_fold("Content-Type", "application/json");
        assert!(
            result.matches('\n').count() >= 2,
            "should have at least 2 continuation lines: {result:?}"
        );
        assert!(!result.contains("\r\n"));
    }

    #[test]
    fn multi_line_folding_short_no_split() {
        let result = multi_line_fold("X", "ab");
        assert!(!result.contains("\r\n"));
    }

    #[test]
    fn duplicate_header_produces_two() {
        let (benign, real) = duplicate_header("Authorization", "Bearer evil_token", "safe_value");
        assert!(benign.contains("safe_value"));
        assert!(real.contains("evil_token"));
    }

    #[test]
    fn underscore_substitution_replaces_hyphens() {
        assert_eq!(underscore_substitute("Content-Type"), "Content_Type");
        assert_eq!(underscore_substitute("X-Forwarded-For"), "X_Forwarded_For");
    }

    #[test]
    fn null_byte_injection_inserts_null() {
        let result = null_byte_inject("Content-Type");
        assert!(result.contains('\x00'), "should contain null byte");
        assert!(
            result.len() > "Content-Type".len(),
            "should be longer due to null byte"
        );
    }

    #[test]
    fn null_byte_short_name_no_panic() {
        let result = null_byte_inject("X");
        assert_eq!(result, "X");
    }

    #[test]
    fn trailing_space_before_colon() {
        let result = trailing_space("Content-Type", "text/html");
        assert!(
            result.contains(" : "),
            "should have space-colon-space: {result:?}"
        );
    }

    #[test]
    fn comma_join_combines_values() {
        let result = comma_join("Accept", "text/html", "safe_value");
        assert!(result.contains("safe_value, text/html"));
    }

    #[test]
    fn all_obfuscations_returns_all_techniques() {
        let obfs = all_obfuscations("Content-Type", "application/json");
        assert_eq!(obfs.len(), 12);
        let techniques: Vec<_> = obfs.iter().map(|(t, _)| *t).collect();
        assert!(techniques.contains(&HeaderTechnique::CaseMixing));
        assert!(techniques.contains(&HeaderTechnique::TabSeparator));
        assert!(techniques.contains(&HeaderTechnique::WhitespacePadding));
        assert!(techniques.contains(&HeaderTechnique::LineFolding));
        assert!(techniques.contains(&HeaderTechnique::LfOnlyLineFolding));
        assert!(techniques.contains(&HeaderTechnique::DuplicateHeader));
        assert!(techniques.contains(&HeaderTechnique::UnderscoreSubstitution));
        assert!(techniques.contains(&HeaderTechnique::NullByteInjection));
        assert!(techniques.contains(&HeaderTechnique::TrailingSpace));
        assert!(techniques.contains(&HeaderTechnique::MultiLineFolding));
        assert!(techniques.contains(&HeaderTechnique::LfOnlyMultiLineFolding));
        assert!(techniques.contains(&HeaderTechnique::CommaJoin));
    }

    #[test]
    fn header_technique_display() {
        assert_eq!(HeaderTechnique::CaseMixing.to_string(), "case-mixing");
        assert_eq!(
            HeaderTechnique::NullByteInjection.to_string(),
            "null-byte-injection"
        );
    }

    #[test]
    fn empty_header_name_doesnt_panic() {
        let _ = case_mix("");
        let _ = tab_separator("", "value");
        let _ = underscore_substitute("");
        let _ = null_byte_inject("");
        let _ = trailing_space("", "");
        let _ = comma_join("", "", "safe");
        let _ = multi_line_fold("", "");
        let _ = lf_only_multi_line_fold("", "");
    }

    #[test]
    fn techniques_are_unique() {
        let obfs = all_obfuscations("Host", "evil.com");
        let lines: Vec<&str> = obfs.iter().map(|(_, line)| line.as_str()).collect();
        let unique: std::collections::HashSet<&&str> = lines.iter().collect();
        assert_eq!(
            lines.len(),
            unique.len(),
            "all obfuscation lines should be unique"
        );
    }

    #[test]
    fn line_fold_multibyte_utf8() {
        let value = "日本語のテスト";
        let result = line_fold("X-Test", value);
        assert!(result.contains("\r\n\t"));
        // Should not panic and should preserve all chars
        assert!(result.contains("日"));
    }

    #[test]
    fn multi_line_fold_multibyte_utf8() {
        let value = "日本語のテストデータ";
        let result = multi_line_fold("X-Test", value);
        assert!(result.contains("\r\n"));
        assert!(result.contains("日"));
    }

    #[test]
    fn null_byte_inject_multibyte_utf8() {
        let result = null_byte_inject("日本語");
        assert!(result.contains('\x00'));
        assert!(result.contains("日"));
        assert!(result.contains("語"));
    }
}
